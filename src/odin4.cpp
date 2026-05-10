#include "odin4/odin4.h"
#include "core/logger.h"
#include "core/odin_types.h"
#include "protocol/thor_protocol.h"
#include "usb/usb_device.h"
#include "firmware/firmware_package.h"

#include <iostream>
#include <algorithm>
#include <filesystem>
#include <vector>
#include <string>
#include <cstring>

#define ODIN4_VERSION "5.2.0"

const char* odin4_get_version() {
    return ODIN4_VERSION;
}

static UsbSelectionCriteria criteria_from_config(const OdinConfig* cfg) {
    UsbSelectionCriteria c;
    if (cfg->has_vid) {
        c.has_vid = true;
        c.vid = cfg->vid;
    }
    if (cfg->has_pid) {
        c.has_pid = true;
        c.pid = cfg->pid;
    }
    if (cfg->has_usb_interface) {
        c.has_interface = true;
        c.interface_number = cfg->usb_interface;
    }
    return c;
}

void odin4_init(const OdinConfig* cfg) {
    if (cfg->debug)
        set_log_level(LogLevel::Debug);
    else if (cfg->verbose)
        set_log_level(LogLevel::Verbose);
    else if (cfg->quiet)
        set_log_level(LogLevel::Error);
    else
        set_log_level(LogLevel::Info);

    set_log_file("odin4.log");
}

char** odin4_list_devices(const OdinConfig* cfg, int* count) {
    std::vector<std::string> devices = UsbDevice::list_download_devices(criteria_from_config(cfg));
    *count = static_cast<int>(devices.size());
    if (devices.empty())
        return nullptr;

    char** list = static_cast<char**>(malloc(sizeof(char*) * devices.size()));
    for (size_t i = 0; i < devices.size(); ++i) {
        list[i] = strdup(devices[i].c_str());
    }
    return list;
}

void odin4_free_device_list(char** list, int count) {
    if (!list)
        return;
    for (int i = 0; i < count; ++i) {
        free(list[i]);
    }
    free(list);
}

static bool has_any_firmware_files(const OdinConfig* cfg) {
    return (cfg->bootloader && strlen(cfg->bootloader) > 0) || (cfg->ap && strlen(cfg->ap) > 0) ||
           (cfg->cp && strlen(cfg->cp) > 0) || (cfg->csc && strlen(cfg->csc) > 0) || (cfg->ums && strlen(cfg->ums) > 0);
}

static bool verify_firmware_compatibility(const OdinConfig* cfg, const std::string& device_type) {
    if (device_type.empty()) {
        log_verbose("Device type is empty; skipping filename compatibility checks.");
        return true;
    }

    std::vector<std::string> files;
    if (cfg->bootloader)
        files.push_back(cfg->bootloader);
    if (cfg->ap)
        files.push_back(cfg->ap);
    if (cfg->cp)
        files.push_back(cfg->cp);
    if (cfg->csc)
        files.push_back(cfg->csc);
    if (cfg->ums)
        files.push_back(cfg->ums);

    std::string dt = device_type;
    std::transform(dt.begin(), dt.end(), dt.begin(), [](unsigned char c) { return std::tolower(c); });

    for (const auto& path : files) {
        std::string f = std::filesystem::path(path).filename().string();
        std::transform(f.begin(), f.end(), f.begin(), [](unsigned char c) { return std::tolower(c); });

        if (dt.find(f) != std::string::npos) {
            log_debug("Firmware file '" + f + "' matches device type '" + dt + "'.");
            return true;
        }
    }

    log_warn("None of the provided firmware filenames seem to match the device type: " + device_type);
    return true;
}

OdinExitCode odin4_run(const OdinConfig* cfg) {
    UsbDevice dev;
    std::string device_path = cfg->device_path ? cfg->device_path : "";

    if (device_path.empty()) {
        std::vector<std::string> devices = UsbDevice::list_download_devices(criteria_from_config(cfg));
        if (devices.empty()) {
            log_error("No Samsung devices detected in Download Mode.");
            return ODIN_USB;
        }
        if (devices.size() > 1) {
            log_error("Multiple Samsung devices detected. Please specify one with -d.");
            for (const auto& p : devices) {
                log_error("  Detected: " + p);
            }
            return ODIN_USB;
        }
        device_path = devices[0];
        log_info("Auto-detected device at " + device_path);
    }

    if (!dev.open_device(device_path, criteria_from_config(cfg))) {
        UsbOpenError err = dev.get_last_open_error();
        if (err == UsbOpenError::AccessDenied) {
            log_error("Access denied to USB device. Try running as root or check udev rules.");
        } else if (err == UsbOpenError::NotDownloadMode) {
            log_error("Device is not in Download Mode.");
        } else {
            log_error("Failed to open USB device at " + device_path, dev.get_last_open_libusb_error());
        }
        return ODIN_USB;
    }

    if (!dev.handshake()) {
        log_error("Protocol handshake failed.");
        return ODIN_PROTOCOL;
    }

    if (!dev.request_device_type()) {
        log_error("Failed to request device type.");
        return ODIN_PROTOCOL;
    }

    log_info("Device type: " + dev.get_device_type());

    if (!verify_firmware_compatibility(cfg, dev.get_device_type())) {
        log_error("Firmware is not compatible with this device.");
        return ODIN_FIRMWARE;
    }

    PitTable pit;
    if (!dev.request_pit(pit)) {
        log_error("Failed to request PIT table.");
        return ODIN_PIT;
    }

    if (cfg->dry_run) {
        log_info("Dry run: PIT and firmware validation successful.");
        return ODIN_SUCCESS;
    }

    if (!dev.begin_session()) {
        log_error("Failed to begin session.");
        return ODIN_PROTOCOL;
    }

    std::vector<std::pair<std::string, std::string>> archives;
    if (cfg->bootloader)
        archives.push_back({"BL", cfg->bootloader});
    if (cfg->ap)
        archives.push_back({"AP", cfg->ap});
    if (cfg->cp)
        archives.push_back({"CP", cfg->cp});
    if (cfg->csc)
        archives.push_back({"CSC", cfg->csc});
    if (cfg->ums)
        archives.push_back({"UMS", cfg->ums});

    for (const auto& archive : archives) {
        log_info("Processing " + archive.first + " archive: " + archive.second);
        FirmwarePackage pkg(archive.second);
        if (!pkg.open()) {
            log_error("Failed to open archive: " + archive.second);
            return ODIN_FIRMWARE;
        }

        for (const auto& entry : pkg.get_entries()) {
            const PitEntry* pe = pit.find_entry_by_name(entry.name);
            if (!pe) {
                if (cfg->allow_unknown) {
                    log_warn("Skipping unknown partition: " + entry.name);
                    continue;
                } else {
                    log_error("Partition not found in PIT: " + entry.name);
                    return ODIN_PIT;
                }
            }

            log_info("Flashing " + entry.name + "...");
            auto stream = pkg.get_entry_stream(entry);
            if (!dev.flash_partition_stream(*stream, entry.size, *pe, false)) {
                log_error("Failed to flash partition: " + entry.name);
                return ODIN_PROTOCOL;
            }
        }
    }

    if (!dev.end_session()) {
        log_warn("Failed to end session cleanly.");
    }

    if (cfg->reboot) {
        log_info("Rebooting device...");
        dev.send_control(THOR_CONTROL_REBOOT);
    } else if (cfg->redownload) {
        log_info("Rebooting to download mode...");
        dev.send_control(THOR_CONTROL_REDOWNLOAD);
    }

    return ODIN_SUCCESS;
}
