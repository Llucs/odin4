#include "odin4/odin4.h"
#include "core/logger.h"
#include "core/odin_types.h"
#include "protocol/thor_protocol.h"
#include "usb/usb_device.h"
#include "firmware/firmware_package.h"

#include <iostream>
#include <algorithm>
#include <filesystem>

#define ODIN4_VERSION "5.1.1-ef8f688"

auto odin4_get_version() -> const char* {
    return ODIN4_VERSION;
}

static auto criteria_from_config(const OdinConfig& cfg) -> UsbSelectionCriteria {
    UsbSelectionCriteria c;
    if (cfg.has_vid) {
        c.has_vid = true;
        c.vid = cfg.vid;
    }
    if (cfg.has_pid) {
        c.has_pid = true;
        c.pid = cfg.pid;
    }
    if (cfg.has_usb_interface) {
        c.has_interface = true;
        c.interface_number = cfg.usb_interface;
    }
    return c;
}

void odin4_init(const OdinConfig& cfg) {
    if (cfg.debug) {
        set_log_level(LogLevel::Debug);
    } else if (cfg.verbose) {
        set_log_level(LogLevel::Verbose);
    } else if (cfg.quiet) {
        set_log_level(LogLevel::Error);
    } else {
        set_log_level(LogLevel::Info);
    }

    set_log_file("odin4.log");
}

auto odin4_list_devices(const OdinConfig& cfg) -> std::vector<std::string> {
    return UsbDevice::list_download_devices(criteria_from_config(cfg));
}

static auto has_any_firmware_files(const OdinConfig& cfg) -> bool {
    return !cfg.bootloader.empty() || !cfg.ap.empty() || !cfg.cp.empty() || !cfg.csc.empty() || !cfg.ums.empty();
}

static auto verify_firmware_compatibility(const OdinConfig& cfg, const std::string& device_type) -> bool {
    if (device_type.empty()) {
        log_verbose("Device type is empty; skipping filename compatibility checks.");
        return true;
    }

    std::string dt = device_type;
    dt.erase(
        std::remove_if(dt.begin(), dt.end(),
                       [](unsigned char c) { return (std::isspace(c) != 0) || c == '\\' || c == '/' || c == '-'; }),
        dt.end());

    std::transform(dt.begin(), dt.end(), dt.begin(),
                   [](unsigned char c) { return static_cast<char>(std::toupper(c)); });

    if (dt.rfind("SM", 0) == 0) {
        dt = dt.substr(2);
    }

    auto file_matches = [&](const std::string& path) -> bool {
        if (path.empty()) {
            return true;
        }
        std::string fname = std::filesystem::path(path).filename().string();
        std::string f;
        f.reserve(fname.size());
        for (unsigned char c : fname) {
            if (std::isalnum(c) != 0) {
                f.push_back(static_cast<char>(std::toupper(c)));
            }
        }
        return f.find(dt) != std::string::npos;
    };

    for (const std::string& p : {cfg.bootloader, cfg.ap, cfg.cp, cfg.csc, cfg.ums}) {
        if (p.empty()) {
            continue;
        }
        if (!file_matches(p)) {
            log_error("Firmware file name does not appear to match device type: " +
                      std::filesystem::path(p).filename().string() + " vs " + device_type);
            return false;
        }
    }

    return true;
}

static void print_access_hint() {
    log_error("Permission denied while opening the USB device. This usually means udev rules are missing.");
    log_info("Install the udev rule shipped with odin4: udev/60-odin4.rules");
    log_info("Then reload udev rules and reconnect the device.");
}

static auto run_for_device(const OdinConfig& cfg) -> OdinExitCode {
    UsbDevice usb;
    const UsbSelectionCriteria criteria = criteria_from_config(cfg);

    if (!usb.open_device(cfg.device_path, criteria)) {
        if (usb.get_last_open_error() == UsbOpenError::AccessDenied) {
            print_access_hint();
        } else if (usb.get_last_open_error() == UsbOpenError::NotDownloadMode) {
            log_error("Device detected, but it does not appear to be in Download Mode.");
        } else {
            log_error("No compatible device could be opened. Ensure the device is in Download Mode and try again.");
        }
        return OdinExitCode::Usb;
    }

    if (!usb.handshake()) {
        log_error("USB handshake failed.");
        return OdinExitCode::Protocol;
    }
    log_info("Handshake successful.");

    if (!usb.request_device_type()) {
        log_error("Failed to query device type.");
        return OdinExitCode::Protocol;
    }

    const std::string device_type = usb.get_device_type();
    if (!device_type.empty()) {
        log_info("Device type: " + device_type);
    }

    if (has_any_firmware_files(cfg)) {
        if (!verify_firmware_compatibility(cfg, device_type)) {
            return OdinExitCode::Pit;
        }
    }

    if (!usb.begin_session()) {
        log_error("Failed to begin session.");
        return OdinExitCode::Protocol;
    }

    PitTable pit;
    if (!usb.request_pit(pit)) {
        log_error("Failed to retrieve or parse PIT from device.");
        usb.end_session();
        return OdinExitCode::Pit;
    }
    log_info("PIT received with " + std::to_string(pit.entries.size()) + " entries.");

    if (has_any_firmware_files(cfg)) {
        const std::vector<std::pair<std::string, std::string>> archives = {
            {"BL", cfg.bootloader}, {"AP", cfg.ap}, {"CP", cfg.cp}, {"CSC", cfg.csc}, {"UMS", cfg.ums}};

        if (usb.is_odin_legacy()) {
            uint64_t total_bytes = 0;
            for (const auto& item : archives) {
                if (item.second.empty()) {
                    continue;
                }
                std::error_code ec;
                auto sz = std::filesystem::file_size(item.second, ec);
                if (!ec) {
                    total_bytes += sz;
                }
            }
            if (total_bytes > 0 && !usb.notify_total_bytes(total_bytes)) {
                log_error("Failed to send total bytes to device.");
                usb.end_session();
                return OdinExitCode::Protocol;
            }
        }

        for (const auto& item : archives) {
            if (item.second.empty()) {
                continue;
            }
            ExitCode rc = process_tar_file(item.second, usb, pit, !cfg.dry_run, cfg.allow_unknown);
            if (rc != ExitCode::Success) {
                usb.end_session();
                return static_cast<OdinExitCode>(rc);
            }
        }
    }

    if (!cfg.dry_run) {
        if (cfg.reboot) {
            if (!usb.send_control(THOR_CONTROL_REBOOT)) {
                log_error("Failed to send reboot command.");
                usb.end_session();
                return OdinExitCode::Protocol;
            }
        }
        if (cfg.redownload) {
            if (!usb.send_control(THOR_CONTROL_REDOWNLOAD)) {
                log_error("Failed to send redownload command.");
                usb.end_session();
                return OdinExitCode::Protocol;
            }
        }
    } else {
        if (cfg.reboot || cfg.redownload) {
            log_verbose("Check-only mode: reboot/redownload commands skipped.");
        }
    }

    if (!usb.end_session()) {
        log_error("Failed to end session.");
        return OdinExitCode::Protocol;
    }

    if (cfg.dry_run) {
        log_info("Validation completed successfully (check-only).");
    } else if (has_any_firmware_files(cfg)) {
        log_info("Flashing completed successfully.");
    }

    return OdinExitCode::Success;
}

auto odin4_run(const OdinConfig& cfg) -> OdinExitCode {
    if (cfg.device_path.empty()) {
        const std::vector<std::string> devices = UsbDevice::list_download_devices(criteria_from_config(cfg));
        if (devices.empty()) {
            log_error("No compatible devices detected in Download Mode.");
            return OdinExitCode::Usb;
        }
        if (devices.size() > 1) {
            log_error("Multiple compatible devices detected in Download Mode. Use -d to select one device.");
            for (const auto& dev_path : devices) {
                log_info("Detected device: " + dev_path);
            }
            return OdinExitCode::Usb;
        }
        OdinConfig one = cfg;
        one.device_path = devices.front();
        log_info("Using device: " + one.device_path);
        return run_for_device(one);
    }

    return run_for_device(cfg);
}
