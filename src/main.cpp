// ============================================================================
// odin4 - Samsung Device Flashing Tool
// Protocol: Thor USB Communication
// ============================================================================

#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include <algorithm>
#include <cctype>
#include <filesystem>
#include <chrono>
#include <sstream>

#include <libusb.h>

#include "logger.h"
#include "odin_types.h"
#include "thor_protocol.h"
#include "usb_device.h"
#include "firmware_package.h"

#define ODIN4_VERSION "5.0.0-167ff56"

static void print_usage() {
    std::cout << "Usage: odin4 [options]" << std::endl;
    std::cout << "Samsung firmware flashing tool for Linux. Version: " << ODIN4_VERSION << std::endl;
    std::cout << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -h                  Show this help message" << std::endl;
    std::cout << "  -v                  Show version" << std::endl;
    std::cout << "  -w                  Show license" << std::endl;
    std::cout << "  -l                  List detected Download Mode devices" << std::endl;
    std::cout << "  -d <path>            Select a specific USB device path (e.g. /dev/bus/usb/001/002)" << std::endl;
    std::cout << "  -b <file>            Bootloader archive (.tar or .tar.md5)" << std::endl;
    std::cout << "  -a <file>            AP archive (.tar or .tar.md5)" << std::endl;
    std::cout << "  -c <file>            CP archive (.tar or .tar.md5)" << std::endl;
    std::cout << "  -s <file>            CSC archive (.tar or .tar.md5)" << std::endl;
    std::cout << "  -u <file>            UMS archive (.tar or .tar.md5)" << std::endl;
    std::cout << "  --check-only         Validate PIT + archives and exit without flashing" << std::endl;
    std::cout << "  --allow-unknown      Allow archive entries without a PIT match (disabled by default)" << std::endl;
    std::cout << "  --reboot             Reboot device after flashing" << std::endl;
    std::cout << "  --redownload         Reboot into download mode if supported" << std::endl;
    std::cout << std::endl;
    std::cout << "Logging:" << std::endl;
    std::cout << "  --quiet              Only print errors" << std::endl;
    std::cout << "  --verbose            More detailed logs" << std::endl;
    std::cout << "  --debug              Debug logs (includes USB packet hexdumps)" << std::endl;
    std::cout << std::endl;
    std::cout << "USB selection overrides (optional):" << std::endl;
    std::cout << "  --vid <hex>          Override USB vendor ID (hex, e.g. 04e8)" << std::endl;
    std::cout << "  --pid <hex>          Override USB product ID (hex)" << std::endl;
    std::cout << "  --usb-interface <n>  Force a specific USB interface number" << std::endl;
    std::cout << std::endl;
    std::cout << "Linux permissions:" << std::endl;
    std::cout << "  If you get LIBUSB_ERROR_ACCESS, install the provided udev rule:" << std::endl;
    std::cout << "    udev/60-odin4.rules -> /etc/udev/rules.d/60-odin4.rules" << std::endl;
}

static void print_version() {
    std::cout << "odin4 version " << ODIN4_VERSION << std::endl;
}

static void print_license() {
    std::cout << "odin4 — Open Odin Reimplementation" << std::endl;
    std::cout << std::endl;
    std::cout << "Copyright (c) 2026 Llucs" << std::endl;
    std::cout << std::endl;
    std::cout << "Licensed under the Apache License, Version 2.0 (the \"License\");" << std::endl;
    std::cout << "you may not use this software except in compliance with the License." << std::endl;
    std::cout << "You may obtain a copy of the License at:" << std::endl;
    std::cout << std::endl;
    std::cout << "  http://www.apache.org/licenses/LICENSE-2.0" << std::endl;
    std::cout << std::endl;
    std::cout << "This software is provided \"AS IS\", WITHOUT WARRANTIES OR CONDITIONS" << std::endl;
    std::cout << "OF ANY KIND, either express or implied." << std::endl;
}

static bool parse_hex_u16(const std::string& s, uint16_t& out) {
    std::string v = s;
    if (v.rfind("0x", 0) == 0 || v.rfind("0X", 0) == 0) v = v.substr(2);
    if (v.empty() || v.size() > 4) return false;
    for (unsigned char c : v) {
        if (!std::isxdigit(c)) return false;
    }
    try {
        out = static_cast<uint16_t>(std::stoul(v, nullptr, 16));
        return true;
    } catch (...) {
        return false;
    }
}

static bool parse_int(const std::string& s, int& out) {
    try {
        size_t idx = 0;
        int v = std::stoi(s, &idx, 10);
        if (idx != s.size()) return false;
        out = v;
        return true;
    } catch (...) {
        return false;
    }
}

static bool has_any_firmware_files(const OdinConfig& cfg) {
    return !cfg.bootloader.empty() || !cfg.ap.empty() || !cfg.cp.empty() || !cfg.csc.empty() || !cfg.ums.empty();
}

static UsbSelectionCriteria criteria_from_config(const OdinConfig& cfg) {
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

static void list_devices(const UsbSelectionCriteria& criteria) {
    const std::vector<std::string> devices = UsbDevice::list_download_devices(criteria);
    if (devices.empty()) {
        std::cout << "No devices detected in Download Mode." << std::endl;
        return;
    }
    for (const auto& path : devices) {
        std::cout << path << std::endl;
    }
}

static bool verify_firmware_compatibility(const OdinConfig& cfg, const std::string& device_type) {
    if (device_type.empty()) {
        log_verbose("Device type is empty; skipping filename compatibility checks.");
        return true;
    }

    std::string dt = device_type;
    dt.erase(std::remove_if(dt.begin(), dt.end(), [](unsigned char c) {
        return std::isspace(c) || c == '\\' || c == '/' || c == '-';
    }), dt.end());

    std::transform(dt.begin(), dt.end(), dt.begin(), [](unsigned char c) {
        return static_cast<char>(std::toupper(c));
    });

    if (dt.rfind("SM", 0) == 0) dt = dt.substr(2);

    auto file_matches = [&](const std::string& path) -> bool {
        if (path.empty()) return true;
        std::string fname = std::filesystem::path(path).filename().string();
        std::string f;
        f.reserve(fname.size());
        for (unsigned char c : fname) {
            if (std::isspace(c) || c == '-') continue;
            f.push_back(static_cast<char>(std::toupper(c)));
        }
        return f.find(dt) != std::string::npos;
    };

    for (const std::string& p : {cfg.bootloader, cfg.ap, cfg.cp, cfg.csc, cfg.ums}) {
        if (p.empty()) continue;
        if (!file_matches(p)) {
            log_error("Firmware file name does not appear to match device type: " + std::filesystem::path(p).filename().string() + " vs " + device_type);
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

static ExitCode run_for_device(const OdinConfig& cfg) {
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
        return ExitCode::Usb;
    }

    if (!usb.handshake()) {
        log_error("USB handshake failed.");
        return ExitCode::Protocol;
    }
    log_info("Handshake successful.");

    if (!usb.request_device_type()) {
        log_error("Failed to query device type.");
        return ExitCode::Protocol;
    }

    const std::string device_type = usb.get_device_type();
    if (!device_type.empty()) log_info("Device type: " + device_type);

    if (has_any_firmware_files(cfg)) {
        if (!verify_firmware_compatibility(cfg, device_type)) {
            return ExitCode::Pit;
        }
    }

    if (!usb.begin_session()) {
        log_error("Failed to begin session.");
        return ExitCode::Protocol;
    }

    PitTable pit;
    if (!usb.request_pit(pit)) {
        log_error("Failed to retrieve or parse PIT from device.");
        usb.end_session();
        return ExitCode::Pit;
    }
    log_info("PIT received with " + std::to_string(pit.entries.size()) + " entries.");

    if (has_any_firmware_files(cfg)) {
        const std::vector<std::pair<std::string, std::string>> archives = {
            {"BL", cfg.bootloader},
            {"AP", cfg.ap},
            {"CP", cfg.cp},
            {"CSC", cfg.csc},
            {"UMS", cfg.ums}
        };

        for (const auto& item : archives) {
            if (item.second.empty()) continue;
            ExitCode rc = process_tar_file(item.second, usb, pit, !cfg.dry_run, cfg.allow_unknown);
            if (rc != ExitCode::Success) {
                usb.end_session();
                return rc;
            }
        }
    }

    if (!cfg.dry_run) {
        if (cfg.reboot) {
            if (!usb.send_control(THOR_CONTROL_REBOOT)) {
                log_error("Failed to send reboot command.");
                usb.end_session();
                return ExitCode::Protocol;
            }
        }
        if (cfg.redownload) {
            if (!usb.send_control(THOR_CONTROL_REDOWNLOAD)) {
                log_error("Failed to send redownload command.");
                usb.end_session();
                return ExitCode::Protocol;
            }
        }
    } else {
        if (cfg.reboot || cfg.redownload) {
            log_verbose("Check-only mode: reboot/redownload commands skipped.");
        }
    }

    if (!usb.end_session()) {
        log_error("Failed to end session.");
        return ExitCode::Protocol;
    }

    if (cfg.dry_run) {
        log_info("Validation completed successfully (check-only)." );
    } else if (has_any_firmware_files(cfg)) {
        log_info("Flashing completed successfully.");
    }

    return ExitCode::Success;
}

static ExitCode process_arguments_and_run(int argc, char** argv) {
    OdinConfig cfg;

    auto apply_log_flags = [&]() {
        if (cfg.debug) set_log_level(LogLevel::Debug);
        else if (cfg.verbose) set_log_level(LogLevel::Verbose);
        else if (cfg.quiet) set_log_level(LogLevel::Error);
        else set_log_level(LogLevel::Info);
    };

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];

        if (arg == "-h") {
            print_usage();
            return ExitCode::Success;
        }
        if (arg == "-v") {
            print_version();
            return ExitCode::Success;
        }
        if (arg == "-w") {
            print_license();
            return ExitCode::Success;
        }

        if (arg == "--quiet") {
            cfg.quiet = true;
            cfg.verbose = false;
            cfg.debug = false;
            continue;
        }
        if (arg == "--verbose") {
            cfg.verbose = true;
            cfg.quiet = false;
            continue;
        }
        if (arg == "--debug") {
            cfg.debug = true;
            cfg.verbose = true;
            cfg.quiet = false;
            continue;
        }

        if (arg == "--reboot") {
            cfg.reboot = true;
            continue;
        }
        if (arg == "--redownload") {
            cfg.redownload = true;
            continue;
        }
        if (arg == "--check-only") {
            cfg.dry_run = true;
            continue;
        }
        if (arg == "--allow-unknown") {
            cfg.allow_unknown = true;
            continue;
        }

        auto take_value = [&](std::string& out) -> bool {
            if (i + 1 >= argc) return false;
            out = argv[++i];
            return true;
        };

        auto take_value_u16hex = [&](uint16_t& out) -> bool {
            if (i + 1 >= argc) return false;
            return parse_hex_u16(argv[++i], out);
        };

        auto take_value_int = [&](int& out) -> bool {
            if (i + 1 >= argc) return false;
            return parse_int(argv[++i], out);
        };

        if (arg == "--vid") {
            uint16_t v = 0;
            if (!take_value_u16hex(v)) {
                log_error("--vid requires a hex value");
                return ExitCode::Usage;
            }
            cfg.has_vid = true;
            cfg.vid = v;
            continue;
        }
        if (arg == "--pid") {
            uint16_t p = 0;
            if (!take_value_u16hex(p)) {
                log_error("--pid requires a hex value");
                return ExitCode::Usage;
            }
            cfg.has_pid = true;
            cfg.pid = p;
            continue;
        }
        if (arg == "--usb-interface") {
            int n = 0;
            if (!take_value_int(n) || n < 0 || n > 255) {
                log_error("--usb-interface requires an integer in the range 0..255");
                return ExitCode::Usage;
            }
            cfg.has_usb_interface = true;
            cfg.usb_interface = n;
            continue;
        }

        if (arg == "-l") {
            apply_log_flags();
            list_devices(criteria_from_config(cfg));
            return ExitCode::Success;
        }

        if (arg == "-b" || arg == "-a" || arg == "-c" || arg == "-s" || arg == "-u" || arg == "-d") {
            std::string value;
            if (!take_value(value)) {
                log_error("Option requires an argument: " + arg);
                return ExitCode::Usage;
            }
            if (arg == "-b") cfg.bootloader = value;
            else if (arg == "-a") cfg.ap = value;
            else if (arg == "-c") cfg.cp = value;
            else if (arg == "-s") cfg.csc = value;
            else if (arg == "-u") cfg.ums = value;
            else if (arg == "-d") cfg.device_path = value;
            continue;
        }

        if (!arg.empty() && arg[0] == '-') {
            log_error("Unknown option: " + arg);
            return ExitCode::Usage;
        }
    }

    apply_log_flags();

    if (!has_any_firmware_files(cfg) && !cfg.reboot && !cfg.redownload) {
        print_usage();
        return ExitCode::Usage;
    }

    if (cfg.dry_run && !has_any_firmware_files(cfg)) {
        log_error("--check-only requires at least one firmware archive (-b/-a/-c/-s/-u)");
        return ExitCode::Usage;
    }

    const UsbSelectionCriteria criteria = criteria_from_config(cfg);

    if (cfg.device_path.empty()) {
        const std::vector<std::string> devices = UsbDevice::list_download_devices(criteria);
        if (devices.empty()) {
            log_error("No compatible devices detected in Download Mode.");
            return ExitCode::Usb;
        }
        for (const auto& dev_path : devices) {
            OdinConfig one = cfg;
            one.device_path = dev_path;
            log_info("Using device: " + dev_path);
            const ExitCode rc = run_for_device(one);
            if (rc != ExitCode::Success) return rc;
        }
        return ExitCode::Success;
    }

    return run_for_device(cfg);
}

int main(int argc, char** argv) {
    int err = libusb_init(NULL);
    if (err < 0) {
        std::cerr << "Failed to initialize libusb: " << libusb_error_name(err) << std::endl;
        std::cerr << "This may indicate that libusb is missing or incompatible on this system." << std::endl;
        return static_cast<int>(ExitCode::Usb);
    }

    const ExitCode rc = process_arguments_and_run(argc, argv);

    libusb_exit(NULL);
    return static_cast<int>(rc);
}
