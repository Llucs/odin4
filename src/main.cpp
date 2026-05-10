#include <iostream>
#include <string>
#include <vector>
#include <filesystem>
#include "odin4/odin4.h"

static void print_usage() {
    std::cout << "Usage: odin4 [options]" << std::endl;
    std::cout << "Samsung firmware flashing tool. Version: " << odin4_get_version() << std::endl;
    std::cout << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -h                  Show this help message" << std::endl;
    std::cout << "  -v                  Show version" << std::endl;
    std::cout << "  -w                  Show license" << std::endl;
    std::cout << "  -l                  List detected Download Mode devices" << std::endl;
    std::cout << "  -d <path>            Select a specific USB device path (e.g. 1:2)" << std::endl;
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
    std::cout << "Permissions:" << std::endl;
    std::cout << "  - Linux: If you get LIBUSB_ERROR_ACCESS, install the udev rule in the 'udev' folder." << std::endl;
    std::cout << "  - Windows: Use Zadig to install the WinUSB driver for the device." << std::endl;
    std::cout << "  - macOS: No additional drivers are usually required." << std::endl;
}

static void print_version() {
    std::cout << "odin4 version " << odin4_get_version() << std::endl;
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
    if (v.rfind("0x", 0) == 0 || v.rfind("0X", 0) == 0)
        v = v.substr(2);
    if (v.empty() || v.size() > 4)
        return false;
    for (unsigned char c : v) {
        if (!std::isxdigit(c))
            return false;
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
        if (idx != s.size())
            return false;
        out = v;
        return true;
    } catch (...) {
        return false;
    }
}

static bool has_any_firmware_files(const OdinConfig& cfg) {
    return !cfg.bootloader.empty() || !cfg.ap.empty() || !cfg.cp.empty() || !cfg.csc.empty() || !cfg.ums.empty();
}

int main(int argc, char** argv) {
    OdinConfig cfg;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];

        if (arg == "-h") {
            print_usage();
            return 0;
        }
        if (arg == "-v") {
            print_version();
            return 0;
        }
        if (arg == "-w") {
            print_license();
            return 0;
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
            if (i + 1 >= argc)
                return false;
            out = argv[++i];
            return true;
        };

        auto take_value_u16hex = [&](uint16_t& out) -> bool {
            if (i + 1 >= argc)
                return false;
            return parse_hex_u16(argv[++i], out);
        };

        auto take_value_int = [&](int& out) -> bool {
            if (i + 1 >= argc)
                return false;
            return parse_int(argv[++i], out);
        };

        if (arg == "--vid") {
            uint16_t v = 0;
            if (!take_value_u16hex(v)) {
                std::cerr << "Error: --vid requires a hex value" << std::endl;
                return 1;
            }
            cfg.has_vid = true;
            cfg.vid = v;
            continue;
        }
        if (arg == "--pid") {
            uint16_t p = 0;
            if (!take_value_u16hex(p)) {
                std::cerr << "Error: --pid requires a hex value" << std::endl;
                return 1;
            }
            cfg.has_pid = true;
            cfg.pid = p;
            continue;
        }
        if (arg == "--usb-interface") {
            int n = 0;
            if (!take_value_int(n) || n < 0 || n > 255) {
                std::cerr << "Error: --usb-interface requires an integer in the range 0..255" << std::endl;
                return 1;
            }
            cfg.has_usb_interface = true;
            cfg.usb_interface = n;
            continue;
        }

        if (arg == "-l") {
            odin4_init(cfg);
            const std::vector<std::string> devices = odin4_list_devices(cfg);
            if (devices.empty()) {
                std::cout << "No devices detected in Download Mode." << std::endl;
            } else {
                for (const auto& path : devices) {
                    std::cout << path << std::endl;
                }
            }
            return 0;
        }

        if (arg == "-b" || arg == "-a" || arg == "-c" || arg == "-s" || arg == "-u" || arg == "-d") {
            std::string value;
            if (!take_value(value)) {
                std::cerr << "Error: Option requires an argument: " << arg << std::endl;
                return 1;
            }
            if (arg == "-b")
                cfg.bootloader = value;
            else if (arg == "-a")
                cfg.ap = value;
            else if (arg == "-c")
                cfg.cp = value;
            else if (arg == "-s")
                cfg.csc = value;
            else if (arg == "-u")
                cfg.ums = value;
            else if (arg == "-d")
                cfg.device_path = value;
            continue;
        }

        if (!arg.empty() && arg[0] == '-') {
            std::cerr << "Error: Unknown option: " << arg << std::endl;
            return 1;
        }
    }

    odin4_init(cfg);

    if (cfg.dry_run && !has_any_firmware_files(cfg)) {
        std::cerr << "Error: --check-only requires at least one firmware archive (-b/-a/-c/-s/-u)" << std::endl;
        return 1;
    }

    if (!has_any_firmware_files(cfg) && !cfg.reboot && !cfg.redownload) {
        print_usage();
        return 1;
    }

    for (const auto& path : {cfg.bootloader, cfg.ap, cfg.cp, cfg.csc, cfg.ums}) {
        if (!path.empty() && !std::filesystem::exists(path)) {
            std::cerr << "Error: Firmware file not found: " << path << std::endl;
            return 5; // Firmware error
        }
    }

    return static_cast<int>(odin4_run(cfg));
}
