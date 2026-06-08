/*
 * Copyright (c) 2026 Llucs
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <iostream>
#include <format>
#include <string>
#include <vector>
#include <filesystem>
#include <cctype>
#include "odin4/odin4.h"

static void print_usage() {
    std::cout << std::format("Usage: odin4 [options]\nSamsung firmware flashing tool. Version: {}\n", odin4_get_version());
    std::cout << "\nOptions:\n"
              << "  -h                  Show this help message\n"
              << "  -v                  Show version\n"
              << "  -w                  Show license\n"
              << "  -l                  List detected Download Mode devices\n"
#if defined(_WIN32)
              << "  -d <path>            Select a specific USB device path (e.g. bus-port)\n"
#else
              << "  -d <path>            Select a specific USB device path\n"
#endif
              << "  -b <file>            Bootloader archive (.tar or .tar.md5)\n"
              << "  -a <file>            AP archive (.tar or .tar.md5)\n"
              << "  -c <file>            CP archive (.tar or .tar.md5)\n"
              << "  -s <file>            CSC archive (.tar or .tar.md5)\n"
              << "  -u <file>            UMS archive (.tar or .tar.md5)\n"
              << "  --check-only         Validate PIT + archives and exit without flashing\n"
              << "  --allow-unknown      Allow archive entries without a PIT match (disabled by default)\n"
              << "  --reboot             Reboot device after flashing\n"
              << "  --redownload         Reboot into download mode if supported\n"
              << "  --efs-clear          Clear EFS partition during flash (repair IMEI/calibration)\n"
              << "  --bl-update          Signal bootloader update to device\n"
              << "\nLogging:\n"
              << "  --quiet              Only print errors\n"
              << "  --verbose            More detailed logs\n"
              << "  --debug              Debug logs (includes USB packet hexdumps)\n"
              << "\nUSB selection overrides (optional):\n"
              << "  --vid <hex>          Override USB vendor ID (hex, e.g. 04e8)\n"
              << "  --pid <hex>          Override USB product ID (hex)\n"
              << "  --usb-interface <n>  Force a specific USB interface number\n"
              << "\n"
#if defined(__linux__)
              << "Permissions:\n"
              << "  If you get LIBUSB_ERROR_ACCESS, install the provided udev rule:\n"
              << "    udev/60-odin4.rules -> /etc/udev/rules.d/60-odin4.rules\n"
#elif defined(_WIN32)
              << "Permissions:\n"
              << "  If you get LIBUSB_ERROR_ACCESS, use Zadig to install a WinUSB driver.\n"
#elif defined(__APPLE__)
              << "Permissions:\n"
              << "  If you get LIBUSB_ERROR_ACCESS, check System Settings > Privacy & Security > USB.\n"
#endif
        ;
}

static void print_version() {
    std::cout << std::format("odin4 version {}\n", odin4_get_version());
}

static void print_license() {
    std::cout << "odin4 \xe2\x80\x94 Open Odin Reimplementation\n\n"
              << "Copyright (c) 2026 Llucs\n\n"
              << "Licensed under the Apache License, Version 2.0 (the \"License\");\n"
              << "you may not use this software except in compliance with the License.\n"
              << "You may obtain a copy of the License at:\n\n"
              << "  http://www.apache.org/licenses/LICENSE-2.0\n\n"
              << "This software is provided \"AS IS\", WITHOUT WARRANTIES OR CONDITIONS\n"
              << "OF ANY KIND, either express or implied.\n";
}

static auto parse_hex_u16(const std::string& s, uint16_t& out) -> bool {
    std::string v = s;
    if (v.starts_with("0x") || v.starts_with("0X")) {
        v = v.substr(2);
    }
    if (v.empty() || v.size() > 4) {
        return false;
    }
    for (unsigned char c : v) {
        if (std::isxdigit(c) == 0) {
            return false;
        }
    }
    try {
        out = static_cast<uint16_t>(std::stoul(v, nullptr, 16));
        return true;
    } catch (...) {
        return false;
    }
}

static auto parse_int(const std::string& s, int& out) -> bool {
    try {
        size_t idx = 0;
        int v = std::stoi(s, &idx, 10);
        if (idx != s.size()) {
            return false;
        }
        out = v;
        return true;
    } catch (...) {
        return false;
    }
}

static auto has_any_firmware_files(const OdinConfig& cfg) -> bool {
    return !cfg.bootloader.empty() || !cfg.ap.empty() || !cfg.cp.empty() || !cfg.csc.empty() || !cfg.ums.empty();
}

// Entry point for the odin4 CLI.
//
// High-level flow:
// 1) Parse command-line options into an OdinConfig instance.
// 2) Handle informational options that terminate early (-h/-v/-w/-l).
// 3) Validate option combinations and required arguments.
// 4) Execute the requested device interaction / flashing workflow.
// 5) Return a process exit code indicating success or failure.
auto main(int argc, char** argv) -> int {
    OdinConfig cfg;

    // Phase 1: parse CLI arguments and apply them to cfg.
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];

        // Informational flags: print and exit immediately.
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
        if (arg == "--efs-clear") {
            cfg.efs_clear = true;
            continue;
        }
        if (arg == "--bl-update") {
            cfg.boot_update = true;
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
            if (i + 1 >= argc) {
                return false;
            }
            out = argv[++i];
            return true;
        };

        auto take_value_u16hex = [&](uint16_t& out) -> bool {
            if (i + 1 >= argc) {
                return false;
            }
            return parse_hex_u16(argv[++i], out);
        };

        auto take_value_int = [&](int& out) -> bool {
            if (i + 1 >= argc) {
                return false;
            }
            return parse_int(argv[++i], out);
        };

        if (arg == "--vid") {
            uint16_t v = 0;
            if (!take_value_u16hex(v)) {
                std::cerr << "Error: --vid requires a hex value\n";
                return 1;
            }
            cfg.has_vid = true;
            cfg.vid = v;
            continue;
        }
        if (arg == "--pid") {
            uint16_t p = 0;
            if (!take_value_u16hex(p)) {
                std::cerr << "Error: --pid requires a hex value\n";
                return 1;
            }
            cfg.has_pid = true;
            cfg.pid = p;
            continue;
        }
        if (arg == "--usb-interface") {
            int n = 0;
            if (!take_value_int(n) || n < 0 || n > 255) {
                std::cerr << "Error: --usb-interface requires an integer in the range 0..255\n";
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
                std::cout << "No devices detected in Download Mode.\n";
            } else {
                for (const auto& path : devices) {
                    std::cout << path << '\n';
                }
            }
            return 0;
        }

        if (arg == "-b" || arg == "-a" || arg == "-c" || arg == "-s" || arg == "-u" || arg == "-d") {
            std::string value;
            if (!take_value(value)) {
                std::cerr << std::format("Error: Option requires an argument: {}\n", arg);
                return 1;
            }
            if (arg == "-b") {
                cfg.bootloader = value;
            } else if (arg == "-a") {
                cfg.ap = value;
            } else if (arg == "-c") {
                cfg.cp = value;
            } else if (arg == "-s") {
                cfg.csc = value;
            } else if (arg == "-u") {
                cfg.ums = value;
            } else if (arg == "-d") {
                cfg.device_path = value;
            }
            continue;
        }

        if (!arg.empty() && arg.starts_with('-')) {
            std::cerr << std::format("Error: Unknown option: {}\n", arg);
            return 1;
        }
    }

    odin4_init(cfg);

    if (cfg.dry_run && !has_any_firmware_files(cfg)) {
        std::cerr << "Error: --check-only requires at least one firmware archive (-b/-a/-c/-s/-u)\n";
        return 1;
    }

    if (!has_any_firmware_files(cfg) && !cfg.reboot && !cfg.redownload) {
        print_usage();
        return 1;
    }

    for (const auto& path : {cfg.bootloader, cfg.ap, cfg.cp, cfg.csc, cfg.ums}) {
        if (!path.empty() && !std::filesystem::exists(path)) {
            std::cerr << std::format("Error: Firmware file not found: {}\n", path);
            return 5; // Firmware error
        }
    }

    return static_cast<int>(odin4_run(cfg));
}
