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
#include <string>
#include <vector>
#include <filesystem>
#include "odin4/odin4.h"

static void print_usage() {
    std::cout << "Usage: odin4 [options]" << '\n';
    std::cout << "Samsung firmware flashing tool for Linux. Version: " << odin4_get_version() << '\n';
    std::cout << '\n';
    std::cout << "Options:" << '\n';
    std::cout << "  -h                  Show this help message" << '\n';
    std::cout << "  -v                  Show version" << '\n';
    std::cout << "  -w                  Show license" << '\n';
    std::cout << "  -l                  List detected Download Mode devices" << '\n';
    std::cout << "  -d <path>            Select a specific USB device path (e.g. /dev/bus/usb/001/002)" << '\n';
    std::cout << "  -b <file>            Bootloader archive (.tar or .tar.md5)" << '\n';
    std::cout << "  -a <file>            AP archive (.tar or .tar.md5)" << '\n';
    std::cout << "  -c <file>            CP archive (.tar or .tar.md5)" << '\n';
    std::cout << "  -s <file>            CSC archive (.tar or .tar.md5)" << '\n';
    std::cout << "  -u <file>            UMS archive (.tar or .tar.md5)" << '\n';
    std::cout << "  --check-only         Validate PIT + archives and exit without flashing" << '\n';
    std::cout << "  --allow-unknown      Allow archive entries without a PIT match (disabled by default)" << '\n';
    std::cout << "  --reboot             Reboot device after flashing" << '\n';
    std::cout << "  --redownload         Reboot into download mode if supported" << '\n';
    std::cout << '\n';
    std::cout << "Logging:" << '\n';
    std::cout << "  --quiet              Only print errors" << '\n';
    std::cout << "  --verbose            More detailed logs" << '\n';
    std::cout << "  --debug              Debug logs (includes USB packet hexdumps)" << '\n';
    std::cout << '\n';
    std::cout << "USB selection overrides (optional):" << '\n';
    std::cout << "  --vid <hex>          Override USB vendor ID (hex, e.g. 04e8)" << '\n';
    std::cout << "  --pid <hex>          Override USB product ID (hex)" << '\n';
    std::cout << "  --usb-interface <n>  Force a specific USB interface number" << '\n';
    std::cout << '\n';
    std::cout << "Linux permissions:" << '\n';
    std::cout << "  If you get LIBUSB_ERROR_ACCESS, install the provided udev rule:" << '\n';
    std::cout << "    udev/60-odin4.rules -> /etc/udev/rules.d/60-odin4.rules" << '\n';
}

static void print_version() {
    std::cout << "odin4 version " << odin4_get_version() << '\n';
}

static void print_license() {
    std::cout << "odin4 — Open Odin Reimplementation" << '\n';
    std::cout << '\n';
    std::cout << "Copyright (c) 2026 Llucs" << '\n';
    std::cout << '\n';
    std::cout << "Licensed under the Apache License, Version 2.0 (the \"License\");" << '\n';
    std::cout << "you may not use this software except in compliance with the License." << '\n';
    std::cout << "You may obtain a copy of the License at:" << '\n';
    std::cout << '\n';
    std::cout << "  http://www.apache.org/licenses/LICENSE-2.0" << '\n';
    std::cout << '\n';
    std::cout << "This software is provided \"AS IS\", WITHOUT WARRANTIES OR CONDITIONS" << '\n';
    std::cout << "OF ANY KIND, either express or implied." << '\n';
}

static auto parse_hex_u16(const std::string& s, uint16_t& out) -> bool {
    std::string v = s;
    if (v.rfind("0x", 0) == 0 || v.rfind("0X", 0) == 0) {
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

auto main(int argc, char** argv) -> int {
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
                std::cerr << "Error: --vid requires a hex value" << '\n';
                return 1;
            }
            cfg.has_vid = true;
            cfg.vid = v;
            continue;
        }
        if (arg == "--pid") {
            uint16_t p = 0;
            if (!take_value_u16hex(p)) {
                std::cerr << "Error: --pid requires a hex value" << '\n';
                return 1;
            }
            cfg.has_pid = true;
            cfg.pid = p;
            continue;
        }
        if (arg == "--usb-interface") {
            int n = 0;
            if (!take_value_int(n) || n < 0 || n > 255) {
                std::cerr << "Error: --usb-interface requires an integer in the range 0..255" << '\n';
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
                std::cout << "No devices detected in Download Mode." << '\n';
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
                std::cerr << "Error: Option requires an argument: " << arg << '\n';
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

        if (!arg.empty() && arg[0] == '-') {
            std::cerr << "Error: Unknown option: " << arg << '\n';
            return 1;
        }
    }

    odin4_init(cfg);

    if (cfg.dry_run && !has_any_firmware_files(cfg)) {
        std::cerr << "Error: --check-only requires at least one firmware archive (-b/-a/-c/-s/-u)" << '\n';
        return 1;
    }

    if (!has_any_firmware_files(cfg) && !cfg.reboot && !cfg.redownload) {
        print_usage();
        return 1;
    }

    for (const auto& path : {cfg.bootloader, cfg.ap, cfg.cp, cfg.csc, cfg.ums}) {
        if (!path.empty() && !std::filesystem::exists(path)) {
            std::cerr << "Error: Firmware file not found: " << path << '\n';
            return 5; // Firmware error
        }
    }

    return static_cast<int>(odin4_run(cfg));
}
