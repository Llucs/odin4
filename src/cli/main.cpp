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
#include "core/print_compat.h"
#include <string>
#include <vector>
#include <filesystem>
#include <cctype>
#include "odin4/odin4.h"

static void print_usage() {
    odin4::println("Usage: odin4 [options]");
    odin4::println("Samsung firmware flashing tool for Linux. Version: {}", odin4_get_version());
    odin4::println("");
    odin4::println("Options:");
    odin4::println("  -h                  Show this help message");
    odin4::println("  -v                  Show version");
    odin4::println("  -w                  Show license");
    odin4::println("  -l                  List detected Download Mode devices");
    odin4::println("  -d <path>            Select a specific USB device path (e.g. /dev/bus/usb/001/002)");
    odin4::println("  -b <file>            Bootloader archive (.tar or .tar.md5)");
    odin4::println("  -a <file>            AP archive (.tar or .tar.md5)");
    odin4::println("  -c <file>            CP archive (.tar or .tar.md5)");
    odin4::println("  -s <file>            CSC archive (.tar or .tar.md5)");
    odin4::println("  -u <file>            UMS archive (.tar or .tar.md5)");
    odin4::println("  --check-only         Validate PIT + archives and exit without flashing");
    odin4::println("  --allow-unknown      Allow archive entries without a PIT match (disabled by default)");
    odin4::println("  --reboot             Reboot device after flashing");
    odin4::println("  --redownload         Reboot into download mode if supported");
    odin4::println("  --efs-clear          Clear EFS partition during flash (repair IMEI/calibration)");
    odin4::println("  --bl-update          Signal bootloader update to device");
    odin4::println("");
    odin4::println("Logging:");
    odin4::println("  --quiet              Only print errors");
    odin4::println("  --verbose            More detailed logs");
    odin4::println("  --debug              Debug logs (includes USB packet hexdumps)");
    odin4::println("");
    odin4::println("USB selection overrides (optional):");
    odin4::println("  --vid <hex>          Override USB vendor ID (hex, e.g. 04e8)");
    odin4::println("  --pid <hex>          Override USB product ID (hex)");
    odin4::println("  --usb-interface <n>  Force a specific USB interface number");
    odin4::println("");
    odin4::println("Linux permissions:");
    odin4::println("  If you get LIBUSB_ERROR_ACCESS, install the provided udev rule:");
    odin4::println("    udev/60-odin4.rules -> /etc/udev/rules.d/60-odin4.rules");
}

static void print_version() {
    odin4::println("odin4 version {}", odin4_get_version());
}

static void print_license() {
    odin4::println("odin4 — Open Odin Reimplementation");
    odin4::println("");
    odin4::println("Copyright (c) 2026 Llucs");
    odin4::println("");
    odin4::println("Licensed under the Apache License, Version 2.0 (the \"License\");");
    odin4::println("you may not use this software except in compliance with the License.");
    odin4::println("You may obtain a copy of the License at:");
    odin4::println("");
    odin4::println("  http://www.apache.org/licenses/LICENSE-2.0");
    odin4::println("");
    odin4::println("This software is provided \"AS IS\", WITHOUT WARRANTIES OR CONDITIONS");
    odin4::println("OF ANY KIND, either express or implied.");
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
                odin4::println(std::cerr, "Error: --vid requires a hex value");
                return 1;
            }
            cfg.has_vid = true;
            cfg.vid = v;
            continue;
        }
        if (arg == "--pid") {
            uint16_t p = 0;
            if (!take_value_u16hex(p)) {
                odin4::println(std::cerr, "Error: --pid requires a hex value");
                return 1;
            }
            cfg.has_pid = true;
            cfg.pid = p;
            continue;
        }
        if (arg == "--usb-interface") {
            int n = 0;
            if (!take_value_int(n) || n < 0 || n > 255) {
                odin4::println(std::cerr, "Error: --usb-interface requires an integer in the range 0..255");
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
                odin4::println("No devices detected in Download Mode.");
            } else {
                for (const auto& path : devices) {
                    odin4::println("{}", path);
                }
            }
            return 0;
        }

        if (arg == "-b" || arg == "-a" || arg == "-c" || arg == "-s" || arg == "-u" || arg == "-d") {
            std::string value;
            if (!take_value(value)) {
                odin4::println(std::cerr, "Error: Option requires an argument: {}", arg);
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
            odin4::println(std::cerr, "Error: Unknown option: {}", arg);
            return 1;
        }
    }

    odin4_init(cfg);

    if (cfg.dry_run && !has_any_firmware_files(cfg)) {
        odin4::println(std::cerr, "Error: --check-only requires at least one firmware archive (-b/-a/-c/-s/-u)");
        return 1;
    }

    if (!has_any_firmware_files(cfg) && !cfg.reboot && !cfg.redownload) {
        print_usage();
        return 1;
    }

    for (const auto& path : {cfg.bootloader, cfg.ap, cfg.cp, cfg.csc, cfg.ums}) {
        if (!path.empty() && !std::filesystem::exists(path)) {
            odin4::println(std::cerr, "Error: Firmware file not found: {}", path);
            return 5; // Firmware error
        }
    }

    return static_cast<int>(odin4_run(cfg));
}
