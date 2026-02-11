// ============================================================================
// odin4 - Samsung Device Flashing Tool
// Version: 4.1.0-ac22b8e
// Protocol: Thor USB Communication
// Developer: Llucs
// ============================================================================

#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include <libusb.h>
#include <algorithm>
#include <cctype>
#include <filesystem>
#include <chrono>
#include <sstream>
#include "logger.h"

#include "odin_types.h"
#include "thor_protocol.h"
#include "usb_device.h"
#include "firmware_package.h"

#define ODIN4_VERSION "4.1.0-ac22b8e"

// Logging utilities are now defined in src/logger.cpp. See logger.h for declarations.

// ============================================================================
// CLI UTILITIES
// ============================================================================

void print_usage() {
    std::cout << "Usage: odin4 [options]" << std::endl;
    std::cout << "Odin4 downloader. Version: " << ODIN4_VERSION << std::endl;
    std::cout << " -h        Show this help message" << std::endl;
    std::cout << " -v        Show version" << std::endl;
    std::cout << " -w        Show license" << std::endl;
    std::cout << " -b        Add Bootloader file" << std::endl;
    std::cout << " -a        Add AP image file" << std::endl;
    std::cout << " -c        Add CP image file" << std::endl;
    std::cout << " -s        Add CSC file" << std::endl;
    std::cout << " -u        Add UMS file" << std::endl;
    // The -e and -V options have been removed as they are not supported.
    std::cout << " --reboot  Reboot into normal mode" << std::endl;
    
    std::cout << " --redownload   Reboot into download mode if possible" << std::endl;
    std::cout << " --check-only   Validate firmware and skip flashing" << std::endl;
    std::cout << " -d        Set a device path (detect automatically without this option)" << std::endl;
    std::cout << " -l        Show downloadable devices path" << std::endl;
    std::cout << std::endl;
    std::cout << "IMPORTANT: You must set up your system to detect your device on LINUX host." << std::endl;
    std::cout << "Create this file: /etc/udev/rules.d/51-android.rules" << std::endl;
    std::cout << "Add this line to the file:" << std::endl;
    std::cout << "SUBSYSTEM==\"usb\", ATTR{idVendor}==\"04e8\", MODE=\"0666\", GROUP=\"plugdev\"" << std::endl;
    std::cout << std::endl;
    std::cout << "Example:" << std::endl;
    std::cout << "$ odin4 -b BL_XXXX.tar.md5 -a AP_XXXX.tar.md5 -c CP_XXXX.tar.md5 -s CSC_XXXX.tar.md5" << std::endl;
    std::cout << "Example (Select One Device):" << std::endl;
    std::cout << "$ odin4 -l" << std::endl;
    std::cout << "$ odin4 -b BL_XXXX.tar.md5 -a AP_XXXX.tar.md5 -c CP_XXXX.tar.md5 -s CSC_XXXX.tar.md5 -d /dev/bus/usb/001/002" << std::endl;
    std::cout << std::endl;
    std::cout << "Odin Repository: https://github.com/Llucs/odin4" << std::endl;
}

void print_version() {
    std::cout << "odin4 version " << ODIN4_VERSION << std::endl;
}

void print_license() {
    std::cout << "Odin4 — Open Odin Reimplementation" << std::endl;
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

// List all Samsung devices detected in download mode. This helper prints
// their USB bus/address paths. The enumeration is performed via the
// UsbDevice::list_download_devices() static member.
void list_devices() {
    std::vector<std::string> devices = UsbDevice::list_download_devices();
    if (devices.empty()) {
        std::cout << "No Samsung devices found in download mode." << std::endl;
    } else {
        for (const auto& path : devices) {
            std::cout << path << std::endl;
        }
    }
}

// ---------------------------------------------------------------------------
// Firmware compatibility verification
// ---------------------------------------------------------------------------
// This function performs a simple compatibility check between the connected
// device and the firmware image filenames provided by the user. It attempts
// to extract the model identifier from the device type string (typically
// something like "SM-G970F") and ensures that each firmware filename
// contains that identifier (case-insensitive). If the device type cannot be
// determined or no files are provided, the function returns true. On
// mismatch it logs an error and returns false.
bool verify_firmware_compatibility(const OdinConfig& cfg, const std::string& device_type) {
    if (device_type.empty()) {
        log_info("Device type string is empty; skipping firmware compatibility checks.");
        return true;
    }
    // Normalise the device_type by converting to uppercase and removing "SM-" prefix.
    std::string dt = device_type;
    // Remove whitespace and common separators
    dt.erase(std::remove_if(dt.begin(), dt.end(), [](unsigned char c) {
        return std::isspace(c) || c == '\\' || c == '/' || c == '-';
    }), dt.end());
    // Convert to uppercase for case-insensitive comparison
    std::transform(dt.begin(), dt.end(), dt.begin(), [](unsigned char c){ return static_cast<char>(std::toupper(c)); });
    if (dt.rfind("SM", 0) == 0) {
        // If begins with "SM" drop it for matching (e.g. SMG970F -> G970F)
        dt = dt.substr(2);
    }
    // Lambda to test a single file path
    auto check_file = [&](const std::string& path) -> bool {
        if (path.empty()) return true;
        // Extract the filename from a full path by finding the last separator.
        std::string fname;
        size_t pos = path.find_last_of("/\\");
        if (pos != std::string::npos) {
            fname = path.substr(pos + 1);
        } else {
            fname = path;
        }
        // Convert filename to uppercase and strip common separators to improve match.
        std::string f_upper;
        f_upper.reserve(fname.size());
        for (char c : fname) {
            unsigned char uc = static_cast<unsigned char>(c);
            if (std::isspace(uc)) continue;
            if (uc == '-') continue;
            f_upper.push_back(static_cast<char>(std::toupper(uc)));
        }
        if (f_upper.find(dt) == std::string::npos) {
            log_error("Firmware file '" + fname + "' does not appear compatible with device type '" + device_type + "'.");
            return false;
        }
        return true;
    };
    if (!check_file(cfg.bootloader)) return false;
    if (!check_file(cfg.ap)) return false;
    if (!check_file(cfg.cp)) return false;
    if (!check_file(cfg.csc)) return false;
    if (!check_file(cfg.ums)) return false;
    log_info("All firmware files appear compatible with device type " + device_type + ".");
    return true;
}

// ============================================================================
// FLASHING LOGIC
// ============================================================================

int run_flash_logic(const OdinConfig& config) {
    UsbDevice usb_device;
    if (!usb_device.open_device(config.device_path)) {
        // Provide clearer error messaging when the device cannot be opened.  The
        // previous text was grammatically incorrect and ambiguous.
        log_error("The device could not be found or the connection could not be established.");
        return 1;
    }

    if (!usb_device.handshake()) {
        log_error("Handshake failed.");
        return 1;
    }
    // Log successful handshake
    log_info("Handshake successful.");

    if (!usb_device.request_device_type()) {
        log_error("The device type request failed.");
        return 1;
    }
    // Record the device type for logging
    log_info("Device type: " + usb_device.get_device_type());

    // Verify that all provided firmware images appear to match the device type.
    if (!verify_firmware_compatibility(config, usb_device.get_device_type())) {
        log_error("Firmware compatibility verification failed.");
        return 1;
    }

    // Log session begin
    log_info("Beginning session.");
    if (!usb_device.begin_session()) {
        log_error("Session begin failed.");
        return 1;
    }

    // Request the PIT and log
    log_info("Requesting PIT from device.");
    if (!usb_device.request_pit()) {
        log_error("PIT request failed.");
        return 1;
    }

    PitTable pit_table;
    if (!usb_device.receive_pit_table(pit_table)) {
        log_error("PIT receipt failed.");
        return 1;
    }
    log_info("PIT received with " + std::to_string(pit_table.entries.size()) + " entries.");

    // Compute total size of firmware files for statistics. This uses std::filesystem
    // and ignores any missing or zero-length files gracefully.
    uint64_t total_bytes = 0;
    auto accumulate_size = [&](const std::string& path) {
        if (!path.empty()) {
            std::error_code ec;
            auto sz = std::filesystem::file_size(path, ec);
            if (!ec) total_bytes += static_cast<uint64_t>(sz);
        }
    };
    accumulate_size(config.bootloader);
    accumulate_size(config.ap);
    accumulate_size(config.cp);
    accumulate_size(config.csc);
    accumulate_size(config.ums);
    // Record start time for statistics
    auto start_time = std::chrono::steady_clock::now();

    std::vector<std::pair<std::string, std::string>> files = {
        {"BL", config.bootloader}, 
        {"AP", config.ap}, 
        {"CP", config.cp}, 
        {"CSC", config.csc},
        {"UMS", config.ums}
    };

    bool success = true;
    for (const auto& f : files) {
        if (!f.second.empty()) {
            if (!process_tar_file(f.second, usb_device, pit_table, !config.dry_run)) {
                log_error("Flash failed during file processing: " + f.first);
                success = false;
                break;
            }
        }
    }

    if (!success) {
        usb_device.end_session();
        return 1;
    }

    // In dry-run mode, skip sending reboot or redownload commands to avoid writing
    if (!config.dry_run) {
        if (config.reboot) {
            if (!usb_device.send_control(THOR_CONTROL_REBOOT)) {
                log_error("The reboot command failed.");
                return 1;
            }
        }
        if (config.redownload) {
            if (!usb_device.send_control(THOR_CONTROL_REDOWNLOAD)) {
                log_error("The redownload command failed.");
                return 1;
            }
        }
    } else {
        if (config.reboot || config.redownload) {
            log_info("Dry run mode: reboot/redownload commands skipped.");
        }
    }

    if (!usb_device.end_session()) {
        log_error("Session closure failed.");
        return 1;
    }

    // Compute elapsed time and statistics
    auto end_time = std::chrono::steady_clock::now();
    double elapsed_seconds = std::chrono::duration_cast<std::chrono::duration<double>>(end_time - start_time).count();
    if (elapsed_seconds < 0.001) elapsed_seconds = 0.001; // prevent divide-by-zero
    // Log summary based on mode
    std::ostringstream oss;
    if (config.dry_run) {
        oss << "Dry run completed. Total data size: " << total_bytes << " bytes. Elapsed time: " << std::fixed << std::setprecision(2) << elapsed_seconds << " s.";
        log_info(oss.str());
    } else {
        double mb = total_bytes / (1024.0 * 1024.0);
        double speed = mb / elapsed_seconds;
        oss << "Flashed " << total_bytes << " bytes in " << std::fixed << std::setprecision(2) << elapsed_seconds << " s. Average speed: " << std::setprecision(2) << speed << " MB/s.";
        log_info(oss.str());
    }

    log_info("Flash process completed successfully.");
    return 0;
}

int process_arguments_and_run(int argc, char** argv) {
    OdinConfig config;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
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
        if (arg == "-l") { 
            list_devices(); 
            return 0; 
        }
        if (arg == "--reboot") { 
            config.reboot = true; 
            continue; 
        }
        if (arg == "--redownload") { 
            config.redownload = true; 
            continue; 
        }
        if (arg == "--check-only") {
            // Enable dry-run mode: verify images and PIT but skip flashing
            config.dry_run = true;
            continue;
        }
        // The -e (nand erase) and -V (validation) options are no longer supported.

        if (arg == "-b" || arg == "-a" || arg == "-c" || arg == "-s" || arg == "-u" || arg == "-d") {
            if (i + 1 >= argc) {
                std::cerr << "Error: Option '" << arg << "' requires an argument." << std::endl;
                return 1;
            }
            if (arg == "-b") config.bootloader = argv[++i];
            else if (arg == "-a") config.ap = argv[++i];
            else if (arg == "-c") config.cp = argv[++i];
            else if (arg == "-s") config.csc = argv[++i];
            else if (arg == "-u") config.ums = argv[++i];
            else if (arg == "-d") config.device_path = argv[++i];
        } else if (arg[0] == '-') {
            std::cerr << "odin4: illegal option -- '" << (arg.length() > 1 ? arg[1] : '?') << "'" << std::endl;
            return 1;
        }
    }

    if (config.bootloader.empty() && config.ap.empty() && config.cp.empty() && config.csc.empty() && config.ums.empty() && !config.reboot && !config.redownload) {
        print_usage();
        return 1;
    }

    // If no specific device path is provided, attempt to flash all detected devices.
    if (config.device_path.empty()) {
        std::vector<std::string> devices = UsbDevice::list_download_devices();
        if (devices.empty()) {
            log_error("No Samsung devices found in download mode. Connect a device or specify -d.");
            return 1;
        }
        // Flash each device sequentially. If an error occurs on any device, abort.
        int aggregate_result = 0;
        for (const auto& dev : devices) {
            OdinConfig cfg = config;
            cfg.device_path = dev;
            log_info("Flashing device: " + dev);
            int result = run_flash_logic(cfg);
            if (result != 0) {
                aggregate_result = result;
                break;
            }
        }
        return aggregate_result;
    }
    // Otherwise, flash the single specified device.
    return run_flash_logic(config);
}

int main(int argc, char** argv) {
    // Configure a default log file. Logging will also be printed to the console.
    // The log file path could be made configurable via a future command-line
    // option. For now we use a fixed name in the current working directory.
    set_log_file("odin4.log");

    int err = libusb_init(NULL);
    if (err < 0) {
        std::cerr << "[ERROR] Failed to initialize libusb: " << libusb_error_name(err) << std::endl;
        return 1;
    }
    
    int result = process_arguments_and_run(argc, argv);
    
    libusb_exit(NULL);
    return result;
}
