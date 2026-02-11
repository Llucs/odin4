// ============================================================================
// logger.cpp - Implementation of logging utilities for odin4
//
// These functions provide simple logging to stdout/stderr and optionally to
// a log file. A mutex protects concurrent writes to the file. Each log
// entry is prefixed with a timestamp and a log level tag.
// ============================================================================
#include "logger.h"

#include <iostream>
#include <fstream>
#include <mutex>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <libusb.h>

// Static variables for log file state and thread safety. These live
// in an unnamed namespace to give them internal linkage.
namespace {
    std::ofstream log_stream;
    std::mutex log_mutex;

    // Helper to obtain a formatted current time string in ISO 8601 format.
    std::string current_time() {
        std::time_t t = std::time(nullptr);
        std::tm tm{};
#if defined(_WIN32)
        localtime_s(&tm, &t);
#else
        localtime_r(&t, &tm);
#endif
        std::ostringstream oss;
        oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S");
        return oss.str();
    }
}

void set_log_file(const std::string& path) {
    std::lock_guard<std::mutex> lock(log_mutex);
    if (log_stream.is_open()) {
        log_stream.close();
    }
    if (!path.empty()) {
        log_stream.open(path, std::ios::app);
        if (!log_stream) {
            // If the file cannot be opened, fall back to console only.
            std::cerr << "[ERROR] Unable to open log file: " << path << std::endl;
        }
    }
}

static void write_to_log(const std::string& level, const std::string& message) {
    std::lock_guard<std::mutex> lock(log_mutex);
    if (log_stream.is_open()) {
        log_stream << current_time() << " " << level << " " << message << std::endl;
        log_stream.flush();
    }
}

void log_info(const std::string& msg) {
    // Write to stdout and file
    std::cout << "[INFO] " << msg << std::endl;
    write_to_log("[INFO]", msg);
}

void log_error(const std::string& msg, int libusb_err) {
    std::string final_msg = msg;
    if (libusb_err != 0) {
        // Append libusb error name when available. libusb provides error names
        // via libusb_error_name().
        const char* err_name = libusb_error_name(libusb_err);
        final_msg += " (libusb: ";
        final_msg += err_name ? err_name : "unknown";
        final_msg += ")";
    }
    std::cerr << "[ERROR] " << final_msg << std::endl;
    write_to_log("[ERROR]", final_msg);
}

void log_hexdump(const std::string& title, const void* data, size_t size) {
    if (size == 0 || data == nullptr) {
        return;
    }
    const unsigned char* bytes = static_cast<const unsigned char*>(data);

    // Save current formatting state for cout
    std::ios_base::fmtflags f(std::cout.flags());
    char fill = std::cout.fill();
    std::streamsize old_width = std::cout.width();

    std::ostringstream oss;
    oss << "[DEBUG] " << title << " (" << size << " bytes):";

    std::cout << oss.str() << std::endl;
    write_to_log("[DEBUG]", oss.str());

    std::cout << std::hex << std::setfill('0');
    for (size_t i = 0; i < size; ++i) {
        std::ostringstream byte_stream;
        byte_stream << std::setw(2) << (unsigned int)bytes[i] << " ";
        std::string byte_str = byte_stream.str();
        std::cout << byte_str;
        write_to_log("[DEBUG]", byte_str);
        if ((i + 1) % 16 == 0) {
            std::cout << std::endl;
            write_to_log("[DEBUG]", "");
        }
    }
    if (size % 16 != 0) {
        std::cout << std::endl;
        write_to_log("[DEBUG]", "");
    }

    // Restore cout state
    std::cout.flags(f);
    std::cout.fill(fill);
    std::cout.width(old_width);
}
