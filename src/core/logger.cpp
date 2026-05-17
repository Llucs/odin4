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

#include "core/logger.h"

#include <iostream>
#include <fstream>
#include <mutex>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <iostream>
#include <libusb.h>

namespace {
std::ofstream g_log_stream;
std::mutex g_log_mutex;
LogLevel g_level = LogLevel::Info;
LogCallback g_callback = nullptr;

auto timestamp_now() -> std::string {
    using namespace std::chrono;
    const auto now = system_clock::now();
    const auto ms = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;

    std::time_t t = system_clock::to_time_t(now);
    std::tm tm{};
#if defined(_WIN32)
    localtime_s(&tm, &t);
#else
    localtime_r(&t, &tm);
#endif
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S") << "." << std::setw(3) << std::setfill('0') << ms.count();
    return oss.str();
}

auto level_tag(LogLevel lvl) -> const char* {
    switch (lvl) {
    case LogLevel::Error:
        return "ERROR";
    case LogLevel::Warn:
        return "WARN";
    case LogLevel::Info:
        return "INFO";
    case LogLevel::Verbose:
        return "VERBOSE";
    case LogLevel::Debug:
        return "DEBUG";
    default:
        return "INFO";
    }
}

auto should_emit(LogLevel lvl) -> bool {
    if (lvl == LogLevel::Error) {
        return true;
    }
    return static_cast<int>(lvl) <= static_cast<int>(g_level);
}

void write_line(std::ostream& os, LogLevel lvl, const std::string& msg) {
    os << timestamp_now() << " [" << level_tag(lvl) << "] " << msg << std::endl;
}

void write_to_file(LogLevel lvl, const std::string& msg) {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    if (!g_log_stream.is_open()) {
        return;
    }
    g_log_stream << timestamp_now() << " [" << level_tag(lvl) << "] " << msg << '\n';
    g_log_stream.flush();
}

void log_impl(LogLevel lvl, const std::string& msg, bool to_stderr) {
    LogCallback cb = nullptr;
    if (should_emit(lvl)) {
        if (to_stderr) {
            write_line(std::cerr, lvl, msg);
        } else {
            write_line(std::cout, lvl, msg);
        }
        {
            std::lock_guard<std::mutex> lock(g_log_mutex);
            cb = g_callback;
        }
        if (cb) {
            cb(lvl, msg);
        }
    }
    write_to_file(lvl, msg);
}
} // namespace

void set_log_callback(LogCallback cb) {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    g_callback = std::move(cb);
}

void set_log_level(LogLevel level) {
    g_level = level;
}

auto get_log_level() -> LogLevel {
    return g_level;
}

void set_log_file(const std::string& path) {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    if (g_log_stream.is_open()) {
        g_log_stream.close();
    }
    if (!path.empty()) {
        g_log_stream.open(path, std::ios::app);
        if (!g_log_stream) {
            std::cerr << timestamp_now() << " [ERROR] Unable to open log file: " << path << std::endl;
        }
    }
}

void log_error(const std::string& msg, int libusb_err) {
    std::string final_msg = msg;
    if (libusb_err != 0) {
        const char* err_name = libusb_error_name(libusb_err);
        final_msg += " (libusb: ";
        final_msg += (err_name != nullptr) ? err_name : "unknown";
        final_msg += ")";
    }
    log_impl(LogLevel::Error, final_msg, true);
}

void log_warn(const std::string& msg) {
    log_impl(LogLevel::Warn, msg, false);
}

void log_info(const std::string& msg) {
    log_impl(LogLevel::Info, msg, false);
}

void log_verbose(const std::string& msg) {
    log_impl(LogLevel::Verbose, msg, false);
}

void log_debug(const std::string& msg) {
    log_impl(LogLevel::Debug, msg, false);
}

void log_hexdump(const std::string& title, const void* data, size_t size) {
    if (get_log_level() != LogLevel::Debug) {
        return;
    }
    if ((data == nullptr) || size == 0) {
        return;
    }

    const auto* bytes = static_cast<const unsigned char*>(data);

    std::ostringstream header;
    header << title << " (" << size << " bytes)";
    log_debug(header.str());

    std::ostringstream line;
    for (size_t i = 0; i < size; ++i) {
        if ((i % 16) == 0) {
            if (i != 0) {
                log_debug(line.str());
                line.str(std::string());
                line.clear();
            }
        }
        line << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(bytes[i]) << " ";
    }
    if (!line.str().empty()) {
        log_debug(line.str());
    }
}
