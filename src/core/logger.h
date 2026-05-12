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

#ifndef LOGGER_H
#define LOGGER_H

#include <string>
#include <cstddef>

enum class LogLevel : int { Error = 0, Warn = 1, Info = 2, Verbose = 3, Debug = 4 };

// Configure the console/file verbosity. Errors are always printed.
void set_log_level(LogLevel level);
auto get_log_level() -> LogLevel;

// Configure an optional log file. If the path is empty no file logging will occur.
void set_log_file(const std::string& path);

void log_error(const std::string& msg, int libusb_err = 0);
void log_warn(const std::string& msg);
void log_info(const std::string& msg);
void log_verbose(const std::string& msg);
void log_debug(const std::string& msg);

// Produce a hex dump of a binary buffer. Only emitted when log level is Debug.
void log_hexdump(const std::string& title, const void* data, size_t size);

#endif // LOGGER_H
