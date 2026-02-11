// ============================================================================
// Logger utilities for odin4
// Provides basic logging with optional file output and thread safety.
// All log messages are prefixed with their level and written to std::cout or std::cerr.
// When a log file is configured, messages are also appended to that file.
// ============================================================================
#ifndef LOGGER_H
#define LOGGER_H

#include <string>
#include <cstddef>

// Configure the log file. If the path is empty no file logging will occur.
// This function can be called multiple times; subsequent calls will close the
// previous file and open the new one.
void set_log_file(const std::string& path);

// Log an informational message. Messages are written to stdout and the log file.
void log_info(const std::string& msg);

// Log an error message. Messages are written to stderr and the log file.
// If a non-zero libusb error code is provided the error name is appended.
void log_error(const std::string& msg, int libusb_err = 0);

// Produce a hex dump of a binary buffer. The title will prefix the output.
// The dump is written to stdout and the log file when enabled.
void log_hexdump(const std::string& title, const void* data, size_t size);

#endif // LOGGER_H
