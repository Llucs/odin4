#ifndef LOGGER_H
#define LOGGER_H

#include <string>
#include <cstddef>

enum class LogLevel : int { Error = 0, Warn = 1, Info = 2, Verbose = 3, Debug = 4 };

// Configure the console/file verbosity. Errors are always printed.
void set_log_level(LogLevel level);
LogLevel get_log_level();

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
