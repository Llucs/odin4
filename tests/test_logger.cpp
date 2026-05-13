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

#include "test_framework.h"
#include "../src/core/logger.h"
#include <cstring>
#include <string>

namespace {

LogLevel global_log_level = LogLevel::Info;

}

void set_log_callback(LogCallback) {}
void set_log_level(LogLevel level) {
    global_log_level = level;
}
auto get_log_level() -> LogLevel {
    return global_log_level;
}
void set_log_file(const std::string&) {}
void log_error(const std::string&, int) {}
void log_warn(const std::string&) {}
void log_info(const std::string&) {}
void log_verbose(const std::string&) {}
void log_debug(const std::string&) {}
void log_hexdump(const std::string&, const void*, size_t) {}

void test_Logger_LogLevel_Values() {
    EXPECT_EQ(static_cast<int>(LogLevel::Error), 0);
    EXPECT_EQ(static_cast<int>(LogLevel::Warn), 1);
    EXPECT_EQ(static_cast<int>(LogLevel::Info), 2);
    EXPECT_EQ(static_cast<int>(LogLevel::Verbose), 3);
    EXPECT_EQ(static_cast<int>(LogLevel::Debug), 4);
}
REGISTER_TEST(Logger, LogLevel_Values);

void test_Logger_SetLogLevel() {
    set_log_level(LogLevel::Error);
    EXPECT_EQ(static_cast<int>(get_log_level()), static_cast<int>(LogLevel::Error));

    set_log_level(LogLevel::Warn);
    EXPECT_EQ(static_cast<int>(get_log_level()), static_cast<int>(LogLevel::Warn));

    set_log_level(LogLevel::Info);
    EXPECT_EQ(static_cast<int>(get_log_level()), static_cast<int>(LogLevel::Info));

    set_log_level(LogLevel::Verbose);
    EXPECT_EQ(static_cast<int>(get_log_level()), static_cast<int>(LogLevel::Verbose));

    set_log_level(LogLevel::Debug);
    EXPECT_EQ(static_cast<int>(get_log_level()), static_cast<int>(LogLevel::Debug));
}
REGISTER_TEST(Logger, SetLogLevel);

void test_Logger_DefaultLogLevel() {
    set_log_level(LogLevel::Info);
    EXPECT_EQ(static_cast<int>(get_log_level()), static_cast<int>(LogLevel::Info));
}
REGISTER_TEST(Logger, DefaultLogLevel);