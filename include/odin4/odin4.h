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

#ifndef ODIN4_H
#define ODIN4_H

#include <string>
#include <vector>
#include <cstdint>

/**
 * @brief Exit codes for Odin4 operations.
 */
enum class OdinExitCode : int { Success = 0, Usage = 1, Usb = 2, Protocol = 3, Pit = 4, Firmware = 5, Unknown = 99 };

/**
 * @brief Configuration for Odin4 operations.
 */
struct OdinConfig {
    std::string bootloader;
    std::string ap;
    std::string cp;
    std::string csc;
    std::string ums;
    std::string device_path;

    bool dry_run = false;
    bool allow_unknown = false;
    bool reboot = false;
    bool redownload = false;
    bool efs_clear = false;
    bool boot_update = false;

    bool quiet = false;
    bool verbose = false;
    bool debug = false;

    bool has_vid = false;
    uint16_t vid = 0;
    bool has_pid = false;
    uint16_t pid = 0;
    bool has_usb_interface = false;
    int usb_interface = 0;

    int preflash_timeout_ms = 1000;
    int flash_timeout_ms = 45000;
    unsigned preflash_retries = 2;
};

void odin4_init(const OdinConfig& cfg);

auto odin4_list_devices(const OdinConfig& cfg) -> std::vector<std::string>;

auto odin4_run(const OdinConfig& cfg) -> OdinExitCode;

auto odin4_get_version() -> const char*;

typedef void (*OdinLogCallback)(int level, const char* message);
void odin4_set_log_callback(OdinLogCallback callback);

#endif // ODIN4_H
