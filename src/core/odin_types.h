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

#ifndef ODIN_TYPES_H
#define ODIN_TYPES_H

#include <string>
#include <vector>
#include <cstdint>

// Exit codes are part of the CLI contract.
// 0: success
// 1: argument/usage error
// 2: USB/device error
// 3: flashing/protocol error
// 4: PIT/compatibility error
// 5: firmware/archive/MD5 error
enum class ExitCode : int { Success = 0, Usage = 1, Usb = 2, Protocol = 3, Pit = 4, Firmware = 5 };

// ============================================================================
// PARTITION INFORMATION TABLE (PIT)
// ============================================================================

#pragma pack(push, 1)
struct PitEntry {
    // Layout matches the 132-byte PIT entry used by Samsung download mode.
    uint32_t binary_type;
    uint32_t device_type;
    uint32_t identifier;
    uint32_t attributes;
    uint32_t update_attributes;
    uint32_t block_size_or_offset;
    uint32_t block_count;
    uint32_t file_offset;
    uint32_t file_size;
    char partition_name[32];
    char file_name[32];
    char fota_name[32];
};
#pragma pack(pop)

struct PitTable {
    uint32_t entry_count = 0;
    uint32_t header_size = 0;
    uint32_t unknown1 = 0;
    uint32_t unknown2 = 0;
    uint16_t unknown3 = 0;
    uint16_t unknown4 = 0;
    uint16_t unknown5 = 0;
    uint16_t unknown6 = 0;
    uint16_t unknown7 = 0;
    uint16_t unknown8 = 0;
    std::vector<PitEntry> entries;
};

#endif // ODIN_TYPES_H
