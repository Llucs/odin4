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

#include "odin4/fuzz_utils.h"
#include "protocol/thor_protocol.h"
#include <vector>
#include <cstring>
#include <unordered_set>

// PIT parsing - extracted from usb_device.cpp for fuzzing
// This duplicates the core logic to make it accessible without modifications
auto fuzz_parse_pit_bytes(PitTable& pit_table, const std::vector<unsigned char>& pit_data) -> bool {
    if (pit_data.size() < 28) {
        return false;
    }

    auto read_u32 = [&](size_t off) -> uint32_t {
        uint32_t v = 0;
        std::memcpy(&v, pit_data.data() + off, sizeof(v));
        return le32_to_h(v);
    };
    auto read_u16 = [&](size_t off) -> uint16_t {
        uint16_t v = 0;
        std::memcpy(&v, pit_data.data() + off, sizeof(v));
        return static_cast<uint16_t>(le16toh(v));
    };

    const uint32_t file_id = read_u32(0);
    if (file_id != 0x12349876) {
        return false;
    }

    pit_table.entry_count = read_u32(4);
    if (pit_table.entry_count == 0 || pit_table.entry_count > 512) {
        return false;
    }

    pit_table.unknown1 = read_u32(8);
    pit_table.unknown2 = read_u32(12);
    pit_table.unknown3 = read_u16(16);
    pit_table.unknown4 = read_u16(18);
    pit_table.unknown5 = read_u16(20);
    pit_table.unknown6 = read_u16(22);
    pit_table.unknown7 = read_u16(24);
    pit_table.unknown8 = read_u16(26);

    pit_table.header_size = 28;
    const size_t entry_size = 132;
    const size_t required = pit_table.header_size + static_cast<size_t>(pit_table.entry_count) * entry_size;
    if (pit_data.size() < required) {
        return false;
    }

    pit_table.entries.clear();
    pit_table.entries.reserve(pit_table.entry_count);

    auto extract_field = [](const char* field, size_t max_len) -> std::string {
        size_t n = 0;
        while (n < max_len && field[n] != '\0') {
            ++n;
        }
        std::string s(field, n);
        while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) {
            s.pop_back();
        }
        return s;
    };

    std::unordered_set<uint32_t> seen_identifiers;

    for (uint32_t i = 0; i < pit_table.entry_count; ++i) {
        const size_t off = pit_table.header_size + static_cast<size_t>(i) * entry_size;
        PitEntry e = {};
        e.binary_type = read_u32(off + 0);
        e.device_type = read_u32(off + 4);
        e.identifier = read_u32(off + 8);
        e.attributes = read_u32(off + 12);
        e.update_attributes = read_u32(off + 16);
        e.block_size_or_offset = read_u32(off + 20);
        e.block_count = read_u32(off + 24);
        e.file_offset = read_u32(off + 28);
        e.file_size = read_u32(off + 32);
        std::memcpy(e.partition_name, pit_data.data() + off + 36, 32);
        std::memcpy(e.file_name, pit_data.data() + off + 68, 32);
        std::memcpy(e.fota_name, pit_data.data() + off + 100, 32);

        const std::string part_name = extract_field(e.partition_name, 32);

        if (part_name.empty()) {
            return false;
        }
        if (e.identifier == 0) {
            return false;
        }
        if (!seen_identifiers.insert(e.identifier).second) {
            return false;
        }

        pit_table.entries.push_back(e);
    }

    return true;
}