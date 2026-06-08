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

#include <cstdint>
#include <cstddef>
#include <cstring>
#include "protocol/thor_protocol.h"
#include "firmware/firmware_package.h"
#include "odin4/fuzz_utils.h"

static void fuzz_parse_tar_header(const uint8_t* data, size_t size) {
    if (size < 512) return;
    char name[101]{};
    std::memcpy(name, data, 100);
    for (int i = 0; i < 100; ++i) {
        if (name[i] == '\0') break;
        if (name[i] < 32) name[i] = '.';
    }
    name[100] = '\0';
    unsigned int checksum = 0;
    for (int i = 0; i < 512; ++i) checksum += data[i];
    (void)checksum;
}

static void fuzz_detect_md5_trailer(const uint8_t* data, size_t size) {
    if (size < 32) return;
    for (size_t i = size - 32; i < size; ++i) {
        char c = static_cast<char>(data[i]);
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) return;
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    try {
        // Test TAR header parsing - 512 byte blocks
        if (size >= 512) {
            // Test first block as TAR header
            fuzz_parse_tar_header(data, 512);

            // For larger inputs, test consecutive blocks
            for (size_t i = 0; i + 512 <= size; i += 512) {
                fuzz_parse_tar_header(data + i, 512);
            }
        }

        // Test MD5 trailer detection
        if (size > 32) {
            fuzz_detect_md5_trailer(data, size);
        }
    } catch (...) {
    }
    return 0;
}