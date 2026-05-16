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
#include <lz4frame.h>
#include "lz4/lz4.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    try {
        // Test LZ4 frame parsing
        if (size > 0) {
            fuzz_lz4_decompress(data, size);
        }

        // Test raw LZ4 compression decompression (non-frame)
        if (size > 0 && size < (1 << 20)) {
            char decompressed[4096];
            const int decompressed_size =
                LZ4_decompress_safe(reinterpret_cast<const char*>(data), decompressed, static_cast<int>(size), 4096);
            if (decompressed_size > 0) {
                (void) decompressed_size;
            }
        }
    } catch (...) {
    }
    return 0;
}