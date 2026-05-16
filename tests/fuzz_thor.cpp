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
#include "protocol/thor_protocol.h"
#include "odin4/fuzz_helpers.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    try {
        // Test Thor protocol packet parsing
        fuzz_parse_thor_packet(data, size);

        // Also test specific packet types
        if (size >= sizeof(ThorHandshakePacket)) {
            auto* pkt = reinterpret_cast<const ThorHandshakePacket*>(data);
            (void) pkt->magic;
            (void) pkt->version;
        }

        if (size >= sizeof(ThorPitFilePacket)) {
            auto* pkt = reinterpret_cast<const ThorPitFilePacket*>(data);
            (void) pkt->pit_file_size;
        }

        if (size >= sizeof(ThorResponsePacket)) {
            auto* pkt = reinterpret_cast<const ThorResponsePacket*>(data);
            (void) pkt->response_code;
        }
    } catch (...) {
    }
    return 0;
}