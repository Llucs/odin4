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

#ifndef TAR_MD5_TRAILER_H
#define TAR_MD5_TRAILER_H

#include <cstddef>
#include <cstdint>

namespace tar_md5 {

/// Returns true for an ASCII hex digit (0-9, a-f, A-F).
inline auto is_hex_char(unsigned char c) -> bool {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

/// Position of a .tar.md5 trailer within the tail buffer passed to locate_trailer().
struct TrailerPos {
    /// Offset of the 32 hex digits within the tail buffer, or -1 if none was found.
    int64_t md5_pos = -1;
    /// Offset within the tail buffer where the trailer line starts (== end of TAR content).
    int64_t trailer_start = -1;
};

/// Locates the MD5 trailer of a Samsung .tar.md5 file ("<md5>  <name>\n" appended after the TAR).
/// `tail` holds the last `tail_len` bytes of the file; `tail_offset` is the absolute file offset of tail[0].
///
/// A TAR archive always ends on a 512-byte boundary, so a block-aligned MD5 is the trailer start as-is.
/// Scanning back for '\n' from there would walk into binary TAR payload (e.g. lz4 images contain 0x0A)
/// and truncate the content range. The newline scan is kept only for the non-aligned fallback, and even
/// then it never crosses the preceding 512-byte boundary, since the TAR content cannot end before it.
inline auto locate_trailer(const char* tail, size_t tail_len, uint64_t tail_offset) -> TrailerPos {
    auto hex_at = [&](int64_t i) { return is_hex_char(static_cast<unsigned char>(tail[static_cast<size_t>(i)])); };

    auto find_md5 = [&](bool require_block_aligned) -> int64_t {
        for (int64_t pos = static_cast<int64_t>(tail_len) - 32; pos >= 0; --pos) {
            if (require_block_aligned && (tail_offset + static_cast<uint64_t>(pos)) % 512 != 0) {
                continue;
            }

            bool ok = true;
            for (int i = 0; i < 32; ++i) {
                if (!hex_at(pos + i)) {
                    ok = false;
                    break;
                }
            }
            if (!ok)
                continue;

            const bool left_ok = (pos == 0) || !hex_at(pos - 1);
            const bool right_ok = (static_cast<size_t>(pos + 32) >= tail_len) || !hex_at(pos + 32);
            if (!left_ok || !right_ok)
                continue;

            return pos;
        }
        return -1;
    };

    TrailerPos result;
    if (tail_len < 32) {
        return result;
    }

    bool block_aligned = true;
    result.md5_pos = find_md5(true);
    if (result.md5_pos < 0) {
        block_aligned = false;
        result.md5_pos = find_md5(false);
    }
    if (result.md5_pos < 0) {
        return result;
    }

    result.trailer_start = result.md5_pos;
    if (!block_aligned) {
        const uint64_t abs_md5 = tail_offset + static_cast<uint64_t>(result.md5_pos);
        const uint64_t abs_boundary = abs_md5 - (abs_md5 % 512);
        const int64_t min_pos = abs_boundary > tail_offset ? static_cast<int64_t>(abs_boundary - tail_offset) : 0;
        for (int64_t p = result.md5_pos - 1; p >= min_pos; --p) {
            if (tail[static_cast<size_t>(p)] == '\n') {
                result.trailer_start = p + 1;
                break;
            }
        }
    }
    return result;
}

} // namespace tar_md5

#endif // TAR_MD5_TRAILER_H
