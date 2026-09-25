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
#include "../src/firmware/tar_md5_trailer.h"
#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace {

const std::string kMd5 = "2eeb1bd4db54e49dae48120c359db629";

// Builds "<content><md5>  <name>\n", mirroring a Samsung .tar.md5 file.
auto make_file(const std::vector<char>& content) -> std::vector<char> {
    std::vector<char> file = content;
    const std::string trailer = kMd5 + "  BL_TEST.tar\n";
    file.insert(file.end(), trailer.begin(), trailer.end());
    return file;
}

// Returns the absolute content end computed from the last `max_tail` bytes, as detect_tar_md5_info() does.
auto content_end_of(const std::vector<char>& file, size_t max_tail = 65536) -> int64_t {
    const size_t tail_len = std::min(file.size(), max_tail);
    const uint64_t tail_offset = file.size() - tail_len;
    const auto pos = tar_md5::locate_trailer(file.data() + tail_offset, tail_len, tail_offset);
    if (pos.md5_pos < 0)
        return -1;
    return static_cast<int64_t>(tail_offset) + pos.trailer_start;
}

// Binary TAR-like payload that contains 0x0A bytes, as lz4 images do.
auto binary_payload(size_t size) -> std::vector<char> {
    std::vector<char> v(size);
    uint32_t x = 0x12345678;
    for (auto& c : v) {
        x = x * 1103515245u + 12345u;
        c = static_cast<char>(x >> 24);
    }
    v[size - 1500] = '\n';
    v[size - 3] = '\n';
    v[size - 1] = '\0';
    return v;
}

} // namespace

// Regression for #279: newlines in the payload must not pull content_end into the TAR data.
void test_TarMd5Trailer_aligned_payload_with_newlines() {
    const auto content = binary_payload(512 * 300);
    const auto file = make_file(content);
    EXPECT_EQ(content_end_of(file), static_cast<int64_t>(content.size()));
}

void test_TarMd5Trailer_aligned_tail_offset_nonzero() {
    const auto content = binary_payload(512 * 1024);
    const auto file = make_file(content);
    EXPECT_EQ(content_end_of(file, 4096), static_cast<int64_t>(content.size()));
}

void test_TarMd5Trailer_aligned_payload_without_newlines() {
    std::vector<char> content(512 * 4, '\0');
    const auto file = make_file(content);
    EXPECT_EQ(content_end_of(file), static_cast<int64_t>(content.size()));
}

void test_TarMd5Trailer_md5_position() {
    const auto content = binary_payload(512 * 8);
    const auto file = make_file(content);
    const auto pos = tar_md5::locate_trailer(file.data(), file.size(), 0);
    EXPECT_EQ(pos.md5_pos, static_cast<int64_t>(content.size()));
    EXPECT_TRUE(std::string(file.data() + pos.md5_pos, 32) == kMd5);
}

// Non-aligned fallback: a newline right before the MD5 still marks the trailer start.
void test_TarMd5Trailer_unaligned_newline_before_md5() {
    std::vector<char> content(512 * 4 + 100, '\0');
    content.back() = '\n';
    const auto file = make_file(content);
    EXPECT_EQ(content_end_of(file), static_cast<int64_t>(content.size()));
}

// Non-aligned fallback: the newline scan must not cross the preceding 512-byte boundary.
void test_TarMd5Trailer_unaligned_scan_bounded_by_block() {
    auto content = binary_payload(512 * 4 + 100);
    std::fill(content.end() - 100, content.end(), 'x');
    content[512 * 4 - 10] = '\n';
    const auto file = make_file(content);
    EXPECT_EQ(content_end_of(file), static_cast<int64_t>(content.size()));
}

void test_TarMd5Trailer_no_md5() {
    std::vector<char> file(2048, 'z');
    EXPECT_EQ(content_end_of(file), -1);
}

void test_TarMd5Trailer_tail_too_short() {
    const std::string s = "abc";
    const auto pos = tar_md5::locate_trailer(s.data(), s.size(), 0);
    EXPECT_EQ(pos.md5_pos, -1);
}

REGISTER_TEST(TarMd5Trailer, aligned_payload_with_newlines);
REGISTER_TEST(TarMd5Trailer, aligned_tail_offset_nonzero);
REGISTER_TEST(TarMd5Trailer, aligned_payload_without_newlines);
REGISTER_TEST(TarMd5Trailer, md5_position);
REGISTER_TEST(TarMd5Trailer, unaligned_newline_before_md5);
REGISTER_TEST(TarMd5Trailer, unaligned_scan_bounded_by_block);
REGISTER_TEST(TarMd5Trailer, no_md5);
REGISTER_TEST(TarMd5Trailer, tail_too_short);
