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

#include "firmware/firmware_package.h"
#include "core/logger.h"

#include <iostream>
#include <vector>
#include <cstdlib>
#include <unistd.h>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <ranges>
#include <span>
#include <unordered_set>
#include <sstream>
#include <limits>
#include <format>
#include <print>
#include <filesystem>
#include <lz4frame.h>

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>
#include <cryptopp/hex.h>

namespace {
struct TarMd5Info {
    bool has_md5 = false;
    uint64_t content_end = 0;
    std::string expected_md5;
};

auto is_hex_char(unsigned char c) -> bool {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

auto is_hex32(const std::string& s) -> bool {
    return s.size() == 32 && std::ranges::all_of(s, [](unsigned char c) { return is_hex_char(c); });
}

auto to_lower_copy(std::string s) -> std::string {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

auto ends_with_case_insensitive(const std::string& s, const std::string& suffix) -> bool {
    if (s.size() < suffix.size()) {
        return false;
    }
    return to_lower_copy(s).ends_with(to_lower_copy(suffix));
}

auto tar_field_string(const char* field, size_t max_len) -> std::string {
    size_t n = 0;
    while (n < max_len && field[n] != '\0') {
        ++n;
    }
    std::string s(field, n);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) {
        s.pop_back();
    }
    return s;
}

auto parse_octal_u64(const char* field, size_t len, uint64_t& out) -> bool {
    out = 0;
    if ((field == nullptr) || len == 0) {
        return true;
    }

    size_t i = 0;
    while (i < len && (field[i] == ' ' || field[i] == '\t')) {
        ++i;
    }
    if (i < len && field[i] == '\0') {
        return true;
    }

    bool any = false;
    for (; i < len; ++i) {
        const auto c = static_cast<unsigned char>(field[i]);
        if (c == '\0' || c == ' ' || c == '\t') {
            break;
        }
        if (c < '0' || c > '7') {
            return false;
        }
        const uint64_t prev = out;
        out = (out << 3) + static_cast<uint64_t>(c - '0');
        if ((out >> 3) != prev) {
            return false;
        }
        any = true;
    }

    if (!any) {
        out = 0;
    }
    return true;
}

auto read_exact(std::ifstream& file, void* buf, size_t len) -> bool {
    file.read(static_cast<char*>(buf), static_cast<std::streamsize>(len));
    return static_cast<size_t>(file.gcount()) == len;
}

auto detect_tar_md5_info(const std::string& file_path, TarMd5Info& info) -> ExitCode {
    info = TarMd5Info{};

    std::ifstream file(file_path, std::ios::binary | std::ios::ate);
    if (!file) {
        log_error(std::format("Could not open file: {}", file_path));
        return ExitCode::Firmware;
    }

    const std::streampos sp = file.tellg();
    if (sp < 0) {
        log_error(std::format("Failed to determine file size: {}", file_path));
        return ExitCode::Firmware;
    }
    const auto file_size = static_cast<uint64_t>(sp);
    file.seekg(0);

    info.content_end = file_size;

    if (!ends_with_case_insensitive(file_path, ".tar.md5")) {
        return ExitCode::Success;
    }

    if (file_size < 32) {
        log_error(std::format("File too small to contain an MD5 trailer: {}", file_path));
        return ExitCode::Firmware;
    }

    const uint64_t tail_len = std::min<uint64_t>(file_size, 65536);
    file.seekg(static_cast<std::streamoff>(file_size - tail_len));

    std::vector<char> tail(static_cast<size_t>(tail_len));
    if (!read_exact(file, tail.data(), tail.size())) {
        log_error(std::format("Failed to read MD5 trailer region: {}", file_path));
        return ExitCode::Firmware;
    }

    int64_t best_pos = -1;
    for (int64_t pos = static_cast<int64_t>(tail.size()) - 32; pos >= 0; --pos) {
        bool ok = true;
        for (int i = 0; i < 32; ++i) {
            if (!is_hex_char(static_cast<unsigned char>(tail[static_cast<size_t>(pos + i)]))) {
                ok = false;
                break;
            }
        }
        if (!ok) {
            continue;
        }

        const bool left_ok = (pos == 0) || !is_hex_char(static_cast<unsigned char>(tail[static_cast<size_t>(pos - 1)]));
        const bool right_ok = (static_cast<size_t>(pos + 32) >= tail.size()) ||
                              !is_hex_char(static_cast<unsigned char>(tail[static_cast<size_t>(pos + 32)]));
        if (!left_ok || !right_ok) {
            continue;
        }

        best_pos = pos;
        break;
    }

    if (best_pos < 0) {
        std::string last32(tail.end() - 32, tail.end());
        if (!is_hex32(last32)) {
            log_error(std::format("Unable to locate a valid MD5 trailer in: {}", file_path));
            return ExitCode::Firmware;
        }
        info.has_md5 = true;
        info.expected_md5 = to_lower_copy(last32);
        info.content_end = file_size - 32;
        return ExitCode::Success;
    }

    std::string md5(tail.data() + best_pos, 32);
    if (!is_hex32(md5)) {
        log_error(std::format("Detected an invalid MD5 trailer in: {}", file_path));
        return ExitCode::Firmware;
    }

    int64_t line_start = best_pos;
    for (int64_t p = best_pos - 1; p >= 0; --p) {
        if (tail[static_cast<size_t>(p)] == '\n') {
            line_start = p + 1;
            break;
        }
    }

    const uint64_t trailer_start = (file_size - tail_len) + static_cast<uint64_t>(line_start);
    if (trailer_start >= file_size) {
        log_error(std::format("Invalid MD5 trailer position in: {}", file_path));
        return ExitCode::Firmware;
    }

    info.has_md5 = true;
    info.expected_md5 = to_lower_copy(md5);
    info.content_end = trailer_start;
    return ExitCode::Success;
}

auto verify_tar_md5(const std::string& file_path, const TarMd5Info& info) -> ExitCode {
    if (!info.has_md5) {
        return ExitCode::Success;
    }

    if (info.content_end == 0) {
        log_error(std::format("Invalid MD5 content size (0): {}", file_path));
        return ExitCode::Firmware;
    }

    std::ifstream file(file_path, std::ios::binary);
    if (!file) {
        log_error(std::format("Could not open file for MD5 verification: {}", file_path));
        return ExitCode::Firmware;
    }

    CryptoPP::Weak::MD5 hash;
    std::vector<unsigned char> digest(hash.DigestSize());

    const size_t buf_size = 1024 * 1024;
    std::vector<char> buf(buf_size);

    uint64_t remaining = info.content_end;
    while (remaining > 0) {
        const size_t to_read = static_cast<size_t>(std::min<uint64_t>(remaining, buf.size()));
        if (!read_exact(file, buf.data(), to_read)) {
            log_error(std::format("Short read during MD5 verification: {}", file_path));
            return ExitCode::Firmware;
        }
        hash.Update(reinterpret_cast<const unsigned char*>(buf.data()), to_read);
        remaining -= to_read;
    }

    hash.Final(digest.data());

    std::string calculated;
    CryptoPP::HexEncoder encoder;
    encoder.Attach(new CryptoPP::StringSink(calculated));
    encoder.Put(digest.data(), digest.size());
    encoder.MessageEnd();

    const std::string calc_lower = to_lower_copy(calculated);
    if (calc_lower != info.expected_md5) {
        log_error(std::format("MD5 verification failed. Expected: {} | Calculated: {}", info.expected_md5, calc_lower));
        return ExitCode::Firmware;
    }

    log_info("MD5 verification successful.");
    return ExitCode::Success;
}

auto is_all_zeros_block(const char* header) -> bool {
    return std::ranges::all_of(std::span(header, 512), [](char c) { return c == 0; });
}

auto tar_header_checksum_valid(const char* header) -> bool {
    uint64_t expected = 0;
    if (!parse_octal_u64(header + 148, 8, expected)) {
        return false;
    }

    uint64_t sum_unsigned = 0;
    int64_t sum_signed = 0;
    for (int i = 0; i < 512; ++i) {
        unsigned char u = 0;
        if (i >= 148 && i < 156) {
            u = static_cast<unsigned char>(' ');
        } else {
            u = static_cast<unsigned char>(header[i]);
        }
        sum_unsigned += static_cast<uint64_t>(u);
        sum_signed += static_cast<int64_t>(static_cast<int8_t>(u));
    }

    if (expected == sum_unsigned) {
        return true;
    }
    if (sum_signed >= 0 && expected == static_cast<uint64_t>(sum_signed)) {
        return true;
    }
    return false;
}

auto sanitize_tar_name(const std::string& s) -> std::string {
    std::string out = s;
    while (!out.empty() && (out.back() == '\0' || out.back() == '\n' || out.back() == '\r')) {
        out.pop_back();
    }
    return out;
}

auto base_name_from_path(const std::string& p) -> std::string {
    const size_t pos = p.find_last_of("/\\");
    if (pos == std::string::npos) {
        return p;
    }
    return p.substr(pos + 1);
}
} // namespace

auto sanitize_filename(const std::string& filename) -> std::string {
    std::string sanitized = filename;
    size_t last_dot = sanitized.find_last_of('.');
    while (last_dot != std::string::npos) {
        std::string ext = sanitized.substr(last_dot);
        std::string ext_lower = to_lower_copy(ext);
        if (ext_lower == ".lz4" || ext_lower == ".ext4" || ext_lower == ".img" || ext_lower == ".bin") {
            sanitized = sanitized.substr(0, last_dot);
            last_dot = sanitized.find_last_of('.');
        } else {
            break;
        }
    }
    return sanitized;
}

auto check_md5_signature(const std::string& file_path) -> bool {
    TarMd5Info info;
    const ExitCode di = detect_tar_md5_info(file_path, info);
    if (di != ExitCode::Success) {
        return false;
    }
    const ExitCode vr = verify_tar_md5(file_path, info);
    return vr == ExitCode::Success;
}

auto decompress_lz4_to_file(std::ifstream& file, uint64_t compressed_size, const std::string& out_path) -> bool {
    const std::streampos entry_start = file.tellg();
    if (entry_start < 0) {
        log_error("Unexpected end of file during LZ4 decompression.");
        return false;
    }

    LZ4F_decompressionContext_t dctx;
    LZ4F_errorCode_t err = LZ4F_createDecompressionContext(&dctx, LZ4F_VERSION);
    if (LZ4F_isError(err) != 0U) {
        log_error("Failed to create LZ4 decompression context: " + std::string(LZ4F_getErrorName(err)));
        return false;
    }

    struct DctxCleanup {
        LZ4F_decompressionContext_t ctx;
        explicit DctxCleanup(LZ4F_decompressionContext_t c) : ctx(c) {}
        ~DctxCleanup() { LZ4F_freeDecompressionContext(ctx); }
    } cleanup(dctx);

    std::ofstream out(out_path, std::ios::binary);
    if (!out) {
        log_error("Failed to create temporary file: " + out_path);
        return false;
    }

    size_t in_buf_size = 1024 * 1024;
    size_t out_buf_size = 4 * 1024 * 1024;
    if (compressed_size > 1024ULL * 1024ULL * 1024ULL) {
        in_buf_size = 8 * 1024 * 1024;
        out_buf_size = 16 * 1024 * 1024;
    }

    std::vector<unsigned char> in_buf(in_buf_size);
    std::vector<unsigned char> out_buf(out_buf_size);

    uint64_t remaining_compressed = compressed_size;
    uint64_t total_uncompressed = 0;

    const size_t header_read_size = static_cast<size_t>(std::min<uint64_t>(1024, compressed_size));
    std::vector<unsigned char> header_buf(header_read_size);
    file.read(reinterpret_cast<char*>(header_buf.data()), static_cast<std::streamsize>(header_read_size));
    if (static_cast<size_t>(file.gcount()) != header_read_size) {
        log_error("Failed to read LZ4 header");
        return false;
    }
    file.seekg(entry_start);

    LZ4F_frameInfo_t frame_info;
    size_t consumed = header_read_size;
    err = LZ4F_getFrameInfo(dctx, &frame_info, header_buf.data(), &consumed);
    if (LZ4F_isError(err) != 0U) {
        log_error("Failed to get LZ4 frame info: " + std::string(LZ4F_getErrorName(err)));
        return false;
    }

    uint64_t uncompressed_size = frame_info.contentSize;

    if (uncompressed_size == 0) {
        log_info("LZ4 frame does not include uncompressed size; scanning to determine size.");
        LZ4F_decompressionContext_t scan_ctx;
        LZ4F_errorCode_t scan_err = LZ4F_createDecompressionContext(&scan_ctx, LZ4F_VERSION);
        if (LZ4F_isError(scan_err) != 0U) {
            log_error("Failed to create LZ4 scan context: " + std::string(LZ4F_getErrorName(scan_err)));
            return false;
        }

        uint64_t scan_remaining = compressed_size;
        std::streampos scan_start = file.tellg();
        if (scan_start < 0) {
            LZ4F_freeDecompressionContext(scan_ctx);
            log_error("Unexpected end of file during LZ4 decompression.");
            return false;
        }

        size_t src_offset = 0;
        size_t src_size = 0;
        bool frame_ended = false;

        while (!frame_ended && (scan_remaining > 0 || src_size > 0)) {
            if (src_size == 0 && scan_remaining > 0) {
                const auto to_read = static_cast<size_t>(std::min<uint64_t>(in_buf_size, scan_remaining));
                file.read(reinterpret_cast<char*>(in_buf.data()), static_cast<std::streamsize>(to_read));
                const auto read = static_cast<size_t>(file.gcount());
                if (read == 0) {
                    LZ4F_freeDecompressionContext(scan_ctx);
                    log_error("Unexpected end of file during LZ4 decompression.");
                    return false;
                }
                src_offset = 0;
                src_size = read;
                scan_remaining -= read;
            }

            while (src_size > 0 && !frame_ended) {
                size_t dst_sz = out_buf_size;
                size_t src_consumed = src_size;
                scan_err = LZ4F_decompress(scan_ctx, out_buf.data(), &dst_sz, in_buf.data() + src_offset, &src_consumed, nullptr);
                if (LZ4F_isError(scan_err) != 0U) {
                    LZ4F_freeDecompressionContext(scan_ctx);
                    log_error("LZ4 scan decompression error: " + std::string(LZ4F_getErrorName(scan_err)));
                    return false;
                }

                if (dst_sz != 0) {
                    if (uncompressed_size > (std::numeric_limits<uint64_t>::max() - dst_sz)) {
                        LZ4F_freeDecompressionContext(scan_ctx);
                        log_error("LZ4 scan decompression overflow");
                        return false;
                    }
                    uncompressed_size += dst_sz;
                }

                if (src_consumed == 0 && dst_sz == 0 && scan_err != 0) {
                    if (scan_remaining == 0) {
                        LZ4F_freeDecompressionContext(scan_ctx);
                        log_error("LZ4 scan decompression made no progress");
                        return false;
                    }
                    if (src_offset != 0) {
                        if (src_offset + src_size > in_buf_size) {
                            LZ4F_freeDecompressionContext(scan_ctx);
                            log_error("LZ4 scan buffer overflow");
                            return false;
                        }
                        std::memmove(in_buf.data(), in_buf.data() + src_offset, src_size);
                        src_offset = 0;
                    }
                    const size_t space = in_buf_size - src_size;
                    const auto to_read = static_cast<size_t>(std::min<uint64_t>(space, scan_remaining));
                    if (to_read == 0) {
                        LZ4F_freeDecompressionContext(scan_ctx);
                        log_error("LZ4 scan decompression made no progress");
                        return false;
                    }
                    file.read(reinterpret_cast<char*>(in_buf.data() + src_size), static_cast<std::streamsize>(to_read));
                    const auto read = static_cast<size_t>(file.gcount());
                    if (read == 0) {
                        LZ4F_freeDecompressionContext(scan_ctx);
                        log_error("Unexpected end of file during LZ4 decompression.");
                        return false;
                    }
                    src_size += read;
                    scan_remaining -= read;
                    continue;
                }

                src_offset += src_consumed;
                src_size -= src_consumed;
                if (scan_err == 0) frame_ended = true;
            }
        }

        if (!frame_ended) {
            LZ4F_freeDecompressionContext(scan_ctx);
            log_error("LZ4 scan decompression did not find frame end");
            return false;
        }

        if (scan_remaining > 0) {
            if (scan_remaining > static_cast<uint64_t>(std::numeric_limits<std::streamoff>::max())) {
                LZ4F_freeDecompressionContext(scan_ctx);
                log_error("Unexpected end of file during LZ4 decompression.");
                return false;
            }
            file.seekg(static_cast<std::streamoff>(scan_remaining), std::ios::cur);
        }

        LZ4F_freeDecompressionContext(scan_ctx);
        file.clear();
        file.seekg(scan_start);
        if (!file) {
            log_error("Failed to rewind file after LZ4 size scan");
            return false;
        }
        remaining_compressed = compressed_size;
        log_verbose(std::format("LZ4 size scan complete: {} bytes", uncompressed_size));
    }

    LZ4F_resetDecompressionContext(dctx);

    size_t src_offset = 0;
    size_t src_size = 0;

    while (remaining_compressed > 0 || src_size > 0) {
        if (src_size == 0 && remaining_compressed > 0) {
            const auto to_read = static_cast<size_t>(std::min<uint64_t>(in_buf_size, remaining_compressed));
            file.read(reinterpret_cast<char*>(in_buf.data()), static_cast<std::streamsize>(to_read));
            src_size = static_cast<size_t>(file.gcount());
            if (src_size == 0) {
                log_error("Unexpected end of file during LZ4 decompression.");
                return false;
            }
            remaining_compressed -= src_size;
            src_offset = 0;
        }

        while (src_size > 0) {
            size_t dst_size = out_buf_size;
            size_t src_consumed = src_size;
            err = LZ4F_decompress(dctx, out_buf.data(), &dst_size, in_buf.data() + src_offset, &src_consumed, nullptr);
            if (LZ4F_isError(err) != 0U) {
                log_error(std::format("LZ4 decompression error: {}", LZ4F_getErrorName(err)));
                return false;
            }

            if (src_consumed == 0 && dst_size == 0 && err != 0) {
                if (remaining_compressed == 0) {
                    log_error("LZ4 decompression made no progress");
                    return false;
                }
                if (src_offset != 0) {
                    if (src_offset + src_size > in_buf_size) {
                        log_error("LZ4 buffer overflow");
                        return false;
                    }
                    std::memmove(in_buf.data(), in_buf.data() + src_offset, src_size);
                    src_offset = 0;
                }
                const size_t space = in_buf_size - src_size;
                const auto to_read = static_cast<size_t>(std::min<uint64_t>(space, remaining_compressed));
                if (to_read == 0) {
                    log_error("LZ4 decompression made no progress");
                    return false;
                }
                file.read(reinterpret_cast<char*>(in_buf.data() + src_size), static_cast<std::streamsize>(to_read));
                const auto read = static_cast<size_t>(file.gcount());
                if (read == 0) {
                    log_error("Unexpected end of file during LZ4 decompression.");
                    return false;
                }
                src_size += read;
                remaining_compressed -= read;
                continue;
            }

            if (dst_size > 0) {
                out.write(reinterpret_cast<char*>(out_buf.data()), static_cast<std::streamsize>(dst_size));
                if (!out) {
                    log_error("Failed to write decompressed data to temporary file");
                    return false;
                }
                total_uncompressed += dst_size;
            }

            src_offset += src_consumed;
            src_size -= src_consumed;
            if (err == 0) break;
        }
        if (err == 0) break;
    }

    out.close();
    if (!out) {
        log_error("Failed to close temporary file after LZ4 decompression");
        return false;
    }

    if (uncompressed_size != 0 && total_uncompressed != uncompressed_size) {
        log_error(std::format("Decompressed size mismatch: expected {}, got {}", uncompressed_size, total_uncompressed));
        return false;
    }

    log_verbose(std::format("LZ4 decompressed {} -> {} bytes", compressed_size, total_uncompressed));
    return true;
}

auto process_tar_file(const std::string& tar_path, UsbDevice& usb_device, const PitTable& pit_table, bool do_flash,
                      bool allow_unknown, bool efs_clear, bool boot_update) -> ExitCode {
    // End-to-end TAR processing entry point:
    //  1) validate archive integrity (TAR/MD5),
    //  2) enumerate and validate package entries against PIT/partition policy,
    //  3) optionally stream payloads to device when flashing is enabled.
    // Any failure in these phases returns a non-success ExitCode immediately.
    log_info(std::format("Processing archive: {}", tar_path));

    // Preflight integrity checks: detect trailing md5 metadata (if present)
    // and verify archive checksum before parsing any content.
    TarMd5Info md5_info;
    ExitCode ec = detect_tar_md5_info(tar_path, md5_info);
    if (ec != ExitCode::Success) {
        return ec;
    }
    ec = verify_tar_md5(tar_path, md5_info);
    if (ec != ExitCode::Success) {
        return ec;
    }

    // Open archive stream and determine total readable size used by the
    // subsequent TAR entry traversal logic.
    std::ifstream file(tar_path, std::ios::binary);
    if (!file) {
        log_error(std::format("Could not open archive: {}", tar_path));
        return ExitCode::Firmware;
    }

    file.seekg(0, std::ios::end);
    const std::streampos sp = file.tellg();
    if (sp < 0) {
        log_error(std::format("Failed to determine archive size: {}", tar_path));
        return ExitCode::Firmware;
    }
    const auto file_size = static_cast<uint64_t>(sp);
    file.seekg(0);

    const uint64_t content_end = md5_info.has_md5 ? md5_info.content_end : file_size;
    if (content_end < 512) {
        log_error(std::format("Archive content is too small: {}", tar_path));
        return ExitCode::Firmware;
    }

    auto pit_field_to_string = [](const char* field, size_t max_len) -> std::string {
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

    std::unordered_set<uint32_t> used_partition_ids;

    std::string pending_gnu_long_name;
    std::string pending_pax_path;

    char header[512];
    while (true) {
        const std::streampos hpos = file.tellg();
        if (hpos < 0) {
            log_error(std::format("Archive read error: {}", tar_path));
            return ExitCode::Firmware;
        }
        const auto pos = static_cast<uint64_t>(hpos);
        if (pos + 512 > content_end) {
            break;
        }

        if (!read_exact(file, header, 512)) {
            log_error(std::format("Failed to read TAR header (truncated archive): {}", tar_path));
            return ExitCode::Firmware;
        }

        if (is_all_zeros_block(header)) {
            break;
        }

        if (!tar_header_checksum_valid(header)) {
            log_error("Invalid TAR header checksum");
            return ExitCode::Firmware;
        }

        uint64_t data_size = 0;
        if (!parse_octal_u64(header + 124, 12, data_size)) {
            log_error("Invalid TAR size field");
            return ExitCode::Firmware;
        }

        const char typeflag = header[156];

        std::string filename;
        if (!pending_gnu_long_name.empty()) {
            filename = pending_gnu_long_name;
            pending_gnu_long_name.clear();
        } else if (!pending_pax_path.empty()) {
            filename = pending_pax_path;
            pending_pax_path.clear();
        } else {
            const std::string name = tar_field_string(header, 100);
            if (std::memcmp(header + 257, "ustar", 5) == 0) {
                const std::string prefix = tar_field_string(header + 345, 155);
                if (!prefix.empty()) {
                    filename = prefix + "/" + name;
                } else {
                    filename = name;
                }
            } else {
                filename = name;
            }
        }

        filename = sanitize_tar_name(filename);

        const std::streampos dspos = file.tellg();
        if (dspos < 0) {
            log_error("Archive read error: " + tar_path);
            return ExitCode::Firmware;
        }
        const auto data_start = static_cast<uint64_t>(dspos);
        if (data_start > content_end || data_size > (content_end - data_start)) {
            log_error("Archive entry exceeds declared content length: " + filename);
            return ExitCode::Firmware;
        }

        auto skip_entry_data = [&](uint64_t size) -> ExitCode {
            if (size > static_cast<uint64_t>(std::numeric_limits<std::streamoff>::max())) {
                log_error("Failed to skip TAR entry data");
                return ExitCode::Firmware;
            }
            file.seekg(static_cast<std::streamoff>(size), std::ios::cur);
            if (!file) {
                log_error("Failed to skip TAR entry data");
                return ExitCode::Firmware;
            }
            const uint64_t padding = (512 - (size % 512)) % 512;
            file.seekg(static_cast<std::streamoff>(padding), std::ios::cur);
            if (!file) {
                log_error("Failed to skip TAR entry padding");
                return ExitCode::Firmware;
            }
            return ExitCode::Success;
        };

        if (typeflag == 'L') {
            if (data_size > 1024 * 1024) {
                log_error("GNU long name entry is too large");
                return ExitCode::Firmware;
            }
            std::vector<char> buf(static_cast<size_t>(data_size));
            if (!read_exact(file, buf.data(), buf.size())) {
                log_error("Truncated GNU long name entry");
                return ExitCode::Firmware;
            }
            std::string long_name(buf.begin(), buf.end());
            const size_t nul = long_name.find('\0');
            if (nul != std::string::npos) {
                long_name = long_name.substr(0, nul);
            }
            pending_gnu_long_name = sanitize_tar_name(long_name);
            const uint64_t padding = (512 - (data_size % 512)) % 512;
            file.seekg(static_cast<std::streamoff>(padding), std::ios::cur);
            if (!file) {
                log_error("Failed to skip TAR entry padding");
                return ExitCode::Firmware;
            }
            continue;
        }

        if (typeflag == 'x' || typeflag == 'g') {
            if (data_size > 1024 * 1024) {
                log_error("PAX header entry is too large");
                return ExitCode::Firmware;
            }
            std::vector<char> buf(static_cast<size_t>(data_size));
            if (!read_exact(file, buf.data(), buf.size())) {
                log_error("Truncated PAX header entry");
                return ExitCode::Firmware;
            }
            std::string pax(buf.begin(), buf.end());
            size_t off = 0;
            while (off < pax.size()) {
                const size_t nl = pax.find('\n', off);
                const size_t line_end = (nl == std::string::npos) ? pax.size() : nl;
                const std::string line = pax.substr(off, line_end - off);
                const size_t space = line.find(' ');
                if (space != std::string::npos) {
                    const std::string kv = line.substr(space + 1);
                    const size_t eq = kv.find('=');
                    if (eq != std::string::npos) {
                        const std::string key = kv.substr(0, eq);
                        const std::string val = kv.substr(eq + 1);
                        if (key == "path") {
                            pending_pax_path = sanitize_tar_name(val);
                        }
                    }
                }
                if (nl == std::string::npos) {
                    break;
                }
                off = nl + 1;
            }
            const uint64_t padding = (512 - (data_size % 512)) % 512;
            file.seekg(static_cast<std::streamoff>(padding), std::ios::cur);
            if (!file) {
                log_error("Failed to skip TAR entry padding");
                return ExitCode::Firmware;
            }
            continue;
        }

        // Skip non-regular entries (directories, symlinks, etc.)
        if (typeflag != 0 && typeflag != '0') {
            ec = skip_entry_data(data_size);
            if (ec != ExitCode::Success) {
                return ec;
            }
            continue;
        }

        if (filename.empty()) {
            log_error("Encountered an empty TAR entry name");
            return ExitCode::Firmware;
        }

        const std::string basename = base_name_from_path(filename);
        const std::string base_name_sanitized = to_lower_copy(sanitize_filename(basename));
        const std::string filename_lower = to_lower_copy(filename);

        const PitEntry* pit_entry = nullptr;
        std::string partition_name;

        for (const auto& entry : pit_table.entries) {
            const std::string pit_file = pit_field_to_string(entry.file_name, 32);
            const std::string pit_part = pit_field_to_string(entry.partition_name, 32);
            const std::string pit_file_s = to_lower_copy(sanitize_filename(pit_file));
            const std::string pit_part_s = to_lower_copy(sanitize_filename(pit_part));

            if (!pit_file.empty() &&
                (pit_file_s == base_name_sanitized || to_lower_copy(pit_file) == to_lower_copy(basename))) {
                pit_entry = &entry;
                partition_name = pit_part;
                break;
            }
            if (pit_part_s == base_name_sanitized) {
                pit_entry = &entry;
                partition_name = pit_part;
                break;
            }
            if (!pit_file.empty() && to_lower_copy(pit_file) == filename_lower) {
                pit_entry = &entry;
                partition_name = pit_part;
                break;
            }
        }

        if (pit_entry == nullptr) {
            if (allow_unknown) {
                log_warn("Skipping unknown archive entry (no PIT match): " + filename);
                ec = skip_entry_data(data_size);
                if (ec != ExitCode::Success) {
                    return ec;
                }
                continue;
            }
            log_error("Archive entry does not match any PIT partition: " + filename);
            return ExitCode::Pit;
        }

        if (!used_partition_ids.insert(pit_entry->identifier).second) {
            log_error("Archive contains multiple entries for the same PIT partition identifier: " +
                      std::to_string(pit_entry->identifier));
            return ExitCode::Pit;
        }

        std::string part_upper = partition_name;
        std::transform(part_upper.begin(), part_upper.end(), part_upper.begin(),
                       [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
        const bool is_large = (part_upper == "SYSTEM" || part_upper == "USERDATA" || part_upper == "SUPER");

        const std::string lower_basename = to_lower_copy(basename);
        const bool is_lz4 = ends_with_case_insensitive(lower_basename, ".lz4");

        log_verbose("TAR entry: " + filename + " (" + std::to_string(data_size) + " bytes) -> PIT: " + partition_name +
                    " (ID " + std::to_string(pit_entry->identifier) + ")");

        if (is_lz4) {
            bool compressed_ok = false;
            if (do_flash && usb_device.supports_compressed()) {
                compressed_ok = usb_device.flash_partition_stream_compressed(file, data_size, *pit_entry, is_large, efs_clear, boot_update);
            }
            if (!compressed_ok) {
                if (do_flash) {
                    file.clear();
                    file.seekg(static_cast<std::streamoff>(data_start));
                    std::error_code fs_ec;
                    auto tmp_dir = std::filesystem::temp_directory_path();
                    auto tmp_pattern = tmp_dir / "odin4_XXXXXX";
                    std::string tmpl = tmp_pattern.string();
                    std::vector<char> buf(tmpl.begin(), tmpl.end());
                    buf.push_back('\0');
                    int fd = mkstemp(buf.data());
                    if (fd == -1) {
                        log_error("Failed to create temporary file");
                        return ExitCode::Firmware;
                    }
                    close(fd);
                    std::filesystem::path temp_path(std::string(buf.data()));
                    if (!decompress_lz4_to_file(file, data_size, temp_path.string())) {
                        std::filesystem::remove(temp_path, fs_ec);
                        return ExitCode::Firmware;
                    }
                    uint64_t decomp_size = 0;
                    auto fs_size = std::filesystem::file_size(temp_path, fs_ec);
                    if (!fs_ec) decomp_size = static_cast<uint64_t>(fs_size);
                    std::ifstream temp_in(temp_path.string(), std::ios::binary);
                    bool flash_ok = temp_in && decomp_size > 0 &&
                        usb_device.flash_partition_stream(temp_in, decomp_size, *pit_entry, is_large, efs_clear, boot_update);
                    temp_in.close();
                    std::filesystem::remove(temp_path, fs_ec);
                    if (!flash_ok) {
                        return ExitCode::Protocol;
                    }
                }
            }
            if (!compressed_ok || !do_flash) {
                file.seekg(static_cast<std::streamoff>(data_start + data_size));
                if (!file) {
                    log_error("Failed to skip archive entry data: " + filename);
                    return ExitCode::Firmware;
                }
            }
        } else {
            if (do_flash) {
                if (!usb_device.flash_partition_stream(file, data_size, *pit_entry, is_large, efs_clear, boot_update)) {
                    return ExitCode::Protocol;
                }
            } else {
                file.seekg(static_cast<std::streamoff>(data_size), std::ios::cur);
                if (!file) {
                    log_error("Failed to skip archive entry data: " + filename);
                    return ExitCode::Firmware;
                }
            }
        }

        const uint64_t padding = (512 - (data_size % 512)) % 512;
        file.seekg(static_cast<std::streamoff>(padding), std::ios::cur);
        if (!file) {
            log_error("Failed to skip archive padding for: " + filename);
            return ExitCode::Firmware;
        }
    }

    return ExitCode::Success;
    // Reaching this point means all selected entries were processed successfully
    // (and flashed when requested) and archive-level checks passed.
}
