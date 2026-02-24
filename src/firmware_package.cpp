#include "firmware_package.h"
#include "logger.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <iostream>
#include <limits>
#include <lz4frame.h>
#include <sstream>
#include <unordered_set>
#include <vector>

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/hex.h>
#include <cryptopp/md5.h>

namespace {
struct TarMd5Info {
  bool has_md5 = false;
  uint64_t content_end = 0;
  std::string expected_md5;
};

bool is_hex_char(unsigned char c) {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
         (c >= 'A' && c <= 'F');
}

bool is_hex32(const std::string &s) {
  if (s.size() != 32)
    return false;
  for (unsigned char c : s) {
    if (!is_hex_char(c))
      return false;
  }
  return true;
}

std::string to_lower_copy(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return s;
}

bool ends_with_case_insensitive(const std::string &s,
                                const std::string &suffix) {
  if (s.size() < suffix.size())
    return false;
  return to_lower_copy(s.substr(s.size() - suffix.size())) ==
         to_lower_copy(suffix);
}

std::string tar_field_string(const char *field, size_t max_len) {
  size_t n = 0;
  while (n < max_len && field[n] != '\0')
    ++n;
  std::string s(field, n);
  while (!s.empty() && (s.back() == ' ' || s.back() == '\t'))
    s.pop_back();
  return s;
}

bool parse_octal_u64(const char *field, size_t len, uint64_t &out) {
  out = 0;
  if (!field || len == 0)
    return true;

  size_t i = 0;
  while (i < len && (field[i] == ' ' || field[i] == '\t'))
    ++i;
  if (i < len && field[i] == '\0')
    return true;

  bool any = false;
  for (; i < len; ++i) {
    const unsigned char c = static_cast<unsigned char>(field[i]);
    if (c == '\0' || c == ' ' || c == '\t')
      break;
    if (c < '0' || c > '7')
      return false;
    const uint64_t prev = out;
    out = (out << 3) + static_cast<uint64_t>(c - '0');
    if ((out >> 3) != prev)
      return false;
    any = true;
  }

  if (!any)
    out = 0;
  return true;
}

bool read_exact(std::ifstream &file, void *buf, size_t len) {
  file.read(static_cast<char *>(buf), static_cast<std::streamsize>(len));
  return static_cast<size_t>(file.gcount()) == len;
}

ExitCode detect_tar_md5_info(const std::string &file_path, TarMd5Info &info) {
  info = TarMd5Info{};

  std::ifstream file(file_path, std::ios::binary | std::ios::ate);
  if (!file) {
    log_error("Could not open file: " + file_path);
    return ExitCode::Firmware;
  }

  const std::streampos sp = file.tellg();
  if (sp < 0) {
    log_error("Failed to determine file size: " + file_path);
    return ExitCode::Firmware;
  }
  const uint64_t file_size = static_cast<uint64_t>(sp);
  file.seekg(0);

  info.content_end = file_size;

  if (!ends_with_case_insensitive(file_path, ".tar.md5")) {
    return ExitCode::Success;
  }

  if (file_size < 32) {
    log_error("File too small to contain an MD5 trailer: " + file_path);
    return ExitCode::Firmware;
  }

  const uint64_t tail_len = std::min<uint64_t>(file_size, 65536);
  file.seekg(static_cast<std::streamoff>(file_size - tail_len));

  std::vector<char> tail(static_cast<size_t>(tail_len));
  if (!read_exact(file, tail.data(), tail.size())) {
    log_error("Failed to read MD5 trailer region: " + file_path);
    return ExitCode::Firmware;
  }

  int64_t best_pos = -1;
  for (int64_t pos = static_cast<int64_t>(tail.size()) - 32; pos >= 0; --pos) {
    bool ok = true;
    for (int i = 0; i < 32; ++i) {
      if (!is_hex_char(
              static_cast<unsigned char>(tail[static_cast<size_t>(pos + i)]))) {
        ok = false;
        break;
      }
    }
    if (!ok)
      continue;

    const bool left_ok = (pos == 0) || !is_hex_char(static_cast<unsigned char>(
                                           tail[static_cast<size_t>(pos - 1)]));
    const bool right_ok = (static_cast<size_t>(pos + 32) >= tail.size()) ||
                          !is_hex_char(static_cast<unsigned char>(
                              tail[static_cast<size_t>(pos + 32)]));
    if (!left_ok || !right_ok)
      continue;

    best_pos = pos;
    break;
  }

  if (best_pos < 0) {
    std::string last32(tail.end() - 32, tail.end());
    if (!is_hex32(last32)) {
      log_error("Unable to locate a valid MD5 trailer in: " + file_path);
      return ExitCode::Firmware;
    }
    info.has_md5 = true;
    info.expected_md5 = to_lower_copy(last32);
    info.content_end = file_size - 32;
    return ExitCode::Success;
  }

  std::string md5(tail.data() + best_pos, 32);
  if (!is_hex32(md5)) {
    log_error("Detected an invalid MD5 trailer in: " + file_path);
    return ExitCode::Firmware;
  }

  int64_t line_start = best_pos;
  for (int64_t p = best_pos - 1; p >= 0; --p) {
    if (tail[static_cast<size_t>(p)] == '\n') {
      line_start = p + 1;
      break;
    }
  }

  const uint64_t trailer_start =
      (file_size - tail_len) + static_cast<uint64_t>(line_start);
  if (trailer_start >= file_size) {
    log_error("Invalid MD5 trailer position in: " + file_path);
    return ExitCode::Firmware;
  }

  info.has_md5 = true;
  info.expected_md5 = to_lower_copy(md5);
  info.content_end = trailer_start;
  return ExitCode::Success;
}

ExitCode verify_tar_md5(const std::string &file_path, const TarMd5Info &info) {
  if (!info.has_md5)
    return ExitCode::Success;

  if (info.content_end == 0) {
    log_error("Invalid MD5 content size (0): " + file_path);
    return ExitCode::Firmware;
  }

  std::ifstream file(file_path, std::ios::binary);
  if (!file) {
    log_error("Could not open file for MD5 verification: " + file_path);
    return ExitCode::Firmware;
  }

  CryptoPP::Weak::MD5 hash;
  std::vector<unsigned char> digest(hash.DigestSize());

  const size_t buf_size = 1024 * 1024;
  std::vector<char> buf(buf_size);

  uint64_t remaining = info.content_end;
  while (remaining > 0) {
    const size_t to_read =
        static_cast<size_t>(std::min<uint64_t>(remaining, buf.size()));
    if (!read_exact(file, buf.data(), to_read)) {
      log_error("Short read during MD5 verification: " + file_path);
      return ExitCode::Firmware;
    }
    hash.Update(reinterpret_cast<const unsigned char *>(buf.data()), to_read);
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
    log_error("MD5 verification failed. Expected: " + info.expected_md5 +
              " | Calculated: " + calc_lower);
    return ExitCode::Firmware;
  }

  log_info("MD5 verification successful.");
  return ExitCode::Success;
}

bool is_all_zeros_block(const char *header) {
  for (int i = 0; i < 512; ++i) {
    if (header[i] != 0)
      return false;
  }
  return true;
}

std::string sanitize_tar_name(const std::string &s) {
  std::string out = s;
  while (!out.empty() &&
         (out.back() == '\0' || out.back() == '\n' || out.back() == '\r'))
    out.pop_back();
  return out;
}

std::string base_name_from_path(const std::string &p) {
  const size_t pos = p.find_last_of("/\\");
  if (pos == std::string::npos)
    return p;
  return p.substr(pos + 1);
}
} // namespace

std::string sanitize_filename(const std::string &filename) {
  std::string sanitized = filename;
  size_t last_dot = sanitized.find_last_of('.');
  while (last_dot != std::string::npos) {
    std::string ext = sanitized.substr(last_dot);
    if (ext == ".lz4" || ext == ".ext4" || ext == ".img" || ext == ".bin") {
      sanitized = sanitized.substr(0, last_dot);
      last_dot = sanitized.find_last_of('.');
    } else {
      break;
    }
  }
  return sanitized;
}

bool check_md5_signature(const std::string &file_path) {
  TarMd5Info info;
  const ExitCode di = detect_tar_md5_info(file_path, info);
  if (di != ExitCode::Success)
    return false;
  const ExitCode vr = verify_tar_md5(file_path, info);
  return vr == ExitCode::Success;
}

bool process_lz4_streaming(std::ifstream &file, uint64_t compressed_size,
                           UsbDevice &usb_device, const std::string &filename,
                           bool large_partition, bool do_flash) {
  const std::streampos entry_start = file.tellg();
  if (entry_start < 0) {
    log_error("Unexpected end of file during LZ4 streaming.");
    return false;
  }

  LZ4F_decompressionContext_t dctx;
  LZ4F_errorCode_t err = LZ4F_createDecompressionContext(&dctx, LZ4F_VERSION);
  if (LZ4F_isError(err)) {
    log_error("Failed to create LZ4 decompression context: " +
              std::string(LZ4F_getErrorName(err)));
    return false;
  }

  struct DctxCleanup {
    LZ4F_decompressionContext_t ctx;
    explicit DctxCleanup(LZ4F_decompressionContext_t c) : ctx(c) {}
    ~DctxCleanup() { LZ4F_freeDecompressionContext(ctx); }
  } cleanup(dctx);

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
  uint32_t chunk_index = 0;

  const bool show_progress =
      static_cast<int>(get_log_level()) >= static_cast<int>(LogLevel::Info);
  int last_percent = -1;

  // Read some bytes for frame info.
  std::streampos start_pos = entry_start;
  const size_t header_read_size =
      static_cast<size_t>(std::min<uint64_t>(1024, compressed_size));
  std::vector<unsigned char> header_buf(header_read_size);
  file.read(reinterpret_cast<char *>(header_buf.data()),
            static_cast<std::streamsize>(header_read_size));
  if (static_cast<size_t>(file.gcount()) != header_read_size) {
    log_error("Failed to read LZ4 header for " + filename);
    return false;
  }
  file.seekg(start_pos);

  LZ4F_frameInfo_t frame_info;
  size_t consumed = header_read_size;
  err = LZ4F_getFrameInfo(dctx, &frame_info, header_buf.data(), &consumed);
  if (LZ4F_isError(err)) {
    log_error("Failed to get LZ4 frame info for " + filename + ": " +
              std::string(LZ4F_getErrorName(err)));
    return false;
  }

  uint64_t uncompressed_size = frame_info.contentSize;

  if (uncompressed_size == 0) {
    log_info(
        "LZ4 frame for " + filename +
        " does not include uncompressed size; scanning to determine size.");
    LZ4F_decompressionContext_t scan_ctx;
    LZ4F_errorCode_t scan_err =
        LZ4F_createDecompressionContext(&scan_ctx, LZ4F_VERSION);
    if (LZ4F_isError(scan_err)) {
      log_error("Failed to create LZ4 scan context: " +
                std::string(LZ4F_getErrorName(scan_err)));
      return false;
    }

    uint64_t scan_remaining = compressed_size;
    std::streampos scan_start = file.tellg();
    if (scan_start < 0) {
      LZ4F_freeDecompressionContext(scan_ctx);
      log_error("Unexpected end of file during LZ4 streaming.");
      return false;
    }

    size_t src_offset = 0;
    size_t src_size = 0;
    bool frame_ended = false;

    while (!frame_ended && (scan_remaining > 0 || src_size > 0)) {
      if (src_size == 0 && scan_remaining > 0) {
        const size_t to_read = static_cast<size_t>(
            std::min<uint64_t>(in_buf_size, scan_remaining));
        file.read(reinterpret_cast<char *>(in_buf.data()),
                  static_cast<std::streamsize>(to_read));
        const size_t read = static_cast<size_t>(file.gcount());
        if (read == 0) {
          log_error("Unexpected end of file during LZ4 streaming.");
          LZ4F_freeDecompressionContext(scan_ctx);
          return false;
        }
        src_offset = 0;
        src_size = read;
        scan_remaining -= read;
      }

      while (src_size > 0 && !frame_ended) {
        size_t dst_sz = out_buf_size;
        size_t src_consumed = src_size;
        scan_err =
            LZ4F_decompress(scan_ctx, out_buf.data(), &dst_sz,
                            in_buf.data() + src_offset, &src_consumed, nullptr);
        if (LZ4F_isError(scan_err)) {
          log_error("LZ4 scan decompression error for " + filename + ": " +
                    std::string(LZ4F_getErrorName(scan_err)));
          LZ4F_freeDecompressionContext(scan_ctx);
          return false;
        }

        if (dst_sz != 0) {
          if (uncompressed_size >
              (std::numeric_limits<uint64_t>::max() - dst_sz)) {
            log_error("LZ4 scan decompression error for " + filename + ": " +
                      std::string(LZ4F_getErrorName(scan_err)));
            LZ4F_freeDecompressionContext(scan_ctx);
            return false;
          }
          uncompressed_size += dst_sz;
        }

        if (src_consumed == 0 && dst_sz == 0 && scan_err != 0) {
          if (scan_remaining == 0) {
            log_error("LZ4 scan decompression error for " + filename + ": " +
                      std::string(LZ4F_getErrorName(scan_err)));
            LZ4F_freeDecompressionContext(scan_ctx);
            return false;
          }

          if (src_offset != 0 && src_size > 0) {
            std::memmove(in_buf.data(), in_buf.data() + src_offset, src_size);
            src_offset = 0;
          }
          const size_t space = in_buf_size - src_size;
          const size_t to_read =
              static_cast<size_t>(std::min<uint64_t>(space, scan_remaining));
          if (to_read == 0) {
            log_error("LZ4 scan decompression error for " + filename + ": " +
                      std::string(LZ4F_getErrorName(scan_err)));
            LZ4F_freeDecompressionContext(scan_ctx);
            return false;
          }
          file.read(reinterpret_cast<char *>(in_buf.data() + src_size),
                    static_cast<std::streamsize>(to_read));
          const size_t read = static_cast<size_t>(file.gcount());
          if (read == 0) {
            log_error("Unexpected end of file during LZ4 streaming.");
            LZ4F_freeDecompressionContext(scan_ctx);
            return false;
          }
          src_size += read;
          scan_remaining -= read;
          continue;
        }

        src_offset += src_consumed;
        src_size -= src_consumed;
        if (scan_err == 0) {
          frame_ended = true;
        }
      }
    }

    if (!frame_ended) {
      log_error("LZ4 scan decompression error for " + filename + ": " +
                std::string(LZ4F_getErrorName(scan_err)));
      LZ4F_freeDecompressionContext(scan_ctx);
      return false;
    }

    if (scan_remaining > 0) {
      if (scan_remaining >
          static_cast<uint64_t>(std::numeric_limits<std::streamoff>::max())) {
        log_error("Unexpected end of file during LZ4 streaming.");
        LZ4F_freeDecompressionContext(scan_ctx);
        return false;
      }
      file.seekg(static_cast<std::streamoff>(scan_remaining), std::ios::cur);
      if (!file) {
        log_error("Unexpected end of file during LZ4 streaming.");
        LZ4F_freeDecompressionContext(scan_ctx);
        return false;
      }
    }

    LZ4F_freeDecompressionContext(scan_ctx);
    file.clear();
    file.seekg(scan_start);
    if (!file) {
      log_error("Failed to rewind file after LZ4 size scan for " + filename);
      return false;
    }
    remaining_compressed = compressed_size;
    log_verbose("LZ4 size scan complete for " + filename + ": " +
                std::to_string(uncompressed_size) + " bytes");
  }

  if (do_flash) {
    if (!usb_device.send_file_part_header(uncompressed_size))
      return false;
  }

  // Reset the decompression context to ensure we can start decoding from the
  // beginning of the frame after calling LZ4F_getFrameInfo().
  LZ4F_resetDecompressionContext(dctx);

  size_t src_offset = 0;
  size_t src_size = 0;

  while (remaining_compressed > 0 || src_size > 0) {
    if (src_size == 0 && remaining_compressed > 0) {
      const size_t to_read = static_cast<size_t>(
          std::min<uint64_t>(in_buf_size, remaining_compressed));
      file.read(reinterpret_cast<char *>(in_buf.data()),
                static_cast<std::streamsize>(to_read));
      src_size = static_cast<size_t>(file.gcount());
      if (src_size == 0) {
        log_error("Unexpected end of file during LZ4 streaming.");
        return false;
      }
      remaining_compressed -= src_size;
      src_offset = 0;
    }

    while (src_size > 0) {
      size_t dst_size = out_buf_size;
      size_t src_consumed = src_size;
      err = LZ4F_decompress(dctx, out_buf.data(), &dst_size,
                            in_buf.data() + src_offset, &src_consumed, nullptr);
      if (LZ4F_isError(err)) {
        log_error("LZ4 decompression error for " + filename + ": " +
                  std::string(LZ4F_getErrorName(err)));
        return false;
      }
      if (src_consumed == 0 && dst_size == 0 && err != 0) {
        if (remaining_compressed == 0) {
          log_error("LZ4 decompression made no progress for " + filename);
          return false;
        }

        if (src_offset != 0 && src_size > 0) {
          std::memmove(in_buf.data(), in_buf.data() + src_offset, src_size);
          src_offset = 0;
        }

        const size_t space = in_buf_size - src_size;
        const size_t to_read = static_cast<size_t>(
            std::min<uint64_t>(space, remaining_compressed));
        if (to_read == 0) {
          log_error("LZ4 decompression made no progress for " + filename);
          return false;
        }

        file.read(reinterpret_cast<char *>(in_buf.data() + src_size),
                  static_cast<std::streamsize>(to_read));
        const size_t read = static_cast<size_t>(file.gcount());
        if (read == 0) {
          log_error("Unexpected end of file during LZ4 streaming.");
          return false;
        }
        src_size += read;
        remaining_compressed -= read;
        continue;
      }

      if (dst_size > 0) {
        if (do_flash) {
          if (!usb_device.send_file_part_chunk(out_buf.data(), dst_size,
                                               chunk_index++, large_partition))
            return false;
        }
        total_uncompressed += dst_size;
        if (show_progress && uncompressed_size > 0) {
          const int percent =
              static_cast<int>((static_cast<double>(total_uncompressed) /
                                static_cast<double>(uncompressed_size)) *
                               100.0);
          if (percent != last_percent) {
            std::cout << "\r[Flash] " << filename << ": " << percent << "%"
                      << std::flush;
            last_percent = percent;
          }
        }
      }

      src_offset += src_consumed;
      src_size -= src_consumed;
      if (err == 0)
        break;
    }
    if (err == 0)
      break;
  }

  file.clear();
  if (compressed_size >
      static_cast<uint64_t>(std::numeric_limits<std::streamoff>::max())) {
    log_error("Unexpected end of file during LZ4 streaming.");
    return false;
  }
  file.seekg(entry_start);
  file.seekg(static_cast<std::streamoff>(compressed_size), std::ios::cur);
  if (!file) {
    log_error("Unexpected end of file during LZ4 streaming.");
    return false;
  }

  if (show_progress && uncompressed_size > 0) {
    std::cout << "\r[Flash] " << filename << ": 100%" << std::endl;
  } else if (show_progress) {
    std::cout << std::endl;
  }

  if (uncompressed_size != 0 && total_uncompressed != uncompressed_size) {
    log_error("Decompressed size mismatch for " + filename + ": expected " +
              std::to_string(uncompressed_size) + ", got " +
              std::to_string(total_uncompressed));
    return false;
  }

  return true;
}

ExitCode process_tar_file(const std::string &tar_path, UsbDevice &usb_device,
                          const PitTable &pit_table, bool do_flash,
                          bool allow_unknown) {
  log_info("Processing archive: " + tar_path);

  TarMd5Info md5_info;
  ExitCode ec = detect_tar_md5_info(tar_path, md5_info);
  if (ec != ExitCode::Success)
    return ec;
  ec = verify_tar_md5(tar_path, md5_info);
  if (ec != ExitCode::Success)
    return ec;

  std::ifstream file(tar_path, std::ios::binary);
  if (!file) {
    log_error("Could not open archive: " + tar_path);
    return ExitCode::Firmware;
  }

  file.seekg(0, std::ios::end);
  const std::streampos sp = file.tellg();
  if (sp < 0) {
    log_error("Failed to determine archive size: " + tar_path);
    return ExitCode::Firmware;
  }
  const uint64_t file_size = static_cast<uint64_t>(sp);
  file.seekg(0);

  const uint64_t content_end =
      md5_info.has_md5 ? md5_info.content_end : file_size;
  if (content_end < 512) {
    log_error("Archive content is too small: " + tar_path);
    return ExitCode::Firmware;
  }

  auto pit_field_to_string = [](const char *field,
                                size_t max_len) -> std::string {
    size_t n = 0;
    while (n < max_len && field[n] != '\0')
      ++n;
    std::string s(field, n);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t'))
      s.pop_back();
    return s;
  };

  std::unordered_set<uint32_t> used_partition_ids;

  std::string pending_gnu_long_name;
  std::string pending_pax_path;

  char header[512];
  while (true) {
    const std::streampos hpos = file.tellg();
    if (hpos < 0) {
      log_error("Archive read error: " + tar_path);
      return ExitCode::Firmware;
    }
    const uint64_t pos = static_cast<uint64_t>(hpos);
    if (pos + 512 > content_end)
      break;

    if (!read_exact(file, header, 512)) {
      log_error("Failed to read TAR header (truncated archive): " + tar_path);
      return ExitCode::Firmware;
    }

    if (is_all_zeros_block(header)) {
      break;
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
        if (!prefix.empty())
          filename = prefix + "/" + name;
        else
          filename = name;
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
    const uint64_t data_start = static_cast<uint64_t>(dspos);
    if (data_start > content_end || data_size > (content_end - data_start)) {
      log_error("Archive entry exceeds declared content length: " + filename);
      return ExitCode::Firmware;
    }

    auto skip_entry_data = [&](uint64_t size) -> ExitCode {
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
      if (nul != std::string::npos)
        long_name = long_name.substr(0, nul);
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
        if (nl == std::string::npos)
          break;
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
    if (!(typeflag == 0 || typeflag == '0')) {
      ec = skip_entry_data(data_size);
      if (ec != ExitCode::Success)
        return ec;
      continue;
    }

    if (filename.empty()) {
      log_error("Encountered an empty TAR entry name");
      return ExitCode::Firmware;
    }

    const std::string basename = base_name_from_path(filename);
    const std::string base_name_sanitized =
        to_lower_copy(sanitize_filename(basename));
    const std::string filename_lower = to_lower_copy(filename);

    const PitEntry *pit_entry = nullptr;
    std::string partition_name;

    for (const auto &entry : pit_table.entries) {
      const std::string pit_file = pit_field_to_string(entry.file_name, 32);
      const std::string pit_part =
          pit_field_to_string(entry.partition_name, 32);
      const std::string pit_file_s = to_lower_copy(sanitize_filename(pit_file));
      const std::string pit_part_s = to_lower_copy(sanitize_filename(pit_part));

      if (!pit_file.empty() &&
          (pit_file_s == base_name_sanitized ||
           to_lower_copy(pit_file) == to_lower_copy(basename))) {
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

    if (!pit_entry) {
      if (allow_unknown) {
        log_warn("Skipping unknown archive entry (no PIT match): " + filename);
        ec = skip_entry_data(data_size);
        if (ec != ExitCode::Success)
          return ec;
        continue;
      }
      log_error("Archive entry does not match any PIT partition: " + filename);
      return ExitCode::Pit;
    }

    if (!used_partition_ids.insert(pit_entry->identifier).second) {
      log_error("Archive contains multiple entries for the same PIT partition "
                "identifier: " +
                std::to_string(pit_entry->identifier));
      return ExitCode::Pit;
    }

    const std::string part_upper = partition_name;
    const bool is_large = (part_upper == "SYSTEM" || part_upper == "USERDATA" ||
                           part_upper == "SUPER");

    const std::string lower_basename = to_lower_copy(basename);
    const bool is_lz4 = (lower_basename.find(".lz4") != std::string::npos);

    log_verbose("TAR entry: " + filename + " (" + std::to_string(data_size) +
                " bytes) -> PIT: " + partition_name + " (ID " +
                std::to_string(pit_entry->identifier) + ")");

    if (is_lz4) {
      if (usb_device.is_odin_legacy() && do_flash) {
        log_error("LZ4 images are not supported in Odin legacy mode");
        return ExitCode::Protocol;
      }
      if (!process_lz4_streaming(file, data_size, usb_device, filename,
                                 is_large, do_flash)) {
        return do_flash ? ExitCode::Protocol : ExitCode::Firmware;
      }
    } else {
      if (do_flash) {
        if (!usb_device.flash_partition_stream(file, data_size, *pit_entry,
                                               is_large)) {
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

    if (do_flash) {
      if (!usb_device.end_file_transfer(pit_entry->identifier)) {
        return ExitCode::Protocol;
      }
    }
  }

  return ExitCode::Success;
}
