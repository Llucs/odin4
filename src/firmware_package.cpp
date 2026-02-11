#include "firmware_package.h"
#include "logger.h"
#include <iostream>
#include <vector>
#include <algorithm>
#include <cstring>
#include <cctype>
#include <lz4frame.h>

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>
#include <cryptopp/hex.h>

std::string sanitize_filename(const std::string& filename) {
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

bool check_md5_signature(const std::string& file_path) {
    if (file_path.size() < 8 || file_path.substr(file_path.size() - 8) != ".tar.md5") {
        return true; 
    }

    log_info("Verifying MD5 signature for " + file_path);
    std::ifstream file(file_path, std::ios::binary | std::ios::ate);
    if (!file) {
        log_error("Could not open file for MD5 verification: " + file_path);
        return false;
    }

    std::streampos file_size = file.tellg();
    if (file_size < 32) {
        log_error("File too small to contain MD5 signature.");
        return false;
    }

    file.seekg((std::streamoff)file_size - 32);
    char expected_md5_hex[33];
    file.read(expected_md5_hex, 32);
    if (file.gcount() != 32) {
        log_error("Incomplete MD5 signature read from file.");
        return false;
    }
    expected_md5_hex[32] = '\0';
    std::string expected_md5(expected_md5_hex);
    // Trim any trailing or leading whitespace characters from the expected MD5 string
    expected_md5.erase(expected_md5.find_last_not_of(" \n\r\t") + 1);
    expected_md5.erase(0, expected_md5.find_first_not_of(" \n\r\t"));

    log_info("Expected MD5: " + expected_md5);

    file.seekg(0);
    if (file_size < 32) return false;
    size_t content_size = (size_t)file_size - 32;

    CryptoPP::Weak::MD5 hash;
    std::vector<unsigned char> digest(hash.DigestSize());
    size_t buffer_size = (content_size > 1024 * 1024 * 1024) ? (32 * 1024 * 1024) : 1048576;
    std::vector<char> buffer(buffer_size);
    size_t total_read = 0;
    int last_progress = -1;

    while (total_read < content_size) {
        size_t to_read = std::min((size_t)buffer.size(), content_size - total_read);
        file.read(buffer.data(), (std::streamsize)to_read);
        size_t read_count = (size_t)file.gcount();

        if (read_count == 0) {
            if (total_read < content_size) {
                log_error("Premature read error during MD5 check.");
                return false;
            }
            break;
        }

        hash.Update((const unsigned char*)buffer.data(), read_count);
        total_read += read_count;

        int progress = (int)((double)total_read / content_size * 100);
        if (progress != last_progress) {
            std::cout << "\r[MD5] Verifying integrity... " << progress << "%" << std::flush;
            last_progress = progress;
        }
    }
    std::cout << std::endl;

    if (total_read != content_size) {
        log_error("Failed to read full file content for MD5 check. Read " + std::to_string(total_read) + " of " + std::to_string(content_size));
        return false;
    }

    hash.Final(digest.data());

    std::string calculated_md5;
    CryptoPP::HexEncoder encoder;
    encoder.Attach(new CryptoPP::StringSink(calculated_md5));
    encoder.Put(digest.data(), digest.size());
    encoder.MessageEnd();

    auto to_lower = [](std::string s) {
        std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return static_cast<char>(::tolower(static_cast<unsigned char>(c))); });
        return s;
    };

    std::string calculated_md5_lower = to_lower(calculated_md5);
    std::string expected_md5_lower = to_lower(expected_md5);

    log_info("Calculated MD5: " + calculated_md5_lower);

    if (calculated_md5_lower == expected_md5_lower) {
        log_info("MD5 verification successful.");
        return true;
    } else {
        log_error("MD5 verification failed! Expected: " + expected_md5_lower + " | Calculated: " + calculated_md5_lower);
        return false;
    }
}

bool process_lz4_streaming(std::ifstream& file, uint64_t compressed_size, UsbDevice& usb_device, const std::string& filename, bool large_partition, bool do_flash) {
    LZ4F_decompressionContext_t dctx;
    LZ4F_errorCode_t err = LZ4F_createDecompressionContext(&dctx, LZ4F_VERSION);
    if (LZ4F_isError(err)) {
        log_error("Failed to create LZ4 decompression context: " + std::string(LZ4F_getErrorName(err)));
        return false;
    }

    struct DctxCleanup {
        LZ4F_decompressionContext_t ctx;
        DctxCleanup(LZ4F_decompressionContext_t c) : ctx(c) {}
        ~DctxCleanup() { LZ4F_freeDecompressionContext(ctx); }
    } cleanup(dctx);

    size_t in_buf_size = 1024 * 1024;
    size_t out_buf_size = 4 * 1024 * 1024;
    if (compressed_size > 1024 * 1024 * 1024) {
        in_buf_size = 8 * 1024 * 1024;
        out_buf_size = 16 * 1024 * 1024;
    }
    std::vector<unsigned char> in_buf(in_buf_size);
    std::vector<unsigned char> out_buf(out_buf_size);

    uint64_t remaining_compressed = compressed_size;
    uint64_t total_uncompressed_sent = 0;
    int last_percent = -1;

    // Read frame header to get content size
    std::streampos start_pos = file.tellg();
    size_t header_read_size = std::min((size_t)1024, (size_t)compressed_size);
    std::vector<unsigned char> header_buf(header_read_size);
    file.read((char*)header_buf.data(), header_read_size);
    if ((size_t)file.gcount() != header_read_size) {
        log_error("Failed to read LZ4 header for " + filename);
        return false;
    }
    file.seekg(start_pos);

    LZ4F_frameInfo_t frame_info;
    size_t consumed = header_read_size;
    err = LZ4F_getFrameInfo(dctx, &frame_info, header_buf.data(), &consumed);
    if (LZ4F_isError(err)) {
        log_error("Failed to get LZ4 frame info for " + filename + ": " + std::string(LZ4F_getErrorName(err)));
        return false;
    }

    uint64_t uncompressed_size = frame_info.contentSize;
    if (uncompressed_size == 0) {
        log_info("LZ4 frame for " + filename + " does not contain uncompressed size. Calculating LZ4 size (this may take a while)...");
        LZ4F_decompressionContext_t scan_dctx;
        LZ4F_errorCode_t create_err = LZ4F_createDecompressionContext(&scan_dctx, LZ4F_VERSION);
        if (LZ4F_isError(create_err)) {
            log_error("Failed to create LZ4 scan decompression context: " + std::string(LZ4F_getErrorName(create_err)));
            return false;
        }
        uint64_t scan_remaining = compressed_size;
        while (scan_remaining > 0) {
            size_t to_read = std::min(in_buf_size, (size_t)scan_remaining);
            file.read((char*)in_buf.data(), to_read);
            size_t read = (size_t)file.gcount();
            if (read == 0) break;
            size_t src_off = 0;
            while (src_off < read) {
                size_t dst_sz = out_buf_size;
                size_t src_sz = read - src_off;
                LZ4F_errorCode_t dec_err = LZ4F_decompress(scan_dctx, out_buf.data(), &dst_sz, in_buf.data() + src_off, &src_sz, nullptr);
                if (LZ4F_isError(dec_err)) {
                    log_error("LZ4 decompression error during pre-scan for " + filename + ": " + std::string(LZ4F_getErrorName(dec_err)));
                    LZ4F_freeDecompressionContext(scan_dctx);
                    return false;
                }
                uncompressed_size += dst_sz;
                src_off += src_sz;
            }
            scan_remaining -= read;
        }
        LZ4F_freeDecompressionContext(scan_dctx);
        file.seekg(start_pos);
        remaining_compressed = compressed_size;
        log_info("Pre-scan complete. Uncompressed size: " + std::to_string(uncompressed_size));
    }

    // When do_flash is false, skip sending headers to the device. We still
    // decompress the file to ensure its integrity and to report progress.
    if (do_flash) {
        if (!usb_device.send_file_part_header(uncompressed_size)) return false;
    }

    size_t src_offset = 0;
    size_t src_size = 0;
    
    while (remaining_compressed > 0 || src_size > 0) {
        if (src_size == 0 && remaining_compressed > 0) {
            size_t to_read = std::min(in_buf_size, (size_t)remaining_compressed);
            file.read((char*)in_buf.data(), to_read);
            src_size = (size_t)file.gcount();
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
            err = LZ4F_decompress(dctx, out_buf.data(), &dst_size, in_buf.data() + src_offset, &src_consumed, nullptr);
            
            if (LZ4F_isError(err)) {
                log_error("LZ4 decompression error for " + filename + ": " + std::string(LZ4F_getErrorName(err)));
                return false;
            }

            if (dst_size > 0) {
                if (do_flash) {
                    if (!usb_device.send_file_part_chunk(out_buf.data(), dst_size, large_partition)) return false;
                }
                total_uncompressed_sent += dst_size;
                // Update progress and print when the percentage changes.
                if (uncompressed_size > 0) {
                    int percent = static_cast<int>((static_cast<double>(total_uncompressed_sent) / uncompressed_size) * 100.0);
                    if (percent != last_percent) {
                        std::cout << "\r[Flash] " << filename << ": " << percent << "%" << std::flush;
                        last_percent = percent;
                    }
                }
            }

            src_offset += src_consumed;
            src_size -= src_consumed;
            if (err == 0) break; 
        }
        if (err == 0) break;
    }

    if (total_uncompressed_sent != uncompressed_size) {
        log_error("Decompressed size mismatch for " + filename + ": expected " + std::to_string(uncompressed_size) + ", got " + std::to_string(total_uncompressed_sent));
        return false;
    }
    // Ensure the progress bar ends at 100% and move to the next line.
    if (uncompressed_size > 0 && last_percent < 100) {
        std::cout << "\r[Flash] " << filename << ": 100%" << std::endl;
    } else {
        std::cout << std::endl;
    }
    return true;
}

bool process_tar_file(const std::string& tar_path, UsbDevice& usb_device, const PitTable& pit_table, bool do_flash) {
    log_info("Processing TAR file: " + tar_path);
    
    if (!check_md5_signature(tar_path)) return false;

    std::ifstream file(tar_path, std::ios::binary);
    if (!file) {
        log_error("Could not open TAR file: " + tar_path);
        return false;
    }

    file.seekg(0, std::ios::end);
    std::streampos file_size = file.tellg();
    file.seekg(0);
    uint64_t max_read_pos = (uint64_t)file_size;

    if (tar_path.size() >= 8 && tar_path.substr(tar_path.size() - 8) == ".tar.md5") {
        max_read_pos -= 32;
    }

    char header[512];
    size_t chunk_size = 1048576;

    while ((uint64_t)file.tellg() < max_read_pos) {
        if (!file.read(header, 512)) {
            if (file.eof()) break;
            log_error("Failed to read TAR header.");
            return false;
        }

        std::string filename_str(header, 100);
        size_t name_len = 0;
        while (name_len < 100 && header[name_len] != '\0') name_len++;
        std::string filename = filename_str.substr(0, name_len);

        if (filename.empty()) {
            bool all_zeros = true;
            for (int k = 0; k < 512; ++k) if (header[k] != 0) { all_zeros = false; break; }
            if (all_zeros) break;
            continue;
        }

        std::string size_str(header + 124, 12);
        uint64_t data_size = 0;
        try {
            data_size = std::stoull(size_str, nullptr, 8);
        } catch (...) {
            log_error("Invalid file size in TAR header for " + filename);
            return false;
        }

        log_info("Found file in TAR: " + filename + " (" + std::to_string(data_size) + " bytes)");

        uint32_t partition_id = 0;
        std::string partition_name = "";
        std::string base_name = sanitize_filename(filename);
        // Determine if this entry is an LZ4-compressed file using a case-insensitive comparison
        bool is_lz4 = false;
        {
            std::string lower_filename = filename;
            std::transform(lower_filename.begin(), lower_filename.end(), lower_filename.begin(), [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
            if (lower_filename.find(".lz4") != std::string::npos) {
                is_lz4 = true;
            }
        }

        for (const auto& entry : pit_table.entries) {
            std::string pit_file_sanitized = sanitize_filename(entry.file_name);
            std::string pit_name_sanitized = sanitize_filename(entry.partition_name);
            if (pit_file_sanitized == base_name || pit_name_sanitized == base_name || std::string(entry.file_name) == filename) {
                partition_id = entry.identifier;
                partition_name = entry.partition_name;
                log_info("Partition found in PIT: " + partition_name + " (ID: " + std::to_string(partition_id) + ")");
                break;
            }
        }

        bool is_large = (partition_name == "SYSTEM" || partition_name == "USERDATA" || partition_name == "SUPER");

        if (partition_id == 0) {
            // Abort if a file in the TAR does not correspond to any PIT entry
            log_error("File " + filename + " does not match any partition in the PIT table.");
            return false;
        }

        if (is_lz4) {
            // Process LZ4 entry. If do_flash is false, data will be decompressed but
            // not transmitted to the device.
            if (!process_lz4_streaming(file, data_size, usb_device, filename, is_large, do_flash)) return false;
        } else {
            if (do_flash) {
                // Send the file header only when flashing
                if (!usb_device.send_file_part_header(data_size)) return false;
            }

            uint64_t remaining_size = data_size;
            size_t current_chunk_size = chunk_size;
            if (data_size > 1024ULL * 1024ULL * 1024ULL) {
                current_chunk_size = 16 * 1024 * 1024;
            }
            std::vector<unsigned char> buffer(current_chunk_size);
            uint64_t sent_size = 0;
            int last_percent = -1;

            // Read and optionally send each chunk
            while (remaining_size > 0) {
                size_t to_read = std::min((uint64_t)current_chunk_size, remaining_size);
                file.read((char*)buffer.data(), to_read);
                size_t read_count = (size_t)file.gcount();

                if (read_count == 0) {
                    log_error("Unexpected read error in TAR file.");
                    return false;
                }
                if (do_flash) {
                    if (!usb_device.send_file_part_chunk(buffer.data(), read_count, is_large)) return false;
                }
                remaining_size -= read_count;
                sent_size += read_count;
                if (data_size > 0) {
                    int percent = static_cast<int>((static_cast<double>(sent_size) / data_size) * 100.0);
                    if (percent != last_percent) {
                        std::cout << "\r[Flash] " << filename << ": " << percent << "%" << std::flush;
                        last_percent = percent;
                    }
                }
            }
            // After sending the entire file, ensure the progress reaches 100%
            if (data_size > 0 && last_percent < 100) {
                std::cout << "\r[Flash] " << filename << ": 100%" << std::endl;
            } else {
                std::cout << std::endl;
            }
        }

        // Skip any padding at the end of the archive entry
        size_t padding = (512 - (data_size % 512)) % 512;
        file.seekg((std::streamoff)padding, std::ios::cur);

        // End the transfer if we actually flashed the partition
        if (do_flash) {
            if (!usb_device.end_file_transfer(partition_id)) return false;
        }
    }

    return true;
}
