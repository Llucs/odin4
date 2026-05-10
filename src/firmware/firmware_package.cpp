#include "firmware/firmware_package.h"
#include "core/logger.h"

#include <iostream>
#include <vector>
#include <algorithm>
#include <cstring>
#include <cctype>
#include <unordered_set>
#include <sstream>
#include <limits>
#include <lz4frame.h>

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <md5.h>
#include <hex.h>

namespace {
struct TarMd5Info {
    bool has_md5 = false;
    uint64_t content_end = 0;
    std::string expected_md5;
};

bool is_hex_char(unsigned char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

bool is_hex32(const std::string& s) {
    if (s.size() != 32)
        return false;
    for (unsigned char c : s) {
        if (!is_hex_char(c))
            return false;
    }
    return true;
}

TarMd5Info parse_tar_md5_footer(std::istream& stream, uint64_t size) {
    TarMd5Info info;
    if (size < 32)
        return info;

    stream.seekg(static_cast<int64_t>(size) - 32, std::ios::beg);
    char buf[33];
    stream.read(buf, 32);
    buf[32] = '\0';
    std::string md5_str(buf);

    if (is_hex32(md5_str)) {
        info.has_md5 = true;
        info.content_end = size - 32;
        info.expected_md5 = md5_str;
    }
    return info;
}
} // namespace

FirmwarePackage::FirmwarePackage(const std::string& path) : path(path) {}

bool FirmwarePackage::open() {
    stream.open(path, std::ios::binary);
    if (!stream.is_open())
        return false;

    stream.seekg(0, std::ios::end);
    uint64_t size = static_cast<uint64_t>(stream.tellg());
    stream.seekg(0, std::ios::beg);

    TarMd5Info md5_info = parse_tar_md5_footer(stream, size);
    uint64_t content_limit = size;
    if (md5_info.has_md5) {
        log_info("MD5 footer detected. Verifying...");
        content_limit = md5_info.content_end;

        CryptoPP::Weak::MD5 hash;
        stream.seekg(0, std::ios::beg);
        std::vector<char> buffer(1024 * 1024);
        uint64_t remaining = content_limit;
        while (remaining > 0) {
            uint64_t to_read = std::min<uint64_t>(remaining, buffer.size());
            stream.read(buffer.data(), static_cast<std::streamsize>(to_read));
            hash.Update(reinterpret_cast<const unsigned char*>(buffer.data()), static_cast<size_t>(stream.gcount()));
            remaining -= static_cast<uint64_t>(stream.gcount());
        }

        std::string digest;
        digest.resize(hash.DigestSize());
        hash.Final(reinterpret_cast<unsigned char*>(&digest[0]));

        std::string hex_digest;
        CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(hex_digest), false);
        encoder.Put(reinterpret_cast<const unsigned char*>(digest.data()), digest.size());
        encoder.MessageEnd();

        if (hex_digest != md5_info.expected_md5) {
            log_error("MD5 mismatch! Expected: " + md5_info.expected_md5 + ", Got: " + hex_digest);
            return false;
        }
        log_info("MD5 verification successful.");
    }

    stream.seekg(0, std::ios::beg);
    while (static_cast<uint64_t>(stream.tellg()) < content_limit) {
        uint64_t pos = static_cast<uint64_t>(stream.tellg());
        char header[512];
        stream.read(header, 512);
        if (stream.gcount() != 512)
            break;

        if (header[0] == '\0')
            break;

        std::string name(header, 100);
        name = name.c_str(); // truncate at null

        char size_buf[13];
        std::memcpy(size_buf, header + 124, 12);
        size_buf[12] = '\0';
        uint64_t entry_size = std::stoull(size_buf, nullptr, 8);

        entries.push_back({name, entry_size, pos + 512});
        uint64_t padding = (512 - (entry_size % 512)) % 512;
        stream.seekg(static_cast<int64_t>(entry_size + padding), std::ios::cur);
    }

    return true;
}

std::unique_ptr<std::istream> FirmwarePackage::get_entry_stream(const FirmwareEntry& entry) {
    // This is a simplified implementation. In a real scenario, we might want to
    // return a wrapper that limits the stream to the entry's size.
    stream.seekg(static_cast<int64_t>(entry.offset), std::ios::beg);
    return std::make_unique<std::reference_wrapper<std::ifstream>>(stream);
}
