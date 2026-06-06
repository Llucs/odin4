#ifndef ODIN_PROTOCOL_H
#define ODIN_PROTOCOL_H

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <span>

#if defined(_WIN32)
#include <cstdlib>
#define le16toh(x) (x)
#define le32toh(x) (x)
#define le64toh(x) (x)
#define htole16(x) (x)
#define htole32(x) (x)
#define htole64(x) (x)
#elif defined(__APPLE__)
#include <libkern/OSByteOrder.h>
#define le16toh(x) OSSwapLittleToHostInt16(x)
#define le32toh(x) OSSwapLittleToHostInt32(x)
#define le64toh(x) OSSwapLittleToHostInt64(x)
#define htole16(x) OSSwapHostToLittleInt16(x)
#define htole32(x) OSSwapHostToLittleInt32(x)
#define htole64(x) OSSwapHostToLittleInt64(x)
#else
#if defined(__has_include)
#if __has_include(<endian.h>)
#include <endian.h>
#endif
#endif
#ifndef le16toh
static inline uint16_t odin_swap16(uint16_t v) {
    return static_cast<uint16_t>((v << 8) | (v >> 8));
}
static inline uint32_t odin_swap32(uint32_t v) {
    return ((v >> 24) & 0x000000FF) | ((v >> 8) & 0x0000FF00) | ((v << 8) & 0x00FF0000) | ((v << 24) & 0xFF000000);
}
static inline uint64_t odin_swap64(uint64_t v) {
    uint32_t lo = static_cast<uint32_t>(v & 0xFFFFFFFFULL);
    uint32_t hi = static_cast<uint32_t>((v >> 32) & 0xFFFFFFFFULL);
    return (static_cast<uint64_t>(odin_swap32(lo)) << 32) | odin_swap32(hi);
}
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#define le16toh(x) odin_swap16(x)
#define le32toh(x) odin_swap32(x)
#define le64toh(x) odin_swap64(x)
#define htole16(x) odin_swap16(x)
#define htole32(x) odin_swap32(x)
#define htole64(x) odin_swap64(x)
#else
#define le16toh(x) (x)
#define le32toh(x) (x)
#define le64toh(x) (x)
#define htole16(x) (x)
#define htole32(x) (x)
#define htole64(x) (x)
#endif
#endif
#endif

inline auto le32_to_h(uint32_t val) -> uint32_t { return le32toh(val); }
inline auto h_to_le32(uint32_t val) -> uint32_t { return htole32(val); }
inline auto h_to_le16(uint16_t val) -> uint16_t { return htole16(val); }
inline auto le64_to_h(uint64_t val) -> uint64_t { return le64toh(val); }
inline auto h_to_le64(uint64_t val) -> uint64_t { return htole64(val); }

// Odin/Thor wire protocol command types
enum class OdinCommandType : int32_t {
    RQT_INIT = 0x64,
    RQT_PIT  = 0x65,
    RQT_XMIT = 0x66,
    RQT_CLOSE = 0x67,
    RQT_EMPTY = 0,
};

// Odin/Thor wire protocol command parameters
enum class OdinCommandParam : int32_t {
    // INIT params
    RQT_INIT_TARGET = 0,
    RQT_INIT_RESETTIME = 1,
    RQT_INIT_TOTALSIZE = 2,
    RQT_INIT_OEMSTATE = 3,
    RQT_INIT_NOOEMSTATE = 4,
    RQT_INIT_PACKETSIZE = 5,
    RQT_INIT_XMIT_SIZE = 6,

    // PIT params
    RQT_PIT_SET = 0,
    RQT_PIT_GET = 1,
    RQT_PIT_START = 2,
    RQT_PIT_COMPLETE = 3,

    // XMIT params (uncompressed)
    RQT_XMIT_DOWNLOAD = 0,
    RQT_XMIT_DUMP = 1,
    RQT_XMIT_START = 2,
    RQT_XMIT_COMPLETE = 3,
    RQT_XMIT_SMD = 4,

    // XMIT params (compressed)
    RQT_XMIT_COMPRESSED_DOWNLOAD = 5,
    RQT_XMIT_COMPRESSED_START = 6,
    RQT_XMIT_COMPRESSED_COMPLETE = 7,

    // CLOSE params
    RQT_CLOSE_END = 0,
    RQT_CLOSE_REBOOT = 1,
    RQT_CLOSE_DISCONNECT = 2,
    RQT_CLOSE_REBOOT_RECOVERY = 3,
};

// Protocol version negotiation
enum class ProtocolVersion : int16_t {
    PROTOCOL_NONE = 0,
    PROTOCOL_VER1 = 1,
    PROTOCOL_VER2 = 2,
    PROTOCOL_VER3 = 3,
    PROTOCOL_VER4 = 4,
    PROTOCOL_VER5 = 5,
};

// InitTargetInfo extracted from the ack word returned by RQT_INIT_TARGET
struct InitTargetInfo {
    uint32_t ack_word = 0;

    ProtocolVersion protocol() const noexcept {
        auto raw = static_cast<uint16_t>((ack_word >> 16) & 0xFFFFu);
        if (raw == 0) return ProtocolVersion::PROTOCOL_VER1;
        return static_cast<ProtocolVersion>(static_cast<int16_t>(raw));
    }

    bool supports_compressed_download() const noexcept {
        return (ack_word & 0x8000u) != 0;
    }
};

// Sentinel value indicating bootloader failure in response id field
constexpr int32_t BOOTLOADER_FAIL = -1; // 0xFFFFFFFF

// Handshake magic strings (exact byte counts)
constexpr char kOdinHandshakeUsb[] = { 'O', 'D', 'I', 'N', '\0' }; // 5 bytes
constexpr char kLokeResponse[]     = { 'L', 'O', 'K', 'E' };        // 4 bytes

constexpr std::size_t kOdinHandshakeUsbSize = 5;
constexpr std::size_t kLokeResponseSize     = 4;

// PIT download chunk size (used for legacy protocol)
constexpr std::size_t kPitChunkSize = 500;

// Control types for send_control
enum OdinControlType : uint32_t {
    ODIN_CONTROL_REBOOT = 0x0001,
    ODIN_CONTROL_REDOWNLOAD = 0x0002,
};

#pragma pack(push, 1)

// 8-byte response from device
struct OdinResponseBox {
    int32_t id;
    int32_t ack;
};

// 1024-byte request to device
struct OdinRequestBox {
    static constexpr int DATA_INT_SIZE = 9;
    static constexpr int DATA_CHAR_SIZE = 128;
    static constexpr int MD5_SIZE = 32;

    int32_t id;
    int32_t data;
    int32_t intData[DATA_INT_SIZE];
    int8_t charData[DATA_CHAR_SIZE];
    int8_t md5[MD5_SIZE];
    int8_t dummy[1024 - (2 * 4 + DATA_INT_SIZE * 4 + DATA_CHAR_SIZE + MD5_SIZE)];
};

#pragma pack(pop)

static_assert(sizeof(OdinResponseBox) == 8, "OdinResponseBox must be 8 bytes");
static_assert(sizeof(OdinRequestBox) == 1024, "OdinRequestBox must be 1024 bytes");

inline void response_from_le(OdinResponseBox& r) noexcept {
    r.id = le32_to_h(static_cast<uint32_t>(r.id));
    r.ack = le32_to_h(static_cast<uint32_t>(r.ack));
}

// Check response for common error conditions
inline bool is_valid_response(const OdinResponseBox& r, int32_t expected_id) noexcept {
    if (r.id == BOOTLOADER_FAIL) return false;
    if (r.id == std::numeric_limits<int32_t>::min()) return false;
    if (r.id != expected_id) return false;
    if (r.ack < 0) return false;
    return true;
}

inline OdinRequestBox make_request(OdinCommandType type, OdinCommandParam param,
                                   std::span<const int32_t> ints = {},
                                   std::span<const int8_t> chars = {}) {
    OdinRequestBox r{};
    r.id = h_to_le32(static_cast<uint32_t>(type));
    r.data = h_to_le32(static_cast<uint32_t>(param));

    if (!ints.empty()) {
        auto n = (ints.size() > OdinRequestBox::DATA_INT_SIZE) ? OdinRequestBox::DATA_INT_SIZE : ints.size();
        for (std::size_t i = 0; i < n; ++i)
            r.intData[i] = h_to_le32(static_cast<uint32_t>(ints[i]));
    }

    if (!chars.empty()) {
        auto n = (chars.size() > OdinRequestBox::DATA_CHAR_SIZE) ? OdinRequestBox::DATA_CHAR_SIZE : chars.size();
        std::memcpy(r.charData, chars.data(), n);
    }

    return r;
}

#endif // ODIN_PROTOCOL_H
