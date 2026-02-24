#ifndef THOR_PROTOCOL_H
#define THOR_PROTOCOL_H

#include <cstdint>
// Include endian definitions when available and provide fallbacks for other
// platforms
#if defined(__has_include)
#if __has_include(<endian.h>)
#include <endian.h>
#endif
#endif

// Fallback definitions for little-endian architectures when standard macros are
// unavailable.
#ifndef le16toh
static inline uint16_t thor_swap16(uint16_t v) {
  return static_cast<uint16_t>((v << 8) | (v >> 8));
}
static inline uint32_t thor_swap32(uint32_t v) {
  return ((v >> 24) & 0x000000FF) | ((v >> 8) & 0x0000FF00) |
         ((v << 8) & 0x00FF0000) | ((v << 24) & 0xFF000000);
}
static inline uint64_t thor_swap64(uint64_t v) {
  uint32_t lo = static_cast<uint32_t>(v & 0xFFFFFFFFULL);
  uint32_t hi = static_cast<uint32_t>((v >> 32) & 0xFFFFFFFFULL);
  uint64_t swapped =
      static_cast<uint64_t>(thor_swap32(lo)) << 32 | thor_swap32(hi);
  return swapped;
}
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#define le16toh(x) thor_swap16(x)
#define le32toh(x) thor_swap32(x)
#define le64toh(x) thor_swap64(x)
#define htole16(x) thor_swap16(x)
#define htole32(x) thor_swap32(x)
#define htole64(x) thor_swap64(x)
#else
#define le16toh(x) (x)
#define le32toh(x) (x)
#define le64toh(x) (x)
#define htole16(x) (x)
#define htole32(x) (x)
#define htole64(x) (x)
#endif
#endif

// ============================================================================
// THOR PROTOCOL - PACKET STRUCTURES
// ============================================================================

#pragma pack(push, 1)

// --- Thor Packet Header ---
struct ThorPacketHeader {
  uint32_t packet_size;
  uint16_t packet_type;
  uint16_t packet_flags;
};

// --- Thor Packet Types ---
enum ThorPacketType {
  THOR_PACKET_HANDSHAKE = 0x0001,
  THOR_PACKET_DEVICE_TYPE = 0x0002,
  THOR_PACKET_FILE_PART = 0x0003,
  THOR_PACKET_END_FILE_TRANSFER = 0x0004,
  THOR_PACKET_END_SESSION = 0x0005,
  THOR_PACKET_RESPONSE = 0x0006,
  THOR_PACKET_PIT_FILE = 0x0007,
  THOR_PACKET_BEGIN_SESSION = 0x0008,
  THOR_PACKET_FILE_PART_SIZE = 0x0009,
  THOR_PACKET_RECEIVE_FILE_PART = 0x000A,
  THOR_PACKET_CONTROL = 0x000B,
};

// --- Thor Control Types ---
enum ThorControlType {
  THOR_CONTROL_REBOOT = 0x0001,
  THOR_CONTROL_REDOWNLOAD = 0x0002,
};

// --- Handshake Packet ---
struct ThorHandshakePacket {
  ThorPacketHeader header;
  uint32_t magic;
  uint32_t version;
  uint32_t packet_size;
};

// --- Device Type Packet ---
struct ThorDeviceTypePacket {
  ThorPacketHeader header;
  char device_type[128];
};

// --- Begin Session Packet ---
struct ThorBeginSessionPacket {
  ThorPacketHeader header;
  uint32_t unknown1;
  uint32_t unknown2;
};

// --- PIT File Packet ---
struct ThorPitFilePacket {
  ThorPacketHeader header;
  uint32_t pit_file_size;
};

// --- File Part Size Packet ---
struct ThorFilePartSizePacket {
  ThorPacketHeader header;
  uint64_t file_part_size;
};

// --- File Part Packet ---
struct ThorFilePartPacket {
  ThorPacketHeader header;
  uint32_t file_part_index;
  uint32_t file_part_size;
};

// --- End File Transfer Packet ---
struct ThorEndFileTransferPacket {
  ThorPacketHeader header;
  uint32_t partition_id;
};

// --- End Session Packet ---
struct ThorEndSessionPacket {
  ThorPacketHeader header;
};

// --- Control Packet ---
struct ThorControlPacket {
  ThorPacketHeader header;
  uint32_t control_type;
};

// --- Response Packet ---
struct ThorResponsePacket {
  ThorPacketHeader header;
  uint32_t response_code;
};

#pragma pack(pop)

// --- Endianness Helpers ---
inline uint32_t le32_to_h(uint32_t val) { return le32toh(val); }
inline uint32_t h_to_le32(uint32_t val) { return htole32(val); }
inline uint16_t h_to_le16(uint16_t val) { return htole16(val); }

// 64-bit conversion helpers. These wrappers complement the 16- and 32-bit
// helpers above and forward to the underlying macros defined earlier.
inline uint64_t le64_to_h(uint64_t val) { return le64toh(val); }
inline uint64_t h_to_le64(uint64_t val) { return htole64(val); }

#endif // THOR_PROTOCOL_H
