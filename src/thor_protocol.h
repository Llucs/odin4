#ifndef THOR_PROTOCOL_H
#define THOR_PROTOCOL_H

#include <cstdint>
#include <endian.h>

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

#endif // THOR_PROTOCOL_H
