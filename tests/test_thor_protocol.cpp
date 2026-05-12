/**
 * Tests for changes in src/protocol/thor_protocol.h
 *
 * The PR introduced 64-bit endianness helper functions complementing the
 * existing 16- and 32-bit helpers:
 *   - le64_to_h(uint64_t val) -> uint64_t
 *   - h_to_le64(uint64_t val) -> uint64_t
 *
 * The trailing return type syntax was also applied to all endianness helpers:
 *   - le32_to_h(uint32_t val) -> uint32_t
 *   - h_to_le32(uint32_t val) -> uint32_t
 *   - h_to_le16(uint16_t val) -> uint16_t
 *
 * These tests verify:
 *   1. All endianness helper functions return the correct values.
 *   2. The pack(push,1) structures have the expected byte sizes.
 *   3. The protocol enum values match the documented protocol constants.
 *   4. Roundtrip host↔LE conversions are consistent.
 */

#include <gtest/gtest.h>
#include "protocol/thor_protocol.h"

#include <cstdint>
#include <cstring>
#include <type_traits>

// ---------------------------------------------------------------------------
// Struct size checks (compile-time via static_assert, run-time via EXPECT)
// The structures use #pragma pack(push, 1) so each byte matters.
// ---------------------------------------------------------------------------

TEST(ThorPacketSizes, HeaderSize) {
    // ThorPacketHeader: uint32_t (4) + uint16_t (2) + uint16_t (2) = 8 bytes
    static_assert(sizeof(ThorPacketHeader) == 8, "ThorPacketHeader must be 8 bytes");
    EXPECT_EQ(sizeof(ThorPacketHeader), 8u);
}

TEST(ThorPacketSizes, HandshakePacketSize) {
    // ThorHandshakePacket: header (8) + uint32_t (4) + uint32_t (4) + uint32_t (4) = 20 bytes
    static_assert(sizeof(ThorHandshakePacket) == 20, "ThorHandshakePacket must be 20 bytes");
    EXPECT_EQ(sizeof(ThorHandshakePacket), 20u);
}

TEST(ThorPacketSizes, DeviceTypePacketSize) {
    // ThorDeviceTypePacket: header (8) + char[128] = 136 bytes
    static_assert(sizeof(ThorDeviceTypePacket) == 136, "ThorDeviceTypePacket must be 136 bytes");
    EXPECT_EQ(sizeof(ThorDeviceTypePacket), 136u);
}

TEST(ThorPacketSizes, BeginSessionPacketSize) {
    // ThorBeginSessionPacket: header (8) + uint32_t (4) + uint32_t (4) = 16 bytes
    static_assert(sizeof(ThorBeginSessionPacket) == 16, "ThorBeginSessionPacket must be 16 bytes");
    EXPECT_EQ(sizeof(ThorBeginSessionPacket), 16u);
}

TEST(ThorPacketSizes, PitFilePacketSize) {
    // ThorPitFilePacket: header (8) + uint32_t (4) = 12 bytes
    static_assert(sizeof(ThorPitFilePacket) == 12, "ThorPitFilePacket must be 12 bytes");
    EXPECT_EQ(sizeof(ThorPitFilePacket), 12u);
}

TEST(ThorPacketSizes, FilePartSizePacketSize) {
    // ThorFilePartSizePacket: header (8) + uint64_t (8) = 16 bytes
    static_assert(sizeof(ThorFilePartSizePacket) == 16, "ThorFilePartSizePacket must be 16 bytes");
    EXPECT_EQ(sizeof(ThorFilePartSizePacket), 16u);
}

TEST(ThorPacketSizes, FilePartPacketSize) {
    // ThorFilePartPacket: header (8) + uint32_t (4) + uint32_t (4) = 16 bytes
    static_assert(sizeof(ThorFilePartPacket) == 16, "ThorFilePartPacket must be 16 bytes");
    EXPECT_EQ(sizeof(ThorFilePartPacket), 16u);
}

TEST(ThorPacketSizes, EndFileTransferPacketSize) {
    // ThorEndFileTransferPacket: header (8) + uint32_t (4) = 12 bytes
    static_assert(sizeof(ThorEndFileTransferPacket) == 12, "ThorEndFileTransferPacket must be 12 bytes");
    EXPECT_EQ(sizeof(ThorEndFileTransferPacket), 12u);
}

TEST(ThorPacketSizes, EndSessionPacketSize) {
    // ThorEndSessionPacket: header (8) = 8 bytes
    static_assert(sizeof(ThorEndSessionPacket) == 8, "ThorEndSessionPacket must be 8 bytes");
    EXPECT_EQ(sizeof(ThorEndSessionPacket), 8u);
}

TEST(ThorPacketSizes, ControlPacketSize) {
    // ThorControlPacket: header (8) + uint32_t (4) = 12 bytes
    static_assert(sizeof(ThorControlPacket) == 12, "ThorControlPacket must be 12 bytes");
    EXPECT_EQ(sizeof(ThorControlPacket), 12u);
}

TEST(ThorPacketSizes, ResponsePacketSize) {
    // ThorResponsePacket: header (8) + uint32_t (4) = 12 bytes
    static_assert(sizeof(ThorResponsePacket) == 12, "ThorResponsePacket must be 12 bytes");
    EXPECT_EQ(sizeof(ThorResponsePacket), 12u);
}

// ---------------------------------------------------------------------------
// Packet type enum values
// ---------------------------------------------------------------------------

TEST(ThorPacketTypeEnums, Values) {
    EXPECT_EQ(THOR_PACKET_HANDSHAKE, 0x0001);
    EXPECT_EQ(THOR_PACKET_DEVICE_TYPE, 0x0002);
    EXPECT_EQ(THOR_PACKET_FILE_PART, 0x0003);
    EXPECT_EQ(THOR_PACKET_END_FILE_TRANSFER, 0x0004);
    EXPECT_EQ(THOR_PACKET_END_SESSION, 0x0005);
    EXPECT_EQ(THOR_PACKET_RESPONSE, 0x0006);
    EXPECT_EQ(THOR_PACKET_PIT_FILE, 0x0007);
    EXPECT_EQ(THOR_PACKET_BEGIN_SESSION, 0x0008);
    EXPECT_EQ(THOR_PACKET_FILE_PART_SIZE, 0x0009);
    EXPECT_EQ(THOR_PACKET_RECEIVE_FILE_PART, 0x000A);
    EXPECT_EQ(THOR_PACKET_CONTROL, 0x000B);
}

TEST(ThorControlTypeEnums, Values) {
    EXPECT_EQ(THOR_CONTROL_REBOOT, 0x0001);
    EXPECT_EQ(THOR_CONTROL_REDOWNLOAD, 0x0002);
}

// ---------------------------------------------------------------------------
// 32-bit endianness helpers — le32_to_h / h_to_le32
// The PR applied trailing-return-type syntax to these helpers.
// On a little-endian host the helpers are no-ops; on big-endian they swap.
// The important property is that roundtrip conversion is identity.
// ---------------------------------------------------------------------------

TEST(Endianness32, RoundtripZero) {
    uint32_t val = 0u;
    EXPECT_EQ(le32_to_h(h_to_le32(val)), val);
    EXPECT_EQ(h_to_le32(le32_to_h(val)), val);
}

TEST(Endianness32, RoundtripMaxValue) {
    uint32_t val = 0xFFFFFFFFu;
    EXPECT_EQ(le32_to_h(h_to_le32(val)), val);
    EXPECT_EQ(h_to_le32(le32_to_h(val)), val);
}

TEST(Endianness32, RoundtripArbitraryValue) {
    uint32_t val = 0x12345678u;
    EXPECT_EQ(le32_to_h(h_to_le32(val)), val);
}

TEST(Endianness32, LittleEndianEncoding) {
    // On a little-endian host, h_to_le32(0x01020304) should produce
    // bytes {0x04, 0x03, 0x02, 0x01} when stored in memory.
    uint32_t le_val = h_to_le32(0x01020304u);
    uint8_t bytes[4];
    std::memcpy(bytes, &le_val, 4);
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
    EXPECT_EQ(bytes[0], 0x04u);
    EXPECT_EQ(bytes[1], 0x03u);
    EXPECT_EQ(bytes[2], 0x02u);
    EXPECT_EQ(bytes[3], 0x01u);
#endif
}

// ---------------------------------------------------------------------------
// 16-bit endianness helpers — h_to_le16
// ---------------------------------------------------------------------------

TEST(Endianness16, RoundtripZero) {
    // h_to_le16 has no le16_to_h counterpart; verify via memcpy on LE host
    uint16_t val = 0u;
    EXPECT_EQ(h_to_le16(val), val);
}

TEST(Endianness16, RoundtripMaxValue) {
    uint16_t val = 0xFFFFu;
    // Swapping twice must restore the original
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
    EXPECT_EQ(h_to_le16(val), val); // no-op on LE
#endif
}

TEST(Endianness16, LittleEndianEncoding) {
    uint16_t le_val = h_to_le16(0x0102u);
    uint8_t bytes[2];
    std::memcpy(bytes, &le_val, 2);
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
    EXPECT_EQ(bytes[0], 0x02u);
    EXPECT_EQ(bytes[1], 0x01u);
#endif
}

// ---------------------------------------------------------------------------
// 64-bit endianness helpers — le64_to_h / h_to_le64
// These were ADDED in this PR.
// ---------------------------------------------------------------------------

TEST(Endianness64, RoundtripZero) {
    uint64_t val = 0u;
    EXPECT_EQ(le64_to_h(h_to_le64(val)), val);
    EXPECT_EQ(h_to_le64(le64_to_h(val)), val);
}

TEST(Endianness64, RoundtripMaxValue) {
    uint64_t val = 0xFFFFFFFFFFFFFFFFull;
    EXPECT_EQ(le64_to_h(h_to_le64(val)), val);
    EXPECT_EQ(h_to_le64(le64_to_h(val)), val);
}

TEST(Endianness64, RoundtripArbitraryValue) {
    uint64_t val = 0x0102030405060708ull;
    EXPECT_EQ(le64_to_h(h_to_le64(val)), val);
}

TEST(Endianness64, RoundtripHighBitsOnly) {
    uint64_t val = 0xDEADBEEF00000000ull;
    EXPECT_EQ(le64_to_h(h_to_le64(val)), val);
}

TEST(Endianness64, RoundtripLowBitsOnly) {
    uint64_t val = 0x00000000DEADBEEFull;
    EXPECT_EQ(le64_to_h(h_to_le64(val)), val);
}

TEST(Endianness64, LittleEndianEncoding) {
    // On a little-endian host h_to_le64 is a no-op; the bytes should be
    // in LSB-first order (little-endian byte order).
    uint64_t le_val = h_to_le64(0x0102030405060708ull);
    uint8_t bytes[8];
    std::memcpy(bytes, &le_val, 8);
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
    EXPECT_EQ(bytes[0], 0x08u);
    EXPECT_EQ(bytes[1], 0x07u);
    EXPECT_EQ(bytes[2], 0x06u);
    EXPECT_EQ(bytes[3], 0x05u);
    EXPECT_EQ(bytes[4], 0x04u);
    EXPECT_EQ(bytes[5], 0x03u);
    EXPECT_EQ(bytes[6], 0x02u);
    EXPECT_EQ(bytes[7], 0x01u);
#endif
}

TEST(Endianness64, IdentityAfterDoubleConversion) {
    // le64_to_h(h_to_le64(x)) == x for all x — this is the fundamental invariant
    const uint64_t values[] = {
        0u,
        1u,
        0x7FFFFFFFFFFFFFFFull,
        0x8000000000000000ull,
        0xFFFFFFFFFFFFFFFFull,
        0xCAFEBABEDEADBEEFull,
        0x0000000100000002ull,
    };
    for (uint64_t v : values) {
        EXPECT_EQ(le64_to_h(h_to_le64(v)), v) << "le64_to_h(h_to_le64(0x" << std::hex << v << ")) != 0x" << v;
    }
}

// ---------------------------------------------------------------------------
// Cross-width consistency
// The 64-bit helpers should be consistent with the 32-bit helpers for values
// that fit in 32 bits.
// ---------------------------------------------------------------------------

TEST(EndiannessCrossWidth, Lo32BitsConsistent) {
    // For a value that fits in 32 bits, the low 32 bits of le64_to_h(h_to_le64(v))
    // must equal le32_to_h(h_to_le32(v & 0xFFFFFFFF))
    const uint32_t lo = 0xABCDEF01u;
    const uint64_t v64 = static_cast<uint64_t>(lo);

    uint32_t result32 = le32_to_h(h_to_le32(lo));
    uint64_t result64 = le64_to_h(h_to_le64(v64));

    EXPECT_EQ(result32, lo);
    EXPECT_EQ(result64, v64);
    EXPECT_EQ(static_cast<uint32_t>(result64 & 0xFFFFFFFFu), result32);
}

// ---------------------------------------------------------------------------
// ThorPacketHeader field layout
// ---------------------------------------------------------------------------

TEST(ThorPacketHeader, FieldLayout) {
    ThorPacketHeader hdr{};
    hdr.packet_size = 0x12345678u;
    hdr.packet_type = 0xABCDu;
    hdr.packet_flags = 0x1234u;

    // Because the struct is packed, the fields must be laid out sequentially
    uint8_t raw[sizeof(ThorPacketHeader)];
    std::memcpy(raw, &hdr, sizeof(hdr));

    // On a little-endian host:
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
    // bytes 0..3: packet_size in LE
    EXPECT_EQ(raw[0], 0x78u);
    EXPECT_EQ(raw[1], 0x56u);
    EXPECT_EQ(raw[2], 0x34u);
    EXPECT_EQ(raw[3], 0x12u);
    // bytes 4..5: packet_type in LE
    EXPECT_EQ(raw[4], 0xCDu);
    EXPECT_EQ(raw[5], 0xABu);
    // bytes 6..7: packet_flags in LE
    EXPECT_EQ(raw[6], 0x34u);
    EXPECT_EQ(raw[7], 0x12u);
#endif
}

// ---------------------------------------------------------------------------
// Return type checks: all helpers must return the expected types
// ---------------------------------------------------------------------------

TEST(EndiannesReturnTypes, CorrectTypes) {
    static_assert(std::is_same_v<decltype(le32_to_h(uint32_t{})), uint32_t>, "le32_to_h must return uint32_t");
    static_assert(std::is_same_v<decltype(h_to_le32(uint32_t{})), uint32_t>, "h_to_le32 must return uint32_t");
    static_assert(std::is_same_v<decltype(h_to_le16(uint16_t{})), uint16_t>, "h_to_le16 must return uint16_t");
    static_assert(std::is_same_v<decltype(le64_to_h(uint64_t{})), uint64_t>, "le64_to_h must return uint64_t");
    static_assert(std::is_same_v<decltype(h_to_le64(uint64_t{})), uint64_t>, "h_to_le64 must return uint64_t");
    // If we get here, static_asserts passed at compile time
    SUCCEED();
}
