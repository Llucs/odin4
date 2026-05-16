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

#include <cstdint>
#include <cstring>

namespace {

inline uint16_t test_swap16(uint16_t v) {
    return static_cast<uint16_t>((v << 8) | (v >> 8));
}

inline uint32_t test_swap32(uint32_t v) {
    return ((v >> 24) & 0x000000FF) | ((v >> 8) & 0x0000FF00) | ((v << 8) & 0x00FF0000) | ((v << 24) & 0xFF000000);
}

inline uint64_t test_swap64(uint64_t v) {
    uint32_t lo = static_cast<uint32_t>(v & 0xFFFFFFFFULL);
    uint32_t hi = static_cast<uint32_t>((v >> 32) & 0xFFFFFFFFULL);
    return (static_cast<uint64_t>(test_swap32(lo)) << 32) | test_swap32(hi);
}

} // namespace

#include "test_framework.h"
#include "../src/protocol/thor_protocol.h"
#include <cstdint>
#include <vector>

void test_ThorProtocol_Endian16_Swap() {
    uint16_t val = 0x1234;
    uint16_t swapped = test_swap16(val);
    EXPECT_EQ(swapped, 0x3412);
}
REGISTER_TEST(ThorProtocol, Endian16_Swap);

void test_ThorProtocol_Endian16_SwapTwice() {
    uint16_t val = 0xABCD;
    uint16_t swapped = test_swap16(val);
    uint16_t back = test_swap16(swapped);
    EXPECT_EQ(back, val);
}
REGISTER_TEST(ThorProtocol, Endian16_SwapTwice);

void test_ThorProtocol_Endian32_Swap() {
    uint32_t val = 0x12345678;
    uint32_t swapped = test_swap32(val);
    EXPECT_EQ(swapped, 0x78563412);
}
REGISTER_TEST(ThorProtocol, Endian32_Swap);

void test_ThorProtocol_Endian32_SwapTwice() {
    uint32_t val = 0xDEADBEEF;
    uint32_t swapped = test_swap32(val);
    uint32_t back = test_swap32(swapped);
    EXPECT_EQ(back, val);
}
REGISTER_TEST(ThorProtocol, Endian32_SwapTwice);

void test_ThorProtocol_Endian64_Swap() {
    uint64_t val = 0x0123456789ABCDEF;
    uint64_t swapped = test_swap64(val);
    EXPECT_EQ(swapped, 0xEFCDAB8967452301);
}
REGISTER_TEST(ThorProtocol, Endian64_Swap);

void test_ThorProtocol_Endian64_SwapTwice() {
    uint64_t val = 0xCAFEBABE12345678;
    uint64_t swapped = test_swap64(val);
    uint64_t back = test_swap64(swapped);
    EXPECT_EQ(back, val);
}
REGISTER_TEST(ThorProtocol, Endian64_SwapTwice);

void test_ThorProtocol_Le16ToH() {
    uint16_t little = 0x3412;
    uint16_t host = le16toh(little);
    EXPECT_EQ(host, 0x3412);
}
REGISTER_TEST(ThorProtocol, Le16ToH);

void test_ThorProtocol_HToLe16() {
    uint16_t host = 0xABCD;
    uint16_t little = htole16(host);
    EXPECT_EQ(little, 0xABCD);
}
REGISTER_TEST(ThorProtocol, HToLe16);

void test_ThorProtocol_Le32ToH() {
    uint32_t little = 0x78563412;
    uint32_t host = le32toh(little);
    EXPECT_EQ(host, 0x78563412);
}
REGISTER_TEST(ThorProtocol, Le32ToH);

void test_ThorProtocol_HToLe32() {
    uint32_t host = 0xDEADBEEF;
    uint32_t little = htole32(host);
    EXPECT_EQ(little, 0xDEADBEEF);
}
REGISTER_TEST(ThorProtocol, HToLe32);

void test_ThorProtocol_Le64ToH() {
    uint64_t little = 0xEFCDAB8967452301;
    uint64_t host = le64toh(little);
    EXPECT_EQ(host, 0xEFCDAB8967452301);
}
REGISTER_TEST(ThorProtocol, Le64ToH);

void test_ThorProtocol_HToLe64() {
    uint64_t host = 0xCAFEBABE12345678;
    uint64_t little = htole64(host);
    EXPECT_EQ(little, 0xCAFEBABE12345678);
}
REGISTER_TEST(ThorProtocol, HToLe64);

void test_ThorProtocol_Le32ToH_Function() {
    uint32_t val = 0x12345678;
    uint32_t result = le32_to_h(val);
    EXPECT_EQ(result, val);
}
REGISTER_TEST(ThorProtocol, Le32ToH_Function);

void test_ThorProtocol_HToLe32_Function() {
    uint32_t val = 0x12345678;
    uint32_t result = h_to_le32(val);
    EXPECT_EQ(result, val);
}
REGISTER_TEST(ThorProtocol, HToLe32_Function);

void test_ThorProtocol_HToLe16_Function() {
    uint16_t val = 0x1234;
    uint16_t result = h_to_le16(val);
    EXPECT_EQ(result, val);
}
REGISTER_TEST(ThorProtocol, HToLe16_Function);

void test_ThorProtocol_Le64ToH_Function() {
    uint64_t val = 0x0123456789ABCDEF;
    uint64_t result = le64_to_h(val);
    EXPECT_EQ(result, val);
}
REGISTER_TEST(ThorProtocol, Le64ToH_Function);

void test_ThorProtocol_HToLe64_Function() {
    uint64_t val = 0x0123456789ABCDEF;
    uint64_t result = h_to_le64(val);
    EXPECT_EQ(result, val);
}
REGISTER_TEST(ThorProtocol, HToLe64_Function);

void test_ThorProtocol_PacketHeader_Size() {
    EXPECT_EQ(sizeof(ThorPacketHeader), 8u);
}
REGISTER_TEST(ThorProtocol, PacketHeader_Size);

void test_ThorProtocol_PacketTypes_Values() {
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
REGISTER_TEST(ThorProtocol, PacketTypes_Values);

void test_ThorProtocol_ControlTypes_Values() {
    EXPECT_EQ(THOR_CONTROL_REBOOT, 0x0001);
    EXPECT_EQ(THOR_CONTROL_REDOWNLOAD, 0x0002);
}
REGISTER_TEST(ThorProtocol, ControlTypes_Values);

void test_ThorProtocol_HandshakePacket_Size() {
    EXPECT_EQ(sizeof(ThorHandshakePacket), 20u);
}
REGISTER_TEST(ThorProtocol, HandshakePacket_Size);

void test_ThorProtocol_DeviceTypePacket_Size() {
    EXPECT_EQ(sizeof(ThorDeviceTypePacket), 136u);
}
REGISTER_TEST(ThorProtocol, DeviceTypePacket_Size);

void test_ThorProtocol_BeginSessionPacket_Size() {
    EXPECT_EQ(sizeof(ThorBeginSessionPacket), 16u);
}
REGISTER_TEST(ThorProtocol, BeginSessionPacket_Size);

void test_ThorProtocol_PitFilePacket_Size() {
    EXPECT_EQ(sizeof(ThorPitFilePacket), 12u);
}
REGISTER_TEST(ThorProtocol, PitFilePacket_Size);

void test_ThorProtocol_FilePartSizePacket_Size() {
    EXPECT_EQ(sizeof(ThorFilePartSizePacket), 16u);
}
REGISTER_TEST(ThorProtocol, FilePartSizePacket_Size);

void test_ThorProtocol_FilePartPacket_Size() {
    EXPECT_EQ(sizeof(ThorFilePartPacket), 16u);
}
REGISTER_TEST(ThorProtocol, FilePartPacket_Size);

void test_ThorProtocol_EndFileTransferPacket_Size() {
    EXPECT_EQ(sizeof(ThorEndFileTransferPacket), 12u);
}
REGISTER_TEST(ThorProtocol, EndFileTransferPacket_Size);

void test_ThorProtocol_EndSessionPacket_Size() {
    EXPECT_EQ(sizeof(ThorEndSessionPacket), 8u);
}
REGISTER_TEST(ThorProtocol, EndSessionPacket_Size);

void test_ThorProtocol_ControlPacket_Size() {
    EXPECT_EQ(sizeof(ThorControlPacket), 12u);
}
REGISTER_TEST(ThorProtocol, ControlPacket_Size);

void test_ThorProtocol_ResponsePacket_Size() {
    EXPECT_EQ(sizeof(ThorResponsePacket), 12u);
}
REGISTER_TEST(ThorProtocol, ResponsePacket_Size);
