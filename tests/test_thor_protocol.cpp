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

}

#include "test_framework.h"
#include "../src/protocol/thor_protocol.h"
#include <cstdint>
#include <vector>

void test_OdinProtocol_Endian16_Swap() {
    uint16_t val = 0x1234;
    uint16_t swapped = test_swap16(val);
    EXPECT_EQ(swapped, 0x3412);
}
REGISTER_TEST(OdinProtocol, Endian16_Swap);

void test_OdinProtocol_Endian16_SwapTwice() {
    uint16_t val = 0xABCD;
    uint16_t swapped = test_swap16(val);
    uint16_t back = test_swap16(swapped);
    EXPECT_EQ(back, val);
}
REGISTER_TEST(OdinProtocol, Endian16_SwapTwice);

void test_OdinProtocol_Endian32_Swap() {
    uint32_t val = 0x12345678;
    uint32_t swapped = test_swap32(val);
    EXPECT_EQ(swapped, 0x78563412U);
}
REGISTER_TEST(OdinProtocol, Endian32_Swap);

void test_OdinProtocol_Endian32_SwapTwice() {
    uint32_t val = 0xDEADBEEF;
    uint32_t swapped = test_swap32(val);
    uint32_t back = test_swap32(swapped);
    EXPECT_EQ(back, val);
}
REGISTER_TEST(OdinProtocol, Endian32_SwapTwice);

void test_OdinProtocol_Endian64_Swap() {
    uint64_t val = 0x0123456789ABCDEF;
    uint64_t swapped = test_swap64(val);
    EXPECT_EQ(swapped, 0xEFCDAB8967452301ULL);
}
REGISTER_TEST(OdinProtocol, Endian64_Swap);

void test_OdinProtocol_Endian64_SwapTwice() {
    uint64_t val = 0xCAFEBABE12345678;
    uint64_t swapped = test_swap64(val);
    uint64_t back = test_swap64(swapped);
    EXPECT_EQ(back, val);
}
REGISTER_TEST(OdinProtocol, Endian64_SwapTwice);

void test_OdinProtocol_Le16ToH() {
    uint16_t little = 0x3412;
    uint16_t host = le16toh(little);
    EXPECT_EQ(host, 0x3412);
}
REGISTER_TEST(OdinProtocol, Le16ToH);

void test_OdinProtocol_HToLe16() {
    uint16_t host = 0xABCD;
    uint16_t little = htole16(host);
    EXPECT_EQ(little, 0xABCD);
}
REGISTER_TEST(OdinProtocol, HToLe16);

void test_OdinProtocol_Le32ToH() {
    uint32_t little = 0x78563412;
    uint32_t host = le32toh(little);
    EXPECT_EQ(host, 0x78563412U);
}
REGISTER_TEST(OdinProtocol, Le32ToH);

void test_OdinProtocol_HToLe32() {
    uint32_t host = 0xDEADBEEF;
    uint32_t little = htole32(host);
    EXPECT_EQ(little, 0xDEADBEEF);
}
REGISTER_TEST(OdinProtocol, HToLe32);

void test_OdinProtocol_Le64ToH() {
    uint64_t little = 0xEFCDAB8967452301;
    uint64_t host = le64toh(little);
    EXPECT_EQ(host, 0xEFCDAB8967452301);
}
REGISTER_TEST(OdinProtocol, Le64ToH);

void test_OdinProtocol_HToLe64() {
    uint64_t host = 0xCAFEBABE12345678;
    uint64_t little = htole64(host);
    EXPECT_EQ(little, 0xCAFEBABE12345678);
}
REGISTER_TEST(OdinProtocol, HToLe64);

void test_OdinProtocol_RequestBox_Size() {
    EXPECT_EQ(sizeof(OdinRequestBox), 1024u);
}
REGISTER_TEST(OdinProtocol, RequestBox_Size);

void test_OdinProtocol_ResponseBox_Size() {
    EXPECT_EQ(sizeof(OdinResponseBox), 8u);
}
REGISTER_TEST(OdinProtocol, ResponseBox_Size);

void test_OdinProtocol_CommandType_Values() {
    EXPECT_EQ(static_cast<int>(OdinCommandType::RQT_INIT), 0x64);
    EXPECT_EQ(static_cast<int>(OdinCommandType::RQT_PIT), 0x65);
    EXPECT_EQ(static_cast<int>(OdinCommandType::RQT_XMIT), 0x66);
    EXPECT_EQ(static_cast<int>(OdinCommandType::RQT_CLOSE), 0x67);
    EXPECT_EQ(static_cast<int>(OdinCommandType::RQT_EMPTY), 0);
}
REGISTER_TEST(OdinProtocol, CommandType_Values);

void test_OdinProtocol_ControlType_Values() {
    EXPECT_EQ(ODIN_CONTROL_REBOOT, 0x0001U);
    EXPECT_EQ(ODIN_CONTROL_REDOWNLOAD, 0x0002U);
}
REGISTER_TEST(OdinProtocol, ControlType_Values);

void test_OdinProtocol_MakeRequest_SetsIdAndData() {
    OdinRequestBox rq = make_request(OdinCommandType::RQT_INIT, OdinCommandParam::RQT_INIT_TARGET);
    EXPECT_EQ(static_cast<uint32_t>(le32_to_h(static_cast<uint32_t>(rq.id))), 0x64U);
    EXPECT_EQ(static_cast<uint32_t>(le32_to_h(static_cast<uint32_t>(rq.data))), 0U);
}
REGISTER_TEST(OdinProtocol, MakeRequest_SetsIdAndData);

void test_OdinProtocol_RqtPitSet_Value() {
    EXPECT_EQ(static_cast<int>(OdinCommandParam::RQT_PIT_SET), 0);
}
REGISTER_TEST(OdinProtocol, RqtPitSet_Value);

void test_OdinProtocol_RqtPitGet_Value() {
    EXPECT_EQ(static_cast<int>(OdinCommandParam::RQT_PIT_GET), 1);
}
REGISTER_TEST(OdinProtocol, RqtPitGet_Value);

void test_OdinProtocol_RqtPitStart_Value() {
    EXPECT_EQ(static_cast<int>(OdinCommandParam::RQT_PIT_START), 2);
}
REGISTER_TEST(OdinProtocol, RqtPitStart_Value);

void test_OdinProtocol_RqtPitComplete_Value() {
    EXPECT_EQ(static_cast<int>(OdinCommandParam::RQT_PIT_COMPLETE), 3);
}
REGISTER_TEST(OdinProtocol, RqtPitComplete_Value);

void test_OdinProtocol_HandshakeStringSize() {
    EXPECT_EQ(kOdinHandshakeUsbSize, 5u);
    EXPECT_EQ(kLokeResponseSize, 4u);
}
REGISTER_TEST(OdinProtocol, HandshakeStringSize);

void test_OdinProtocol_MakeRequest_WithInts() {
    std::vector<int32_t> ints = {5, 10};
    OdinRequestBox rq = make_request(OdinCommandType::RQT_INIT, OdinCommandParam::RQT_INIT_PACKETSIZE, ints);
    EXPECT_EQ(static_cast<uint32_t>(le32_to_h(static_cast<uint32_t>(rq.intData[0]))), 5U);
    EXPECT_EQ(static_cast<uint32_t>(le32_to_h(static_cast<uint32_t>(rq.intData[1]))), 10U);
}
REGISTER_TEST(OdinProtocol, MakeRequest_WithInts);

void test_OdinProtocol_ResponseFromLe() {
    OdinResponseBox r;
    r.id = h_to_le32(0x66);
    r.ack = h_to_le32(0);
    response_from_le(r);
    EXPECT_EQ(r.id, 0x66);
    EXPECT_EQ(r.ack, 0);
}
REGISTER_TEST(OdinProtocol, ResponseFromLe);
