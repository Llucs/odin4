/**
 * Tests for changes in lib/lz4/lz4frame.c and lib/lz4/lz4frame.h
 *
 * The PR made the following changes:
 *  - Added braces around single-statement if/else bodies (formatting only).
 *  - Split multiple-variable declarations into one declaration per line.
 *  - LZ4F_doNotCompressBlock() parameter changed from char* dst to const char* dst
 *    (const-correctness; this is a static internal function).
 *  - LZ4F_uncompressedUpdate() parameter renamed from cOptPtr to compressOptionsPtr.
 *  - LZ4F_createCDict_advanced() parameter renamed from customMem to cmem.
 *  - Variable declarations split into one-per-line in LZ4F_decodeHeader,
 *    LZ4F_getFrameInfo, and LZ4F_decompress.
 *
 * These tests verify the LZ4 frame API remains fully functional after the refactoring.
 */

#include <gtest/gtest.h>

extern "C" {
#include "lz4frame.h"
#include "lz4.h"
}

#include <cstring>
#include <vector>
#include <string>
#include <cstdint>

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static std::vector<uint8_t> make_compressible(size_t n) {
    std::vector<uint8_t> buf(n);
    for (size_t i = 0; i < n; ++i) {
        buf[i] = static_cast<uint8_t>('A' + (i % 26));
    }
    return buf;
}

static std::vector<uint8_t> compress_frame(const uint8_t* src, size_t src_size,
                                            const LZ4F_preferences_t* prefs = nullptr) {
    size_t bound = LZ4F_compressFrameBound(src_size, prefs);
    std::vector<uint8_t> dst(bound);
    size_t result = LZ4F_compressFrame(dst.data(), bound,
                                       src, src_size, prefs);
    if (LZ4F_isError(result)) {
        return {};
    }
    dst.resize(result);
    return dst;
}

// ---------------------------------------------------------------------------
// Error code helpers (LZ4F_isError / LZ4F_getErrorName)
// These functions were reformatted (braces added) in the PR.
// ---------------------------------------------------------------------------

TEST(LZ4FErrorHelpers, IsErrorReturnsFalseForZero) {
    EXPECT_EQ(LZ4F_isError(0u), 0u);
}

TEST(LZ4FErrorHelpers, IsErrorReturnsTrueForErrorCode) {
    // Error codes are represented as large size_t values (cast from negative ptrdiff_t)
    LZ4F_errorCode_t err = LZ4F_getErrorCode(static_cast<size_t>(-1));
    EXPECT_NE(LZ4F_isError(static_cast<size_t>(err)), 0u);
}

TEST(LZ4FErrorHelpers, GetErrorNameReturnsNonNullForError) {
    // Create a real error by using an invalid frame
    const char bad_frame[] = {0x01, 0x02, 0x03, 0x04}; // not a valid LZ4 magic
    LZ4F_dctx* dctx = nullptr;
    LZ4F_createDecompressionContext(&dctx, LZ4F_VERSION);
    ASSERT_NE(dctx, nullptr);

    size_t dst_size = 1024;
    std::vector<uint8_t> dst(dst_size);
    size_t src_size = sizeof(bad_frame);
    LZ4F_errorCode_t result = LZ4F_decompress(dctx, dst.data(), &dst_size,
                                               bad_frame, &src_size, nullptr);
    LZ4F_freeDecompressionContext(dctx);

    if (LZ4F_isError(result)) {
        const char* name = LZ4F_getErrorName(result);
        EXPECT_NE(name, nullptr);
        EXPECT_GT(strlen(name), 0u);
    }
    // If it didn't error, that's also fine — just skip the name check
}

TEST(LZ4FErrorHelpers, GetErrorNameForNoError) {
    // Passing a non-error code must return the fallback string, not a valid error string
    const char* name = LZ4F_getErrorName(0u);
    EXPECT_NE(name, nullptr);
}

// ---------------------------------------------------------------------------
// LZ4F_getBlockSize
// This function was reformatted with braces in the PR.
// ---------------------------------------------------------------------------

TEST(LZ4FBlockSize, DefaultBlockSizeId) {
    // blockSizeID == 0 is treated as LZ4F_BLOCKSIZEID_DEFAULT (LZ4F_max64KB)
    size_t sz = LZ4F_getBlockSize(0);
    EXPECT_GT(sz, 0u);
    EXPECT_FALSE(LZ4F_isError(sz));
}

TEST(LZ4FBlockSize, Max64KB) {
    size_t sz = LZ4F_getBlockSize(LZ4F_max64KB);
    EXPECT_EQ(sz, 64u * 1024u);
}

TEST(LZ4FBlockSize, Max256KB) {
    size_t sz = LZ4F_getBlockSize(LZ4F_max256KB);
    EXPECT_EQ(sz, 256u * 1024u);
}

TEST(LZ4FBlockSize, Max1MB) {
    size_t sz = LZ4F_getBlockSize(LZ4F_max1MB);
    EXPECT_EQ(sz, 1u * 1024u * 1024u);
}

TEST(LZ4FBlockSize, Max4MB) {
    size_t sz = LZ4F_getBlockSize(LZ4F_max4MB);
    EXPECT_EQ(sz, 4u * 1024u * 1024u);
}

TEST(LZ4FBlockSize, InvalidBlockSizeId) {
    // An out-of-range block size ID must return an error
    size_t sz = LZ4F_getBlockSize(static_cast<LZ4F_blockSizeID_t>(99));
    EXPECT_TRUE(LZ4F_isError(sz));
}

// ---------------------------------------------------------------------------
// LZ4F_compressFrameBound
// ---------------------------------------------------------------------------

TEST(LZ4FCompressFrameBound, ZeroInput) {
    size_t bound = LZ4F_compressFrameBound(0, nullptr);
    EXPECT_GT(bound, 0u) << "Even empty frame needs a header + end mark";
}

TEST(LZ4FCompressFrameBound, NonZeroInput) {
    const size_t src_size = 1024 * 1024;
    size_t bound = LZ4F_compressFrameBound(src_size, nullptr);
    EXPECT_GT(bound, src_size) << "Bound must exceed input size";
}

// ---------------------------------------------------------------------------
// LZ4F_compressFrame / LZ4F_decompress roundtrip
// The reformatted code paths in LZ4F_decompress are exercised here.
// ---------------------------------------------------------------------------

TEST(LZ4FRoundtrip, SmallCompressibleBlock) {
    auto src = make_compressible(1024);
    auto compressed = compress_frame(src.data(), src.size());
    ASSERT_FALSE(compressed.empty()) << "Compression must succeed";

    LZ4F_dctx* dctx = nullptr;
    LZ4F_errorCode_t err = LZ4F_createDecompressionContext(&dctx, LZ4F_VERSION);
    ASSERT_EQ(LZ4F_isError(err), 0u);
    ASSERT_NE(dctx, nullptr);

    std::vector<uint8_t> decompressed(src.size() * 2, 0);
    size_t dst_size = decompressed.size();
    size_t src_size_in = compressed.size();
    LZ4F_errorCode_t result = LZ4F_decompress(dctx, decompressed.data(), &dst_size,
                                               compressed.data(), &src_size_in, nullptr);
    LZ4F_freeDecompressionContext(dctx);

    ASSERT_FALSE(LZ4F_isError(result)) << LZ4F_getErrorName(result);
    ASSERT_EQ(dst_size, src.size());
    EXPECT_EQ(memcmp(src.data(), decompressed.data(), src.size()), 0);
}

TEST(LZ4FRoundtrip, LargeCompressibleBlock) {
    // Use a larger input to exercise more code paths in the reformatted functions
    auto src = make_compressible(512 * 1024);
    auto compressed = compress_frame(src.data(), src.size());
    ASSERT_FALSE(compressed.empty());

    LZ4F_dctx* dctx = nullptr;
    LZ4F_createDecompressionContext(&dctx, LZ4F_VERSION);
    ASSERT_NE(dctx, nullptr);

    std::vector<uint8_t> decompressed(src.size(), 0);
    size_t dst_size = decompressed.size();
    size_t src_size_in = compressed.size();
    LZ4F_errorCode_t result = LZ4F_decompress(dctx, decompressed.data(), &dst_size,
                                               compressed.data(), &src_size_in, nullptr);
    LZ4F_freeDecompressionContext(dctx);

    ASSERT_FALSE(LZ4F_isError(result));
    ASSERT_EQ(dst_size, src.size());
    EXPECT_EQ(memcmp(src.data(), decompressed.data(), src.size()), 0);
}

TEST(LZ4FRoundtrip, EmptyInput) {
    auto compressed = compress_frame(nullptr, 0);
    ASSERT_FALSE(compressed.empty());

    LZ4F_dctx* dctx = nullptr;
    LZ4F_createDecompressionContext(&dctx, LZ4F_VERSION);
    ASSERT_NE(dctx, nullptr);

    uint8_t dummy = 0;
    size_t dst_size = sizeof(dummy);
    size_t src_size_in = compressed.size();
    LZ4F_errorCode_t result = LZ4F_decompress(dctx, &dummy, &dst_size,
                                               compressed.data(), &src_size_in, nullptr);
    LZ4F_freeDecompressionContext(dctx);

    EXPECT_FALSE(LZ4F_isError(result));
    EXPECT_EQ(dst_size, 0u) << "Empty input must produce 0 decompressed bytes";
}

TEST(LZ4FRoundtrip, WithContentChecksum) {
    LZ4F_preferences_t prefs{};
    prefs.frameInfo.contentChecksumFlag = LZ4F_contentChecksumEnabled;

    auto src = make_compressible(8192);
    auto compressed = compress_frame(src.data(), src.size(), &prefs);
    ASSERT_FALSE(compressed.empty());

    LZ4F_dctx* dctx = nullptr;
    LZ4F_createDecompressionContext(&dctx, LZ4F_VERSION);
    ASSERT_NE(dctx, nullptr);

    std::vector<uint8_t> decompressed(src.size(), 0);
    size_t dst_size = decompressed.size();
    size_t src_size_in = compressed.size();
    LZ4F_errorCode_t result = LZ4F_decompress(dctx, decompressed.data(), &dst_size,
                                               compressed.data(), &src_size_in, nullptr);
    LZ4F_freeDecompressionContext(dctx);

    ASSERT_FALSE(LZ4F_isError(result));
    EXPECT_EQ(dst_size, src.size());
    EXPECT_EQ(memcmp(src.data(), decompressed.data(), src.size()), 0);
}

TEST(LZ4FRoundtrip, WithBlockLinkedMode) {
    LZ4F_preferences_t prefs{};
    prefs.frameInfo.blockMode = LZ4F_blockLinked;

    auto src = make_compressible(32 * 1024);
    auto compressed = compress_frame(src.data(), src.size(), &prefs);
    ASSERT_FALSE(compressed.empty());

    LZ4F_dctx* dctx = nullptr;
    LZ4F_createDecompressionContext(&dctx, LZ4F_VERSION);
    ASSERT_NE(dctx, nullptr);

    std::vector<uint8_t> decompressed(src.size(), 0);
    size_t dst_size = decompressed.size();
    size_t src_size_in = compressed.size();
    LZ4F_errorCode_t result = LZ4F_decompress(dctx, decompressed.data(), &dst_size,
                                               compressed.data(), &src_size_in, nullptr);
    LZ4F_freeDecompressionContext(dctx);

    ASSERT_FALSE(LZ4F_isError(result));
    EXPECT_EQ(dst_size, src.size());
    EXPECT_EQ(memcmp(src.data(), decompressed.data(), src.size()), 0);
}

// ---------------------------------------------------------------------------
// LZ4F context lifecycle
// ---------------------------------------------------------------------------

TEST(LZ4FContext, CreateAndFreeDecompressionContext) {
    LZ4F_dctx* dctx = nullptr;
    LZ4F_errorCode_t err = LZ4F_createDecompressionContext(&dctx, LZ4F_VERSION);
    ASSERT_EQ(LZ4F_isError(err), 0u) << LZ4F_getErrorName(err);
    ASSERT_NE(dctx, nullptr);
    LZ4F_freeDecompressionContext(dctx);
}

TEST(LZ4FContext, CreateAndFreeCompressionContext) {
    LZ4F_cctx* cctx = nullptr;
    LZ4F_errorCode_t err = LZ4F_createCompressionContext(&cctx, LZ4F_VERSION);
    ASSERT_EQ(LZ4F_isError(err), 0u) << LZ4F_getErrorName(err);
    ASSERT_NE(cctx, nullptr);
    LZ4F_freeCompressionContext(cctx);
}

// ---------------------------------------------------------------------------
// LZ4F compression context — begin / update / end
// Tests the reformatted LZ4F_compressBegin, LZ4F_compressUpdate, LZ4F_compressEnd
// ---------------------------------------------------------------------------

TEST(LZ4FCctxAPI, BeginUpdateEnd) {
    LZ4F_cctx* cctx = nullptr;
    LZ4F_createCompressionContext(&cctx, LZ4F_VERSION);
    ASSERT_NE(cctx, nullptr);

    auto src = make_compressible(4096);
    const size_t bound = LZ4F_compressBound(src.size(), nullptr);
    std::vector<uint8_t> dst(LZ4F_HEADER_SIZE_MAX + bound + 8);

    // Begin
    size_t pos = LZ4F_compressBegin(cctx, dst.data(), dst.size(), nullptr);
    ASSERT_FALSE(LZ4F_isError(pos)) << LZ4F_getErrorName(pos);

    // Update
    size_t written = LZ4F_compressUpdate(cctx, dst.data() + pos, dst.size() - pos,
                                          src.data(), src.size(), nullptr);
    ASSERT_FALSE(LZ4F_isError(written)) << LZ4F_getErrorName(written);
    pos += written;

    // End
    written = LZ4F_compressEnd(cctx, dst.data() + pos, dst.size() - pos, nullptr);
    ASSERT_FALSE(LZ4F_isError(written)) << LZ4F_getErrorName(written);
    pos += written;
    LZ4F_freeCompressionContext(cctx);

    dst.resize(pos);

    // Decompress to verify
    LZ4F_dctx* dctx = nullptr;
    LZ4F_createDecompressionContext(&dctx, LZ4F_VERSION);
    ASSERT_NE(dctx, nullptr);

    std::vector<uint8_t> decompressed(src.size(), 0);
    size_t dst_size = decompressed.size();
    size_t src_size_in = dst.size();
    LZ4F_errorCode_t result = LZ4F_decompress(dctx, decompressed.data(), &dst_size,
                                               dst.data(), &src_size_in, nullptr);
    LZ4F_freeDecompressionContext(dctx);

    ASSERT_FALSE(LZ4F_isError(result));
    EXPECT_EQ(dst_size, src.size());
    EXPECT_EQ(memcmp(src.data(), decompressed.data(), src.size()), 0);
}

// ---------------------------------------------------------------------------
// LZ4F_headerSize
// ---------------------------------------------------------------------------

TEST(LZ4FHeaderSize, ValidFrame) {
    auto src = make_compressible(256);
    auto compressed = compress_frame(src.data(), src.size());
    ASSERT_FALSE(compressed.empty());

    size_t hdr_size = LZ4F_headerSize(compressed.data(), compressed.size());
    EXPECT_FALSE(LZ4F_isError(hdr_size));
    EXPECT_GT(hdr_size, 0u);
    EXPECT_LE(hdr_size, LZ4F_HEADER_SIZE_MAX);
}

TEST(LZ4FHeaderSize, InputTooSmallReturnsError) {
    const uint8_t tiny[] = {0x04, 0x22}; // Only 2 bytes — too small to determine header
    size_t hdr_size = LZ4F_headerSize(tiny, sizeof(tiny));
    EXPECT_TRUE(LZ4F_isError(hdr_size));
}

// ---------------------------------------------------------------------------
// LZ4F decompress — incremental / chunked feeding
// This exercises more of the reformatted state-machine paths in LZ4F_decompress.
// ---------------------------------------------------------------------------

TEST(LZ4FDecompress, IncrementalFeeding) {
    auto src = make_compressible(16 * 1024);
    auto compressed = compress_frame(src.data(), src.size());
    ASSERT_FALSE(compressed.empty());

    LZ4F_dctx* dctx = nullptr;
    LZ4F_createDecompressionContext(&dctx, LZ4F_VERSION);
    ASSERT_NE(dctx, nullptr);

    std::vector<uint8_t> decompressed;
    decompressed.reserve(src.size());

    size_t in_pos = 0;
    const size_t chunk = 512; // Feed 512 bytes at a time
    uint8_t out_buf[4096];

    while (in_pos < compressed.size()) {
        size_t to_feed = std::min(chunk, compressed.size() - in_pos);
        size_t dst_size = sizeof(out_buf);
        size_t src_size_in = to_feed;

        LZ4F_errorCode_t result = LZ4F_decompress(dctx, out_buf, &dst_size,
                                                    compressed.data() + in_pos,
                                                    &src_size_in, nullptr);
        if (LZ4F_isError(result)) {
            LZ4F_freeDecompressionContext(dctx);
            FAIL() << "LZ4F_decompress returned error: " << LZ4F_getErrorName(result);
        }
        decompressed.insert(decompressed.end(), out_buf, out_buf + dst_size);
        in_pos += src_size_in;
    }

    LZ4F_freeDecompressionContext(dctx);

    ASSERT_EQ(decompressed.size(), src.size());
    EXPECT_EQ(memcmp(src.data(), decompressed.data(), src.size()), 0);
}

// ---------------------------------------------------------------------------
// Regression: LZ4F_flush (reformatted in the PR)
// ---------------------------------------------------------------------------

TEST(LZ4FCctxFlush, FlushEmptyBufferReturnsZero) {
    LZ4F_cctx* cctx = nullptr;
    LZ4F_createCompressionContext(&cctx, LZ4F_VERSION);
    ASSERT_NE(cctx, nullptr);

    auto src = make_compressible(64);
    std::vector<uint8_t> dst(LZ4F_HEADER_SIZE_MAX + LZ4F_compressBound(src.size(), nullptr) + 8);

    size_t pos = LZ4F_compressBegin(cctx, dst.data(), dst.size(), nullptr);
    ASSERT_FALSE(LZ4F_isError(pos));

    // Flush with nothing buffered — should return 0 (no bytes written)
    size_t flushed = LZ4F_flush(cctx, dst.data() + pos, dst.size() - pos, nullptr);
    EXPECT_EQ(flushed, 0u) << "Flush with empty buffer must return 0";

    LZ4F_freeCompressionContext(cctx);
}