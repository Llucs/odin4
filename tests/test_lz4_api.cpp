/**
 * Tests for changes in lib/lz4/lz4.c and lib/lz4/lz4.h
 *
 * The PR made the following changes:
 *  - Added braces around single-statement if/else bodies (formatting only, no behavioral change).
 *  - Split multiple-variable declarations into one declaration per line.
 *  - LZ4_resetStreamState() parameter changed from char* to const char* (const-correctness).
 *  - LZ4_create() parameter changed from char* to const char* (const-correctness).
 *
 * These tests verify that the LZ4 block API continues to work correctly after the
 * reformatting, and that the deprecated API functions accept const pointers.
 */

#include <gtest/gtest.h>

extern "C" {
#include "lz4.h"
}

#include <cstring>
#include <string>
#include <vector>
#include <algorithm>
#include <cstdint>

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static std::vector<char> make_compressible_data(size_t n) {
    // Highly compressible: repeating ASCII pattern
    std::vector<char> buf(n);
    for (size_t i = 0; i < n; ++i) {
        buf[i] = static_cast<char>('A' + (i % 26));
    }
    return buf;
}

static std::vector<char> make_incompressible_data(size_t n) {
    // Pseudo-random bytes that are hard to compress
    std::vector<char> buf(n);
    uint32_t lcg = 0xDEADBEEFu;
    for (size_t i = 0; i < n; ++i) {
        lcg = lcg * 1664525u + 1013904223u;
        buf[i] = static_cast<char>(lcg >> 24);
    }
    return buf;
}

// ---------------------------------------------------------------------------
// LZ4 compress bound
// ---------------------------------------------------------------------------

TEST(LZ4CompressBound, ZeroInput) {
    EXPECT_GE(LZ4_compressBound(0), 0);
}

TEST(LZ4CompressBound, SmallInput) {
    // The bound must always be larger than the input size
    for (int sz : {1, 16, 64, 512, 4096}) {
        EXPECT_GT(LZ4_compressBound(sz), sz) << "compressBound(" << sz << ") must exceed input size";
    }
}

TEST(LZ4CompressBound, LargeInput) {
    // 1 MiB
    const int src_size = 1 * 1024 * 1024;
    EXPECT_GT(LZ4_compressBound(src_size), src_size);
}

// ---------------------------------------------------------------------------
// LZ4 compress / decompress — simple API (LZ4_compress_default / LZ4_decompress_safe)
// ---------------------------------------------------------------------------

TEST(LZ4BlockRoundtrip, CompressibleData) {
    auto src = make_compressible_data(65536);
    int src_size = static_cast<int>(src.size());
    int max_dst = LZ4_compressBound(src_size);
    std::vector<char> dst(max_dst);

    int compressed_size = LZ4_compress_default(src.data(), dst.data(), src_size, max_dst);
    ASSERT_GT(compressed_size, 0) << "Compression of compressible data must succeed";
    // Highly compressible data should actually compress
    EXPECT_LT(compressed_size, src_size);

    std::vector<char> decompressed(src_size);
    int decompressed_size = LZ4_decompress_safe(dst.data(), decompressed.data(), compressed_size, src_size);
    ASSERT_EQ(decompressed_size, src_size) << "Decompressed size must match original";
    EXPECT_EQ(std::memcmp(src.data(), decompressed.data(), src_size), 0) << "Decompressed data must match original";
}

TEST(LZ4BlockRoundtrip, IncompressibleData) {
    auto src = make_incompressible_data(4096);
    int src_size = static_cast<int>(src.size());
    int max_dst = LZ4_compressBound(src_size);
    std::vector<char> dst(max_dst);

    // Compression of incompressible data still succeeds (may expand slightly)
    int compressed_size = LZ4_compress_default(src.data(), dst.data(), src_size, max_dst);
    ASSERT_GT(compressed_size, 0) << "Compression must succeed even for incompressible data";

    std::vector<char> decompressed(src_size);
    int decompressed_size = LZ4_decompress_safe(dst.data(), decompressed.data(), compressed_size, src_size);
    ASSERT_EQ(decompressed_size, src_size);
    EXPECT_EQ(std::memcmp(src.data(), decompressed.data(), src_size), 0);
}

TEST(LZ4BlockRoundtrip, EmptyInput) {
    const char* src = "";
    char dst[16] = {};
    int compressed_size = LZ4_compress_default(src, dst, 0, sizeof(dst));
    ASSERT_GE(compressed_size, 0) << "Empty input must not return a negative (error) size";

    char decompressed[16] = {};
    int decompressed_size = LZ4_decompress_safe(dst, decompressed, compressed_size, sizeof(decompressed));
    EXPECT_EQ(decompressed_size, 0) << "Decompressing empty block must yield 0 bytes";
}

TEST(LZ4BlockRoundtrip, SingleByte) {
    const char src[1] = {'\x42'};
    int max_dst = LZ4_compressBound(1);
    std::vector<char> dst(max_dst);

    int compressed_size = LZ4_compress_default(src, dst.data(), 1, max_dst);
    ASSERT_GT(compressed_size, 0);

    char decompressed[1] = {};
    int decompressed_size = LZ4_decompress_safe(dst.data(), decompressed, compressed_size, 1);
    ASSERT_EQ(decompressed_size, 1);
    EXPECT_EQ(decompressed[0], '\x42');
}

TEST(LZ4BlockRoundtrip, AllZeroes) {
    const int n = 32768;
    std::vector<char> src(n, '\0');
    int max_dst = LZ4_compressBound(n);
    std::vector<char> dst(max_dst);

    int compressed_size = LZ4_compress_default(src.data(), dst.data(), n, max_dst);
    ASSERT_GT(compressed_size, 0);
    // All-zero data is highly compressible
    EXPECT_LT(compressed_size, n);

    std::vector<char> decompressed(n);
    int decompressed_size = LZ4_decompress_safe(dst.data(), decompressed.data(), compressed_size, n);
    ASSERT_EQ(decompressed_size, n);
    EXPECT_EQ(memcmp(src.data(), decompressed.data(), n), 0);
}

// ---------------------------------------------------------------------------
// LZ4 fast compression (LZ4_compress_fast)
// ---------------------------------------------------------------------------

TEST(LZ4CompressFast, Roundtrip) {
    auto src = make_compressible_data(16384);
    int src_size = static_cast<int>(src.size());
    int max_dst = LZ4_compressBound(src_size);
    std::vector<char> dst(max_dst);

    int compressed_size = LZ4_compress_fast(src.data(), dst.data(), src_size, max_dst, 1);
    ASSERT_GT(compressed_size, 0);

    std::vector<char> decompressed(src_size);
    int decompressed_size = LZ4_decompress_safe(dst.data(), decompressed.data(), compressed_size, src_size);
    ASSERT_EQ(decompressed_size, src_size);
    EXPECT_EQ(memcmp(src.data(), decompressed.data(), src_size), 0);
}

TEST(LZ4CompressFast, HigherAccelerationDoesNotBreakRoundtrip) {
    auto src = make_compressible_data(8192);
    int src_size = static_cast<int>(src.size());
    int max_dst = LZ4_compressBound(src_size);
    std::vector<char> dst(max_dst);

    // Acceleration value of 50 — well above the default of 1
    int compressed_size = LZ4_compress_fast(src.data(), dst.data(), src_size, max_dst, 50);
    ASSERT_GT(compressed_size, 0);

    std::vector<char> decompressed(src_size);
    int decompressed_size = LZ4_decompress_safe(dst.data(), decompressed.data(), compressed_size, src_size);
    ASSERT_EQ(decompressed_size, src_size);
    EXPECT_EQ(memcmp(src.data(), decompressed.data(), src_size), 0);
}

// ---------------------------------------------------------------------------
// LZ4 streaming API (LZ4_stream_t)
// ---------------------------------------------------------------------------

TEST(LZ4Stream, CreateAndFree) {
    LZ4_stream_t* stream = LZ4_createStream();
    ASSERT_NE(stream, nullptr) << "LZ4_createStream() must return a non-null pointer";
    int ret = LZ4_freeStream(stream);
    EXPECT_EQ(ret, 0) << "LZ4_freeStream() must return 0";
}

TEST(LZ4Stream, FreeNull) {
    // Free on NULL must be safe and return 0
    int ret = LZ4_freeStream(nullptr);
    EXPECT_EQ(ret, 0);
}

TEST(LZ4Stream, ContinueRoundtrip) {
    LZ4_stream_t* stream = LZ4_createStream();
    ASSERT_NE(stream, nullptr);

    auto src = make_compressible_data(1024);
    int src_size = static_cast<int>(src.size());
    int max_dst = LZ4_compressBound(src_size);
    std::vector<char> dst(max_dst);

    int compressed_size = LZ4_compress_fast_continue(stream, src.data(), dst.data(), src_size, max_dst, 1);
    ASSERT_GT(compressed_size, 0);

    LZ4_freeStream(stream);

    std::vector<char> decompressed(src_size);
    int decompressed_size = LZ4_decompress_safe(dst.data(), decompressed.data(), compressed_size, src_size);
    ASSERT_EQ(decompressed_size, src_size);
    EXPECT_EQ(memcmp(src.data(), decompressed.data(), src_size), 0);
}

// ---------------------------------------------------------------------------
// Const-correctness: LZ4_create() and LZ4_resetStreamState()
// PR changed char* -> const char* for the deprecated functions below.
// These compile-time tests verify the new signatures are accepted.
// ---------------------------------------------------------------------------

// Suppress deprecation warnings for the deprecated functions being tested
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

TEST(LZ4DeprecatedAPI, CreateWithConstCharPtr) {
    // LZ4_create(const char*) — PR changed the parameter from char* to const char*
    // Passing a string literal (const char*) should now compile without a cast.
    const char* dummy_buf = "dummy";
    void* ctx = LZ4_create(dummy_buf);
    // The implementation ignores inputBuffer and allocates fresh state
    ASSERT_NE(ctx, nullptr);
    // Clean up via the current API (LZ4_create returns an LZ4_stream_t*)
    LZ4_freeStream(static_cast<LZ4_stream_t*>(ctx));
}

TEST(LZ4DeprecatedAPI, ResetStreamStateWithConstCharPtr) {
    // LZ4_resetStreamState(void*, const char*) — PR changed char* -> const char*
    LZ4_stream_t* stream = LZ4_createStream();
    ASSERT_NE(stream, nullptr);

    const char* dummy_buf = "dummy";
    int ret = LZ4_resetStreamState(stream, dummy_buf);
    // The implementation ignores inputBuffer; must return 0 on success
    EXPECT_EQ(ret, 0);
    LZ4_freeStream(stream);
}

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif

// ---------------------------------------------------------------------------
// Decompression error paths
// ---------------------------------------------------------------------------

TEST(LZ4DecompressSafe, TruncatedInputReturnsError) {
    auto src = make_compressible_data(512);
    int src_size = static_cast<int>(src.size());
    int max_dst = LZ4_compressBound(src_size);
    std::vector<char> compressed(max_dst);

    int compressed_size = LZ4_compress_default(src.data(), compressed.data(), src_size, max_dst);
    ASSERT_GT(compressed_size, 0);

    // Feed fewer bytes than the real compressed size — must fail (return < 0)
    std::vector<char> out(src_size);
    int ret = LZ4_decompress_safe(compressed.data(), out.data(), compressed_size / 2, src_size);
    EXPECT_LT(ret, 0) << "Truncated compressed input must return a negative error code";
}

TEST(LZ4DecompressSafe, OutputBufferTooSmallReturnsError) {
    auto src = make_compressible_data(1024);
    int src_size = static_cast<int>(src.size());
    int max_dst = LZ4_compressBound(src_size);
    std::vector<char> compressed(max_dst);

    int compressed_size = LZ4_compress_default(src.data(), compressed.data(), src_size, max_dst);
    ASSERT_GT(compressed_size, 0);

    // Provide an output buffer that is too small
    std::vector<char> out(src_size / 2);
    int ret = LZ4_decompress_safe(compressed.data(), out.data(), compressed_size, src_size / 2);
    EXPECT_LT(ret, 0) << "Too-small output buffer must return a negative error code";
}

// ---------------------------------------------------------------------------
// LZ4_decompress_safe_partial
// ---------------------------------------------------------------------------

TEST(LZ4DecompressSafePartial, DecompressPartialOutput) {
    auto src = make_compressible_data(4096);
    int src_size = static_cast<int>(src.size());
    int max_dst = LZ4_compressBound(src_size);
    std::vector<char> compressed(max_dst);

    int compressed_size = LZ4_compress_default(src.data(), compressed.data(), src_size, max_dst);
    ASSERT_GT(compressed_size, 0);

    // Request only the first 128 bytes of decompressed output
    const int target_size = 128;
    std::vector<char> out(src_size, '\0');
    int ret = LZ4_decompress_safe_partial(compressed.data(), out.data(), compressed_size, target_size, src_size);
    ASSERT_GE(ret, target_size) << "At least targetOutputSize bytes must be produced";
    EXPECT_EQ(memcmp(src.data(), out.data(), target_size), 0)
        << "Partial decompression must match the beginning of the original";
}

// ---------------------------------------------------------------------------
// LZ4 version information
// ---------------------------------------------------------------------------

TEST(LZ4Version, VersionStringNonEmpty) {
    int ver = LZ4_versionNumber();
    EXPECT_GT(ver, 0);
}