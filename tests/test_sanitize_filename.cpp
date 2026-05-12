/**
 * Tests for changes in src/firmware/firmware_package.h and firmware_package.cpp
 *
 * The PR modified firmware_package.h (the exact diff was not shown but the file
 * was listed as changed). The sanitize_filename() and check_md5_signature()
 * functions are public utilities declared in firmware_package.h.
 *
 * sanitize_filename() strips recognised firmware extensions (.lz4, .ext4, .img, .bin)
 * from the end of a filename recursively until no more strippable extensions remain.
 * This is pure string manipulation and is straightforward to unit test.
 *
 * check_md5_signature() wraps file I/O and MD5 verification; those tests use
 * temporary files to avoid external dependencies.
 */

#include <gtest/gtest.h>
#include "firmware/firmware_package.h"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <type_traits>
#include <vector>
#include <unistd.h>

// ---------------------------------------------------------------------------
// sanitize_filename: strips .lz4 .ext4 .img .bin (case-insensitive) from the end
// ---------------------------------------------------------------------------

TEST(SanitizeFilename, NoExtension) {
    EXPECT_EQ(sanitize_filename("boot"), "boot");
}

TEST(SanitizeFilename, UnrecognisedExtension) {
    EXPECT_EQ(sanitize_filename("ap.tar"), "ap.tar");
    EXPECT_EQ(sanitize_filename("firmware.zip"), "firmware.zip");
    EXPECT_EQ(sanitize_filename("file.txt"), "file.txt");
}

TEST(SanitizeFilename, StripLz4) {
    EXPECT_EQ(sanitize_filename("boot.lz4"), "boot");
}

TEST(SanitizeFilename, StripExt4) {
    EXPECT_EQ(sanitize_filename("system.ext4"), "system");
}

TEST(SanitizeFilename, StripImg) {
    EXPECT_EQ(sanitize_filename("recovery.img"), "recovery");
}

TEST(SanitizeFilename, StripBin) {
    EXPECT_EQ(sanitize_filename("modem.bin"), "modem");
}

TEST(SanitizeFilename, StripImgThenLz4) {
    // .lz4 is stripped first, then .img
    EXPECT_EQ(sanitize_filename("system.img.lz4"), "system");
}

TEST(SanitizeFilename, StripExt4ThenLz4) {
    EXPECT_EQ(sanitize_filename("userdata.ext4.lz4"), "userdata");
}

TEST(SanitizeFilename, StripBinThenLz4) {
    EXPECT_EQ(sanitize_filename("cp.bin.lz4"), "cp");
}

TEST(SanitizeFilename, MultipleRecognisedExtensions) {
    // img.lz4 -> strip .lz4 -> .img -> strip .img -> "super"
    EXPECT_EQ(sanitize_filename("super.img.lz4"), "super");
}

TEST(SanitizeFilename, CaseInsensitiveLz4) {
    EXPECT_EQ(sanitize_filename("boot.LZ4"), "boot");
    EXPECT_EQ(sanitize_filename("boot.Lz4"), "boot");
}

TEST(SanitizeFilename, CaseInsensitiveImg) {
    EXPECT_EQ(sanitize_filename("boot.IMG"), "boot");
}

TEST(SanitizeFilename, CaseInsensitiveExt4) {
    EXPECT_EQ(sanitize_filename("system.EXT4"), "system");
}

TEST(SanitizeFilename, CaseInsensitiveBin) {
    EXPECT_EQ(sanitize_filename("modem.BIN"), "modem");
}

TEST(SanitizeFilename, CaseInsensitiveMixed) {
    EXPECT_EQ(sanitize_filename("system.Img.LZ4"), "system");
}

TEST(SanitizeFilename, StopsAtUnrecognisedExtension) {
    // .tar is not stripped; only the trailing .lz4 is removed
    EXPECT_EQ(sanitize_filename("ap.tar.lz4"), "ap.tar");
    EXPECT_EQ(sanitize_filename("ap.tar.md5"), "ap.tar.md5");
}

TEST(SanitizeFilename, EmptyString) {
    EXPECT_EQ(sanitize_filename(""), "");
}

TEST(SanitizeFilename, DotOnly) {
    EXPECT_EQ(sanitize_filename("."), ".");
}

TEST(SanitizeFilename, ExtensionOnly) {
    // ".lz4" as a full filename: the base becomes "" after stripping
    EXPECT_EQ(sanitize_filename(".lz4"), "");
}

TEST(SanitizeFilename, NoDoubleStripIfAlreadyClean) {
    // Already has no recognised extension
    EXPECT_EQ(sanitize_filename("system"), "system");
    EXPECT_EQ(sanitize_filename("SYSTEM"), "SYSTEM");
}

TEST(SanitizeFilename, PreservesPath) {
    // The function receives just a basename in practice, but it must not
    // mangle strings that look like they contain directory separators.
    // Directory components are just part of the filename string.
    EXPECT_EQ(sanitize_filename("dir/file.lz4"), "dir/file");
}

TEST(SanitizeFilename, TripleExtension) {
    // Three strippable extensions in a row are all stripped.
    // Trace for "file.img.bin.lz4":
    //   strip .lz4 -> "file.img.bin"
    //   strip .bin -> "file.img"
    //   strip .img -> "file"
    //   npos       -> return "file"
    EXPECT_EQ(sanitize_filename("file.img.bin.lz4"), "file");
    EXPECT_EQ(sanitize_filename("vendor.img.bin.lz4"), "vendor");
}

TEST(SanitizeFilename, ReturnTypeIsString) {
    static_assert(std::is_same_v<decltype(sanitize_filename("")), std::string>,
                  "sanitize_filename must return std::string");
    SUCCEED();
}

// ---------------------------------------------------------------------------
// Boundary / regression cases
// ---------------------------------------------------------------------------

TEST(SanitizeFilename, LongNameWithNoRecognisedExtension) {
    std::string long_name(200, 'a');
    long_name += ".tar.md5";
    EXPECT_EQ(sanitize_filename(long_name), long_name);
}

TEST(SanitizeFilename, LongNameWithLz4) {
    std::string long_name(200, 'b');
    long_name += ".img.lz4";
    std::string expected(200, 'b');
    EXPECT_EQ(sanitize_filename(long_name), expected);
}

TEST(SanitizeFilename, SamsungTypicalNames) {
    // Names commonly found in Samsung firmware packages
    EXPECT_EQ(sanitize_filename("BOOT.img"), "BOOT");
    EXPECT_EQ(sanitize_filename("AP_firmware.tar.md5"), "AP_firmware.tar.md5");
    EXPECT_EQ(sanitize_filename("system.img.lz4"), "system");
    EXPECT_EQ(sanitize_filename("userdata.ext4.lz4"), "userdata");
    EXPECT_EQ(sanitize_filename("modem.bin"), "modem");
    EXPECT_EQ(sanitize_filename("recovery.img"), "recovery");
}

// ---------------------------------------------------------------------------
// check_md5_signature: verifies an MD5 trailer appended to a .tar.md5 file.
// We test with synthetic files written to a temporary location.
// ---------------------------------------------------------------------------

// Helper: write bytes to a temp file and return its path
static std::string write_temp_file(const std::string& suffix, const std::vector<uint8_t>& content) {
    std::string tmpl = std::string("/tmp/odin4_test_XXXXXX") + suffix;
    // POSIX mkstemps for files with arbitrary suffix
    std::vector<char> buf(tmpl.begin(), tmpl.end());
    buf.push_back('\0');
    int fd = mkstemps(buf.data(), static_cast<int>(suffix.size()));
    if (fd == -1) {
        return "";
    }
    ::write(fd, content.data(), content.size());
    ::close(fd);
    return std::string(buf.data());
}

TEST(CheckMd5Signature, NonTarMd5FileReturnsTrueWithoutChecking) {
    // A file without .tar.md5 extension is considered valid (no MD5 to check)
    auto path = write_temp_file(".bin", {0x01, 0x02, 0x03});
    ASSERT_FALSE(path.empty());
    EXPECT_TRUE(check_md5_signature(path)) << "Files without .tar.md5 extension must always pass MD5 check";
    std::remove(path.c_str());
}

TEST(CheckMd5Signature, NonExistentFileReturnsFalse) {
    EXPECT_FALSE(check_md5_signature("/tmp/this_file_does_not_exist_odin4test.tar.md5"));
}

TEST(CheckMd5Signature, FileTooSmallReturnsFalse) {
    // File must be at least 32 bytes to contain a valid MD5 trailer
    auto path = write_temp_file(".tar.md5", {0x01, 0x02, 0x03});
    ASSERT_FALSE(path.empty());
    EXPECT_FALSE(check_md5_signature(path));
    std::remove(path.c_str());
}

TEST(CheckMd5Signature, ValidMd5TrailerPassesCheck) {
    // Build a minimal .tar.md5 file:
    //   content = 4 zero bytes (the "tar" content)
    //   trailer = md5(content) as 32 hex ASCII chars
    // MD5 of 4 zero bytes: f1d3ff8443297732862df21dc4e57262
    // (known MD5 of "\x00\x00\x00\x00")
    const std::string known_md5_of_4_zeros = "f1d3ff8443297732862df21dc4e57262";
    std::vector<uint8_t> content(4, 0x00);
    // Append the 32-byte hex MD5 trailer
    for (char c : known_md5_of_4_zeros) {
        content.push_back(static_cast<uint8_t>(c));
    }
    auto path = write_temp_file(".tar.md5", content);
    ASSERT_FALSE(path.empty());
    bool result = check_md5_signature(path);
    std::remove(path.c_str());
    EXPECT_TRUE(result) << "Valid MD5 trailer must pass verification";
}

TEST(CheckMd5Signature, WrongMd5TrailerFailsCheck) {
    // Same content but wrong MD5 trailer
    std::vector<uint8_t> content(4, 0x00);
    const std::string wrong_md5 = "aabbccddeeff00112233445566778899"; // 32 hex chars
    for (char c : wrong_md5) {
        content.push_back(static_cast<uint8_t>(c));
    }
    auto path = write_temp_file(".tar.md5", content);
    ASSERT_FALSE(path.empty());
    bool result = check_md5_signature(path);
    std::remove(path.c_str());
    EXPECT_FALSE(result) << "Wrong MD5 trailer must fail verification";
}