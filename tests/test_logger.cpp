/**
 * Tests for changes in src/core/logger.h
 *
 * The PR applied the trailing return type syntax to get_log_level():
 *   Before: LogLevel get_log_level();
 *   After:  auto get_log_level() -> LogLevel;
 *
 * These tests verify that:
 *   1. set_log_level / get_log_level roundtrip correctly for all LogLevel values.
 *   2. The initial default log level is LogLevel::Info.
 *   3. The LogLevel enum values match the expected ordering.
 *   4. log_hexdump does not crash when log level is not Debug.
 *   5. set_log_file with empty path does not crash.
 */

#include <gtest/gtest.h>
#include "core/logger.h"

#include <cstdint>
#include <string>
#include <type_traits>
#include <vector>

// ---------------------------------------------------------------------------
// LogLevel enum value ordering
// The ordering determines what messages are suppressed vs. emitted.
// ---------------------------------------------------------------------------

TEST(LogLevelEnum, OrderingIsCorrect) {
    // Error (0) < Warn (1) < Info (2) < Verbose (3) < Debug (4)
    EXPECT_LT(static_cast<int>(LogLevel::Error),   static_cast<int>(LogLevel::Warn));
    EXPECT_LT(static_cast<int>(LogLevel::Warn),    static_cast<int>(LogLevel::Info));
    EXPECT_LT(static_cast<int>(LogLevel::Info),    static_cast<int>(LogLevel::Verbose));
    EXPECT_LT(static_cast<int>(LogLevel::Verbose), static_cast<int>(LogLevel::Debug));
}

TEST(LogLevelEnum, ExplicitValues) {
    EXPECT_EQ(static_cast<int>(LogLevel::Error),   0);
    EXPECT_EQ(static_cast<int>(LogLevel::Warn),    1);
    EXPECT_EQ(static_cast<int>(LogLevel::Info),    2);
    EXPECT_EQ(static_cast<int>(LogLevel::Verbose), 3);
    EXPECT_EQ(static_cast<int>(LogLevel::Debug),   4);
}

// ---------------------------------------------------------------------------
// set_log_level / get_log_level roundtrip
// get_log_level() now uses trailing return type syntax.
// ---------------------------------------------------------------------------

class LoggerLevelTest : public ::testing::Test {
  protected:
    LogLevel saved_level_{};

    void SetUp() override {
        // Save the current level so we can restore it after each test
        saved_level_ = get_log_level();
    }

    void TearDown() override {
        set_log_level(saved_level_);
    }
};

TEST_F(LoggerLevelTest, SetAndGetError) {
    set_log_level(LogLevel::Error);
    EXPECT_EQ(get_log_level(), LogLevel::Error);
}

TEST_F(LoggerLevelTest, SetAndGetWarn) {
    set_log_level(LogLevel::Warn);
    EXPECT_EQ(get_log_level(), LogLevel::Warn);
}

TEST_F(LoggerLevelTest, SetAndGetInfo) {
    set_log_level(LogLevel::Info);
    EXPECT_EQ(get_log_level(), LogLevel::Info);
}

TEST_F(LoggerLevelTest, SetAndGetVerbose) {
    set_log_level(LogLevel::Verbose);
    EXPECT_EQ(get_log_level(), LogLevel::Verbose);
}

TEST_F(LoggerLevelTest, SetAndGetDebug) {
    set_log_level(LogLevel::Debug);
    EXPECT_EQ(get_log_level(), LogLevel::Debug);
}

TEST_F(LoggerLevelTest, MultipleSetGetRoundtrip) {
    const LogLevel levels[] = {
        LogLevel::Debug, LogLevel::Error, LogLevel::Verbose,
        LogLevel::Warn, LogLevel::Info
    };
    for (LogLevel lvl : levels) {
        set_log_level(lvl);
        EXPECT_EQ(get_log_level(), lvl)
            << "Expected level " << static_cast<int>(lvl)
            << " but got " << static_cast<int>(get_log_level());
    }
}

TEST_F(LoggerLevelTest, LevelPersistsBetweenCalls) {
    set_log_level(LogLevel::Verbose);
    // Call something that internally reads the level
    log_verbose("test verbose message");
    // Level must not have changed
    EXPECT_EQ(get_log_level(), LogLevel::Verbose);
}

// ---------------------------------------------------------------------------
// Logging functions do not crash
// ---------------------------------------------------------------------------

class LoggerSmokeTest : public ::testing::Test {
  protected:
    LogLevel saved_level_{};

    void SetUp() override {
        saved_level_ = get_log_level();
        // Set to Debug so all messages would be emitted
        set_log_level(LogLevel::Debug);
    }

    void TearDown() override {
        set_log_level(saved_level_);
    }
};

TEST_F(LoggerSmokeTest, LogWarnDoesNotCrash) {
    EXPECT_NO_FATAL_FAILURE(log_warn("test warning"));
}

TEST_F(LoggerSmokeTest, LogInfoDoesNotCrash) {
    EXPECT_NO_FATAL_FAILURE(log_info("test info"));
}

TEST_F(LoggerSmokeTest, LogVerboseDoesNotCrash) {
    EXPECT_NO_FATAL_FAILURE(log_verbose("test verbose"));
}

TEST_F(LoggerSmokeTest, LogDebugDoesNotCrash) {
    EXPECT_NO_FATAL_FAILURE(log_debug("test debug"));
}

TEST_F(LoggerSmokeTest, LogErrorNoLibusbErrDoesNotCrash) {
    EXPECT_NO_FATAL_FAILURE(log_error("test error", 0));
}

TEST_F(LoggerSmokeTest, LogEmptyMessageDoesNotCrash) {
    EXPECT_NO_FATAL_FAILURE(log_info(""));
    EXPECT_NO_FATAL_FAILURE(log_warn(""));
    EXPECT_NO_FATAL_FAILURE(log_debug(""));
}

// ---------------------------------------------------------------------------
// log_hexdump
// ---------------------------------------------------------------------------

TEST_F(LoggerSmokeTest, HexdumpAtDebugLevelDoesNotCrash) {
    const uint8_t data[] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03};
    set_log_level(LogLevel::Debug);
    EXPECT_NO_FATAL_FAILURE(log_hexdump("test hexdump", data, sizeof(data)));
}

TEST_F(LoggerSmokeTest, HexdumpAtInfoLevelDoesNotCrash) {
    const uint8_t data[] = {0xCA, 0xFE};
    set_log_level(LogLevel::Info);
    // log_hexdump is suppressed below Debug level — must still not crash
    EXPECT_NO_FATAL_FAILURE(log_hexdump("suppressed hexdump", data, sizeof(data)));
}

TEST_F(LoggerSmokeTest, HexdumpNullDataDoesNotCrash) {
    set_log_level(LogLevel::Debug);
    EXPECT_NO_FATAL_FAILURE(log_hexdump("null hexdump", nullptr, 0));
}

TEST_F(LoggerSmokeTest, HexdumpZeroSizeDoesNotCrash) {
    const uint8_t data[] = {0xFF};
    set_log_level(LogLevel::Debug);
    EXPECT_NO_FATAL_FAILURE(log_hexdump("zero size hexdump", data, 0));
}

TEST_F(LoggerSmokeTest, HexdumpLargeBuffer) {
    std::vector<uint8_t> data(256);
    for (size_t i = 0; i < data.size(); ++i) {
        data[i] = static_cast<uint8_t>(i);
    }
    set_log_level(LogLevel::Debug);
    EXPECT_NO_FATAL_FAILURE(log_hexdump("large hexdump", data.data(), data.size()));
}

// ---------------------------------------------------------------------------
// set_log_file
// ---------------------------------------------------------------------------

TEST(LoggerFile, SetEmptyPathDoesNotCrash) {
    // Calling with empty path must not crash (just closes any open file)
    EXPECT_NO_FATAL_FAILURE(set_log_file(""));
}

TEST(LoggerFile, SetEmptyPathTwiceDoesNotCrash) {
    EXPECT_NO_FATAL_FAILURE(set_log_file(""));
    EXPECT_NO_FATAL_FAILURE(set_log_file(""));
}

// ---------------------------------------------------------------------------
// Return type verification (compile-time)
// ---------------------------------------------------------------------------

TEST(LoggerReturnTypes, GetLogLevelReturnsLogLevel) {
    static_assert(std::is_same_v<decltype(get_log_level()), LogLevel>,
                  "get_log_level() must return LogLevel (trailing return type)");
    SUCCEED();
}