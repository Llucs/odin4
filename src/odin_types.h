#ifndef ODIN_TYPES_H
#define ODIN_TYPES_H

#include <string>
#include <vector>
#include <cstdint>

// ============================================================================
// CONFIGURATION STRUCTURES
// ============================================================================

struct OdinConfig {
    std::string bootloader;
    std::string ap;
    std::string cp;
    std::string csc;
    std::string ums;
    std::string device_path;
    // Flags controlling optional behaviour
    bool reboot = false;
    bool redownload = false;
    // Perform a dry run (check-only) instead of actually flashing. When
    // enabled, odin4 will verify firmware integrity and compatibility,
    // parse PIT tables and tar archives, but will not send any data to
    // the device. This flag corresponds to the --check-only command-line
    // option.
    bool dry_run = false;
};

// ============================================================================
// PARTITION INFORMATION TABLE (PIT)
// ============================================================================

#pragma pack(push, 1)
struct PitEntry {
    uint32_t identifier;
    uint32_t flash_type;
    uint32_t file_size;
    uint32_t block_size;
    char partition_name[32];
    char file_name[32];
};
#pragma pack(pop)

struct PitTable {
    uint32_t header_size;
    uint32_t entry_count;
    std::vector<PitEntry> entries;
};

#endif // ODIN_TYPES_H
