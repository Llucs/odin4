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
    // Layout matches the 132-byte PIT entry used by Samsung download mode.
    uint32_t binary_type;
    uint32_t device_type;
    uint32_t identifier;
    uint32_t attributes;
    uint32_t update_attributes;
    uint32_t block_size_or_offset;
    uint32_t block_count;
    uint32_t file_offset;
    uint32_t file_size;
    char partition_name[32];
    char file_name[32];
    char fota_name[32];
};
#pragma pack(pop)

struct PitTable {
    uint32_t entry_count;
    uint32_t header_size;
    uint32_t unknown1;
    uint32_t unknown2;
    uint16_t unknown3;
    uint16_t unknown4;
    uint16_t unknown5;
    uint16_t unknown6;
    uint16_t unknown7;
    uint16_t unknown8;
    std::vector<PitEntry> entries;
};

#endif // ODIN_TYPES_H
