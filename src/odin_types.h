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
    bool nand_erase = false;
    bool validation = false;
    bool reboot = false;
    bool redownload = false;
    bool show_license = false;
    bool list_devices = false;
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
