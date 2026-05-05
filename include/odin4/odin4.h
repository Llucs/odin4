#ifndef ODIN4_H
#define ODIN4_H

#include <string>
#include <vector>
#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Exit codes for Odin4 operations.
 */
enum class OdinExitCode : int {
    Success = 0,
    Usage = 1,
    Usb = 2,
    Protocol = 3,
    Pit = 4,
    Firmware = 5,
    Unknown = 99
};

/**
 * @brief Configuration for Odin4 operations.
 */
struct OdinConfig {
    std::string bootloader;
    std::string ap;
    std::string cp;
    std::string csc;
    std::string ums;
    std::string device_path;

    bool dry_run = false;
    bool allow_unknown = false;
    bool reboot = false;
    bool redownload = false;

    bool quiet = false;
    bool verbose = false;
    bool debug = false;

    bool has_vid = false;
    uint16_t vid = 0;
    bool has_pid = false;
    uint16_t pid = 0;
    bool has_usb_interface = false;
    int usb_interface = 0;
};

/**
 * @brief Initialize the library (e.g., logging).
 * @param cfg The configuration to use for initialization.
 */
void odin4_init(const OdinConfig& cfg);

/**
 * @brief List detected Samsung devices in Download Mode.
 * @param cfg The configuration containing USB selection criteria.
 * @return A list of device paths.
 */
std::vector<std::string> odin4_list_devices(const OdinConfig& cfg);

/**
 * @brief Run the flashing process or validation for a specific device.
 * @param cfg The configuration for the operation.
 * @return OdinExitCode indicating success or failure.
 */
OdinExitCode odin4_run(const OdinConfig& cfg);

/**
 * @brief Get the version string of the library.
 * @return The version string.
 */
const char* odin4_get_version();

#ifdef __cplusplus
}
#endif

#endif // ODIN4_H
