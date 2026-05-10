#ifndef ODIN4_H
#define ODIN4_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Exit codes for Odin4 operations.
 */
typedef enum {
    ODIN_SUCCESS = 0,
    ODIN_USAGE = 1,
    ODIN_USB = 2,
    ODIN_PROTOCOL = 3,
    ODIN_PIT = 4,
    ODIN_FIRMWARE = 5,
    ODIN_UNKNOWN = 99
} OdinExitCode;

/**
 * @brief Configuration for Odin4 operations.
 */
typedef struct {
    const char* bootloader;
    const char* ap;
    const char* cp;
    const char* csc;
    const char* ums;
    const char* device_path;

    bool dry_run;
    bool allow_unknown;
    bool reboot;
    bool redownload;

    bool quiet;
    bool verbose;
    bool debug;

    bool has_vid;
    uint16_t vid;
    bool has_pid;
    uint16_t pid;
    bool has_usb_interface;
    int usb_interface;
} OdinConfig;

/**
 * @brief Initialize the library (e.g., logging).
 * @param cfg The configuration to use for initialization.
 */
void odin4_init(const OdinConfig* cfg);

/**
 * @brief List detected Samsung devices in Download Mode.
 * @param cfg The configuration containing USB selection criteria.
 * @param count Output pointer for the number of devices found.
 * @return An array of device path strings. Must be freed with odin4_free_device_list.
 */
char** odin4_list_devices(const OdinConfig* cfg, int* count);

/**
 * @brief Free the device list returned by odin4_list_devices.
 * @param list The list to free.
 * @param count The number of devices in the list.
 */
void odin4_free_device_list(char** list, int count);

/**
 * @brief Run the flashing process or validation for a specific device.
 * @param cfg The configuration for the operation.
 * @return OdinExitCode indicating success or failure.
 */
OdinExitCode odin4_run(const OdinConfig* cfg);

/**
 * @brief Get the version string of the library.
 * @return The version string.
 */
const char* odin4_get_version();

#ifdef __cplusplus
}
#endif

#endif // ODIN4_H
