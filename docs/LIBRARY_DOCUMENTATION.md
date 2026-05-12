# Odin4 Library Documentation

This document provides comprehensive technical documentation for the Odin4 library, a modern C++ reimplementation of Samsung's Thor protocol for Linux. It enables the integration of device flashing functionalities into other tools and applications.

## Overview

The `libodin4` library, available in both static (`.a`) and shared (`.so`) formats, offers a C++ API for interacting with Samsung devices in Download Mode. It facilitates operations such as device detection, firmware flashing, and version retrieval.

## Integration

### Required Files
To integrate `libodin4` into a project, the following files are essential:
-   `include/odin4/odin4.h`: The primary header file exposing the public API.
-   `libodin4.so` or `libodin4.a`: The compiled library binary (shared or static, respectively).

### Dependencies
The `libodin4` library has the following external dependencies:
-   **libusb-1.0**: Utilized for low-level USB communication with devices.
-   **Crypto++**: Employed for cryptographic operations, such as MD5 signature verification of firmware packages. The `CMakeLists.txt` indicates a preference for static linking of Crypto++ to minimize runtime dependencies.
-   **LZ4**: Used for the decompression of LZ4-compressed firmware data. The LZ4 source files are included directly within the `odin4` repository and compiled as a static library (`lz4_lib`) internally.

When linking against the shared library (`libodin4.so`), standard system libraries like `libusb-1.0` are required. Depending on the compiler and system configuration, explicit linking with `-lpthread` and `-ldl` might be necessary.

## API Reference

### Main Structures

#### `OdinConfig`
This structure defines the configuration parameters for various Odin4 operations. It is passed to functions like `odin4_init`, `odin4_list_devices`, and `odin4_run`.

```cpp
struct OdinConfig {
    std::string bootloader;      // Path to the Bootloader firmware file
    std::string ap;              // Path to the AP (Application Processor) firmware file
    std::string cp;              // Path to the CP (Modem/Phone) firmware file
    std::string csc;             // Path to the CSC (Consumer Software Customization) firmware file
    std::string ums;             // Path to the UMS (USB Mass Storage) firmware file
    std::string device_path;     // Optional: Specific USB device path to target

    bool dry_run = false;        // If true, simulates flashing without writing to the device
    bool allow_unknown = false;  // If true, allows flashing of unknown firmware files
    bool reboot = false;         // If true, reboots the device after a successful operation
    bool redownload = false;     // If true, instructs the device to re-enter Download Mode after operation

    bool quiet = false;          // Suppresses informational output
    bool verbose = false;        // Enables verbose logging
    bool debug = false;          // Enables debug logging

    bool has_vid = false;        // Indicates if a Vendor ID (VID) is specified for device selection
    uint16_t vid = 0;            // Vendor ID for device selection
    bool has_pid = false;        // Indicates if a Product ID (PID) is specified for device selection
    uint16_t pid = 0;            // Product ID for device selection
    bool has_usb_interface = false; // Indicates if a USB interface number is specified
    int usb_interface = 0;       // USB interface number for device selection
};
```

#### `OdinExitCode`
An enumeration representing the possible exit codes for Odin4 operations, indicating success or specific types of failures.

```cpp
enum class OdinExitCode : int {
    Success = 0,   // Operation completed successfully
    Usage = 1,     // Incorrect usage or arguments
    Usb = 2,       // USB communication or device-related error
    Protocol = 3,  // Thor protocol communication error
    Pit = 4,       // Partition Information Table (PIT) error or incompatibility
    Firmware = 5,  // Firmware file error (e.g., invalid format, MD5 mismatch)
    Unknown = 99   // Unspecified or unknown error
};
```

#### `PitEntry` and `PitTable`
These structures are used internally to represent the Partition Information Table (PIT) obtained from the device. The `PitEntry` describes individual partitions, while `PitTable` holds a collection of these entries along with header information.

```cpp
// Defined in src/core/odin_types.h
struct PitEntry { /* ... */ };
struct PitTable { /* ... */ };
```

### Core Functions

#### `void odin4_init(const OdinConfig& cfg)`
Initializes the Odin4 library, setting up logging levels and other global configurations based on the provided `OdinConfig`.

-   **Parameters**: `cfg` - A constant reference to an `OdinConfig` object containing initialization settings.
-   **Returns**: `void`

#### `std::vector<std::string> odin4_list_devices(const OdinConfig& cfg)`
Detects and lists Samsung devices currently in Download Mode that match the USB selection criteria specified in `cfg`.

-   **Parameters**: `cfg` - A constant reference to an `OdinConfig` object, primarily used for `vid`, `pid`, and `usb_interface` filtering.
-   **Returns**: `std::vector<std::string>` - A list of device paths (e.g., `/dev/bus/usb/001/005`) for detected devices.

#### `OdinExitCode odin4_run(const OdinConfig& cfg)`
Executes the main flashing process or validation based on the provided configuration. This function handles opening the USB device, performing handshakes, retrieving the PIT, processing firmware files, and sending control commands (reboot/redownload).

-   **Parameters**: `cfg` - A constant reference to an `OdinConfig` object detailing the operation (firmware files, dry-run, reboot, etc.).
-   **Returns**: `OdinExitCode` - An enum value indicating the success or specific failure of the operation.

#### `const char* odin4_get_version()`
Retrieves the version string of the Odin4 library.

-   **Parameters**: None
-   **Returns**: `const char*` - A C-style string representing the library's version.

## Usage Example

The following C++ example demonstrates how to initialize the library, list devices, and perform a flashing operation (or dry-run).

```cpp
#include <odin4/odin4.h>
#include <iostream>
#include <vector>

int main() {
    OdinConfig cfg;
    cfg.verbose = true; // Enable verbose logging
    cfg.reboot = true;  // Reboot device after operation
    cfg.ap = "/path/to/AP_firmware.tar.md5"; // Example AP firmware path
    // cfg.dry_run = true; // Uncomment to simulate without flashing

    // Initialize the library
    odin4_init(cfg);

    // Get library version
    std::cout << "Odin4 Library Version: " << odin4_get_version() << std::endl;

    // List devices
    std::vector<std::string> devices = odin4_list_devices(cfg);
    if (devices.empty()) {
        std::cerr << "No compatible devices found in Download Mode." << std::endl;
        return static_cast<int>(OdinExitCode::Usb);
    }

    std::cout << "Detected devices:" << std::endl;
    for (const std::string& dev_path : devices) {
        std::cout << "- " << dev_path << std::endl;
    }

    // If multiple devices are found, you might want to select one explicitly
    // For this example, if only one is found, it will be used automatically by odin4_run
    // If multiple, odin4_run will return an error unless cfg.device_path is set.

    // Run the operation
    OdinExitCode rc = odin4_run(cfg);

    if (rc == OdinExitCode::Success) {
        std::cout << "Operation completed successfully!" << std::endl;
    } else {
        std::cerr << "Operation failed with error code: " << static_cast<int>(rc) << std::endl;
    }

    return static_cast<int>(rc);
}
```

## Building Your Application

To compile an application that uses the Odin4 library, you will typically need to include the header directory and link against the `libodin4` library. Assuming `libodin4.so` and `odin4.h` are in `lib/` and `include/odin4/` relative to your project, respectively:

```bash
g++ my_app.cpp -o my_app -I./include -L./lib -lodin4 -lusb-1.0 -lcryptopp -lpthread -ldl
```

-   `-I./include`: Specifies the directory where `odin4.h` can be found.
-   `-L./lib`: Specifies the directory containing `libodin4.so` or `libodin4.a`.
-   `-lodin4`: Links against the Odin4 library.
-   `-lusb-1.0`: Links against the libusb-1.0 library.
-   `-lcryptopp`: Links against the Crypto++ library.
-   `-lpthread -ldl`: Additional system libraries that might be required for linking, especially on Linux systems with shared libraries.