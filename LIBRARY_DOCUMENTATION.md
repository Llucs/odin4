# Odin4 Library Documentation

This library is a modern reimplementation of Samsung's Thor protocol for Linux, enabling the integration of flashing functionalities into other tools.

## Overview

The `libodin4` library (available in both static and shared formats) provides a C++ API to interact with Samsung devices in Download mode.

## Integration

### Required Files
- `include/odin4/odin4.h`: Main API header.
- `libodin4.so` or `libodin4.a`: Library binaries.

### Dependencies
The shared library (`libodin4.so`) is built to include the following dependencies internally where possible, but still requires standard system libraries:
- **libusb-1.0**: For USB communication.
- **Crypto++**: For cryptographic operations.
- **LZ4**: For firmware decompression.

*Note: On Linux systems, you may need to explicitly link with `-lpthread` and `-ldl` depending on your compiler.*

## API Reference

### Main Structures

#### `Odin4Config`
Configuration for library operations.
```cpp
struct Odin4Config {
    std::string device_path;    // Optional USB device path
    bool dry_run = false;       // Simulate without writing to the device
    bool reboot = false;        // Reboot after operation
    // ... see odin4.h for all fields
};

Odin4ExitCode

Return codes from functions.

Success (0)

Usage (1)

Usb (2)

Protocol (3)

Pit (4)

Firmware (5)


## Core Functions

void odin4_init(const Odin4Config& cfg)

Initializes the logger and global settings.

std::vector<std::string> odin4_list_devices(const Odin4Config& cfg)

Returns a list of detected Samsung device paths.

Odin4ExitCode odin4_run(const Odin4Config& cfg)

Executes the main flashing process based on the provided configuration.

const char* odin4_get_version()

Returns the tool's version string.

## Usage Example

#include <odin4/odin4.h>
#include <iostream>

int main() {
    Odin4Config cfg;
    cfg.reboot = true;

    // Initialize the library
    odin4_init(cfg);

    // List devices
    auto devices = odin4_list_devices(cfg);
    if (devices.empty()) {
        std::cerr << "No devices found!" << std::endl;
        return 1;
    }

    // Run the operation
    Odin4ExitCode rc = odin4_run(cfg);

    if (rc == Odin4ExitCode::Success) {
        std::cout << "Operation completed successfully!" << std::endl;
    } else {
        std::cerr << "Error: " << static_cast<int>(rc) << std::endl;
    }

    return 0;
}

## Building Your Application

To compile your application using the Odin4 library:

g++ my_app.cpp -o my_app -I./include -L./lib -lodin4