<p align="center">
  <img src="./logo.png" width="160" alt="odin4 logo">
</p>

<h1 align="center">odin4</h1>

<p align="center">
  Modern Samsung firmware flashing tool for Linux
</p>

<p align="center">
  <a href="LICENSE">
    <img src="https://img.shields.io/github/license/Llucs/odin4">
  </a>

  <a href="https://github.com/Llucs/odin4/actions/workflows/build.yml">
    <img src="https://github.com/Llucs/odin4/actions/workflows/build.yml/badge.svg">
  </a>

  <a href="https://github.com/Llucs/odin4/actions/workflows/codeql.yml">
    <img src="https://github.com/Llucs/odin4/actions/workflows/codeql.yml/badge.svg">
  </a>

  <img src="https://img.shields.io/badge/platform-linux-blue">
  <img src="https://img.shields.io/badge/language-C%2FC%2B%2B-blue">

<img src="https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/Llucs/odin4/main/version.json">

  </a>
</p>

---

## Table of Contents

*   [Overview](#overview)
*   [Core Features](#core-features)
*   [Safety and Validation](#safety-and-validation)
*   [Getting Started](#getting-started)
    *   [Dependencies](#dependencies)
    *   [Building from Source](#building-from-source)
*   [Usage](#usage)
    *   [Command-Line Options](#command-line-options)
    *   [Examples](#examples)
*   [Linux USB Permissions](#linux-usb-permissions)
*   [Project Status](#project-status)
*   [Contributing](#contributing)
*   [License](#license)
*   [Disclaimer](#disclaimer)

---

## Overview

**odin4** is a modern, open-source Samsung firmware flashing tool specifically designed for Linux environments. It provides a clean, correct, and robust implementation of the Thor USB protocol, offering a reliable alternative for Samsung device maintenance and development workflows on Linux.

The project emphasizes:

*   **Correct Protocol Behavior**: Adherence to the Thor USB protocol specifications for reliable communication.
*   **Strong Validation**: Comprehensive checks before flashing to prevent device bricking or data corruption.
*   **Structured Logging**: Detailed and organized logging for easier debugging and operational oversight.
*   **Deterministic and Safe Flashing Logic**: Ensuring predictable and secure flashing operations.
*   **Clean and Maintainable C++ Code**: A well-structured codebase that is easy to understand, extend, and maintain.

## Core Features

odin4 offers a comprehensive set of features for flashing Samsung devices:

*   **Samsung Download Mode Detection**: Automatic detection of devices in Download Mode via `libusb`.
*   **Native Thor Protocol Implementation**: A custom, native implementation of the Thor protocol for efficient and accurate flashing.
*   **Automatic PIT Retrieval and Parsing**: Automatically retrieves and parses Partition Information Table (PIT) data from devices.
*   **Strict Partition Validation**: Ensures that firmware partitions match the device's PIT, preventing mismatches.
*   **Support for Standard Samsung Firmware Packages**: Compatible with common firmware components:
    *   **BL** (Bootloader)
    *   **AP** (Application Processor)
    *   **CP** (Modem/Phone)
    *   **CSC** (Consumer Software Customization)
    *   **UMS** (USB Mass Storage - less common in modern devices)
*   **`.tar.md5` Integrity Verification**: Verifies the integrity of `.tar.md5` firmware archives using **Crypto++**.
*   **Streaming Flash Support**: Efficient flashing for various image types:
    *   Raw images
    *   **LZ4-compressed images** (for faster transfers)
*   **Per-file Flashing Progress Reporting**: Provides detailed progress for each file being flashed.
*   **Transfer Statistics**: Displays real-time statistics including size, elapsed time, and average speed.
*   **Persistent Log File**: Generates a `odin4.log` file for post-operation analysis and debugging.
*   **Sequential Multi-device Flashing**: Supports flashing multiple devices sequentially when no specific device is targeted with `-d`.
*   **Safe Dry-run Mode**: The `--check-only` option allows validation of PIT and archives without performing any actual flashing, ensuring safety.

## Safety and Validation

odin4 prioritizes device safety by enforcing strict checks before any write operations:

*   **Firmware Integrity Verification**: Ensures the firmware is not corrupted or tampered with.
*   **Partition Name Validation against PIT**: Prevents flashing incorrect partitions to the wrong locations.
*   **Device Model Compatibility Check**: Verifies that the firmware is compatible with the connected device model.
*   **Explicit Flashing Control Flow**: Requires clear commands for flashing, reducing accidental operations.
*   **Optional Dry-run Execution**: Allows users to simulate the flashing process for validation without risk.

The tool is designed to be non-destructive and explicitly avoids high-risk operations such as NAND erase or forced repartitioning, which could lead to irreversible device damage.

## Getting Started

To use odin4, you will need to build it from source on your Linux system.

### Dependencies

Ensure you have the following packages installed on your system:

```bash
sudo apt-get update
sudo apt-get install -y cmake ninja-build zip make pkg-config g++ libusb-1.0-0-dev libcrypto++-dev
```

### Building from Source

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/Llucs/odin4.git
    cd odin4
    ```
2.  **Compile the project**:
    ```bash
    cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
    cmake --build build --parallel $(nproc)
    ```

Upon successful compilation, the `odin4` executable will be located in the `build/` directory.

## Usage

The `odin4` tool is operated via the command line. Here are the available options and common usage examples.

### Command-Line Options

```
Usage: odin4 [options]
Samsung firmware flashing tool for Linux. Version: 5.0.4-40a0096

Options:
  -h                  Show this help message
  -v                  Show version
  -w                  Show license
  -l                  List detected Download Mode devices
  -d <path>            Select a specific USB device path (e.g. /dev/bus/usb/001/002)
  -b <file>            Bootloader archive (.tar or .tar.md5)
  -a <file>            AP archive (.tar or .tar.md5)
  -c <file>            CP archive (.tar or .tar.md5)
  -s <file>            CSC archive (.tar or .tar.md5)
  -u <file>            UMS archive (.tar or .tar.md5)
  --check-only         Validate PIT + archives and exit without flashing
  --allow-unknown      Allow archive entries without a PIT match (disabled by default)
  --reboot             Reboot device after flashing
  --redownload         Reboot into download mode if supported

Logging:
  --quiet              Only print errors
  --verbose            More detailed logs
  --debug              Debug logs (includes USB packet hexdumps)

USB selection overrides (optional):
  --vid <hex>          Override USB vendor ID (hex, e.g. 04e8)
  --pid <hex>          Override USB product ID (hex)
  --usb-interface <n>  Force a specific USB interface number
```

### Examples

*   **List devices in Download Mode**:
    ```bash
    ./build/odin4 -l
    ```

*   **Flash firmware (all components)**:
    ```bash
    ./build/odin4 \ 
      -b BL_XXXX.tar.md5 \ 
      -a AP_XXXX.tar.md5 \ 
      -c CP_XXXX.tar.md5 \ 
      -s CSC_XXXX.tar.md5
    ```

*   **Flash a specific device with selected components**:
    ```bash
    ./build/odin4 -d /dev/bus/usb/001/002 \ 
      -b BL_XXXX.tar.md5 \ 
      -a AP_XXXX.tar.md5
    ```

*   **Perform a dry-run (validation only)**:
    ```bash
    ./build/odin4 --check-only \ 
      -b BL_XXXX.tar.md5 \ 
      -a AP_XXXX.tar.md5
    ```

*   **Reboot device after flashing**:
    ```bash
    ./build/odin4 --reboot \ 
      -b BL_XXXX.tar.md5 \ 
      -a AP_XXXX.tar.md5
    ```

## Linux USB Permissions

If odin4 reports `LIBUSB_ERROR_ACCESS` during operation, it indicates a permission issue with accessing USB devices. To resolve this, you need to install the udev rule provided with this repository:

1.  **Copy the udev rule**: Copy `udev/60-odin4.rules` to `/etc/udev/rules.d/60-odin4.rules`.
    ```bash
    sudo cp udev/60-odin4.rules /etc/udev/rules.d/60-odin4.rules
    ```
2.  **Reload udev rules**: Inform the system about the new rule.
    ```bash
    sudo udevadm control --reload-rules
    sudo udevadm trigger
    ```
3.  **Reconnect your device**: Unplug and then re-plug your Samsung device (in Download Mode) to apply the new permissions.

This rule specifically targets known Samsung Download Mode USB Vendor IDs (`04e8`) and Product IDs (`6601`, `685d`, `68c3`) to grant appropriate access.

## Project Status

The odin4 project is actively maintained and developed with a production-oriented mindset. Its core components, including protocol behavior, validation logic, and firmware handling, are implemented with a strong focus on correctness and reliability. Future improvements will continue to concentrate on refinement, handling of edge cases, and ensuring long-term stability.

## Contributing

We welcome and encourage contributions from the community. Please refer to our [CONTRIBUTING.md](CONTRIBUTING.md) guide for detailed information on how to get involved, report bugs, suggest features, and submit pull requests.

## License

odin4 is licensed under the **Apache License 2.0**.

See the `LICENSE` file for full details.

## Disclaimer

Flashing firmware always carries inherent risks. This tool is provided **as-is**, without any warranties of any kind, express or implied. The developers are not responsible for any damage or loss of data that may occur from its use. Use at your own responsibility.

© 2026 Llucs
