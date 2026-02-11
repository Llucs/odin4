<p align="center">
  <img src="./logo.png" width="160" alt="odin4 logo">
</p>

<h1 align="center">odin4</h1>

<p align="center">
  Modern Samsung firmware flashing tool for Linux
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg"></a>
  <a href="../../actions"><img src="https://img.shields.io/badge/Build-GitHub%20Actions-2ea44f.svg"></a>
  <img src="https://img.shields.io/badge/Platform-Linux-informational.svg">
  <img src="https://img.shields.io/badge/Language-C%2FC%2B%2B-blue.svg">
  <img src="https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/Llucs/odin4/main/version.json">
</p>

---

## Overview

**odin4** is a modern Samsung firmware flashing tool for Linux built around a clean and correct implementation of the Thor USB protocol.

The project focuses on:

- Correct protocol behavior
- Strong validation before flashing
- Structured logging
- Deterministic and safe flashing logic
- Clean and maintainable C++ code

It is designed as a serious Linux-native alternative for Samsung firmware flashing workflows.

---

## Core Features

- Samsung **Download Mode** detection via `libusb`
- Native **Thor protocol** implementation
- Automatic **PIT retrieval and parsing**
- Strict partition validation against PIT
- Support for standard Samsung firmware packages:
  - **BL**
  - **AP**
  - **CP**
  - **CSC**
  - **UMS**
- `.tar.md5` integrity verification using **Crypto++**
- Streaming flash support for:
  - Raw images
  - **LZ4-compressed images**
- Per-file flashing progress reporting
- Transfer statistics (size, elapsed time, average speed)
- Persistent log file (`odin4.log`)
- Sequential multi-device flashing when `-d` is not specified
- Safe **dry-run mode** (`--check-only`) for validation without flashing

---

## Safety and Validation

odin4 enforces strict checks before writing to the device:

- Firmware integrity verification
- Partition name validation against PIT
- Device model compatibility check
- Explicit flashing control flow
- Optional dry-run execution

The tool does not implement destructive or high-risk operations such as NAND erase or forced repartitioning.

---

## Build (Linux)

### Dependencies

```bash
sudo apt-get update
sudo apt-get install -y   cmake ninja-build zip make pkg-config g++   libusb-1.0-0-dev libcrypto++-dev
```

### Compile

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel $(nproc)
```

Binary output:

```bash
build/odin4
```

---

## Usage

### List devices in Download Mode

```bash
./build/odin4 -l
```

### Flash firmware

```bash
./build/odin4   -b BL_XXXX.tar.md5   -a AP_XXXX.tar.md5   -c CP_XXXX.tar.md5   -s CSC_XXXX.tar.md5
```

### Flash a specific device

```bash
./build/odin4   -d /dev/bus/usb/001/002   -b BL_XXXX.tar.md5   -a AP_XXXX.tar.md5
```

### Dry-run (validation only)

```bash
./build/odin4 --check-only   -b BL_XXXX.tar.md5   -a AP_XXXX.tar.md5
```

### Reboot after flashing

```bash
./build/odin4 --reboot   -b BL_XXXX.tar.md5   -a AP_XXXX.tar.md5
```

---

## Linux USB Permissions

To allow access to Samsung devices in Download Mode, create:

```bash
sudo nano /etc/udev/rules.d/51-android.rules
```

Add:

```bash
SUBSYSTEM=="usb", ATTR{idVendor}=="04e8", MODE="0666", GROUP="plugdev"
```

Reload rules:

```bash
sudo udevadm control --reload-rules
sudo udevadm trigger
```

Reconnect the device afterward.

---

## Project Status

The project is actively maintained and production-oriented.

Core protocol behavior, validation logic, and firmware handling are implemented with a focus on correctness and reliability.

Further improvements focus on refinement, edge-case handling, and long-term stability.

---

## Contributing

Contributions are welcome.

Areas of interest:

- libusb improvements
- Protocol robustness
- Testing and validation
- Performance refinement
- Documentation

---

## License

Licensed under the **Apache License 2.0**.

See the `LICENSE` file for full details.

---

## Disclaimer

Flashing firmware always carries risk.

This tool is provided **as-is**, without warranties of any kind.

Use at your own responsibility.

---

© 2026 Llucs
