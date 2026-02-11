<p align="center">
<img width="150" src="./logo.png" align="left"
</p>

# odin4 (WIP)
[Licensed under the Apache License 2.0](LICENSE)


[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Build](https://img.shields.io/badge/Build-GitHub%20Actions-2ea44f.svg)](../../actions)
[![Platform](https://img.shields.io/badge/Platform-Linux-informational.svg)](#)
[![Language](https://img.shields.io/badge/Language-C%2FC%2B%2B-blue.svg)](#)

**odin4** is an open-source Samsung firmware flashing tool for Linux, based on the original **odin4** project for Linux and **Thor USB protocol**.

It aims to be a modern alternative to the original Odin for Windows, with a focus on stability, clean code, correct protocol implementation, and proper logging.

---

## Features
- Samsung **Download Mode** detection via **libusb**
- **Thor protocol** implementation
- Flash support for standard Samsung firmware packages:
  - **BL**
  - **AP**
  - **CP**
  - **CSC**
  - **UMS**
- **.tar.md5** integrity verification (Crypto++)
- Streaming flash support for:
  - raw images
  - **LZ4-compressed images**
- Automatic PIT retrieval and parsing
- Console output + persistent log file (`odin4.log`)
- Per-file flashing progress reporting
- Sequential multi-device flashing when `-d` is not provided

---

## Project Status
This project is under active development.

The tool is already functional and has received major improvements in protocol reliability, firmware parsing, Crypto++ migration, and overall stability.

However, there may still be remaining edge cases depending on device model, firmware format variations, and host environment differences.

---

## Build (Linux)

### Dependencies
```bash
sudo apt-get update
sudo apt-get install -y   cmake ninja-build zip make pkg-config g++   libusb-1.0-0-dev libcrypto++-dev
```

### Build
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

### Flash a firmware set
```bash
./build/odin4   -b BL_XXXX.tar.md5   -a AP_XXXX.tar.md5   -c CP_XXXX.tar.md5   -s CSC_XXXX.tar.md5
```

### Flash a specific device
```bash
./build/odin4   -d /dev/bus/usb/001/002   -b BL_XXXX.tar.md5   -a AP_XXXX.tar.md5   -c CP_XXXX.tar.md5   -s CSC_XXXX.tar.md5
```

### Reboot after flashing
```bash
./build/odin4 --reboot -b BL_XXXX.tar.md5 -a AP_XXXX.tar.md5
```

---

## Linux USB Permissions (udev rule)

To allow access to Samsung devices in Download Mode, create:

```bash
sudo nano /etc/udev/rules.d/51-android.rules
```

Add this line:

```bash
SUBSYSTEM=="usb", ATTR{idVendor}=="04e8", MODE="0666", GROUP="plugdev"
```

Reload rules:

```bash
sudo udevadm control --reload-rules
sudo udevadm trigger
```

Unplug and reconnect the device.

---

## Contributing
Contributions are welcome.

If you have experience with **C/C++**, **libusb**, **Crypto++**, or reverse engineering, feel free to open issues or submit pull requests.

---

## License
Licensed under the **Apache License 2.0**.  
See the `LICENSE` file for details.

---

## Disclaimer
This tool is provided **as-is**.  
Flashing firmware always carries risks, including permanent device damage.

Use at your own risk.  
The author(s) are not responsible for any damage, data loss, or device bricking.
