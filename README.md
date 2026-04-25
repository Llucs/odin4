<p align="center">
  <img src="./logo.png" width="160" alt="odin4 logo">
</p>

<h1 align="center">odin4</h1>

<p align="center">
  <b>The Definitive Samsung Firmware Flashing Tool for Linux</b>
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

## Why odin4?

**odin4** is not just another open-source reimplementation. While other tools (like Heimdall or Galaxy Flasher) are based on reverse-engineered legacy protocols or Windows-based sniffing, **odin4** is built upon the **leaked internal Samsung Linux binary**.

This unique foundation allows odin4 to implement the **undocumented "Odin4-Stream" protocol**—the same high-performance, factory-grade method used by Samsung's own internal engineering tools.

### The "Odin4-Stream" Advantage:
*   **Factory-Grade Stability:** Implements the internal double-ACK handshake for every data chunk, ensuring zero corruption even at maximum speeds.
*   **Maximum Throughput:** Optimized for high-speed data streaming, outperforming standard Thor implementations.
*   **Native Parity:** The only open-source tool that communicates with your device exactly like Samsung's official factory software.
*   **Modern Device Support:** Specifically tuned for modern Samsung SOCs and large partitions (SUPER, USERDATA).

---

## Core Features

*   **Native Thor Protocol Implementation:** A clean, C++17 implementation of the internal Samsung protocol.
*   **Streaming LZ4 Decompression:** Flashes compressed images on-the-fly, saving time and disk space without exhausting RAM.
*   **Automatic PIT Management:** Retrieves and parses the Partition Information Table (PIT) automatically to ensure partition alignment.
*   **Strict Safety Validation:** Comprehensive checks for MD5 integrity, partition names, and device model compatibility before any write operation.
*   **Persistent Logging:** Generates `odin4.log` for professional-grade diagnostic and post-operation analysis.
*   **Dry-run Mode:** Use `--check-only` to validate your firmware and device compatibility without touching the NAND.

---

## Getting Started

### Dependencies

```bash
sudo apt-get update
sudo apt-get install -y cmake ninja-build zip make pkg-config g++ libusb-1.0-0-dev libcrypto++-dev
```

### Building from Source

```bash
git clone https://github.com/Llucs/odin4.git
cd odin4
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel $(nproc)
```

The `odin4` executable will be located in the `build/` directory.

---

## Usage

### Common Examples

*   **Flash Full Firmware (BL, AP, CP, CSC):**
    ```bash
    ./build/odin4 \
      -b BL_XXXX.tar.md5 \
      -a AP_XXXX.tar.md5 \
      -c CP_XXXX.tar.md5 \
      -s CSC_XXXX.tar.md5
    ```

*   **Flash and Reboot Automatically:**
    ```bash
    ./build/odin4 --reboot -a AP_XXXX.tar.md5
    ```

*   **Dry-run (Safety Check):**
    ```bash
    ./build/odin4 --check-only -a AP_XXXX.tar.md5
    ```

---

## Linux USB Permissions

If you encounter `LIBUSB_ERROR_ACCESS`, install the provided udev rule:

```bash
sudo cp udev/60-odin4.rules /etc/udev/rules.d/60-odin4.rules
sudo udevadm control --reload-rules && sudo udevadm trigger
```

---

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for our development standards and pull request process.

## License

Licensed under the **Apache License 2.0**. See `LICENSE` for details.

## Disclaimer

Flashing firmware carries inherent risks. This tool is provided **as-is**. The developers are not responsible for any damage to your device. Use at your own risk.

© 2026 Llucs
