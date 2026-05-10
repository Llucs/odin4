# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [5.2.0] - 2026-05-10

### Added
- Multi-platform support (Windows, macOS, Linux).
- Updated CMake for cross-platform builds.
- GitHub Actions CI for Windows (x64), macOS (Universal), and Linux (x86_64, arm64).
- Portable USB device identification (bus:address format) with legacy Linux path compatibility.

### Changed
- Refactored USB device identification to be platform-agnostic while maintaining support for `/dev/bus/usb/` paths.
- Updated CLI help text with multi-platform instructions.
- Incremented version to 5.2.0.

## [5.1.0] - 2026-05-03

### Fixed
- **Odin legacy protocol: incorrect field in EndSequenceFlash packet** — The `unknown1` field was incorrectly set to `binary_type` instead of `0` for Communication Processor (modem) partitions. This caused a protocol mismatch compared to the reference Heimdall implementation and could cause flashing failures on certain bootloaders.
- **Odin legacy protocol: missing TotalBytes notification** — The TotalBytes packet (`cmd 0x64, sub 0x02`) was never sent before flashing in Odin legacy mode, unlike the reference Heimdall implementation. Some bootloaders require this notification to properly allocate resources for the transfer.
- **Odin legacy protocol: per-file TotalBytes override** — `send_file_part_header` was calling `odin_set_total_bytes` per file in legacy mode, potentially overwriting the global total. This is now a no-op for legacy mode since the global total is sent once before flashing begins.
- **Missing log file initialization** — `set_log_file("odin4.log")` was never called despite the README advertising persistent log file generation.
- **Missing firmware file existence validation** — Firmware files specified via `-b`, `-a`, `-c`, `-s`, `-u` were not validated for existence before attempting USB operations, leading to late and confusing errors.
- **Firmware compatibility false positives** — `verify_firmware_compatibility` had an overly broad matching heuristic (`dt.find(f)`) that could produce false positives when filenames were shorter than the device type string.
- **Silent success for unsupported redownload in Odin legacy mode** — `send_control(THOR_CONTROL_REDOWNLOAD)` in legacy mode silently returned `true` without warning. A warning is now logged.
- **Uninitialized PitTable struct members** — `PitTable` struct members were not default-initialized, risking undefined behavior if accessed before being populated by `parse_pit_bytes`.

### Added
- Progress reporting for raw (non-LZ4) partition flashing in Thor mode.
- CHANGELOG.md for tracking changes across releases.

### Removed
- Dead `odin_send_pit` function declaration (declared in header but never defined or called).

### Changed
- Reorganized `src/` directory into modules: `core/`, `protocol/`, `usb/`, `firmware/` for better code organization and maintainability.
- Version updated to 5.1.0.

## [5.0.5] - Previous Release

Initial tracked release.
