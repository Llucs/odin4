#ifndef FIRMWARE_PACKAGE_H
#define FIRMWARE_PACKAGE_H

#include <string>
#include <fstream>
#include "core/odin_types.h"
#include "usb/usb_device.h"

// Utility functions
auto sanitize_filename(const std::string& filename) -> std::string;
auto check_md5_signature(const std::string& file_path) -> bool;

// Firmware processing functions
// Stream and optionally flash an LZ4-compressed partition. When do_flash
// is false, the data will be decompressed and verified but not sent to the
// device. The large_partition flag controls chunk size handling for very
// large partitions (e.g. SYSTEM, USERDATA, SUPER).
auto process_lz4_streaming(std::ifstream& file, uint64_t compressed_size, UsbDevice& usb_device,
                           const std::string& filename, bool large_partition = false, bool do_flash = true) -> bool;

// Process a TAR archive containing firmware images. For each entry, the
// function validates the presence of a matching partition in the PIT table,
// checks the MD5 signature, and either flashes the content or performs a
// dry-run depending on the do_flash flag. If a file in the TAR does not
// match any PIT entry, the function reports an error instead of silently
// skipping it.
auto process_tar_file(const std::string& tar_path, UsbDevice& usb_device, const PitTable& pit_table,
                      bool do_flash = true, bool allow_unknown = false) -> ExitCode;

#endif // FIRMWARE_PACKAGE_H
