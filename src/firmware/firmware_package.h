#ifndef FIRMWARE_PACKAGE_H
#define FIRMWARE_PACKAGE_H

#include <string>
#include <fstream>
#include "core/odin_types.h"
#include "usb/usb_device.h"

auto sanitize_filename(const std::string& filename) -> std::string;
auto check_md5_signature(const std::string& file_path) -> bool;

auto decompress_lz4_to_file(std::ifstream& file, uint64_t compressed_size, const std::string& out_path) -> bool;

auto process_tar_file(const std::string& tar_path, UsbDevice& usb_device, const PitTable& pit_table,
                      bool do_flash = true, bool allow_unknown = false) -> ExitCode;

#endif // FIRMWARE_PACKAGE_H
