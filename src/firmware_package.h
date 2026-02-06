#ifndef FIRMWARE_PACKAGE_H
#define FIRMWARE_PACKAGE_H

#include <string>
#include <fstream>
#include "odin_types.h"
#include "usb_device.h"

// Utility functions
std::string sanitize_filename(const std::string& filename);
bool check_md5_signature(const std::string& file_path);

// Firmware processing functions
bool process_lz4_streaming(std::ifstream& file, uint64_t compressed_size, UsbDevice& usb_device, const std::string& filename, bool large_partition = false);
bool process_tar_file(const std::string& tar_path, UsbDevice& usb_device, const PitTable& pit_table);

#endif // FIRMWARE_PACKAGE_H
