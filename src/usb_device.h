#ifndef USB_DEVICE_H
#define USB_DEVICE_H

#include <string>
#include <vector>
#include <array>
#include <libusb.h>
#include "odin_types.h"
#include "thor_protocol.h"

// Forward declarations for logging functions used by UsbDevice
void log_info(const std::string& msg);
void log_error(const std::string& msg, int libusb_err = 0);
void log_hexdump(const std::string& title, const void* data, size_t size);

// Constants used by UsbDevice
#define SAMSUNG_VID 0x04E8
#define USB_RETRY_COUNT 3
#define USB_TIMEOUT_BULK 60000
#define USB_TIMEOUT_CONTROL 5000

// List of known Samsung USB product IDs for devices in download mode.
// Centralising this list avoids duplication across different translation units.
static constexpr std::array<uint16_t, 5> SAMSUNG_DOWNLOAD_PIDS{{0x685D, 0x6600, 0x6860, 0x6861, 0x6862}};

class UsbDevice {
private:
    libusb_device_handle *handle = nullptr;
    libusb_device **device_list = nullptr;

    uint8_t endpoint_out = 0x01;
    uint8_t endpoint_in = 0x81;
    int interface_number = 0;

    // Stores the device type string returned during the THOR protocol handshake.
    std::string device_type_str;

public:
    UsbDevice() = default;
    ~UsbDevice();

    bool open_device(const std::string& specific_path = "");
    bool send_packet(const void *data, size_t size, bool is_control = false);
    bool receive_packet(void *data, size_t size, int *actual_length, bool is_control = false);
    bool handshake();
    bool request_device_type();
    bool begin_session();
    bool end_session();
    bool request_pit();
    bool receive_pit_table(PitTable& pit_table);
    bool send_file_part_chunk(const void* data, size_t size, bool large_partition = false);
    bool send_file_part_header(uint64_t total_size);
    bool end_file_transfer(uint32_t partition_id);
    bool send_control(uint32_t control_type);

    // Return the device type string obtained via request_device_type().
    // The returned reference remains valid for the lifetime of the UsbDevice instance.
    const std::string& get_device_type() const { return device_type_str; }

    // Enumerate all Samsung devices currently in download mode. The returned
    // vector contains the device path strings (e.g. "/dev/bus/usb/001/002").
    // This does not require opening any devices.
    static std::vector<std::string> list_download_devices();
};

#endif // USB_DEVICE_H
