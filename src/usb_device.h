#ifndef USB_DEVICE_H
#define USB_DEVICE_H

#include <string>
#include <vector>
#include <array>
#include <istream>
#include <libusb.h>
#include "odin_types.h"
#include "thor_protocol.h"

#include "logger.h"

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

    size_t max_chunk_bytes = 1048576;
    uint16_t endpoint_out_max_packet = 512;

    // Stores the device type string returned during the THOR protocol handshake.
    std::string device_type_str;


enum class ProtocolMode {
    Thor,
    OdinLegacy
};

ProtocolMode protocol_mode = ProtocolMode::Thor;

int odin_flash_timeout_ms = 120000;
int odin_flash_packet_size = 1048576;
int odin_flash_sequence_count = 30;
bool odin_supports_zlp = true;

bool odin_legacy_handshake();
bool odin_begin_session();
bool odin_end_session();
bool odin_reboot();
bool odin_set_total_bytes(uint64_t total_bytes);
bool odin_reset_flash_count();
bool odin_request_file_flash();
bool odin_request_sequence_flash(uint32_t aligned_size);
bool odin_send_file_part_and_ack(const unsigned char* data, size_t size, uint32_t expected_index);
bool odin_end_sequence_flash(const PitEntry& pit_entry, uint32_t real_size, uint32_t is_last);
bool odin_send_pit(const std::vector<unsigned char>& pit);
bool odin_dump_pit(std::vector<unsigned char>& pit_out);
bool odin_command(uint32_t cmd, uint32_t subcmd, const void* payload, size_t payload_size, std::vector<unsigned char>& rsp, int timeout_ms);
bool odin_fail_check(const std::vector<unsigned char>& rsp, const std::string& context, bool allow_progress);

    bool bulk_write_all(const void* data, size_t size, int timeout_ms);
    bool bulk_read_once(void* data, size_t size, int* actual_length, int timeout_ms);

public:
    UsbDevice() = default;
    ~UsbDevice();

    bool open_device(const std::string& specific_path = "");
    bool send_packet(const void *data, size_t size, bool is_control = false);
    bool receive_packet(void *data, size_t size, int *actual_length, bool is_control = false, size_t min_size = 0, int timeout_override_ms = 0);
    bool handshake();
    bool is_odin_legacy() const { return protocol_mode == ProtocolMode::OdinLegacy; }
    bool request_device_type();
    bool begin_session();
    bool end_session();
    bool request_pit();
    bool receive_pit_table(PitTable& pit_table);
    bool flash_partition_stream(std::istream& stream, uint64_t size, const PitEntry& pit_entry, bool large_partition);
    bool send_file_part_chunk(const void* data, size_t size, uint32_t chunk_index, bool large_partition = false);
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
