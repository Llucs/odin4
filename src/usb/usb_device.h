#ifndef USB_DEVICE_H
#define USB_DEVICE_H

#include <string>
#include <vector>
#include <array>
#include <istream>
#include <libusb.h>
#include "core/odin_types.h"
#include "protocol/thor_protocol.h"
#include "core/logger.h"

#define SAMSUNG_VID 0x04E8
#define USB_RETRY_COUNT 5
#define USB_TIMEOUT_BULK 120000
#define USB_TIMEOUT_CONTROL 10000

static constexpr std::array<uint16_t, 6> SAMSUNG_DOWNLOAD_PIDS{{0x6601, 0x685D, 0x68C3, 0x68EF, 0x4EEE, 0x4EEF}};

struct UsbSelectionCriteria {
    bool has_vid = false;
    uint16_t vid = 0;
    bool has_pid = false;
    uint16_t pid = 0;
    bool has_interface = false;
    int interface_number = 0;
};

enum class UsbOpenError { None, NoDevice, NotDownloadMode, AccessDenied, Busy, Other };

class UsbDevice {
  private:
    libusb_device_handle* handle = nullptr;
    libusb_device** device_list = nullptr;

    uint8_t endpoint_out = 0x01;
    uint8_t endpoint_in = 0x81;
    int interface_number = 0;
    int alt_setting = -1;
    bool kernel_driver_detached = false;

    size_t max_chunk_bytes = 1048576;
    uint16_t endpoint_out_max_packet = 512;

    std::string device_type_str;
    UsbOpenError last_open_error = UsbOpenError::None;
    int last_open_libusb_err = 0;

    int odin_flash_timeout_ms = 180000;
    int odin_flash_packet_size = 1048576;
    int odin_flash_sequence_count = 30;
    bool odin_supports_zlp = true;
    bool odin_supports_compressed = false;

    auto odin_handshake() -> bool;
    auto odin_begin_session() -> bool;
    auto odin_end_session() -> bool;
    auto odin_reboot() -> bool;
    auto odin_reboot_to_odin() -> bool;
    auto odin_request_device_type(std::string& out_type) -> bool;
    auto odin_set_total_bytes(uint64_t total_bytes) -> bool;
    auto odin_reset_flash_count() -> bool;
    auto odin_request_file_flash() -> bool;
    auto odin_request_sequence_flash(uint32_t aligned_size) -> bool;
    auto odin_send_file_part_and_ack(const unsigned char* data, size_t size, uint32_t expected_index) -> bool;
    auto odin_end_sequence_flash(const PitEntry& pit_entry, uint32_t real_size, uint32_t is_last,
                                 bool efs_clear = false, bool boot_update = false) -> bool;

    auto odin_request_file_flash_compressed() -> bool;
    auto odin_request_sequence_flash_compressed(uint32_t compressed_size) -> bool;
    auto odin_end_sequence_flash_compressed(const PitEntry& pit_entry, uint32_t compressed_size, uint32_t is_last,
                                            bool efs_clear = false, bool boot_update = false) -> bool;

    auto odin_dump_pit(std::vector<unsigned char>& pit_out) -> bool;
    auto build_lz4_decompressed_index(std::istream& stream, uint64_t compressed_size,
                                      std::vector<std::pair<uint64_t,uint64_t>>& index) -> bool;
    auto odin_command(uint32_t cmd, uint32_t subcmd, const void* payload, size_t payload_size,
                      std::vector<unsigned char>& rsp, int timeout_ms) -> bool;
    static auto odin_fail_check(const std::vector<unsigned char>& rsp, const std::string& context,
                                bool allow_progress, int32_t expected_id = -1) -> bool;

    auto bulk_write_all(const void* data, size_t size, int timeout_ms) -> bool;
    auto bulk_read_once(void* data, size_t size, int* actual_length, int timeout_ms) -> bool;
    auto send_zlp(int timeout_ms) -> bool;
    auto send_empty_transfer() -> bool;
    auto receive_empty_transfer() -> bool;

  public:
    UsbDevice() = default;
    ~UsbDevice();

    auto open_device(const std::string& specific_path = "") -> bool;
    auto open_device(const std::string& specific_path, const UsbSelectionCriteria& criteria) -> bool;

    [[nodiscard]] auto get_last_open_error() const -> UsbOpenError { return last_open_error; }
    [[nodiscard]] auto get_last_open_libusb_error() const -> int { return last_open_libusb_err; }

    auto send_packet(const void* data, size_t size, bool is_control = false) -> bool;
    auto receive_packet(void* data, size_t size, int* actual_length, bool is_control = false, size_t min_size = 0,
                        int timeout_override_ms = 0) -> bool;
    auto handshake() -> bool;
    auto request_device_type() -> bool;
    auto begin_session() -> bool;
    auto end_session() -> bool;
    auto request_pit(PitTable& pit_table) -> bool;
    auto receive_pit_table(PitTable& pit_table) -> bool;
    auto flash_partition_stream(std::istream& stream, uint64_t size, const PitEntry& pit_entry,
                                bool large_partition, bool efs_clear = false, bool boot_update = false) -> bool;
    auto flash_partition_stream_compressed(std::istream& stream, uint64_t compressed_size, const PitEntry& pit_entry,
                                           bool large_partition, bool efs_clear = false, bool boot_update = false) -> bool;
    auto end_file_transfer(uint32_t partition_id) -> bool;
    auto send_control(uint32_t control_type) -> bool;
    auto notify_total_bytes(uint64_t total) -> bool;

    [[nodiscard]] auto get_device_type() const -> const std::string& { return device_type_str; }
    [[nodiscard]] auto supports_compressed() const -> bool { return odin_supports_compressed; }

    static auto list_download_devices() -> std::vector<std::string>;
    static auto list_download_devices(const UsbSelectionCriteria& criteria) -> std::vector<std::string>;
};

#endif // USB_DEVICE_H
