#include "usb/usb_device.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <vector>
#include <algorithm>
#include <unordered_set>
#include <limits>
#include <format>
#include <libusb.h>
#include "core/odin_types.h"
#include "protocol/thor_protocol.h"
#include "core/logger.h"

#include <lz4frame.h>

namespace {

constexpr std::array<unsigned char, 4> kLz4Magic{{0x04, 0x22, 0x4D, 0x18}};

struct Lz4FrameInfo {
    uint64_t content_size = 0;
    bool valid = false;
};

auto read_exact_from_stream(std::istream& s, void* buf, size_t len) -> bool {
    s.read(static_cast<char*>(buf), static_cast<std::streamsize>(len));
    return static_cast<size_t>(s.gcount()) == len;
}

auto parse_lz4_frame_header(std::istream& stream) -> Lz4FrameInfo {
    Lz4FrameInfo info;

    std::array<unsigned char, 4> magic{};
    if (!read_exact_from_stream(stream, magic.data(), magic.size()))
        return info;
    if (magic != kLz4Magic)
        return info;

    unsigned char flg_bd[2]{};
    if (!read_exact_from_stream(stream, flg_bd, 2))
        return info;

    unsigned char flg = flg_bd[0];
    unsigned char bd = flg_bd[1];

    unsigned char version = (flg >> 6) & 0x03;
    if (version != 1) return info;

    bool block_independence = (flg & 0x20) != 0;
    bool block_checksum = (flg & 0x10) != 0;
    bool has_content_size = (flg & 0x08) != 0;
    bool has_dict_id = (flg & 0x01) != 0;

    if (!block_independence) return info;
    if (block_checksum) return info;
    if (has_dict_id) return info;
    if (!has_content_size) return info;

    unsigned char bd_val = (bd >> 4) & 0x07;
    static constexpr size_t block_sizes[] = {0, 0, 0, 0, 65536, 262144, 1048576, 4194304};
    size_t max_block_size = (bd_val < 8) ? block_sizes[bd_val] : 0;
    if (max_block_size == 0) return info;
    if (max_block_size > 1048576) return info;

    unsigned char content_size_bytes[8]{};
    if (!read_exact_from_stream(stream, content_size_bytes, 8))
        return info;

    uint64_t cs = 0;
    std::memcpy(&cs, content_size_bytes, 8);
    info.content_size = cs;

    if (info.content_size > max_block_size)
        return info;

    unsigned char hc{};
    if (!read_exact_from_stream(stream, &hc, 1))
        return info;

    info.valid = true;
    return info;
}

} // anonymous namespace

auto UsbDevice::begin_session() -> bool {
    return odin_begin_session();
}

auto UsbDevice::end_session() -> bool {
    return odin_end_session();
}

static auto parse_pit_bytes(PitTable& pit_table, const std::vector<unsigned char>& pit_data) -> bool {
    if (pit_data.size() < 28) {
        log_error(std::format("PIT data too small: {}", pit_data.size()));
        return false;
    }

    auto read_u32 = [&](size_t off) -> uint32_t {
        uint32_t v = 0;
        std::memcpy(&v, pit_data.data() + off, sizeof(v));
        return le32_to_h(v);
    };
    auto read_u16 = [&](size_t off) -> uint16_t {
        uint16_t v = 0;
        std::memcpy(&v, pit_data.data() + off, sizeof(v));
        return static_cast<uint16_t>(le16toh(v));
    };

    const uint32_t file_id = read_u32(0);
    if (file_id != 0x12349876) {
        std::ostringstream oss;
        oss << std::hex << file_id;
        log_error("PIT file identifier mismatch: 0x" + oss.str());
        return false;
    }

    pit_table.entry_count = read_u32(4);
    if (pit_table.entry_count == 0 || pit_table.entry_count > 512) {
        log_error(std::format("Invalid PIT entry count: {}", pit_table.entry_count));
        return false;
    }

    std::memcpy(pit_table.com_tar2, pit_data.data() + 8, 8);
    std::memcpy(pit_table.cpu_bl_id, pit_data.data() + 16, 8);
    pit_table.lu_count = read_u16(24);
    pit_table.reserved = read_u16(26);

    pit_table.header_size = 28;
    const size_t entry_size = 132;
    const size_t required = pit_table.header_size + static_cast<size_t>(pit_table.entry_count) * entry_size;
    if (pit_data.size() < required) {
        log_error(std::format("PIT truncated: expected at least {} bytes", required));
        return false;
    }

    pit_table.entries.clear();
    pit_table.entries.reserve(pit_table.entry_count);

    auto extract_field = [](const char* field, size_t max_len) -> std::string {
        size_t n = 0;
        while (n < max_len && field[n] != '\0') ++n;
        std::string s(field, n);
        while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.pop_back();
        return s;
    };

    auto is_valid_pit_string = [](const std::string& s) -> bool {
        for (unsigned char c : s) {
            if (c < 0x20 || c > 0x7E) return false;
            if (c == '/' || c == '\\') return false;
        }
        return true;
    };

    std::unordered_set<uint32_t> seen_identifiers;

    for (uint32_t i = 0; i < pit_table.entry_count; ++i) {
        const size_t off = pit_table.header_size + static_cast<size_t>(i) * entry_size;
        PitEntry e = {};
        e.binary_type = read_u32(off + 0);
        e.device_type = read_u32(off + 4);
        e.identifier = read_u32(off + 8);
        e.attributes = read_u32(off + 12);
        e.update_attributes = read_u32(off + 16);
        e.block_size_or_offset = read_u32(off + 20);
        e.block_count = read_u32(off + 24);
        e.file_offset = read_u32(off + 28);
        e.file_size = read_u32(off + 32);
        std::memcpy(e.partition_name, pit_data.data() + off + 36, 32);
        std::memcpy(e.file_name, pit_data.data() + off + 68, 32);
        std::memcpy(e.fota_name, pit_data.data() + off + 100, 32);

        const std::string part_name = extract_field(e.partition_name, 32);
        const std::string file_name = extract_field(e.file_name, 32);

        if (part_name.empty()) {
            log_error(std::format("PIT entry {} has an empty partition name", i));
            return false;
        }
        if (!is_valid_pit_string(part_name)) {
            log_error(std::format("PIT entry {} has an invalid partition name: '{}'", i, part_name));
            return false;
        }
        if (!file_name.empty() && !is_valid_pit_string(file_name)) {
            log_error(std::format("PIT entry {} has an invalid file name: '{}'", i, file_name));
            return false;
        }

        if (e.identifier == 0) {
            log_error(std::format("PIT entry {} has an invalid identifier (0)", i));
            return false;
        }
        if (!seen_identifiers.insert(e.identifier).second) {
            log_error(std::format("PIT contains duplicate partition identifier: {}", e.identifier));
            return false;
        }

        if (e.block_count != 0) {
            const auto a = static_cast<uint64_t>(e.block_size_or_offset);
            const auto b = static_cast<uint64_t>(e.block_count);
            const uint64_t prod = a * b;
            if (a != 0 && prod / a != b) {
                log_error(std::format("PIT entry {} has an overflow in block size/count", i));
                return false;
            }
        }

        pit_table.entries.push_back(e);
    }

    log_info(std::format("Received PIT entries: {}", pit_table.entry_count));
    return true;
}

auto UsbDevice::request_pit(PitTable& pit_table) -> bool {
    std::vector<unsigned char> pit;
    if (!odin_dump_pit(pit)) return false;
    return parse_pit_bytes(pit_table, pit);
}

auto UsbDevice::receive_pit_table(PitTable& pit_table) -> bool {
    return request_pit(pit_table);
}

auto UsbDevice::notify_total_bytes(uint64_t total) -> bool {
    return odin_set_total_bytes(total);
}

auto UsbDevice::end_file_transfer(uint32_t partition_id) -> bool {
    PitEntry dummy{};
    dummy.identifier = partition_id;
    dummy.binary_type = 0;
    dummy.device_type = 0;
    return odin_end_sequence_flash(dummy, 0, 1);
}

auto UsbDevice::send_control(uint32_t control_type) -> bool {
    if (control_type == ODIN_CONTROL_REBOOT) {
        return odin_reboot();
    }
    if (control_type == ODIN_CONTROL_REDOWNLOAD) {
        return odin_reboot_to_odin();
    }
    return true;
}

auto UsbDevice::odin_handshake() -> bool {
    const char preamble[4] = {'O', 'D', 'I', 'N'};
    if (!bulk_write_all(preamble, sizeof(preamble), USB_TIMEOUT_CONTROL)) return false;

    unsigned char reply[512] = {0};
    int actual = 0;
    if (!bulk_read_once(reply, sizeof(reply), &actual, USB_TIMEOUT_CONTROL)) return false;
    if (actual < 4) return false;
    if (reply[0] != 'L' || reply[1] != 'O' || reply[2] != 'K' || reply[3] != 'E') return false;
    return true;
}

auto UsbDevice::odin_command(uint32_t cmd, uint32_t subcmd, const void* payload, size_t payload_size,
                             std::vector<unsigned char>& rsp, int timeout_ms) -> bool {
    std::vector<unsigned char> buf(1024, 0);
    uint32_t le_cmd = h_to_le32(cmd);
    uint32_t le_sub = h_to_le32(subcmd);
    std::memcpy(buf.data() + 0, &le_cmd, sizeof(le_cmd));
    std::memcpy(buf.data() + 4, &le_sub, sizeof(le_sub));
    if (payload_size > 0) {
        if (8 + payload_size > buf.size()) {
            log_error("Odin command payload too large");
            return false;
        }
        std::memcpy(buf.data() + 8, payload, payload_size);
    }
    if (!bulk_write_all(buf.data(), buf.size(), USB_TIMEOUT_CONTROL)) return false;

    rsp.assign(512, 0);
    int read_len = 0;
    if (!bulk_read_once(rsp.data(), rsp.size(), &read_len, timeout_ms)) return false;
    if (read_len < 8) {
        log_error(std::format("Odin response size mismatch: {}", read_len));
        return false;
    }
    rsp.resize(read_len);
    return true;
}

auto UsbDevice::send_empty_transfer() -> bool {
    int actual = 0;
    int err = libusb_bulk_transfer(handle, endpoint_out, nullptr, 0, &actual, 100);
    if (err != 0) {
        log_verbose("Empty bulk transfer failed (non-fatal): " + std::to_string(err));
        return false;
    }
    return true;
}

auto UsbDevice::receive_empty_transfer() -> bool {
    int actual = 0;
    static unsigned char dummy;
    int err = libusb_bulk_transfer(handle, endpoint_in, &dummy, 1, &actual, 100);
    if (err != 0) {
        log_verbose("Empty bulk receive failed (non-fatal): " + std::to_string(err));
        return false;
    }
    if (actual != 0) {
        log_verbose(std::format("Empty bulk receive got {} bytes (unexpected)", actual));
        return false;
    }
    return true;
}

auto UsbDevice::odin_fail_check(const std::vector<unsigned char>& rsp, const std::string& context,
                                bool allow_progress, int32_t expected_id) -> bool {
    if (rsp.size() < 8) return false;

    int32_t id = 0;
    int32_t code = 0;
    std::memcpy(&id, rsp.data(), sizeof(id));
    std::memcpy(&code, rsp.data() + 4, sizeof(code));
    id = static_cast<int32_t>(le32toh(static_cast<uint32_t>(id)));
    code = static_cast<int32_t>(le32toh(static_cast<uint32_t>(code)));

    if (id == BOOTLOADER_FAIL) {
        log_error(std::format("{} failed with BOOTLOADER_FAIL (code={})", context, code));
        return false;
    }

    if (expected_id != -1 && id != expected_id) {
        log_error(std::format("{} failed: unexpected id 0x{:08X}, expected 0x{:08X}", context, id, expected_id));
        return false;
    }

    if (code < 0) {
        std::string suffix;
        if (allow_progress) {
            switch (code) {
            case -7: suffix = " (Ext4)"; break;
            case -6: suffix = " (Size)"; break;
            case -5: suffix = " (Auth)"; break;
            case -4: suffix = " (Write)"; break;
            case -3: suffix = " (Erase)"; break;
            case -2: suffix = " (WP)"; break;
            default: break;
            }
        }

        if (allow_progress && code >= -7 && code <= -2) {
            log_info(std::format("{} progress code {}{}", context, code, suffix));
            return true;
        }

        log_error(std::format("{} failed with code {}{}", context, code, suffix));
        return false;
    }

    return true;
}

auto UsbDevice::odin_begin_session() -> bool {
    std::vector<unsigned char> rsp;
    int32_t max_proto = 0x7FFFFFFF;
    uint32_t le_max = h_to_le32(static_cast<uint32_t>(max_proto));
    if (!odin_command(0x64, 0x00, &le_max, sizeof(le_max), rsp, USB_TIMEOUT_CONTROL)) return false;

    if (rsp.size() < 8) return false;

    int32_t id = 0;
    std::memcpy(&id, rsp.data(), sizeof(id));
    id = static_cast<int32_t>(le32toh(static_cast<uint32_t>(id)));
    if (id == BOOTLOADER_FAIL) {
        log_error("BeginSession failed with BOOTLOADER_FAIL");
        return false;
    }

    uint32_t ack_raw = 0;
    std::memcpy(&ack_raw, rsp.data() + 4, sizeof(ack_raw));
    ack_raw = le32toh(ack_raw);
    uint16_t ack_upper = static_cast<uint16_t>(ack_raw >> 16);
    odin_supports_compressed = (ack_upper & 0x8000) != 0;

    uint16_t version = static_cast<uint16_t>(ack_upper & 0x7FFF);

    if (version <= 1) {
        odin_flash_timeout_ms = 30000;
        odin_flash_packet_size = 131072;
        odin_flash_sequence_count = 240;
    } else {
        odin_flash_timeout_ms = 120000;
        odin_flash_packet_size = 1048576;
        odin_flash_sequence_count = 30;

        uint32_t packet_size = h_to_le32(static_cast<uint32_t>(odin_flash_packet_size));
        if (!odin_command(0x64, 0x05, &packet_size, sizeof(packet_size), rsp, USB_TIMEOUT_CONTROL)) return false;
        if (!odin_fail_check(rsp, "SendFilePartSize", false)) return false;
    }
    return true;
}

auto UsbDevice::odin_end_session() -> bool {
    std::vector<unsigned char> rsp;
    if (!odin_command(0x67, 0x00, nullptr, 0, rsp, USB_TIMEOUT_CONTROL)) return false;
    return odin_fail_check(rsp, "EndSession", false);
}

auto UsbDevice::odin_reboot() -> bool {
    std::vector<unsigned char> rsp;
    if (!odin_command(0x67, 0x01, nullptr, 0, rsp, USB_TIMEOUT_CONTROL)) return false;
    return odin_fail_check(rsp, "Reboot", false);
}

auto UsbDevice::odin_reboot_to_odin() -> bool {
    std::vector<unsigned char> rsp;
    if (!odin_command(0x67, 0x02, nullptr, 0, rsp, USB_TIMEOUT_CONTROL)) return false;
    return odin_fail_check(rsp, "RebootToOdin", false);
}

auto UsbDevice::odin_request_device_type(std::string& out_type) -> bool {
    std::vector<unsigned char> rsp;
    if (!odin_command(0x64, 0x01, nullptr, 0, rsp, USB_TIMEOUT_CONTROL)) return false;
    if (rsp.size() < 12) return false;

    int32_t id = 0;
    std::memcpy(&id, rsp.data(), sizeof(id));
    id = static_cast<int32_t>(le32toh(static_cast<uint32_t>(id)));
    if (id == BOOTLOADER_FAIL) {
        log_error("DeviceType query failed with BOOTLOADER_FAIL");
        return false;
    }

    uint32_t type_raw = 0;
    std::memcpy(&type_raw, rsp.data() + 8, sizeof(type_raw));
    type_raw = le32toh(type_raw);

    out_type = "SM-" + std::to_string(type_raw);
    return true;
}

auto UsbDevice::odin_set_total_bytes(uint64_t total_bytes) -> bool {
    std::vector<unsigned char> rsp;
    uint64_t le_total = h_to_le64(total_bytes);
    if (!odin_command(0x64, 0x02, &le_total, sizeof(le_total), rsp, USB_TIMEOUT_CONTROL)) return false;
    return odin_fail_check(rsp, "SetTotalBytes", false);
}

auto UsbDevice::odin_reset_flash_count() -> bool {
    std::vector<unsigned char> rsp;
    if (!odin_command(0x64, 0x01, nullptr, 0, rsp, USB_TIMEOUT_CONTROL)) return false;
    return odin_fail_check(rsp, "ResetFlashCount", false);
}

auto UsbDevice::odin_request_file_flash() -> bool {
    std::vector<unsigned char> rsp;
    if (!odin_command(0x66, 0x00, nullptr, 0, rsp, USB_TIMEOUT_CONTROL)) return false;
    return odin_fail_check(rsp, "RequestFileFlash", false);
}

auto UsbDevice::odin_request_sequence_flash(uint32_t aligned_size) -> bool {
    std::vector<unsigned char> rsp;
    uint32_t le_sz = h_to_le32(aligned_size);
    if (!odin_command(0x66, 0x02, &le_sz, sizeof(le_sz), rsp, USB_TIMEOUT_CONTROL)) return false;
    return odin_fail_check(rsp, "RequestSequenceFlash", false);
}

auto UsbDevice::odin_request_file_flash_compressed() -> bool {
    std::vector<unsigned char> rsp;
    if (!odin_command(0x66, 0x05, nullptr, 0, rsp, USB_TIMEOUT_CONTROL)) return false;
    return odin_fail_check(rsp, "RequestFileFlashCompressed", false);
}

auto UsbDevice::odin_request_sequence_flash_compressed(uint32_t compressed_size) -> bool {
    std::vector<unsigned char> rsp;
    uint32_t le_sz = h_to_le32(compressed_size);
    if (!odin_command(0x66, 0x06, &le_sz, sizeof(le_sz), rsp, USB_TIMEOUT_CONTROL)) return false;
    return odin_fail_check(rsp, "RequestSequenceFlashCompressed", false);
}

auto UsbDevice::odin_end_sequence_flash_compressed(const PitEntry& pit_entry, uint32_t compressed_size, uint32_t is_last,
                                                   bool efs_clear, bool boot_update) -> bool {
    std::vector<unsigned char> rsp;
    std::vector<unsigned char> payload(64, 0);

    auto w32 = [&](size_t off, uint32_t v) {
        uint32_t le = h_to_le32(v);
        std::memcpy(payload.data() + off, &le, sizeof(le));
    };

    if (pit_entry.binary_type == 1) {
        w32(0, 0x01);
        w32(4, compressed_size);
        w32(8, pit_entry.binary_type);
        w32(12, pit_entry.device_type);
        w32(16, 0U);
        w32(20, (is_last != 0U) ? 1U : 0U);
        w32(24, 0U);
        w32(28, 0U);
    } else {
        w32(0, 0x00);
        w32(4, compressed_size);
        w32(8, pit_entry.binary_type);
        w32(12, pit_entry.device_type);
        w32(16, pit_entry.identifier);
        w32(20, (is_last != 0U) ? 1U : 0U);
        w32(24, efs_clear ? 1U : 0U);
        w32(28, boot_update ? 1U : 0U);
    }

    send_empty_transfer();

    if (!odin_command(0x66, 0x07, payload.data(), 32, rsp, odin_flash_timeout_ms)) return false;

    receive_empty_transfer();

    return odin_fail_check(rsp, "EndSequenceFlashCompressed", true);
}

auto UsbDevice::odin_send_file_part_and_ack(const unsigned char* data, size_t size, uint32_t expected_index) -> bool {
    if (!bulk_write_all(data, size, odin_flash_timeout_ms)) return false;

    std::vector<unsigned char> rsp(8, 0);
    int actual = 0;
    if (!bulk_read_once(rsp.data(), rsp.size(), &actual, odin_flash_timeout_ms)) return false;
    if (actual != 8) return false;
    if (!odin_fail_check(rsp, "SendFilePart", false)) return false;

    int32_t idx = 0;
    std::memcpy(&idx, rsp.data() + 4, sizeof(idx));
    idx = static_cast<int32_t>(le32toh(static_cast<uint32_t>(idx)));
    if (static_cast<uint32_t>(idx) != expected_index) {
        log_error("Bootloader file part index mismatch: expected " + std::to_string(expected_index) + " got " +
                  std::to_string(idx));
        return false;
    }
    return true;
}

auto UsbDevice::odin_end_sequence_flash(const PitEntry& pit_entry, uint32_t real_size, uint32_t is_last,
                                        bool efs_clear, bool boot_update) -> bool {
    std::vector<unsigned char> rsp;
    std::vector<unsigned char> payload(64, 0);

    auto w32 = [&](size_t off, uint32_t v) {
        uint32_t le = h_to_le32(v);
        std::memcpy(payload.data() + off, &le, sizeof(le));
    };

    if (pit_entry.binary_type == 1) {
        w32(0, 0x01);
        w32(4, real_size);
        w32(8, pit_entry.binary_type);
        w32(12, pit_entry.device_type);
        w32(16, 0U);
        w32(20, (is_last != 0U) ? 1U : 0U);
        w32(24, 0U);
        w32(28, 0U);
    } else {
        w32(0, 0x00);
        w32(4, real_size);
        w32(8, pit_entry.binary_type);
        w32(12, pit_entry.device_type);
        w32(16, pit_entry.identifier);
        w32(20, (is_last != 0U) ? 1U : 0U);
        w32(24, efs_clear ? 1U : 0U);
        w32(28, boot_update ? 1U : 0U);
    }

    send_empty_transfer();

    if (!odin_command(0x66, 0x03, payload.data(), 32, rsp, odin_flash_timeout_ms)) return false;

    receive_empty_transfer();

    return odin_fail_check(rsp, "EndSequenceFlash", true);
}

auto UsbDevice::odin_dump_pit(std::vector<unsigned char>& pit_out) -> bool {
    std::vector<unsigned char> rsp;
    if (!odin_command(0x65, 0x01, nullptr, 0, rsp, 5000)) return false;
    if (!odin_fail_check(rsp, "RequestPitDump", false)) return false;

    uint32_t size = 0;
    std::memcpy(&size, rsp.data() + 4, sizeof(size));
    size = le32toh(size);
    if (size == 0 || size > 1048576) {
        log_error("Invalid PIT size reported: " + std::to_string(size));
        return false;
    }

    pit_out.assign(size, 0);
    const uint32_t block = 500;
    uint32_t blocks = (size + block - 1) / block;

    for (uint32_t i = 0; i < blocks; ++i) {
        uint32_t le_i = h_to_le32(i);
        if (!odin_command(0x65, 0x02, &le_i, sizeof(le_i), rsp, 5000)) return false;
        if (rsp.size() < 8) return false;

        size_t off = static_cast<size_t>(i) * block;
        size_t copy = std::min({rsp.size(), pit_out.size() - off, static_cast<size_t>(block)});
        if (copy == 0) return false;
        std::memcpy(pit_out.data() + off, rsp.data(), copy);
    }

    {
        int actual = 0;
        libusb_bulk_transfer(handle, endpoint_in, nullptr, 0, &actual, 100);
    }

    if (!odin_command(0x65, 0x03, nullptr, 0, rsp, 5000)) return false;
    return odin_fail_check(rsp, "EndPitDump", false);
}

auto UsbDevice::flash_partition_stream(std::istream& stream, uint64_t size, const PitEntry& pit_entry,
                                       bool large_partition, bool efs_clear, bool boot_update) -> bool {
    (void) large_partition;

    if (!odin_request_file_flash()) return false;

    const uint64_t sequence_bytes =
        static_cast<uint64_t>(odin_flash_packet_size) * static_cast<uint64_t>(odin_flash_sequence_count);
    if (sequence_bytes == 0) return false;

    const uint64_t sequences64 = (size + sequence_bytes - 1) / sequence_bytes;
    if (sequences64 == 0 || sequences64 > 0xFFFFFFFFULL) {
        log_error("Too many legacy sequences for size: " + std::to_string(size));
        return false;
    }
    const auto sequences = static_cast<uint32_t>(sequences64);

    uint64_t last_sequence64 = size - static_cast<uint64_t>(sequences - 1) * sequence_bytes;
    if (last_sequence64 == 0) last_sequence64 = sequence_bytes;
    if (last_sequence64 > 0xFFFFFFFFULL) {
        log_error("Legacy last sequence too large: " + std::to_string(last_sequence64));
        return false;
    }
    const auto last_sequence = static_cast<uint32_t>(last_sequence64);

    uint64_t total_sent = 0;
    std::vector<unsigned char> part(static_cast<size_t>(odin_flash_packet_size), 0);

    uint32_t expected_index = 0;
    for (uint32_t i = 0; i < sequences; ++i) {
        const bool last = (i + 1 == sequences);
        const uint32_t real_size = last ? last_sequence : static_cast<uint32_t>(sequence_bytes);
        uint32_t aligned_size = real_size;
        if (aligned_size % static_cast<uint32_t>(odin_flash_packet_size) != 0) {
            aligned_size += static_cast<uint32_t>(odin_flash_packet_size) -
                            (aligned_size % static_cast<uint32_t>(odin_flash_packet_size));
        }

        if (!odin_request_sequence_flash(aligned_size)) return false;

        const uint32_t parts = aligned_size / static_cast<uint32_t>(odin_flash_packet_size);
        for (uint32_t j = 0; j < parts; ++j) {
            std::fill(part.begin(), part.end(), 0);

            uint64_t remaining_file_bytes = 0;
            if (total_sent < size) remaining_file_bytes = size - total_sent;
            const size_t to_read = static_cast<size_t>(std::min<uint64_t>(remaining_file_bytes, part.size()));

            if (to_read > 0) {
                stream.read(reinterpret_cast<char*>(part.data()), static_cast<std::streamsize>(to_read));
                if (static_cast<size_t>(stream.gcount()) != to_read) return false;
            }

            if (!odin_send_file_part_and_ack(part.data(), part.size(), expected_index++)) return false;
            total_sent += static_cast<uint64_t>(to_read);
        }

        if (!odin_end_sequence_flash(pit_entry, real_size, last ? 1U : 0U, efs_clear, boot_update)) return false;
    }

    return odin_reset_flash_count();
}

auto UsbDevice::build_lz4_decompressed_index(std::istream& stream, uint64_t compressed_size,
                                              std::vector<std::pair<uint64_t,uint64_t>>& index) -> bool {
    std::streampos saved = stream.tellg();
    if (saved < 0) return false;

    index.clear();
    index.reserve(static_cast<size_t>(compressed_size / 65536) + 2);
    index.emplace_back(0, 0);

    LZ4F_dctx* dctx = nullptr;
    LZ4F_errorCode_t err = LZ4F_createDecompressionContext(&dctx, LZ4F_VERSION);
    if (LZ4F_isError(err)) return false;

    size_t in_buf_size = 1048576;
    std::vector<unsigned char> in_buf(in_buf_size);
    std::vector<unsigned char> out_buf(4194304);

    uint64_t compressed_consumed = 0;
    uint64_t decompressed_produced = 0;
    size_t src_offset = 0;
    size_t src_size = 0;
    bool done = false;

    while (!done && (compressed_consumed < compressed_size || src_size > 0)) {
        if (src_size == 0 && compressed_consumed < compressed_size) {
            size_t to_read = in_buf_size;
            if (to_read > compressed_size - compressed_consumed)
                to_read = static_cast<size_t>(compressed_size - compressed_consumed);
            stream.read(reinterpret_cast<char*>(in_buf.data()), static_cast<std::streamsize>(to_read));
            src_size = static_cast<size_t>(stream.gcount());
            if (src_size == 0) break;
            compressed_consumed += src_size;
            src_offset = 0;
        }

        while (src_size > 0 && !done) {
            size_t dst_size = out_buf.size();
            size_t src_consumed = src_size;

            err = LZ4F_decompress(dctx, out_buf.data(), &dst_size, in_buf.data() + src_offset, &src_consumed, nullptr);
            if (LZ4F_isError(err)) { LZ4F_freeDecompressionContext(dctx); stream.clear(); stream.seekg(saved); return false; }

            if (dst_size > 0) {
                decompressed_produced += dst_size;
                index.emplace_back(compressed_consumed, decompressed_produced);
            }

            if (src_consumed > 0) {
                src_offset += src_consumed;
                src_size -= src_consumed;
            }

            if (src_consumed == 0 && dst_size == 0) {
                if (compressed_consumed >= compressed_size) { done = true; break; }
                if (src_offset > 0) {
                    std::memmove(in_buf.data(), in_buf.data() + src_offset, src_size);
                    src_offset = 0;
                }
                size_t space = in_buf_size - src_size;
                size_t to_read = static_cast<size_t>(std::min<uint64_t>(space, compressed_size - compressed_consumed));
                if (to_read == 0) break;
                stream.read(reinterpret_cast<char*>(in_buf.data() + src_size), static_cast<std::streamsize>(to_read));
                size_t got = static_cast<size_t>(stream.gcount());
                if (got == 0) break;
                src_size += got;
                compressed_consumed += got;
            }

            if (err == 0) done = true;
        }
    }

    LZ4F_freeDecompressionContext(dctx);
    stream.clear();
    stream.seekg(saved);
    return !index.empty() && done;
}

static auto find_decomp_at_comp(const std::vector<std::pair<uint64_t,uint64_t>>& index, uint64_t compressed_pos) -> uint64_t {
    if (index.empty()) return 0;
    auto it = std::upper_bound(index.begin(), index.end(), compressed_pos,
                               [](uint64_t pos, const auto& entry) { return pos < entry.first; });
    if (it == index.begin()) return index.front().second;
    --it;
    return it->second;
}

auto UsbDevice::flash_partition_stream_compressed(std::istream& stream, uint64_t compressed_size,
                                                   const PitEntry& pit_entry, bool large_partition,
                                                   bool efs_clear, bool boot_update) -> bool {
    (void) large_partition;

    std::streampos saved_pos = stream.tellg();
    if (saved_pos < 0) return false;

    Lz4FrameInfo lz4_info = parse_lz4_frame_header(stream);
    if (!lz4_info.valid) {
        log_error("LZ4 frame validation failed: frame must have content size, independent blocks, "
                   "no block checksum, no dict ID, and max block size <= 1 MiB");
        return false;
    }

    uint64_t total_decompressed = lz4_info.content_size;
    if (total_decompressed == 0) {
        log_error("LZ4 frame has zero content size");
        return false;
    }

    log_verbose(std::format("LZ4 frame valid: compressed {} -> decompressed {} bytes", compressed_size, total_decompressed));

    stream.clear();
    stream.seekg(saved_pos);
    if (!stream) return false;

    std::vector<std::pair<uint64_t,uint64_t>> decomp_index;
    if (!build_lz4_decompressed_index(stream, compressed_size, decomp_index)) {
        log_error("Failed to build LZ4 decompressed index");
        return false;
    }
    uint64_t index_total = decomp_index.empty() ? 0 : decomp_index.back().second;
    if (index_total > 0 && index_total != total_decompressed) {
        log_warn(std::format("LZ4 decompressed size mismatch: header says {}, scan says {}; using scan value",
                              total_decompressed, index_total));
        total_decompressed = index_total;
    }

    stream.clear();
    stream.seekg(saved_pos);
    if (!stream) return false;

    if (!odin_request_file_flash_compressed()) return false;

    const uint64_t sequence_bytes =
        static_cast<uint64_t>(odin_flash_packet_size) * static_cast<uint64_t>(odin_flash_sequence_count);
    if (sequence_bytes == 0) return false;

    const uint64_t sequences64 = (compressed_size + sequence_bytes - 1) / sequence_bytes;
    if (sequences64 == 0 || sequences64 > 0xFFFFFFFFULL) {
        log_error("Too many compressed sequences for size: " + std::to_string(compressed_size));
        return false;
    }
    const auto sequences = static_cast<uint32_t>(sequences64);

    uint64_t last_seq64 = compressed_size - static_cast<uint64_t>(sequences - 1) * sequence_bytes;
    if (last_seq64 == 0) last_seq64 = sequence_bytes;
    if (last_seq64 > 0xFFFFFFFFULL) {
        log_error("Compressed last sequence too large: " + std::to_string(last_seq64));
        return false;
    }

    uint64_t total_sent = 0;
    std::vector<unsigned char> buf(static_cast<size_t>(odin_flash_packet_size), 0);

    uint64_t prev_decomp = 0;
    uint32_t expected_index = 0;
    for (uint32_t i = 0; i < sequences; ++i) {
        const bool last = (i + 1 == sequences);
        const uint32_t seq_size = last ? static_cast<uint32_t>(last_seq64) : static_cast<uint32_t>(sequence_bytes);

        if (!odin_request_sequence_flash_compressed(seq_size)) return false;

        uint64_t remaining = seq_size;
        while (remaining > 0) {
            const size_t to_read = static_cast<size_t>(std::min<uint64_t>(remaining, buf.size()));
            stream.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(to_read));
            if (static_cast<size_t>(stream.gcount()) != to_read) return false;

            std::fill(buf.begin() + static_cast<ptrdiff_t>(to_read), buf.end(), 0);

            if (!odin_send_file_part_and_ack(buf.data(), buf.size(), expected_index++)) return false;
            total_sent += to_read;
            remaining -= to_read;
        }

        uint64_t decomp_at_end = find_decomp_at_comp(decomp_index, total_sent);
        uint64_t this_seq_decomp = decomp_at_end - prev_decomp;
        prev_decomp = decomp_at_end;

        if (last) {
            this_seq_decomp = total_decompressed - prev_decomp + this_seq_decomp;
        }
        if (this_seq_decomp == 0) this_seq_decomp = static_cast<uint32_t>(total_decompressed);

        if (!odin_end_sequence_flash_compressed(pit_entry, static_cast<uint32_t>(this_seq_decomp), last ? 1U : 0U, efs_clear, boot_update)) return false;
    }

    return odin_reset_flash_count();
}
