#include "usb_device.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <thread>
#include <chrono>
#include <cstring>
#include <vector>
#include <algorithm>
#include <cctype>
#include <unordered_set>
#include <limits>
#include <mutex>

namespace {
    libusb_context* g_libusb_ctx = nullptr;
    std::once_flag g_libusb_once;

    bool ensure_libusb_initialized() {
        std::call_once(g_libusb_once, []() {
            int rc = libusb_init(&g_libusb_ctx);
            if (rc != 0) g_libusb_ctx = nullptr;
        });
        return g_libusb_ctx != nullptr;
    }

    int clamp_size_to_int(size_t sz) {
        if (sz > static_cast<size_t>(std::numeric_limits<int>::max())) {
            return std::numeric_limits<int>::max();
        }
        return static_cast<int>(sz);
    }
}

static int retry_backoff_ms(int attempt) {
    int ms = 100;
    for (int i = 0; i < attempt; ++i) {
        ms *= 2;
        if (ms > 1500) return 1500;
    }
    return ms;
}

UsbDevice::~UsbDevice() {
    if (handle) {
        libusb_release_interface(handle, interface_number);
        libusb_close(handle);
        handle = nullptr;
    }
    if (device_list) {
        libusb_free_device_list(device_list, 1);
        device_list = nullptr;
    }
}

bool UsbDevice::bulk_write_all(const void* data, size_t size, int timeout_ms) {
    const unsigned char* ptr = static_cast<const unsigned char*>(data);
    size_t offset = 0;
    for (int attempt = 0; attempt < USB_RETRY_COUNT; ++attempt) {
        while (offset < size) {
            int actual_length = 0;
            size_t to_send = size - offset;
            if (to_send > max_chunk_bytes) to_send = max_chunk_bytes;
            int err = libusb_bulk_transfer(handle, endpoint_out, const_cast<unsigned char*>(ptr + offset), clamp_size_to_int(to_send), &actual_length, timeout_ms);
            if (actual_length > 0) {
                offset += static_cast<size_t>(actual_length);
            }
            if (err != 0) {
                log_error("USB bulk write failed", err);
                if (err == LIBUSB_ERROR_NO_DEVICE) return false;
                if (err == LIBUSB_ERROR_PIPE) (void)libusb_clear_halt(handle, endpoint_out);
                // Some devices/controllers behave poorly with ZLP or large transfers.
                // Fall back to small chunks and retry.
                if (err == LIBUSB_ERROR_PIPE || err == LIBUSB_ERROR_TIMEOUT) {
                    max_chunk_bytes = 0x800;
                }
                break;
            }
            if (actual_length <= 0) {
                log_error("USB bulk write returned zero length");
                break;
            }
        }
        if (offset == size) {
            // Only send ZLP once, at the end of the whole transfer.
            // Some Odin legacy bootloaders expect it when the transfer size is an exact multiple of wMaxPacketSize.
            if (protocol_mode == ProtocolMode::OdinLegacy && odin_supports_zlp && endpoint_out_max_packet != 0) {
                if ((size % endpoint_out_max_packet) == 0) {
                    int zlp_len = 0;
                    (void)libusb_bulk_transfer(handle, endpoint_out, nullptr, 0, &zlp_len, timeout_ms);
                }
            }
            return true;
        }
        if (attempt < USB_RETRY_COUNT - 1) {
            std::this_thread::sleep_for(std::chrono::milliseconds(retry_backoff_ms(attempt)));
        }
    }
    return false;
}

bool UsbDevice::bulk_read_once(void* data, size_t size, int* actual_length, int timeout_ms) {
    for (int attempt = 0; attempt < USB_RETRY_COUNT; ++attempt) {
        int err = libusb_bulk_transfer(handle, endpoint_in, static_cast<unsigned char*>(data), clamp_size_to_int(size), actual_length, timeout_ms);
        if (err == 0) return true;
        if (err == LIBUSB_ERROR_NO_DEVICE) return false;
        if (err == LIBUSB_ERROR_PIPE) (void)libusb_clear_halt(handle, endpoint_in);
        log_error("USB bulk read failed", err);
        if (attempt < USB_RETRY_COUNT - 1) {
            std::this_thread::sleep_for(std::chrono::milliseconds(retry_backoff_ms(attempt)));
        }
    }
    return false;
}


static std::string usb_path_for_device(libusb_device* dev) {
    std::ostringstream oss;
    oss << "/dev/bus/usb/" << std::setfill('0') << std::setw(3) << static_cast<int>(libusb_get_bus_number(dev))
        << "/" << std::setfill('0') << std::setw(3) << static_cast<int>(libusb_get_device_address(dev));
    return oss.str();
}

static bool is_known_download_pid(uint16_t pid) {
    for (uint16_t known : SAMSUNG_DOWNLOAD_PIDS) {
        if (pid == known) return true;
    }
    return false;
}

struct InterfaceCandidate {
    int score = -1;
    int interface_number = -1;
    uint8_t ep_in = 0;
    uint8_t ep_out = 0;
    uint16_t ep_out_mps = 0;
    uint8_t interface_class = 0;
    uint8_t num_endpoints = 0;
};

static InterfaceCandidate find_best_interface(libusb_device* dev, const UsbSelectionCriteria& criteria) {
    InterfaceCandidate best;
    libusb_config_descriptor* config = nullptr;
    if (libusb_get_active_config_descriptor(dev, &config) != 0 || !config) return best;

    for (int i = 0; i < config->bNumInterfaces; ++i) {
        const libusb_interface* inter = &config->interface[i];
        for (int j = 0; j < inter->num_altsetting; ++j) {
            const libusb_interface_descriptor* id = &inter->altsetting[j];
            if (criteria.has_interface && id->bInterfaceNumber != criteria.interface_number) continue;

            uint8_t ep_in = 0;
            uint8_t ep_out = 0;
            uint16_t ep_out_mps = 0;
            int bulk_endpoints = 0;

            for (int k = 0; k < id->bNumEndpoints; ++k) {
                const libusb_endpoint_descriptor* ep = &id->endpoint[k];
                if ((ep->bmAttributes & 0x03) != LIBUSB_TRANSFER_TYPE_BULK) continue;
                ++bulk_endpoints;
                if (ep->bEndpointAddress & 0x80) ep_in = ep->bEndpointAddress;
                else {
                    ep_out = ep->bEndpointAddress;
                    ep_out_mps = ep->wMaxPacketSize;
                }
            }

            if (!ep_in || !ep_out) continue;

            int score = 0;
            // Heimdall-style heuristic: CDC Data interface with exactly 2 endpoints.
            if (id->bInterfaceClass == 0x0A && id->bNumEndpoints == 2) score += 100;
            // General fallback: any interface with bulk in/out.
            score += 50;
            // Small preference for "clean" configurations.
            if (bulk_endpoints == 2) score += 10;

            if (score > best.score) {
                best.score = score;
                best.interface_number = id->bInterfaceNumber;
                best.ep_in = ep_in;
                best.ep_out = ep_out;
                best.ep_out_mps = ep_out_mps;
                best.interface_class = id->bInterfaceClass;
                best.num_endpoints = id->bNumEndpoints;
            }
        }
    }

    libusb_free_config_descriptor(config);
    return best;
}

bool UsbDevice::open_device(const std::string& specific_path) {
    UsbSelectionCriteria criteria;
    return open_device(specific_path, criteria);
}

bool UsbDevice::open_device(const std::string& specific_path, const UsbSelectionCriteria& criteria) {
    last_open_error = UsbOpenError::None;
    last_open_libusb_err = 0;

    if (handle) {
        libusb_release_interface(handle, interface_number);
        libusb_close(handle);
        handle = nullptr;
    }
    if (device_list) {
        libusb_free_device_list(device_list, 1);
        device_list = nullptr;
    }

    if (!ensure_libusb_initialized()) {
        last_open_error = UsbOpenError::Other;
        last_open_libusb_err = LIBUSB_ERROR_OTHER;
        log_error("Failed to enumerate USB devices", LIBUSB_ERROR_OTHER);
        return false;
    }

    ssize_t cnt = libusb_get_device_list(g_libusb_ctx, &device_list);
    if (cnt < 0) {
        last_open_error = UsbOpenError::Other;
        last_open_libusb_err = static_cast<int>(cnt);
        log_error("Failed to enumerate USB devices", static_cast<int>(cnt));
        return false;
    }

    libusb_device* target = nullptr;
    InterfaceCandidate chosen_if;
    bool saw_candidate_vendor = false;

    for (ssize_t i = 0; i < cnt; ++i) {
        libusb_device* dev = device_list[i];
        libusb_device_descriptor desc;
        if (libusb_get_device_descriptor(dev, &desc) != 0) continue;

        const uint16_t vid = desc.idVendor;
        const uint16_t pid = desc.idProduct;

        if (criteria.has_vid) {
            if (vid != criteria.vid) continue;
        } else {
            if (vid != SAMSUNG_VID) continue;
        }

        saw_candidate_vendor = true;

        if (criteria.has_pid && pid != criteria.pid) continue;
        if (!specific_path.empty() && usb_path_for_device(dev) != specific_path) continue;

        InterfaceCandidate cand = find_best_interface(dev, criteria);
        if (cand.score < 0) continue;

        const bool pid_known = is_known_download_pid(pid);
        const bool cdc_data = (cand.interface_class == 0x0A);

        // Default behavior: be conservative and only auto-match devices that look
        // like Samsung Download Mode (known PID or CDC Data bulk interface).
        if (!criteria.has_pid && !criteria.has_vid) {
            if (!pid_known && !cdc_data) continue;
        }

        // Prefer known download PIDs when multiple devices match.
        int score = cand.score;
        if (pid_known) score += 20;
        if (score > chosen_if.score) {
            chosen_if = cand;
            target = dev;
        }
    }

    if (!target) {
        last_open_error = saw_candidate_vendor ? UsbOpenError::NotDownloadMode : UsbOpenError::NoDevice;
        log_warn("No compatible device found. Ensure the device is connected and in Download Mode.");
        return false;
    }

    endpoint_in = chosen_if.ep_in;
    endpoint_out = chosen_if.ep_out;
    if (chosen_if.ep_out_mps != 0) endpoint_out_max_packet = chosen_if.ep_out_mps;
    interface_number = chosen_if.interface_number;

    const int open_err = libusb_open(target, &handle);
    if (open_err < 0 || !handle) {
        last_open_libusb_err = open_err;
        if (open_err == LIBUSB_ERROR_ACCESS) last_open_error = UsbOpenError::AccessDenied;
        else if (open_err == LIBUSB_ERROR_BUSY) last_open_error = UsbOpenError::Busy;
        else last_open_error = UsbOpenError::Other;
        log_error("Failed to open USB device", open_err);
        return false;
    }

    if (libusb_kernel_driver_active(handle, interface_number) == 1) {
        const int detach_err = libusb_detach_kernel_driver(handle, interface_number);
        if (detach_err < 0) {
            last_open_error = (detach_err == LIBUSB_ERROR_ACCESS) ? UsbOpenError::AccessDenied : UsbOpenError::Other;
            last_open_libusb_err = detach_err;
            log_error("Failed to detach kernel driver", detach_err);
            libusb_close(handle);
            handle = nullptr;
            return false;
        }
    }

    const int claim_err = libusb_claim_interface(handle, interface_number);
    if (claim_err < 0) {
        last_open_libusb_err = claim_err;
        if (claim_err == LIBUSB_ERROR_ACCESS) last_open_error = UsbOpenError::AccessDenied;
        else last_open_error = UsbOpenError::Other;
        log_error("Failed to claim USB interface", claim_err);
        libusb_close(handle);
        handle = nullptr;
        return false;
    }

    std::ostringstream oss;
    oss << "USB device opened. Path: " << usb_path_for_device(target)
        << ", Interface: " << interface_number
        << ", EP IN: 0x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(endpoint_in)
        << ", EP OUT: 0x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(endpoint_out)
        << std::dec << ", OUT wMaxPacketSize: " << endpoint_out_max_packet;
    log_info(oss.str());
    return true;
}

bool UsbDevice::send_packet(const void *data, size_t size, bool is_control) {
    int timeout = is_control ? USB_TIMEOUT_CONTROL : USB_TIMEOUT_BULK;
    if (!bulk_write_all(data, size, timeout)) return false;
    if (is_control) log_hexdump("Packet Sent (Control)", data, size);
    return true;
}


bool UsbDevice::receive_packet(void *data, size_t size, int *actual_length, bool is_control, size_t min_size, int timeout_override_ms) {
    int timeout = timeout_override_ms > 0 ? timeout_override_ms : (is_control ? USB_TIMEOUT_CONTROL : USB_TIMEOUT_BULK);
    size_t required_min = (min_size == 0) ? size : min_size;

    for (int attempt = 0; attempt < USB_RETRY_COUNT; ++attempt) {
        size_t received = 0;
        *actual_length = 0;

        while (received < required_min && received < size) {
            int chunk = 0;
            const size_t remaining = size - received;
            int err = libusb_bulk_transfer(handle, endpoint_in, static_cast<unsigned char*>(data) + received, clamp_size_to_int(remaining), &chunk, timeout);

            if (chunk > 0) {
                received += static_cast<size_t>(chunk);
                *actual_length = static_cast<int>(received);
            }

            if (err == 0) {
                if (received >= required_min) break;
                if (chunk <= 0) break;
                continue;
            }

            if (err == LIBUSB_ERROR_PIPE) (void)libusb_clear_halt(handle, endpoint_in);
            if (err == LIBUSB_ERROR_TIMEOUT && timeout_override_ms > 0) {
                return false;
            }
            log_error("USB packet receive failed (attempt " + std::to_string(attempt + 1) + ")", err);
            if (err == LIBUSB_ERROR_NO_DEVICE) return false;
            break;
        }

        if (received >= required_min && received <= size) {
            if (is_control) log_hexdump("Packet Received (Control)", data, received);
            return true;
        }

        log_error("Incorrect receive size (attempt " + std::to_string(attempt + 1) + "): expected min " + std::to_string(required_min) + ", max " + std::to_string(size) + ", received " + std::to_string(received));

        if (attempt < USB_RETRY_COUNT - 1) {
            std::this_thread::sleep_for(std::chrono::milliseconds(retry_backoff_ms(attempt)));
        }
    }

    return false;
}


bool UsbDevice::handshake() {
    log_info("Starting handshake");
    protocol_mode = ProtocolMode::Thor;

    if (odin_legacy_handshake()) {
        protocol_mode = ProtocolMode::OdinLegacy;
        return true;
    }

    ThorHandshakePacket handshake_pkt = {};
    handshake_pkt.header.packet_size = h_to_le32(sizeof(handshake_pkt));
    handshake_pkt.header.packet_type = h_to_le16(THOR_PACKET_HANDSHAKE);
    handshake_pkt.header.packet_flags = h_to_le16(0);
    handshake_pkt.magic = h_to_le32(0x4E49444F);
    handshake_pkt.version = h_to_le32(0x00000001);
    handshake_pkt.packet_size = h_to_le32(0x00000000);

    if (!send_packet(&handshake_pkt, sizeof(handshake_pkt), true)) return false;

    ThorResponsePacket rsp = {};
    int actual_length = 0;
    if (!receive_packet(&rsp, sizeof(rsp), &actual_length, true, sizeof(rsp))) return false;
    uint32_t code = le32_to_h(rsp.response_code);
    if (code != 0) {
        log_error("Handshake failed with response code: " + std::to_string(code));
        return false;
    }
    return true;
}

bool UsbDevice::request_device_type() {
    if (protocol_mode == ProtocolMode::OdinLegacy) { device_type_str.clear(); return true; }

    log_info("Requesting device type...");
    ThorPacketHeader pkt = {};
    pkt.packet_size = h_to_le32(sizeof(ThorPacketHeader));
    pkt.packet_type = h_to_le16(THOR_PACKET_DEVICE_TYPE);
    pkt.packet_flags = h_to_le16(0);

    if (!send_packet(&pkt, sizeof(pkt), true)) return false;

    ThorDeviceTypePacket response = {};
    int actual_length;
    if (!receive_packet(&response, sizeof(response), &actual_length, true, sizeof(response))) return false;

    if (le16toh(response.header.packet_type) != THOR_PACKET_DEVICE_TYPE) {
        log_error("Device type request failed. Unexpected packet type: " + std::to_string(le16toh(response.header.packet_type)));
        return false;
    }
    // Copy the device type string from the response. The char array is
    // null-terminated or zero-padded. Convert to a std::string and trim
    // trailing null bytes.
    device_type_str.clear();
    for (int i = 0; i < static_cast<int>(sizeof(response.device_type)); ++i) {
        char c = response.device_type[i];
        if (c == '\0') break;
        device_type_str.push_back(c);
    }
    log_info("Device type received: " + device_type_str);
    return true;
}

std::vector<std::string> UsbDevice::list_download_devices() {
    UsbSelectionCriteria criteria;
    return list_download_devices(criteria);
}

std::vector<std::string> UsbDevice::list_download_devices(const UsbSelectionCriteria& criteria) {
    std::vector<std::string> result;
    libusb_device** list = nullptr;
    if (!ensure_libusb_initialized()) return result;
    const ssize_t cnt = libusb_get_device_list(g_libusb_ctx, &list);
    if (cnt < 0) return result;

    struct Cleanup {
        libusb_device** l;
        explicit Cleanup(libusb_device** ptr) : l(ptr) {}
        ~Cleanup() { if (l) libusb_free_device_list(l, 1); }
    } cleanup(list);

    for (ssize_t i = 0; i < cnt; ++i) {
        libusb_device* dev = list[i];
        libusb_device_descriptor desc;
        if (libusb_get_device_descriptor(dev, &desc) != 0) continue;

        const uint16_t vid = desc.idVendor;
        const uint16_t pid = desc.idProduct;

        if (criteria.has_vid) {
            if (vid != criteria.vid) continue;
        } else {
            if (vid != SAMSUNG_VID) continue;
        }

        if (criteria.has_pid && pid != criteria.pid) continue;

        InterfaceCandidate cand = find_best_interface(dev, criteria);
        if (cand.score < 0) continue;

        const bool pid_known = is_known_download_pid(pid);
        const bool cdc_data = (cand.interface_class == 0x0A);
        if (!criteria.has_pid && !criteria.has_vid) {
            if (!pid_known && !cdc_data) continue;
        }

        result.push_back(usb_path_for_device(dev));
    }
    return result;
}

bool UsbDevice::begin_session() {
    if (protocol_mode == ProtocolMode::OdinLegacy) return odin_begin_session();

    log_info("Beginning session...");
    ThorBeginSessionPacket pkt = {};
    pkt.header.packet_size = h_to_le32(sizeof(ThorBeginSessionPacket));
    pkt.header.packet_type = h_to_le16(THOR_PACKET_BEGIN_SESSION);
    pkt.header.packet_flags = h_to_le16(0);
    pkt.unknown1 = 0;
    pkt.unknown2 = 0;

    if (!send_packet(&pkt, sizeof(pkt), true)) return false;

    ThorResponsePacket response = {};
    int actual_length;
    if (!receive_packet(&response, sizeof(response), &actual_length, true, sizeof(ThorPacketHeader))) return false;

    if (actual_length < static_cast<int>(sizeof(ThorResponsePacket))) {
        log_error("Session begin failed: short response (" + std::to_string(actual_length) + " bytes)");
        return false;
    }

    uint32_t code = le32_to_h(response.response_code);
    if (le16toh(response.header.packet_type) != THOR_PACKET_RESPONSE || code != 0) {
        log_error("Session begin failed. Response code: " + std::to_string(code));
        return false;
    }
    log_info("Session started successfully.");
    return true;
}

bool UsbDevice::end_session() {
    if (protocol_mode == ProtocolMode::OdinLegacy) return odin_end_session();

    log_info("Ending session...");
    ThorEndSessionPacket pkt = {};
    pkt.header.packet_size = h_to_le32(sizeof(ThorEndSessionPacket));
    pkt.header.packet_type = h_to_le16(THOR_PACKET_END_SESSION);
    pkt.header.packet_flags = h_to_le16(0);

    if (!send_packet(&pkt, sizeof(pkt), true)) return false;

    ThorResponsePacket response = {};
    int actual_length;
    if (!receive_packet(&response, sizeof(response), &actual_length, true, sizeof(ThorPacketHeader))) return false;

    if (actual_length < static_cast<int>(sizeof(ThorResponsePacket))) {
        log_error("Session end failed: short response (" + std::to_string(actual_length) + " bytes)");
        return false;
    }

    uint32_t code = le32_to_h(response.response_code);
    if (le16toh(response.header.packet_type) != THOR_PACKET_RESPONSE || code != 0) {
        log_error("Session end failed. Response code: " + std::to_string(code));
        return false;
    }
    log_info("Session ended successfully.");
    return true;
}

static bool parse_pit_bytes(PitTable& pit_table, const std::vector<unsigned char>& pit_data) {
    if (pit_data.size() < 28) {
        log_error("PIT data too small: " + std::to_string(pit_data.size()));
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
        log_error("Invalid PIT entry count: " + std::to_string(pit_table.entry_count));
        return false;
    }

    pit_table.unknown1 = read_u32(8);
    pit_table.unknown2 = read_u32(12);
    pit_table.unknown3 = read_u16(16);
    pit_table.unknown4 = read_u16(18);
    pit_table.unknown5 = read_u16(20);
    pit_table.unknown6 = read_u16(22);
    pit_table.unknown7 = read_u16(24);
    pit_table.unknown8 = read_u16(26);

    pit_table.header_size = 28;
    const size_t entry_size = 132;
    const size_t required = pit_table.header_size + static_cast<size_t>(pit_table.entry_count) * entry_size;
    if (pit_data.size() < required) {
        log_error("PIT truncated: expected at least " + std::to_string(required) + " bytes");
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
            log_error("PIT entry " + std::to_string(i) + " has an empty partition name");
            return false;
        }
        if (!is_valid_pit_string(part_name)) {
            log_error("PIT entry " + std::to_string(i) + " has an invalid partition name: '" + part_name + "'");
            return false;
        }
        if (!file_name.empty() && !is_valid_pit_string(file_name)) {
            log_error("PIT entry " + std::to_string(i) + " has an invalid file name: '" + file_name + "'");
            return false;
        }

        if (e.identifier == 0) {
            log_error("PIT entry " + std::to_string(i) + " has an invalid identifier (0)");
            return false;
        }
        if (!seen_identifiers.insert(e.identifier).second) {
            log_error("PIT contains duplicate partition identifier: " + std::to_string(e.identifier));
            return false;
        }

        if (e.block_count != 0) {
            const uint64_t a = static_cast<uint64_t>(e.block_size_or_offset);
            const uint64_t b = static_cast<uint64_t>(e.block_count);
            const uint64_t prod = a * b;
            if (a != 0 && prod / a != b) {
                log_error("PIT entry " + std::to_string(i) + " has an overflow in block size/count");
                return false;
            }
        }

        // Do NOT force-null-terminate here; treat these as fixed 32-byte fields.
        pit_table.entries.push_back(e);
    }

    log_info("Received PIT entries: " + std::to_string(pit_table.entry_count));
    return true;
}

bool UsbDevice::request_pit(PitTable& pit_table) {
    if (protocol_mode == ProtocolMode::OdinLegacy) {
        std::vector<unsigned char> pit;
        if (!odin_dump_pit(pit)) return false;
        return parse_pit_bytes(pit_table, pit);
    }

    log_info("Requesting PIT...");
    ThorPacketHeader pkt = {};
    pkt.packet_size = h_to_le32(sizeof(ThorPacketHeader));
    pkt.packet_type = h_to_le16(THOR_PACKET_PIT_FILE);
    pkt.packet_flags = h_to_le16(0);

    // The PIT request only sends a header requesting the PIT file. The response
    // containing the PIT size and data will be handled by receive_pit_table().
    // Do not consume any packets here; otherwise the subsequent call to
    // receive_pit_table() will see an empty buffer and fail. Simply send
    // the request and return success if the transfer completed.
    if (!send_packet(&pkt, sizeof(pkt), true)) return false;
    return receive_pit_table(pit_table);
}

bool UsbDevice::receive_pit_table(PitTable& pit_table) {
    ThorPitFilePacket pit_size_pkt = {};
    int actual_length = 0;
    if (!receive_packet(&pit_size_pkt, sizeof(pit_size_pkt), &actual_length, true, sizeof(pit_size_pkt))) return false;

    if (actual_length < static_cast<int>(sizeof(ThorPitFilePacket))) {
        log_error("Short PIT size packet (" + std::to_string(actual_length) + " bytes)");
        return false;
    }

    if (le16toh(pit_size_pkt.header.packet_type) != THOR_PACKET_PIT_FILE) {
        log_error("Unexpected packet type while reading PIT size: " + std::to_string(le16toh(pit_size_pkt.header.packet_type)));
        return false;
    }

    uint32_t pit_data_size = le32_to_h(pit_size_pkt.pit_file_size);
    if (pit_data_size < 28 || pit_data_size > 1048576) {
        log_error("Invalid PIT size: " + std::to_string(pit_data_size));
        return false;
    }

    std::vector<unsigned char> pit_data(pit_data_size);
    if (!receive_packet(pit_data.data(), pit_data_size, &actual_length, false, pit_data_size)) {
        log_error("Failed to receive PIT data");
        return false;
    }

    return parse_pit_bytes(pit_table, pit_data);
}

bool UsbDevice::send_file_part_chunk(const void* data, size_t size, uint32_t chunk_index, bool large_partition) {
    ThorFilePartPacket part_pkt = {};
    part_pkt.header.packet_size = h_to_le32(sizeof(ThorFilePartPacket));
    part_pkt.header.packet_type = h_to_le16(THOR_PACKET_FILE_PART);
    part_pkt.header.packet_flags = h_to_le16(0);
    part_pkt.file_part_index = h_to_le32(chunk_index);
    part_pkt.file_part_size = h_to_le32(static_cast<uint32_t>(size));

    if (!send_packet(&part_pkt, sizeof(part_pkt), true)) return false;

    ThorResponsePacket response = {};
    int actual_length = 0;
    if (!receive_packet(&response, sizeof(response), &actual_length, true, sizeof(ThorPacketHeader))) return false;

    if (actual_length < static_cast<int>(sizeof(ThorResponsePacket))) {
        log_error("File part control failed: short response (" + std::to_string(actual_length) + " bytes)");
        return false;
    }
    uint32_t code = le32toh(response.response_code);
    if (le16toh(response.header.packet_type) != THOR_PACKET_RESPONSE || code != 0) {
        log_error("File part control failed. Code: " + std::to_string(code));
        return false;
    }

    int timeout = large_partition ? 300000 : USB_TIMEOUT_BULK;
    if (!bulk_write_all(data, size, timeout)) return false;

    // Always wait for the post-data ACK, with a reasonable timeout, to avoid leaving it queued in the IN endpoint.
    ThorResponsePacket post = {};
    int post_len = 0;
    int post_timeout = large_partition ? 30000 : 10000;
    if (!receive_packet(&post, sizeof(post), &post_len, true, sizeof(ThorPacketHeader), post_timeout)) {
        log_error("Timed out waiting for post-data ACK");
        return false;
    }
    if (post_len < static_cast<int>(sizeof(ThorResponsePacket))) {
        log_error("Post-data ACK was short (" + std::to_string(post_len) + " bytes)");
        return false;
    }
    uint32_t post_code = le32toh(post.response_code);
    if (le16toh(post.header.packet_type) != THOR_PACKET_RESPONSE || post_code != 0) {
        log_error("File part data ACK reported failure. Code: " + std::to_string(post_code));
        return false;
    }

    return true;
}


bool UsbDevice::send_file_part_header(uint64_t total_size) {
    if (protocol_mode == ProtocolMode::OdinLegacy) return odin_set_total_bytes(total_size);

    ThorFilePartSizePacket size_pkt = {};
    size_pkt.header.packet_size = h_to_le32(sizeof(ThorFilePartSizePacket));
    size_pkt.header.packet_type = h_to_le16(THOR_PACKET_FILE_PART_SIZE);
    size_pkt.header.packet_flags = h_to_le16(0);
    size_pkt.file_part_size = h_to_le64(total_size);

    if (!send_packet(&size_pkt, sizeof(size_pkt), true)) return false;

    ThorResponsePacket response = {};
    int actual_length;
    if (!receive_packet(&response, sizeof(response), &actual_length, true, sizeof(ThorResponsePacket))) return false;

    uint32_t code = 0;
    if (actual_length >= static_cast<int>(sizeof(ThorResponsePacket))) {
        code = le32_to_h(response.response_code);
    }

    if (le16toh(response.header.packet_type) != THOR_PACKET_RESPONSE || code != 0) {
        log_error("Unexpected response sending file part size. Code: " + std::to_string(code));
        return false;
    }
    return true;
}

bool UsbDevice::end_file_transfer(uint32_t partition_id) {
    if (protocol_mode == ProtocolMode::OdinLegacy) {
        // Odin legacy finalisation is handled by the legacy sequence-end commands.
        // Keep this as a no-op to avoid sending THOR packets in legacy mode.
        return true;
    }
    log_info("Finalizing file transfer for partition ID: " + std::to_string(partition_id));
    ThorEndFileTransferPacket pkt = {};
    pkt.header.packet_size = h_to_le32(sizeof(ThorEndFileTransferPacket));
    pkt.header.packet_type = h_to_le16(THOR_PACKET_END_FILE_TRANSFER);
    pkt.header.packet_flags = h_to_le16(0);
    pkt.partition_id = h_to_le32(partition_id);

    if (!send_packet(&pkt, sizeof(pkt), true)) return false;

    ThorResponsePacket response = {};
    int actual_length;
    if (!receive_packet(&response, sizeof(response), &actual_length, true, sizeof(ThorPacketHeader))) return false;

    if (actual_length < static_cast<int>(sizeof(ThorResponsePacket))) {
        log_error("File transfer finalization failed: short response (" + std::to_string(actual_length) + " bytes)");
        return false;
    }
    uint32_t code = le32_to_h(response.response_code);
    if (le16toh(response.header.packet_type) != THOR_PACKET_RESPONSE || code != 0) {
        log_error("File transfer finalization failed. Code: " + std::to_string(code));
        return false;
    }
    log_info("File transfer finalized.");
    return true;
}

bool UsbDevice::send_control(uint32_t control_type) {
    if (protocol_mode == ProtocolMode::OdinLegacy) { if (control_type == THOR_CONTROL_REBOOT) return odin_reboot(); return true; }

    log_info("Sending control command: " + std::to_string(control_type));
    ThorControlPacket pkt = {};
    pkt.header.packet_size = h_to_le32(sizeof(ThorControlPacket));
    pkt.header.packet_type = h_to_le16(THOR_PACKET_CONTROL);
    pkt.header.packet_flags = h_to_le16(0);
    pkt.control_type = h_to_le32(control_type);

    if (!send_packet(&pkt, sizeof(pkt), true)) return false;

    ThorResponsePacket response = {};
    int actual_length;
    if (!receive_packet(&response, sizeof(response), &actual_length, true, sizeof(ThorResponsePacket))) return false;

    uint32_t code = 0;
    if (actual_length >= static_cast<int>(sizeof(ThorResponsePacket))) {
        code = le32_to_h(response.response_code);
    }

    if (le16toh(response.header.packet_type) != THOR_PACKET_RESPONSE || code != 0) {
        log_error("Control command failed. Code: " + std::to_string(code));
        return false;
    }
    log_info("Control command successful.");
    return true;
}


bool UsbDevice::odin_command(uint32_t cmd, uint32_t subcmd, const void* payload, size_t payload_size, std::vector<unsigned char>& rsp, int timeout_ms) {
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

    rsp.assign(8, 0);
    int read_len = 0;
    if (!bulk_read_once(rsp.data(), rsp.size(), &read_len, timeout_ms)) return false;
    if (read_len != 8) {
        log_error("Odin response size mismatch: " + std::to_string(read_len));
        return false;
    }
    return true;
}

bool UsbDevice::odin_fail_check(const std::vector<unsigned char>& rsp, const std::string& context, bool allow_progress) {
    if (rsp.size() < 8) return false;
    if (rsp[0] != 0xFF) return true;

    int32_t code = 0;
    std::memcpy(&code, rsp.data() + 4, sizeof(code));
    code = static_cast<int32_t>(le32toh(static_cast<uint32_t>(code)));

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

    if (allow_progress) {
        // Some bootloaders report intermediate/progress states using 0xFF + a negative code.
        // Treat those as non-fatal when explicitly allowed.
        if (code >= -7 && code <= -2) {
            log_info(context + " progress code " + std::to_string(code) + suffix);
            return true;
        }
    }

    log_error(context + " failed with code " + std::to_string(code) + suffix);
    return false;
}

bool UsbDevice::odin_legacy_handshake() {
    const char preamble[4] = {'O','D','I','N'};
    if (!bulk_write_all(preamble, sizeof(preamble), USB_TIMEOUT_CONTROL)) return false;

    unsigned char reply[4] = {0};
    int actual = 0;
    if (!bulk_read_once(reply, sizeof(reply), &actual, 2000)) return false;
    if (actual != 4) return false;
    if (!(reply[0] == 'L' && reply[1] == 'O' && reply[2] == 'K' && reply[3] == 'E')) return false;
    return true;
}

bool UsbDevice::odin_begin_session() {
    std::vector<unsigned char> rsp;
    int32_t max_proto = 0x7FFFFFFF;
    uint32_t le_max = h_to_le32(static_cast<uint32_t>(max_proto));
    if (!odin_command(0x64, 0x00, &le_max, sizeof(le_max), rsp, 5000)) return false;
    if (!odin_fail_check(rsp, "BeginSession", false)) return false;

    uint16_t version = 0;
    std::memcpy(&version, rsp.data() + 6, sizeof(version));
    version = static_cast<uint16_t>(le16toh(version));

    if (version <= 1) {
        odin_flash_timeout_ms = 30000;
        odin_flash_packet_size = 131072;
        odin_flash_sequence_count = 240;
    } else {
        odin_flash_timeout_ms = 120000;
        odin_flash_packet_size = 1048576;
        odin_flash_sequence_count = 30;

        uint32_t packet_size = h_to_le32(static_cast<uint32_t>(odin_flash_packet_size));
        if (!odin_command(0x64, 0x05, &packet_size, sizeof(packet_size), rsp, 5000)) return false;
        if (!odin_fail_check(rsp, "SendFilePartSize", false)) return false;
    }
    return true;
}

bool UsbDevice::odin_end_session() {
    std::vector<unsigned char> rsp;
    if (!odin_command(0x67, 0x00, nullptr, 0, rsp, 5000)) return false;
    return odin_fail_check(rsp, "EndSession", false);
}

bool UsbDevice::odin_reboot() {
    std::vector<unsigned char> rsp;
    if (!odin_command(0x67, 0x01, nullptr, 0, rsp, 5000)) return false;
    return odin_fail_check(rsp, "Reboot", false);
}

bool UsbDevice::odin_set_total_bytes(uint64_t total_bytes) {
    std::vector<unsigned char> rsp;
    uint64_t le_total = h_to_le64(total_bytes);
    if (!odin_command(0x64, 0x02, &le_total, sizeof(le_total), rsp, 5000)) return false;
    return odin_fail_check(rsp, "SetTotalBytes", false);
}

bool UsbDevice::odin_reset_flash_count() {
    std::vector<unsigned char> rsp;
    if (!odin_command(0x64, 0x01, nullptr, 0, rsp, 5000)) return false;
    return odin_fail_check(rsp, "ResetFlashCount", false);
}

bool UsbDevice::odin_request_file_flash() {
    std::vector<unsigned char> rsp;
    if (!odin_command(0x66, 0x00, nullptr, 0, rsp, 5000)) return false;
    return odin_fail_check(rsp, "RequestFileFlash", false);
}

bool UsbDevice::odin_request_sequence_flash(uint32_t aligned_size) {
    std::vector<unsigned char> rsp;
    uint32_t le_sz = h_to_le32(aligned_size);
    if (!odin_command(0x66, 0x02, &le_sz, sizeof(le_sz), rsp, 5000)) return false;
    return odin_fail_check(rsp, "RequestSequenceFlash", false);
}

bool UsbDevice::odin_send_file_part_and_ack(const unsigned char* data, size_t size, uint32_t expected_index) {
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
        log_error("Bootloader file part index mismatch: expected " + std::to_string(expected_index) + " got " + std::to_string(idx));
        return false;
    }
    return true;
}

bool UsbDevice::odin_end_sequence_flash(const PitEntry& pit_entry, uint32_t real_size, uint32_t is_last) {
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
        w32(16, is_last ? 1u : 0u);
    } else {
        w32(0, 0x00);
        w32(4, real_size);
        w32(8, pit_entry.binary_type);
        w32(12, pit_entry.device_type);
        w32(16, pit_entry.identifier);
        w32(20, is_last ? 1u : 0u);
        w32(24, 0u);
        w32(28, 0u);
    }

    if (!odin_command(0x66, 0x03, payload.data(), 32, rsp, odin_flash_timeout_ms)) return false;
    return odin_fail_check(rsp, "EndSequenceFlash", true);
}

bool UsbDevice::odin_dump_pit(std::vector<unsigned char>& pit_out) {
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
        if (!odin_fail_check(rsp, "PitDumpBlock", false)) return false;

        int got = 0;
        std::vector<unsigned char> data(block, 0);
        if (!bulk_read_once(data.data(), data.size(), &got, 5000)) return false;
        if (got <= 0) return false;

        size_t off = static_cast<size_t>(i) * block;
        size_t copy = std::min(static_cast<size_t>(got), pit_out.size() - off);
        std::memcpy(pit_out.data() + off, data.data(), copy);
    }

    if (!odin_command(0x65, 0x03, nullptr, 0, rsp, 5000)) return false;
    return odin_fail_check(rsp, "EndPitDump", false);
}

bool UsbDevice::flash_partition_stream(std::istream& stream, uint64_t size, const PitEntry& pit_entry, bool large_partition) {
    (void)large_partition;

    if (protocol_mode == ProtocolMode::OdinLegacy) {
        if (!odin_request_file_flash()) return false;

        const uint64_t sequence_bytes = static_cast<uint64_t>(odin_flash_packet_size) * static_cast<uint64_t>(odin_flash_sequence_count);
        if (sequence_bytes == 0) return false;

        const uint64_t sequences64 = (size + sequence_bytes - 1) / sequence_bytes;
        if (sequences64 == 0 || sequences64 > 0xFFFFFFFFull) {
            log_error("Too many legacy sequences for size: " + std::to_string(size));
            return false;
        }
        const uint32_t sequences = static_cast<uint32_t>(sequences64);

        uint64_t last_sequence64 = size - static_cast<uint64_t>(sequences - 1) * sequence_bytes;
        if (last_sequence64 == 0) last_sequence64 = sequence_bytes;
        if (last_sequence64 > 0xFFFFFFFFull) {
            log_error("Legacy last sequence too large: " + std::to_string(last_sequence64));
            return false;
        }
        const uint32_t last_sequence = static_cast<uint32_t>(last_sequence64);

        uint64_t total_sent = 0;
        std::vector<unsigned char> part(static_cast<size_t>(odin_flash_packet_size), 0);

        uint32_t expected_index = 0;
        for (uint32_t i = 0; i < sequences; ++i) {
            const bool last = (i + 1 == sequences);
            const uint32_t real_size = last ? last_sequence : static_cast<uint32_t>(sequence_bytes);
            uint32_t aligned_size = real_size;
            if (aligned_size % static_cast<uint32_t>(odin_flash_packet_size) != 0) {
                aligned_size += static_cast<uint32_t>(odin_flash_packet_size) - (aligned_size % static_cast<uint32_t>(odin_flash_packet_size));
            }

            if (!odin_request_sequence_flash(aligned_size)) return false;

            const uint32_t parts = aligned_size / static_cast<uint32_t>(odin_flash_packet_size);
            for (uint32_t j = 0; j < parts; ++j) {
                std::fill(part.begin(), part.end(), 0);
                stream.read(reinterpret_cast<char*>(part.data()), part.size());
                std::streamsize got = stream.gcount();
                if (got < 0) got = 0;

                if (total_sent + static_cast<uint64_t>(got) > size) {
                    uint64_t remain = size - total_sent;
                    if (remain < static_cast<uint64_t>(part.size())) {
                        for (size_t k = static_cast<size_t>(remain); k < part.size(); ++k) part[k] = 0;
                    }
                }

                if (!odin_send_file_part_and_ack(part.data(), part.size(), expected_index++)) return false;
                total_sent += static_cast<uint64_t>(odin_flash_packet_size);
            }

            if (!odin_end_sequence_flash(pit_entry, real_size, last ? 1u : 0u)) return false;
        }

        return odin_reset_flash_count();
    }

    if (!send_file_part_header(size)) return false;

    const size_t chunk_size = 1024 * 1024;
    std::vector<unsigned char> buf(chunk_size);
    uint64_t remaining = size;
    uint32_t chunk_index = 0;

    while (remaining > 0) {
        size_t to_read = static_cast<size_t>(std::min<uint64_t>(buf.size(), remaining));
        stream.read(reinterpret_cast<char*>(buf.data()), to_read);
        if (static_cast<size_t>(stream.gcount()) != to_read) {
            log_error("Failed to read partition data stream");
            return false;
        }
        if (!send_file_part_chunk(buf.data(), to_read, chunk_index, large_partition)) return false;
        remaining -= to_read;
        chunk_index++;
    }

    return true;
}