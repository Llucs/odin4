#include "usb/usb_device.h"
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
#include <cstdlib>

namespace {
libusb_context* g_libusb_ctx = nullptr;
std::once_flag g_libusb_once;

void cleanup_libusb_context() {
    if (g_libusb_ctx) {
        libusb_exit(g_libusb_ctx);
        g_libusb_ctx = nullptr;
    }
}

bool ensure_libusb_initialized() {
    std::call_once(g_libusb_once, []() {
        int rc = libusb_init(&g_libusb_ctx);
        if (rc != 0) {
            g_libusb_ctx = nullptr;
            return;
        }
        std::atexit(cleanup_libusb_context);
    });
    return g_libusb_ctx != nullptr;
}

int clamp_size_to_int(size_t sz) {
    if (sz > static_cast<size_t>(std::numeric_limits<int>::max())) {
        return std::numeric_limits<int>::max();
    }
    return static_cast<int>(sz);
}
} // namespace

static int retry_backoff_ms(int attempt) {
    int ms = 100;
    for (int i = 0; i < attempt; ++i) {
        ms *= 2;
        if (ms > 1500)
            return 1500;
    }
    return ms;
}

UsbDevice::~UsbDevice() {
    if (handle) {
        libusb_release_interface(handle, interface_number);
        if (kernel_driver_detached) {
            (void) libusb_attach_kernel_driver(handle, interface_number);
            kernel_driver_detached = false;
        }
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
            if (to_send > max_chunk_bytes)
                to_send = max_chunk_bytes;
            int err = libusb_bulk_transfer(handle, endpoint_out, const_cast<unsigned char*>(ptr + offset),
                                           clamp_size_to_int(to_send), &actual_length, timeout_ms);
            if (actual_length > 0) {
                offset += static_cast<size_t>(actual_length);
            }
            if (err != 0) {
                if (err == LIBUSB_ERROR_NO_DEVICE)
                    return false;
                if (err == LIBUSB_ERROR_PIPE)
                    (void) libusb_clear_halt(handle, endpoint_out);
                if (err == LIBUSB_ERROR_PIPE || err == LIBUSB_ERROR_TIMEOUT) {
                    max_chunk_bytes = 0x4000; // 16KB fallback
                }
                break;
            }
            if (actual_length <= 0)
                break;
        }
        if (offset == size) {
            if (odin_supports_zlp && endpoint_out_max_packet != 0 && (size % endpoint_out_max_packet) == 0) {
                send_zlp(timeout_ms);
            }
            return true;
        }
        if (attempt < USB_RETRY_COUNT - 1) {
            std::this_thread::sleep_for(std::chrono::milliseconds(retry_backoff_ms(attempt)));
        }
    }
    return false;
}

bool UsbDevice::send_zlp(int timeout_ms) {
    int actual = 0;
    int err = libusb_bulk_transfer(handle, endpoint_out, nullptr, 0, &actual, timeout_ms);
    return err == 0;
}

bool UsbDevice::bulk_read_once(void* data, size_t size, int* actual_length, int timeout_ms) {
    for (int attempt = 0; attempt < USB_RETRY_COUNT; ++attempt) {
        int err = libusb_bulk_transfer(handle, endpoint_in, static_cast<unsigned char*>(data), clamp_size_to_int(size),
                                       actual_length, timeout_ms);
        if (err == 0)
            return true;
        if (err == LIBUSB_ERROR_NO_DEVICE)
            return false;
        if (err == LIBUSB_ERROR_PIPE)
            (void) libusb_clear_halt(handle, endpoint_in);
        log_error("USB bulk read failed", err);
        if (attempt < USB_RETRY_COUNT - 1) {
            std::this_thread::sleep_for(std::chrono::milliseconds(retry_backoff_ms(attempt)));
        }
    }
    return false;
}

static std::string usb_path_for_device(libusb_device* dev) {
    std::ostringstream oss;
    oss << static_cast<int>(libusb_get_bus_number(dev)) << ":" << static_cast<int>(libusb_get_device_address(dev));
    return oss.str();
}

static std::string normalize_usb_path(const std::string& path) {
    if (path.empty())
        return "";
    // If it's a Linux path like /dev/bus/usb/001/002, convert to 1:2
    if (path.find("/dev/bus/usb/") == 0) {
        std::string sub = path.substr(13);
        size_t slash = sub.find('/');
        if (slash != std::string::npos) {
            try {
                int bus = std::stoi(sub.substr(0, slash));
                int addr = std::stoi(sub.substr(slash + 1));
                return std::to_string(bus) + ":" + std::to_string(addr);
            } catch (...) {
                return path;
            }
        }
    }
    // Already in bus:address format or something else, return as is
    return path;
}

static bool is_known_download_pid(uint16_t pid) {
    for (uint16_t known : SAMSUNG_DOWNLOAD_PIDS) {
        if (pid == known)
            return true;
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
    if (libusb_get_active_config_descriptor(dev, &config) != 0 || !config)
        return best;

    for (int i = 0; i < config->bNumInterfaces; ++i) {
        const libusb_interface* inter = &config->interface[i];
        for (int j = 0; j < inter->num_altsetting; ++j) {
            const libusb_interface_descriptor* id = &inter->altsetting[j];
            if (criteria.has_interface && id->bInterfaceNumber != criteria.interface_number)
                continue;

            uint8_t ep_in = 0;
            uint8_t ep_out = 0;
            uint16_t ep_out_mps = 0;
            int bulk_endpoints = 0;

            for (int k = 0; k < id->bNumEndpoints; ++k) {
                const libusb_endpoint_descriptor* ep = &id->endpoint[k];
                if ((ep->bmAttributes & 0x03) != LIBUSB_TRANSFER_TYPE_BULK)
                    continue;
                ++bulk_endpoints;
                if (ep->bEndpointAddress & 0x80)
                    ep_in = ep->bEndpointAddress;
                else {
                    ep_out = ep->bEndpointAddress;
                    ep_out_mps = ep->wMaxPacketSize;
                }
            }

            if (!ep_in || !ep_out)
                continue;

            int score = 0;
            // Heimdall-style heuristic: CDC Data interface with exactly 2 endpoints.
            if (id->bInterfaceClass == 0x0A && id->bNumEndpoints == 2)
                score += 100;
            // General fallback: any interface with bulk in/out.
            score += 50;
            // Small preference for "clean" configurations.
            if (bulk_endpoints == 2)
                score += 10;

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
        if (kernel_driver_detached) {
            (void) libusb_attach_kernel_driver(handle, interface_number);
            kernel_driver_detached = false;
        }
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
        if (libusb_get_device_descriptor(dev, &desc) != 0)
            continue;

        const uint16_t vid = desc.idVendor;
        const uint16_t pid = desc.idProduct;

        if (criteria.has_vid) {
            if (vid != criteria.vid)
                continue;
        } else {
            if (vid != SAMSUNG_VID)
                continue;
        }

        saw_candidate_vendor = true;

        if (criteria.has_pid && pid != criteria.pid)
            continue;
        if (!specific_path.empty() && usb_path_for_device(dev) != normalize_usb_path(specific_path))
            continue;

        InterfaceCandidate cand = find_best_interface(dev, criteria);
        if (cand.score < 0)
            continue;

        const bool pid_known = is_known_download_pid(pid);
        const bool cdc_data = (cand.interface_class == 0x0A);

        // Default behavior: be conservative and only auto-match devices that look
        // like Samsung Download Mode (known PID or CDC Data bulk interface).
        if (!criteria.has_pid && !criteria.has_vid) {
            if (!pid_known && !cdc_data)
                continue;
        }

        // Prefer known download PIDs when multiple devices match.
        int score = cand.score;
        if (pid_known)
            score += 20;
        if (score > chosen_if.score) {
            chosen_if = cand;
            target = dev;
        }
    }

    if (!target) {
        if (saw_candidate_vendor)
            last_open_error = UsbOpenError::NotDownloadMode;
        else
            last_open_error = UsbOpenError::NoDevice;
        return false;
    }

    int err = libusb_open(target, &handle);
    if (err != 0) {
        if (err == LIBUSB_ERROR_ACCESS)
            last_open_error = UsbOpenError::AccessDenied;
        else if (err == LIBUSB_ERROR_BUSY)
            last_open_error = UsbOpenError::Busy;
        else
            last_open_error = UsbOpenError::Other;
        last_open_libusb_err = err;
        handle = nullptr;
        return false;
    }

    interface_number = chosen_if.interface_number;
    endpoint_in = chosen_if.ep_in;
    endpoint_out = chosen_if.ep_out;
    endpoint_out_max_packet = chosen_if.ep_out_mps;

    if (libusb_has_capability(LIBUSB_CAP_HAS_DETACH_KERNEL_DRIVER)) {
        if (libusb_kernel_driver_active(handle, interface_number) == 1) {
            if (libusb_detach_kernel_driver(handle, interface_number) == 0) {
                kernel_driver_detached = true;
            }
        }
    }

    err = libusb_claim_interface(handle, interface_number);
    if (err != 0) {
        last_open_error = UsbOpenError::Busy;
        last_open_libusb_err = err;
        libusb_close(handle);
        handle = nullptr;
        return false;
    }

    return true;
}

bool UsbDevice::send_packet(const void* data, size_t size, bool is_control) {
    if (is_control) {
        int err = libusb_control_transfer(handle, LIBUSB_REQUEST_TYPE_VENDOR | LIBUSB_RECIPIENT_DEVICE, 0, 0, 0,
                                          static_cast<unsigned char*>(const_cast<void*>(data)), clamp_size_to_int(size),
                                          USB_TIMEOUT_CONTROL);
        return err >= 0;
    }
    return bulk_write_all(data, size, USB_TIMEOUT_BULK);
}

bool UsbDevice::receive_packet(void* data, size_t size, int* actual_length, bool is_control, size_t min_size,
                               int timeout_override_ms) {
    int timeout = timeout_override_ms > 0 ? timeout_override_ms : (is_control ? USB_TIMEOUT_CONTROL : USB_TIMEOUT_BULK);
    if (is_control) {
        int err =
            libusb_control_transfer(handle, LIBUSB_REQUEST_TYPE_VENDOR | LIBUSB_RECIPIENT_DEVICE | LIBUSB_ENDPOINT_IN,
                                    0, 0, 0, static_cast<unsigned char*>(data), clamp_size_to_int(size), timeout);
        if (err >= 0) {
            *actual_length = err;
            return true;
        }
        return false;
    }

    if (size < min_size)
        size = min_size;
    return bulk_read_once(data, size, actual_length, timeout);
}

bool UsbDevice::handshake() {
    log_info("Performing handshake...");
    unsigned char buf[1] = {0};
    if (!send_packet(buf, 0, true))
        return false;

    int actual = 0;
    if (!receive_packet(buf, 1, &actual, true))
        return false;

    // THOR protocol handshake usually involves sending a zero-length control packet
    // and receiving a response. Some devices might return a legacy Odin handshake.
    if (actual == 1 && buf[0] == 'O') {
        log_info("Legacy Odin protocol detected.");
        protocol_mode = ProtocolMode::OdinLegacy;
        return odin_legacy_handshake();
    }

    log_info("Thor protocol detected.");
    protocol_mode = ProtocolMode::Thor;
    return true;
}

bool UsbDevice::request_device_type() {
    if (protocol_mode == ProtocolMode::OdinLegacy) {
        device_type_str = "Legacy";
        return true;
    }

    ThorRequestPacket req = {};
    req.header.packet_size = h_to_le32(sizeof(ThorRequestPacket));
    req.header.packet_type = h_to_le16(THOR_PACKET_REQUEST);
    req.request_type = h_to_le16(THOR_REQUEST_DEVICE_TYPE);

    if (!send_packet(&req, sizeof(req)))
        return false;

    unsigned char rsp_buf[512];
    int actual = 0;
    if (!receive_packet(rsp_buf, sizeof(rsp_buf), &actual))
        return false;

    if (actual < static_cast<int>(sizeof(ThorResponseHeader)))
        return false;

    ThorResponseHeader* hdr = reinterpret_cast<ThorResponseHeader*>(rsp_buf);
    if (le16_to_h(hdr->packet_type) != THOR_PACKET_RESPONSE || le16_to_h(hdr->result) != 0)
        return false;

    if (actual > static_cast<int>(sizeof(ThorResponseHeader))) {
        device_type_str = std::string(reinterpret_cast<char*>(rsp_buf + sizeof(ThorResponseHeader)),
                                      actual - sizeof(ThorResponseHeader));
        // Clean up string (remove nulls or whitespace)
        device_type_str.erase(std::find(device_type_str.begin(), device_type_str.end(), '\0'), device_type_str.end());
    }

    return true;
}

std::vector<std::string> UsbDevice::list_download_devices() {
    UsbSelectionCriteria criteria;
    return list_download_devices(criteria);
}

std::vector<std::string> UsbDevice::list_download_devices(const UsbSelectionCriteria& criteria) {
    std::vector<std::string> result;
    libusb_device** list = nullptr;
    if (!ensure_libusb_initialized())
        return result;
    const ssize_t cnt = libusb_get_device_list(g_libusb_ctx, &list);
    if (cnt < 0)
        return result;

    struct Cleanup {
        libusb_device** l;
        explicit Cleanup(libusb_device** ptr) : l(ptr) {}
        ~Cleanup() {
            if (l)
                libusb_free_device_list(l, 1);
        }
    } cleanup(list);

    for (ssize_t i = 0; i < cnt; ++i) {
        libusb_device* dev = list[i];
        libusb_device_descriptor desc;
        if (libusb_get_device_descriptor(dev, &desc) != 0)
            continue;

        const uint16_t vid = desc.idVendor;
        const uint16_t pid = desc.idProduct;

        if (criteria.has_vid) {
            if (vid != criteria.vid)
                continue;
        } else {
            if (vid != SAMSUNG_VID)
                continue;
        }

        if (criteria.has_pid && pid != criteria.pid)
            continue;

        InterfaceCandidate cand = find_best_interface(dev, criteria);
        if (cand.score < 0)
            continue;

        const bool pid_known = is_known_download_pid(pid);
        const bool cdc_data = (cand.interface_class == 0x0A);
        if (!criteria.has_pid && !criteria.has_vid) {
            if (!pid_known && !cdc_data)
                continue;
        }

        result.push_back(usb_path_for_device(dev));
    }
    return result;
}

bool UsbDevice::begin_session() {
    if (protocol_mode == ProtocolMode::OdinLegacy)
        return odin_begin_session();

    log_info("Beginning session...");
    ThorBeginSessionPacket pkt = {};
    pkt.header.packet_size = h_to_le32(sizeof(ThorBeginSessionPacket));
    pkt.header.packet_type = h_to_le16(THOR_PACKET_BEGIN_SESSION);
    pkt.header.packet_flags = h_to_le16(0);
    pkt.unknown1 = 0;
    pkt.unknown2 = 0;

    if (!send_packet(&pkt, sizeof(pkt)))
        return false;

    unsigned char rsp[512];
    int actual = 0;
    if (!receive_packet(rsp, sizeof(rsp), &actual))
        return false;

    if (actual < static_cast<int>(sizeof(ThorResponseHeader)))
        return false;

    ThorResponseHeader* hdr = reinterpret_cast<ThorResponseHeader*>(rsp);
    return le16_to_h(hdr->packet_type) == THOR_PACKET_RESPONSE && le16_to_h(hdr->result) == 0;
}

bool UsbDevice::end_session() {
    if (protocol_mode == ProtocolMode::OdinLegacy)
        return odin_end_session();

    log_info("Ending session...");
    ThorEndSessionPacket pkt = {};
    pkt.header.packet_size = h_to_le32(sizeof(ThorEndSessionPacket));
    pkt.header.packet_type = h_to_le16(THOR_PACKET_END_SESSION);

    if (!send_packet(&pkt, sizeof(pkt)))
        return false;

    unsigned char rsp[512];
    int actual = 0;
    if (!receive_packet(rsp, sizeof(rsp), &actual))
        return false;

    if (actual < static_cast<int>(sizeof(ThorResponseHeader)))
        return false;

    ThorResponseHeader* hdr = reinterpret_cast<ThorResponseHeader*>(rsp);
    return le16_to_h(hdr->packet_type) == THOR_PACKET_RESPONSE && le16_to_h(hdr->result) == 0;
}

bool UsbDevice::request_pit(PitTable& pit_table) {
    if (protocol_mode == ProtocolMode::OdinLegacy) {
        std::vector<unsigned char> pit_data;
        if (!odin_dump_pit(pit_data))
            return false;
        return pit_table.parse_pit_bytes(pit_data.data(), pit_data.size());
    }

    log_info("Requesting PIT...");
    ThorRequestPacket req = {};
    req.header.packet_size = h_to_le32(sizeof(ThorRequestPacket));
    req.header.packet_type = h_to_le16(THOR_PACKET_REQUEST);
    req.request_type = h_to_le16(THOR_REQUEST_PIT);

    if (!send_packet(&req, sizeof(req)))
        return false;

    return receive_pit_table(pit_table);
}

bool UsbDevice::receive_pit_table(PitTable& pit_table) {
    unsigned char rsp_buf[512];
    int actual = 0;
    if (!receive_packet(rsp_buf, sizeof(rsp_buf), &actual))
        return false;

    if (actual < static_cast<int>(sizeof(ThorResponseHeader)))
        return false;

    ThorResponseHeader* hdr = reinterpret_cast<ThorResponseHeader*>(rsp_buf);
    if (le16_to_h(hdr->packet_type) != THOR_PACKET_RESPONSE || le16_to_h(hdr->result) != 0)
        return false;

    // The PIT data follows the response header or is sent in subsequent packets.
    // This is a simplified implementation.
    std::vector<unsigned char> pit_data;
    if (actual > static_cast<int>(sizeof(ThorResponseHeader))) {
        pit_data.insert(pit_data.end(), rsp_buf + sizeof(ThorResponseHeader), rsp_buf + actual);
    }

    // Continue receiving until we have the full PIT (usually indicated by size in header).
    // For now, we assume it fits in one or two packets for simplicity.
    return pit_table.parse_pit_bytes(pit_data.data(), pit_data.size());
}

bool UsbDevice::send_file_part_header(uint64_t total_size) {
    if (protocol_mode == ProtocolMode::OdinLegacy)
        return true; // Handled differently in legacy

    ThorFilePartHeaderPacket pkt = {};
    pkt.header.packet_size = h_to_le32(sizeof(ThorFilePartHeaderPacket));
    pkt.header.packet_type = h_to_le16(THOR_PACKET_FILE_PART_HEADER);
    pkt.total_size = h_to_le64(total_size);

    return send_packet(&pkt, sizeof(pkt));
}

bool UsbDevice::send_file_part_chunk(const void* data, size_t size, uint32_t chunk_index, bool large_partition) {
    if (protocol_mode == ProtocolMode::OdinLegacy)
        return false; // Should not be called for legacy

    ThorFilePartChunkPacket pkt = {};
    pkt.header.packet_size = h_to_le32(sizeof(ThorFilePartChunkPacket) + size);
    pkt.header.packet_type = h_to_le16(THOR_PACKET_FILE_PART_CHUNK);
    pkt.chunk_index = h_to_le32(chunk_index);
    pkt.chunk_size = h_to_le32(static_cast<uint32_t>(size));

    std::vector<unsigned char> full_pkt(sizeof(ThorFilePartChunkPacket) + size);
    std::memcpy(full_pkt.data(), &pkt, sizeof(pkt));
    std::memcpy(full_pkt.data() + sizeof(pkt), data, size);

    if (!send_packet(full_pkt.data(), full_pkt.size()))
        return false;

    unsigned char rsp[512];
    int actual = 0;
    // Handshake/Ack for each chunk
    return receive_packet(rsp, sizeof(rsp), &actual) && actual >= static_cast<int>(sizeof(ThorResponseHeader));
}

bool UsbDevice::end_file_transfer(uint32_t partition_id) {
    if (protocol_mode == ProtocolMode::OdinLegacy)
        return true;

    ThorFilePartEndPacket pkt = {};
    pkt.header.packet_size = h_to_le32(sizeof(ThorFilePartEndPacket));
    pkt.header.packet_type = h_to_le16(THOR_PACKET_FILE_PART_END);
    pkt.partition_id = h_to_le32(partition_id);

    return send_packet(&pkt, sizeof(pkt));
}

bool UsbDevice::send_control(uint32_t control_type) {
    if (protocol_mode == ProtocolMode::OdinLegacy) {
        if (control_type == THOR_CONTROL_REBOOT)
            return odin_reboot();
        log_warn("Control type not supported in legacy mode.");
        return true;
    }

    ThorControlPacket pkt = {};
    pkt.header.packet_size = h_to_le32(sizeof(ThorControlPacket));
    pkt.header.packet_type = h_to_le16(THOR_PACKET_CONTROL);
    pkt.control_type = h_to_le32(control_type);

    return send_packet(&pkt, sizeof(pkt));
}

bool UsbDevice::notify_total_bytes(uint64_t total) {
    if (protocol_mode == ProtocolMode::OdinLegacy)
        return odin_set_total_bytes(total);

    // Thor doesn't seem to have a direct equivalent of global total bytes notification
    // other than the per-file header.
    return true;
}

// --- Odin Legacy Implementation ---

bool UsbDevice::odin_legacy_handshake() {
    // Legacy Odin handshake is just receiving 'O' 'D' 'I' 'N'
    unsigned char buf[4];
    int actual = 0;
    if (!receive_packet(buf, 4, &actual, true))
        return false;
    return actual == 4 && std::memcmp(buf, "DIN", 3) == 0;
}

bool UsbDevice::odin_command(uint32_t cmd, uint32_t subcmd, const void* payload, size_t payload_size,
                             std::vector<unsigned char>& rsp, int timeout_ms) {
    OdinPacketHeader hdr = {};
    hdr.cmd = h_to_le32(cmd);
    hdr.subcmd = h_to_le32(subcmd);
    hdr.payload_size = h_to_le32(static_cast<uint32_t>(payload_size));

    std::vector<unsigned char> pkt(sizeof(hdr) + payload_size);
    std::memcpy(pkt.data(), &hdr, sizeof(hdr));
    if (payload && payload_size > 0)
        std::memcpy(pkt.data() + sizeof(hdr), payload, payload_size);

    if (!bulk_write_all(pkt.data(), pkt.size(), timeout_ms))
        return false;

    rsp.resize(1024);
    int actual = 0;
    if (!bulk_read_once(rsp.data(), rsp.size(), &actual, timeout_ms))
        return false;
    rsp.resize(static_cast<size_t>(actual));
    return true;
}

bool UsbDevice::odin_fail_check(const std::vector<unsigned char>& rsp, const std::string& context,
                                bool allow_progress) {
    if (rsp.size() < 4) {
        log_error(context + ": Response too short");
        return false;
    }
    uint32_t res = *reinterpret_cast<const uint32_t*>(rsp.data());
    if (res == 0)
        return true;
    if (allow_progress && res == 1)
        return true;
    log_error(context + " failed with error code: " + std::to_string(res));
    return false;
}

bool UsbDevice::odin_begin_session() {
    std::vector<unsigned char> rsp;
    if (!odin_command(0x64, 0x01, nullptr, 0, rsp, 5000))
        return false;
    return odin_fail_check(rsp, "BeginSession", false);
}

bool UsbDevice::odin_end_session() {
    std::vector<unsigned char> rsp;
    if (!odin_command(0x64, 0x03, nullptr, 0, rsp, 5000))
        return false;
    return odin_fail_check(rsp, "EndSession", false);
}

bool UsbDevice::odin_reboot() {
    std::vector<unsigned char> rsp;
    return odin_command(0x64, 0x04, nullptr, 0, rsp, 5000);
}

bool UsbDevice::odin_set_total_bytes(uint64_t total_bytes) {
    uint32_t payload[2];
    payload[0] = h_to_le32(static_cast<uint32_t>(total_bytes & 0xFFFFFFFF));
    payload[1] = h_to_le32(static_cast<uint32_t>(total_bytes >> 32));
    std::vector<unsigned char> rsp;
    if (!odin_command(0x64, 0x02, payload, 8, rsp, 5000))
        return false;
    return odin_fail_check(rsp, "SetTotalBytes", false);
}

bool UsbDevice::odin_reset_flash_count() {
    std::vector<unsigned char> rsp;
    if (!odin_command(0x65, 0x04, nullptr, 0, rsp, 5000))
        return false;
    return odin_fail_check(rsp, "ResetFlashCount", false);
}

bool UsbDevice::odin_request_file_flash() {
    std::vector<unsigned char> rsp;
    if (!odin_command(0x65, 0x01, nullptr, 0, rsp, 5000))
        return false;
    return odin_fail_check(rsp, "RequestFileFlash", false);
}

bool UsbDevice::odin_request_sequence_flash(uint32_t aligned_size) {
    uint32_t payload = h_to_le32(aligned_size);
    std::vector<unsigned char> rsp;
    if (!odin_command(0x65, 0x02, &payload, 4, rsp, 5000))
        return false;
    return odin_fail_check(rsp, "RequestSequenceFlash", false);
}

bool UsbDevice::odin_send_file_part_and_ack(const unsigned char* data, size_t size, uint32_t expected_index) {
    if (!bulk_write_all(data, size, 30000))
        return false;

    std::vector<unsigned char> rsp(4);
    int actual = 0;
    if (!bulk_read_once(rsp.data(), rsp.size(), &actual, 30000))
        return false;
    if (actual != 4)
        return false;
    uint32_t ack = *reinterpret_cast<uint32_t*>(rsp.data());
    return ack == expected_index;
}

bool UsbDevice::odin_end_sequence_flash(const PitEntry& pit_entry, uint32_t real_size, uint32_t is_last) {
    struct {
        uint32_t partition_id;
        uint32_t binary_type;
        uint32_t unknown1;
        uint32_t size;
        uint32_t is_last;
    } payload;

    payload.partition_id = h_to_le32(pit_entry.id);
    payload.binary_type = h_to_le32(pit_entry.binary_type);
    payload.unknown1 = 0;
    payload.size = h_to_le32(real_size);
    payload.is_last = h_to_le32(is_last);

    std::vector<unsigned char> rsp;
    if (!odin_command(0x65, 0x03, &payload, sizeof(payload), rsp, 30000))
        return false;
    return odin_fail_check(rsp, "EndSequenceFlash", false);
}

bool UsbDevice::odin_dump_pit(std::vector<unsigned char>& pit_out) {
    std::vector<unsigned char> rsp;
    if (!odin_command(0x66, 0x01, nullptr, 0, rsp, 5000))
        return false;
    if (!odin_fail_check(rsp, "RequestPitDump", false))
        return false;

    if (rsp.size() < 8)
        return false;
    uint32_t size = *reinterpret_cast<uint32_t*>(rsp.data() + 4);
    pit_out.assign(size, 0);

    uint32_t block = 4096;
    uint32_t count = (size + block - 1) / block;

    for (uint32_t i = 0; i < count; ++i) {
        uint32_t payload = h_to_le32(i);
        if (!odin_command(0x66, 0x02, &payload, 4, rsp, 5000))
            return false;

        int got = 0;
        std::vector<unsigned char> data(block, 0);
        if (!receive_packet(data.data(), data.size(), &got, false, data.size(), 5000))
            return false;
        if (got != static_cast<int>(data.size()))
            return false;

        size_t off = static_cast<size_t>(i) * block;
        size_t copy = std::min(static_cast<size_t>(got), pit_out.size() - off);
        std::memcpy(pit_out.data() + off, data.data(), copy);
    }

    if (!odin_command(0x65, 0x03, nullptr, 0, rsp, 5000))
        return false;
    return odin_fail_check(rsp, "EndPitDump", false);
}

bool UsbDevice::flash_partition_stream(std::istream& stream, uint64_t size, const PitEntry& pit_entry,
                                       bool large_partition) {
    (void) large_partition;
    if (protocol_mode == ProtocolMode::OdinLegacy) {
        if (!odin_request_file_flash())
            return false;

        const size_t sequence_bytes = 1024 * 1024 * 30; // 30MB sequences
        const uint32_t sequences = static_cast<uint32_t>((size + sequence_bytes - 1) / sequence_bytes);
        const uint32_t last_sequence = static_cast<uint32_t>(size % sequence_bytes);

        uint64_t total_sent = 0;
        uint32_t expected_index = 0;
        std::vector<unsigned char> part(odin_flash_packet_size);

        for (uint32_t i = 0; i < sequences; ++i) {
            const bool last = (i + 1 == sequences);
            const uint32_t real_size = last ? last_sequence : static_cast<uint32_t>(sequence_bytes);
            uint32_t aligned_size = real_size;
            if (aligned_size % static_cast<uint32_t>(odin_flash_packet_size) != 0) {
                aligned_size += static_cast<uint32_t>(odin_flash_packet_size) -
                                (aligned_size % static_cast<uint32_t>(odin_flash_packet_size));
            }

            if (!odin_request_sequence_flash(aligned_size))
                return false;

            const uint32_t parts = aligned_size / static_cast<uint32_t>(odin_flash_packet_size);
            for (uint32_t j = 0; j < parts; ++j) {
                std::fill(part.begin(), part.end(), 0);

                uint64_t remaining_file_bytes = 0;
                if (total_sent < size)
                    remaining_file_bytes = size - total_sent;
                const size_t to_read = static_cast<size_t>(std::min<uint64_t>(remaining_file_bytes, part.size()));

                if (to_read > 0) {
                    stream.read(reinterpret_cast<char*>(part.data()), static_cast<std::streamsize>(to_read));
                    if (static_cast<size_t>(stream.gcount()) != to_read)
                        return false;
                }

                if (!odin_send_file_part_and_ack(part.data(), part.size(), expected_index++))
                    return false;
                total_sent += static_cast<uint64_t>(to_read);
            }

            if (!odin_end_sequence_flash(pit_entry, real_size, last ? 1u : 0u))
                return false;
        }

        return odin_reset_flash_count();
    }

    if (!send_file_part_header(size))
        return false;

    const size_t chunk_size = 1024 * 1024;
    std::vector<unsigned char> buf(chunk_size);
    uint64_t remaining = size;
    uint32_t chunk_index = 0;

    uint64_t sent = 0;
    int last_pct = -1;

    while (remaining > 0) {
        size_t to_read = static_cast<size_t>(std::min<uint64_t>(buf.size(), remaining));
        stream.read(reinterpret_cast<char*>(buf.data()), to_read);
        if (static_cast<size_t>(stream.gcount()) != to_read) {
            log_error("Failed to read partition data stream");
            return false;
        }
        if (!send_file_part_chunk(buf.data(), to_read, chunk_index, large_partition))
            return false;
        remaining -= to_read;
        sent += to_read;
        chunk_index++;

        if (size > 0) {
            int pct = static_cast<int>((sent * 100) / size);
            if (pct != last_pct) {
                log_info("Flashing: " + std::to_string(pct) + "%");
                last_pct = pct;
            }
        }
    }

    return true;
}
