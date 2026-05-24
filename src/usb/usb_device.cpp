/*
 * Copyright (c) 2026 Llucs
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "usb/usb_device.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <thread>
#include <chrono>
#include <cstring>
#include <vector>
#include <algorithm>
#include <ranges>
#include <cctype>
#include <unordered_set>
#include <limits>
#include <format>
#include <mutex>
#include <cstdlib>

namespace {
libusb_context* g_libusb_ctx = nullptr;
std::once_flag g_libusb_once;

void cleanup_libusb_context() {
    if (g_libusb_ctx != nullptr) {
        libusb_exit(g_libusb_ctx);
        g_libusb_ctx = nullptr;
    }
}

auto ensure_libusb_initialized() -> bool {
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

auto clamp_size_to_int(size_t sz) -> int {
    if (sz > static_cast<size_t>(std::numeric_limits<int>::max())) {
        return std::numeric_limits<int>::max();
    }
    return static_cast<int>(sz);
}
} // namespace

static auto retry_backoff_ms(int attempt) -> int {
    int ms = 100;
    for (int i = 0; i < attempt; ++i) {
        ms *= 2;
        if (ms > 1500) {
            return 1500;
        }
    }
    return ms;
}

UsbDevice::~UsbDevice() {
    if (handle != nullptr) {
        libusb_release_interface(handle, interface_number);
        if (kernel_driver_detached) {
            (void) libusb_attach_kernel_driver(handle, interface_number);
            kernel_driver_detached = false;
        }
        libusb_close(handle);
        handle = nullptr;
    }
    if (device_list != nullptr) {
        libusb_free_device_list(device_list, 1);
        device_list = nullptr;
    }
}

auto UsbDevice::bulk_write_all(const void* data, size_t size, int timeout_ms) -> bool {
    const auto* ptr = static_cast<const unsigned char*>(data);
    size_t offset = 0;
    for (int attempt = 0; attempt < USB_RETRY_COUNT; ++attempt) {
        while (offset < size) {
            int actual_length = 0;
            size_t to_send = size - offset;
            if (to_send > max_chunk_bytes) {
                to_send = max_chunk_bytes;
            }
            int err = libusb_bulk_transfer(handle, endpoint_out, const_cast<unsigned char*>(ptr + offset),
                                           clamp_size_to_int(to_send), &actual_length, timeout_ms);
            if (actual_length > 0) {
                offset += static_cast<size_t>(actual_length);
            }
            if (err != 0) {
                if (err == LIBUSB_ERROR_NO_DEVICE) {
                    return false;
                }
                if (err == LIBUSB_ERROR_PIPE) {
                    (void) libusb_clear_halt(handle, endpoint_out);
                }
                if (err == LIBUSB_ERROR_PIPE || err == LIBUSB_ERROR_TIMEOUT) {
                    max_chunk_bytes = 0x4000; // 16KB fallback
                }
                break;
            }
            if (actual_length <= 0) {
                break;
            }
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

auto UsbDevice::send_zlp(int timeout_ms) -> bool {
    int actual = 0;
    int err = libusb_bulk_transfer(handle, endpoint_out, nullptr, 0, &actual, timeout_ms);
    return err == 0;
}

auto UsbDevice::bulk_read_once(void* data, size_t size, int* actual_length, int timeout_ms) -> bool {
    for (int attempt = 0; attempt < USB_RETRY_COUNT; ++attempt) {
        int err = libusb_bulk_transfer(handle, endpoint_in, static_cast<unsigned char*>(data), clamp_size_to_int(size),
                                       actual_length, timeout_ms);
        if (err == 0) {
            return true;
        }
        if (err == LIBUSB_ERROR_NO_DEVICE) {
            return false;
        }
        if (err == LIBUSB_ERROR_PIPE) {
            (void) libusb_clear_halt(handle, endpoint_in);
        }
        log_error(std::format("USB bulk read failed (error: {})", static_cast<int>(err)));
        if (attempt < USB_RETRY_COUNT - 1) {
            std::this_thread::sleep_for(std::chrono::milliseconds(retry_backoff_ms(attempt)));
        }
    }
    return false;
}

static auto usb_path_for_device(libusb_device* dev) -> std::string {
    std::ostringstream oss;
    oss << "/dev/bus/usb/" << std::setfill('0') << std::setw(3) << static_cast<int>(libusb_get_bus_number(dev)) << "/"
        << std::setfill('0') << std::setw(3) << static_cast<int>(libusb_get_device_address(dev));
    return oss.str();
}

static auto is_known_download_pid(uint16_t pid) -> bool {
    return std::ranges::any_of(SAMSUNG_DOWNLOAD_PIDS, [pid](uint16_t known) { return pid == known; });
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

static auto find_best_interface(libusb_device* dev, const UsbSelectionCriteria& criteria) -> InterfaceCandidate {
    InterfaceCandidate best;
    libusb_config_descriptor* config = nullptr;
    if (libusb_get_active_config_descriptor(dev, &config) != 0 || (config == nullptr)) {
        return best;
    }

    for (int i = 0; i < config->bNumInterfaces; ++i) {
        const libusb_interface* inter = &config->interface[i];
        for (int j = 0; j < inter->num_altsetting; ++j) {
            const libusb_interface_descriptor* id = &inter->altsetting[j];
            if (criteria.has_interface && id->bInterfaceNumber != criteria.interface_number) {
                continue;
            }

            uint8_t ep_in = 0;
            uint8_t ep_out = 0;
            uint16_t ep_out_mps = 0;
            int bulk_endpoints = 0;

            for (int k = 0; k < id->bNumEndpoints; ++k) {
                const libusb_endpoint_descriptor* ep = &id->endpoint[k];
                if ((ep->bmAttributes & 0x03) != LIBUSB_TRANSFER_TYPE_BULK) {
                    continue;
                }
                ++bulk_endpoints;
                if ((ep->bEndpointAddress & 0x80) != 0) {
                    ep_in = ep->bEndpointAddress;
                } else {
                    ep_out = ep->bEndpointAddress;
                    ep_out_mps = ep->wMaxPacketSize;
                }
            }

            if ((ep_in == 0U) || (ep_out == 0U)) {
                continue;
            }

            int score = 0;
            // Heimdall-style heuristic: CDC Data interface with exactly 2 endpoints.
            if (id->bInterfaceClass == 0x0A && id->bNumEndpoints == 2) {
                score += 100;
            }
            // General fallback: any interface with bulk in/out.
            score += 50;
            // Small preference for "clean" configurations.
            if (bulk_endpoints == 2) {
                score += 10;
            }

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

auto UsbDevice::open_device(const std::string& specific_path) -> bool {
    UsbSelectionCriteria criteria;
    return open_device(specific_path, criteria);
}

auto UsbDevice::open_device(const std::string& specific_path, const UsbSelectionCriteria& criteria) -> bool {
    // Reset open-status fields for this attempt. Any early return below must
    // leave these members describing the current failure (if any).
    last_open_error = UsbOpenError::None;
    last_open_libusb_err = 0;

    // Tear down any previously opened handle/interface so this call starts from
    // a clean state. If we detached a kernel driver earlier, attempt to restore
    // it before closing the handle.
    if (handle != nullptr) {
        libusb_release_interface(handle, interface_number);
        if (kernel_driver_detached) {
            (void) libusb_attach_kernel_driver(handle, interface_number);
            kernel_driver_detached = false;
        }
        libusb_close(handle);
        handle = nullptr;
    }

    // Free any stale enumeration results from a prior open attempt.
    if (device_list != nullptr) {
        libusb_free_device_list(device_list, 1);
        device_list = nullptr;
    }

    // Ensure the process-wide libusb context exists before enumeration.
    if (!ensure_libusb_initialized()) {
        last_open_error = UsbOpenError::Other;
        last_open_libusb_err = LIBUSB_ERROR_OTHER;
        log_error(std::format("Failed to enumerate USB devices (error: {})", static_cast<int>(LIBUSB_ERROR_OTHER)));
        return false;
    }

    // Enumerate all currently visible USB devices. The resulting device list is
    // consumed by the matching/selection logic in the remainder of this method.
    ssize_t cnt = libusb_get_device_list(g_libusb_ctx, &device_list);
    if (cnt < 0) {
        last_open_error = UsbOpenError::Other;
        last_open_libusb_err = static_cast<int>(cnt);
        log_error(std::format("Failed to enumerate USB devices (error: {})", static_cast<int>(cnt)));
        return false;
    }

    libusb_device* target = nullptr;
    InterfaceCandidate chosen_if;
    bool saw_candidate_vendor = false;

    for (ssize_t i = 0; i < cnt; ++i) {
        libusb_device* dev = device_list[i];
        libusb_device_descriptor desc;
        if (libusb_get_device_descriptor(dev, &desc) != 0) {
            continue;
        }

        const uint16_t vid = desc.idVendor;
        const uint16_t pid = desc.idProduct;

        if (criteria.has_vid) {
            if (vid != criteria.vid) {
                continue;
            }
        } else {
            if (vid != SAMSUNG_VID) {
                continue;
            }
        }

        saw_candidate_vendor = true;

        if (criteria.has_pid && pid != criteria.pid) {
            continue;
        }
        if (!specific_path.empty() && usb_path_for_device(dev) != specific_path) {
            continue;
        }

        InterfaceCandidate cand = find_best_interface(dev, criteria);
        if (cand.score < 0) {
            continue;
        }

        const bool pid_known = is_known_download_pid(pid);
        const bool cdc_data = (cand.interface_class == 0x0A);

        // Default behavior: be conservative and only auto-match devices that look
        // like Samsung Download Mode (known PID or CDC Data bulk interface).
        if (!criteria.has_pid && !criteria.has_vid) {
            if (!pid_known && !cdc_data) {
                continue;
            }
        }

        // Prefer known download PIDs when multiple devices match.
        int score = cand.score;
        if (pid_known) {
            score += 20;
        }
        if (score > chosen_if.score) {
            chosen_if = cand;
            target = dev;
        }
    }

    if (target == nullptr) {
        last_open_error = saw_candidate_vendor ? UsbOpenError::NotDownloadMode : UsbOpenError::NoDevice;
        log_warn("No compatible device found. Ensure the device is connected and in Download Mode.");
        return false;
    }

    endpoint_in = chosen_if.ep_in;
    endpoint_out = chosen_if.ep_out;
    if (chosen_if.ep_out_mps != 0) {
        endpoint_out_max_packet = chosen_if.ep_out_mps;
    }
    interface_number = chosen_if.interface_number;
    kernel_driver_detached = false;

    const int open_err = libusb_open(target, &handle);
    if (open_err < 0 || (handle == nullptr)) {
        last_open_libusb_err = open_err;
        if (open_err == LIBUSB_ERROR_ACCESS) {
            last_open_error = UsbOpenError::AccessDenied;
        } else if (open_err == LIBUSB_ERROR_BUSY) {
            last_open_error = UsbOpenError::Busy;
        } else {
            last_open_error = UsbOpenError::Other;
        }
        log_error("Failed to open USB device", open_err);
        return false;
    }

    const int kernel_driver_state = libusb_kernel_driver_active(handle, interface_number);
    if (kernel_driver_state < 0) {
        last_open_libusb_err = kernel_driver_state;
        last_open_error =
            (kernel_driver_state == LIBUSB_ERROR_ACCESS) ? UsbOpenError::AccessDenied : UsbOpenError::Other;
        log_error("Failed to claim USB interface", kernel_driver_state);
        libusb_close(handle);
        handle = nullptr;
        return false;
    }
    if (kernel_driver_state == 1) {
        const int detach_err = libusb_detach_kernel_driver(handle, interface_number);
        if (detach_err < 0) {
            last_open_error = (detach_err == LIBUSB_ERROR_ACCESS) ? UsbOpenError::AccessDenied : UsbOpenError::Other;
            last_open_libusb_err = detach_err;
            log_error("Failed to detach kernel driver", detach_err);
            libusb_close(handle);
            handle = nullptr;
            return false;
        }
        kernel_driver_detached = true;
    }

    const int claim_err = libusb_claim_interface(handle, interface_number);
    if (claim_err < 0) {
        last_open_libusb_err = claim_err;
        if (claim_err == LIBUSB_ERROR_ACCESS) {
            last_open_error = UsbOpenError::AccessDenied;
        } else {
            last_open_error = UsbOpenError::Other;
        }
        log_error("Failed to claim USB interface", claim_err);
        if (kernel_driver_detached) {
            (void) libusb_attach_kernel_driver(handle, interface_number);
            kernel_driver_detached = false;
        }
        libusb_close(handle);
        handle = nullptr;
        return false;
    }

    std::ostringstream oss;
    oss << "USB device opened. Path: " << usb_path_for_device(target) << ", Interface: " << interface_number
        << ", EP IN: 0x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(endpoint_in)
        << ", EP OUT: 0x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(endpoint_out) << std::dec
        << ", OUT wMaxPacketSize: " << endpoint_out_max_packet;
    log_info(oss.str());
    return true;
}

auto UsbDevice::send_packet(const void* data, size_t size, bool is_control) -> bool {
    int timeout = is_control ? USB_TIMEOUT_CONTROL : USB_TIMEOUT_BULK;
    if (!bulk_write_all(data, size, timeout)) {
        return false;
    }
    if (is_control) {
        log_hexdump("Packet Sent (Control)", data, size);
    }
    return true;
}

auto UsbDevice::receive_packet(void* data, size_t size, int* actual_length, bool is_control, size_t min_size,
                               int timeout_override_ms) -> bool {
    int timeout = timeout_override_ms > 0 ? timeout_override_ms : (is_control ? USB_TIMEOUT_CONTROL : USB_TIMEOUT_BULK);
    size_t required_min = (min_size == 0) ? size : min_size;

    for (int attempt = 0; attempt < USB_RETRY_COUNT; ++attempt) {
        size_t received = 0;
        *actual_length = 0;

        while (received < required_min && received < size) {
            int chunk = 0;
            const size_t remaining = size - received;
            int err = libusb_bulk_transfer(handle, endpoint_in, static_cast<unsigned char*>(data) + received,
                                           clamp_size_to_int(remaining), &chunk, timeout);

            if (chunk > 0) {
                received += static_cast<size_t>(chunk);
                *actual_length = static_cast<int>(received);
            }

            if (err == 0) {
                if (received >= required_min) {
                    break;
                }
                if (chunk <= 0) {
                    break;
                }
                continue;
            }

            if (err == LIBUSB_ERROR_PIPE) {
                (void) libusb_clear_halt(handle, endpoint_in);
            }
            if (err == LIBUSB_ERROR_TIMEOUT) {
                if (timeout_override_ms > 0 || attempt == USB_RETRY_COUNT - 1) {
                    return false;
                }
                break;
            }
            log_error("USB packet receive failed (attempt " + std::to_string(attempt + 1) + ")", err);
            if (err == LIBUSB_ERROR_NO_DEVICE) {
                return false;
            }
            break;
        }

        if (received >= required_min && received <= size) {
            if (is_control) {
                log_hexdump("Packet Received (Control)", data, received);
            }
            return true;
        }

        log_error("Incorrect receive size (attempt " + std::to_string(attempt + 1) + "): expected min " +
                  std::to_string(required_min) + ", max " + std::to_string(size) + ", received " +
                  std::to_string(received));

        if (attempt < USB_RETRY_COUNT - 1) {
            std::this_thread::sleep_for(std::chrono::milliseconds(retry_backoff_ms(attempt)));
        }
    }

    return false;
}

auto UsbDevice::handshake() -> bool {
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

    if (!send_packet(&handshake_pkt, sizeof(handshake_pkt), true)) {
        return false;
    }

    ThorResponsePacket rsp = {};
    int actual_length = 0;
    if (!receive_packet(&rsp, sizeof(rsp), &actual_length, true, sizeof(rsp))) {
        return false;
    }
    if (le16toh(rsp.header.packet_type) != THOR_PACKET_RESPONSE) {
        log_error(std::format("Handshake failed with unexpected packet type: {}", le16toh(rsp.header.packet_type)));
        return false;
    }
    uint32_t code = le32_to_h(rsp.response_code);
    if (code != 0) {
        log_error(std::format("Handshake failed with response code: {}", code));
        return false;
    }
    return true;
}

auto UsbDevice::request_device_type() -> bool {
    if (protocol_mode == ProtocolMode::OdinLegacy) {
        device_type_str.clear();
        return true;
    }

    log_info("Requesting device type...");
    ThorPacketHeader pkt = {};
    pkt.packet_size = h_to_le32(sizeof(ThorPacketHeader));
    pkt.packet_type = h_to_le16(THOR_PACKET_DEVICE_TYPE);
    pkt.packet_flags = h_to_le16(0);

    if (!send_packet(&pkt, sizeof(pkt), true)) {
        return false;
    }

    ThorDeviceTypePacket response = {};
    int actual_length;
    if (!receive_packet(&response, sizeof(response), &actual_length, true, sizeof(response))) {
        return false;
    }

    if (le16toh(response.header.packet_type) != THOR_PACKET_DEVICE_TYPE) {
        log_error(std::format("Device type request failed. Unexpected packet type: {}",
                              le16toh(response.header.packet_type)));
        return false;
    }
    // Copy the device type string from the response. The char array is
    // null-terminated or zero-padded. Convert to a std::string and trim
    // trailing null bytes.
    device_type_str.clear();
    for (char c : response.device_type) {
        if (c == '\0') {
            break;
        }
        device_type_str.push_back(c);
    }
    log_info(std::format("Device type received: {}", device_type_str));
    return true;
}

auto UsbDevice::list_download_devices() -> std::vector<std::string> {
    UsbSelectionCriteria criteria;
    return list_download_devices(criteria);
}

auto UsbDevice::list_download_devices(const UsbSelectionCriteria& criteria) -> std::vector<std::string> {
    std::vector<std::string> result;
    libusb_device** list = nullptr;
    if (!ensure_libusb_initialized()) {
        return result;
    }
    const ssize_t cnt = libusb_get_device_list(g_libusb_ctx, &list);
    if (cnt < 0) {
        return result;
    }

    struct Cleanup {
        libusb_device** l;
        explicit Cleanup(libusb_device** ptr) : l(ptr) {}
        ~Cleanup() {
            if (l != nullptr) {
                libusb_free_device_list(l, 1);
            }
        }
    } cleanup(list);

    for (ssize_t i = 0; i < cnt; ++i) {
        libusb_device* dev = list[i];
        libusb_device_descriptor desc;
        if (libusb_get_device_descriptor(dev, &desc) != 0) {
            continue;
        }

        const uint16_t vid = desc.idVendor;
        const uint16_t pid = desc.idProduct;

        if (criteria.has_vid) {
            if (vid != criteria.vid) {
                continue;
            }
        } else {
            if (vid != SAMSUNG_VID) {
                continue;
            }
        }

        if (criteria.has_pid && pid != criteria.pid) {
            continue;
        }

        InterfaceCandidate cand = find_best_interface(dev, criteria);
        if (cand.score < 0) {
            continue;
        }

        const bool pid_known = is_known_download_pid(pid);
        const bool cdc_data = (cand.interface_class == 0x0A);
        if (!criteria.has_pid && !criteria.has_vid) {
            if (!pid_known && !cdc_data) {
                continue;
            }
        }

        result.push_back(usb_path_for_device(dev));
    }
    return result;
}

auto UsbDevice::begin_session() -> bool {
    if (protocol_mode == ProtocolMode::OdinLegacy) {
        return odin_begin_session();
    }

    log_info("Beginning session...");
    ThorBeginSessionPacket pkt = {};
    pkt.header.packet_size = h_to_le32(sizeof(ThorBeginSessionPacket));
    pkt.header.packet_type = h_to_le16(THOR_PACKET_BEGIN_SESSION);
    pkt.header.packet_flags = h_to_le16(0);
    pkt.unknown1 = 0;
    pkt.unknown2 = 0;

    if (!send_packet(&pkt, sizeof(pkt), true)) {
        return false;
    }

    ThorResponsePacket response = {};
    int actual_length;
    if (!receive_packet(&response, sizeof(response), &actual_length, true, sizeof(ThorPacketHeader))) {
        return false;
    }

    if (actual_length < static_cast<int>(sizeof(ThorResponsePacket))) {
        log_error(std::format("Session begin failed: short response ({} bytes)", actual_length));
        return false;
    }

    uint32_t code = le32_to_h(response.response_code);
    if (le16toh(response.header.packet_type) != THOR_PACKET_RESPONSE || code != 0) {
        log_error(std::format("Session begin failed. Response code: {}", code));
        return false;
    }
    log_info("Session started successfully.");
    return true;
}

auto UsbDevice::end_session() -> bool {
    if (protocol_mode == ProtocolMode::OdinLegacy) {
        return odin_end_session();
    }

    log_info("Ending session...");
    ThorEndSessionPacket pkt = {};
    pkt.header.packet_size = h_to_le32(sizeof(ThorEndSessionPacket));
    pkt.header.packet_type = h_to_le16(THOR_PACKET_END_SESSION);
    pkt.header.packet_flags = h_to_le16(0);

    if (!send_packet(&pkt, sizeof(pkt), true)) {
        return false;
    }

    ThorResponsePacket response = {};
    int actual_length;
    if (!receive_packet(&response, sizeof(response), &actual_length, true, sizeof(ThorPacketHeader))) {
        return false;
    }

    if (actual_length < static_cast<int>(sizeof(ThorResponsePacket))) {
        log_error(std::format("Session end failed: short response ({} bytes)", actual_length));
        return false;
    }

    uint32_t code = le32_to_h(response.response_code);
    if (le16toh(response.header.packet_type) != THOR_PACKET_RESPONSE || code != 0) {
        log_error(std::format("Session end failed. Response code: {}", code));
        return false;
    }
    log_info("Session ended successfully.");
    return true;
}

/**
 * Parse raw PIT bytes into a PitTable structure.
 *
 * The PIT payload is expected to be a little-endian binary structure with a fixed
 * header and one or more entry records. This function validates the file identifier
 * and structural constraints before populating `pit_table`.
 *
 * Returns true only when the full payload is structurally valid and all required
 * fields are parsed successfully. Any malformed/truncated input is logged and
 * results in false.
 */
static auto parse_pit_bytes(PitTable& pit_table, const std::vector<unsigned char>& pit_data) -> bool {
    // Minimum PIT header size check before any offset-based reads.
    if (pit_data.size() < 28) {
        log_error(std::format("PIT data too small: {}", pit_data.size()));
        return false;
    }

    // Helpers for little-endian primitive reads from byte offsets.
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

    // Validate PIT magic/file identifier.
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
        log_error(std::format("PIT truncated: expected at least {} bytes", required));
        return false;
    }

    pit_table.entries.clear();
    pit_table.entries.reserve(pit_table.entry_count);

    auto extract_field = [](const char* field, size_t max_len) -> std::string {
        size_t n = 0;
        while (n < max_len && field[n] != '\0') {
            ++n;
        }
        std::string s(field, n);
        while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) {
            s.pop_back();
        }
        return s;
    };

    auto is_valid_pit_string = [](const std::string& s) -> bool {
        for (unsigned char c : s) {
            if (c < 0x20 || c > 0x7E) {
                return false;
            }
            if (c == '/' || c == '\\') {
                return false;
            }
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

        // Do NOT force-null-terminate here; treat these as fixed 32-byte fields.
        pit_table.entries.push_back(e);
    }

    log_info(std::format("Received PIT entries: {}", pit_table.entry_count));
    return true;
}

auto UsbDevice::request_pit(PitTable& pit_table) -> bool {
    if (protocol_mode == ProtocolMode::OdinLegacy) {
        std::vector<unsigned char> pit;
        if (!odin_dump_pit(pit)) {
            return false;
        }
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
    if (!send_packet(&pkt, sizeof(pkt), true)) {
        return false;
    }
    return receive_pit_table(pit_table);
}

auto UsbDevice::receive_pit_table(PitTable& pit_table) -> bool {
    ThorPitFilePacket pit_size_pkt = {};
    int actual_length = 0;
    if (!receive_packet(&pit_size_pkt, sizeof(pit_size_pkt), &actual_length, true, sizeof(pit_size_pkt))) {
        return false;
    }

    if (actual_length < static_cast<int>(sizeof(ThorPitFilePacket))) {
        log_error(std::format("Short PIT size packet ({} bytes)", actual_length));
        return false;
    }

    if (le16toh(pit_size_pkt.header.packet_type) != THOR_PACKET_PIT_FILE) {
        log_error(
            std::format("Unexpected packet type while reading PIT size: {}", le16toh(pit_size_pkt.header.packet_type)));
        return false;
    }

    uint32_t pit_data_size = le32_to_h(pit_size_pkt.pit_file_size);
    if (pit_data_size < 28 || pit_data_size > 1048576) {
        log_error(std::format("Invalid PIT size: {}", pit_data_size));
        return false;
    }

    std::vector<unsigned char> pit_data(pit_data_size);
    if (!receive_packet(pit_data.data(), pit_data_size, &actual_length, false, pit_data_size)) {
        log_error("Failed to receive PIT data");
        return false;
    }

    return parse_pit_bytes(pit_table, pit_data);
}

auto UsbDevice::send_file_part_chunk(const void* data, size_t size, uint32_t chunk_index,
                                     bool large_partition) -> bool {
    ThorFilePartPacket part_pkt = {};
    part_pkt.header.packet_size = h_to_le32(sizeof(ThorFilePartPacket));
    part_pkt.header.packet_type = h_to_le16(THOR_PACKET_FILE_PART);
    part_pkt.header.packet_flags = h_to_le16(0);
    part_pkt.file_part_index = h_to_le32(chunk_index);
    part_pkt.file_part_size = h_to_le32(static_cast<uint32_t>(size));

    if (!send_packet(&part_pkt, sizeof(part_pkt), true)) {
        return false;
    }

    ThorResponsePacket response = {};
    int actual_length = 0;
    if (!receive_packet(&response, sizeof(response), &actual_length, true, sizeof(ThorPacketHeader))) {
        return false;
    }

    if (actual_length < static_cast<int>(sizeof(ThorResponsePacket))) {
        log_error(std::format("File part control failed: short response ({} bytes)", actual_length));
        return false;
    }
    uint32_t code = le32toh(response.response_code);
    if (le16toh(response.header.packet_type) != THOR_PACKET_RESPONSE || code != 0) {
        log_error("File part control failed. Code: " + std::to_string(code));
        return false;
    }

    int timeout = large_partition ? 300000 : USB_TIMEOUT_BULK;
    if (!bulk_write_all(data, size, timeout)) {
        return false;
    }

    // Always wait for the post-data ACK, with a reasonable timeout, to avoid leaving it queued in the IN endpoint.
    ThorResponsePacket post = {};
    int post_len = 0;
    int post_timeout = large_partition ? 30000 : 10000;
    if (!receive_packet(&post, sizeof(post), &post_len, true, sizeof(ThorPacketHeader), post_timeout)) {
        log_error("Timed out waiting for post-data ACK");
        return false;
    }
    if (post_len < static_cast<int>(sizeof(ThorResponsePacket))) {
        log_error(std::format("Post-data ACK was short ({} bytes)", post_len));
        return false;
    }
    uint32_t post_code = le32toh(post.response_code);
    if (le16toh(post.header.packet_type) != THOR_PACKET_RESPONSE || post_code != 0) {
        log_error(std::format("File part data ACK reported failure. Code: {}", post_code));
        return false;
    }

    return true;
}

auto UsbDevice::notify_total_bytes(uint64_t total) -> bool {
    if (protocol_mode != ProtocolMode::OdinLegacy) {
        return true;
    }
    return odin_set_total_bytes(total);
}

auto UsbDevice::send_file_part_header(uint64_t total_size) -> bool {
    if (protocol_mode == ProtocolMode::OdinLegacy) {
        return true;
    }

    ThorFilePartSizePacket size_pkt = {};
    size_pkt.header.packet_size = h_to_le32(sizeof(ThorFilePartSizePacket));
    size_pkt.header.packet_type = h_to_le16(THOR_PACKET_FILE_PART_SIZE);
    size_pkt.header.packet_flags = h_to_le16(0);
    size_pkt.file_part_size = h_to_le64(total_size);

    if (!send_packet(&size_pkt, sizeof(size_pkt), true)) {
        return false;
    }

    ThorResponsePacket response = {};
    int actual_length;
    if (!receive_packet(&response, sizeof(response), &actual_length, true, sizeof(ThorResponsePacket))) {
        return false;
    }

    uint32_t code = 0;
    if (actual_length >= static_cast<int>(sizeof(ThorResponsePacket))) {
        code = le32_to_h(response.response_code);
    }

    if (le16toh(response.header.packet_type) != THOR_PACKET_RESPONSE || code != 0) {
        log_error(std::format("Unexpected response sending file part size. Code: {}", code));
        return false;
    }
    return true;
}

auto UsbDevice::end_file_transfer(uint32_t partition_id) -> bool {
    if (protocol_mode == ProtocolMode::OdinLegacy) {
        // Odin legacy finalisation is handled by the legacy sequence-end commands.
        // Keep this as a no-op to avoid sending THOR packets in legacy mode.
        return true;
    }
    log_info(std::format("Finalizing file transfer for partition ID: {}", partition_id));
    ThorEndFileTransferPacket pkt = {};
    pkt.header.packet_size = h_to_le32(sizeof(ThorEndFileTransferPacket));
    pkt.header.packet_type = h_to_le16(THOR_PACKET_END_FILE_TRANSFER);
    pkt.header.packet_flags = h_to_le16(0);
    pkt.partition_id = h_to_le32(partition_id);

    if (!send_packet(&pkt, sizeof(pkt), true)) {
        return false;
    }

    ThorResponsePacket response = {};
    int actual_length;
    if (!receive_packet(&response, sizeof(response), &actual_length, true, sizeof(ThorPacketHeader))) {
        return false;
    }

    if (actual_length < static_cast<int>(sizeof(ThorResponsePacket))) {
        log_error(std::format("File transfer finalization failed: short response ({} bytes)", actual_length));
        return false;
    }
    uint32_t code = le32_to_h(response.response_code);
    if (le16toh(response.header.packet_type) != THOR_PACKET_RESPONSE || code != 0) {
        log_error(std::format("File transfer finalization failed. Code: {}", code));
        return false;
    }
    log_info("File transfer finalized.");
    return true;
}

auto UsbDevice::send_control(uint32_t control_type) -> bool {
    if (protocol_mode == ProtocolMode::OdinLegacy) {
        if (control_type == THOR_CONTROL_REBOOT) {
            (void) odin_end_session();
            return odin_reboot();
        }
        if (control_type == THOR_CONTROL_REDOWNLOAD) {
            log_warn("Redownload is not supported in Odin legacy mode.");
        }
        return true;
    }

    log_info(std::format("Sending control command: {}", control_type));
    ThorControlPacket pkt = {};
    pkt.header.packet_size = h_to_le32(sizeof(ThorControlPacket));
    pkt.header.packet_type = h_to_le16(THOR_PACKET_CONTROL);
    pkt.header.packet_flags = h_to_le16(0);
    pkt.control_type = h_to_le32(control_type);

    if (!send_packet(&pkt, sizeof(pkt), true)) {
        return false;
    }

    ThorResponsePacket response = {};
    int actual_length;
    if (!receive_packet(&response, sizeof(response), &actual_length, true, sizeof(ThorResponsePacket))) {
        return false;
    }

    uint32_t code = 0;
    if (actual_length >= static_cast<int>(sizeof(ThorResponsePacket))) {
        code = le32_to_h(response.response_code);
    }

    if (le16toh(response.header.packet_type) != THOR_PACKET_RESPONSE || code != 0) {
        log_error(std::format("Control command failed. Code: {}", code));
        return false;
    }
    log_info("Control command successful.");
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
    if (!bulk_write_all(buf.data(), buf.size(), USB_TIMEOUT_CONTROL)) {
        return false;
    }

    rsp.assign(512, 0);
    int read_len = 0;
    if (!bulk_read_once(rsp.data(), rsp.size(), &read_len, timeout_ms)) {
        return false;
    }
    if (read_len < 8) {
        log_error(std::format("Odin response size mismatch: {}", read_len));
        return false;
    }
    rsp.resize(read_len);
    return true;
}

auto UsbDevice::odin_fail_check(const std::vector<unsigned char>& rsp, const std::string& context,
                                bool allow_progress) -> bool {
    if (rsp.size() < 8) {
        return false;
    }
    if (rsp[0] != 0xFF) {
        return true;
    }

    int32_t code = 0;
    std::memcpy(&code, rsp.data() + 4, sizeof(code));
    code = static_cast<int32_t>(le32toh(static_cast<uint32_t>(code)));

    std::string suffix;
    if (allow_progress) {
        switch (code) {
        case -7:
            suffix = " (Ext4)";
            break;
        case -6:
            suffix = " (Size)";
            break;
        case -5:
            suffix = " (Auth)";
            break;
        case -4:
            suffix = " (Write)";
            break;
        case -3:
            suffix = " (Erase)";
            break;
        case -2:
            suffix = " (WP)";
            break;
        default:
            break;
        }
    }

    if (allow_progress) {
        // Some bootloaders report intermediate/progress states using 0xFF + a negative code.
        // Treat those as non-fatal when explicitly allowed.
        if (code >= -7 && code <= -2) {
            log_info(std::format("{} progress code {}{}", context, code, suffix));
            return true;
        }
    }

    log_error(std::format("{} failed with code {}{}", context, code, suffix));
    return false;
}

auto UsbDevice::odin_legacy_handshake() -> bool {
    const char preamble[4] = {'O', 'D', 'I', 'N'};
    if (!bulk_write_all(preamble, sizeof(preamble), USB_TIMEOUT_CONTROL)) {
        return false;
    }

    unsigned char reply[512] = {0};
    int actual = 0;
    if (!bulk_read_once(reply, sizeof(reply), &actual, USB_TIMEOUT_CONTROL)) {
        return false;
    }
    if (actual < 4) {
        return false;
    }
    if (reply[0] != 'L' || reply[1] != 'O' || reply[2] != 'K' || reply[3] != 'E') {
        return false;
    }
    return true;
}

auto UsbDevice::odin_begin_session() -> bool {
    std::vector<unsigned char> rsp;
    int32_t max_proto = 0x7FFFFFFF;
    uint32_t le_max = h_to_le32(static_cast<uint32_t>(max_proto));
    if (!odin_command(0x64, 0x00, &le_max, sizeof(le_max), rsp, USB_TIMEOUT_CONTROL)) {
        return false;
    }
    if (!odin_fail_check(rsp, "BeginSession", false)) {
        return false;
    }

    uint16_t version = 0;
    std::memcpy(&version, rsp.data() + 6, sizeof(version));
    version = static_cast<uint16_t>(le16toh(version));

    if (version <= 1) {
        odin_flash_timeout_ms = 60000;
        odin_flash_packet_size = 131072;
        odin_flash_sequence_count = 240;
    } else {
        odin_flash_timeout_ms = 180000;
        odin_flash_packet_size = 1048576;
        odin_flash_sequence_count = 30;

        uint32_t packet_size = h_to_le32(static_cast<uint32_t>(odin_flash_packet_size));
        if (!odin_command(0x64, 0x05, &packet_size, sizeof(packet_size), rsp, USB_TIMEOUT_CONTROL)) {
            return false;
        }
        if (!odin_fail_check(rsp, "SendFilePartSize", false)) {
            return false;
        }
    }
    return true;
}

auto UsbDevice::odin_end_session() -> bool {
    std::vector<unsigned char> rsp;
    if (!odin_command(0x67, 0x00, nullptr, 0, rsp, USB_TIMEOUT_CONTROL)) {
        return false;
    }
    return odin_fail_check(rsp, "EndSession", false);
}

auto UsbDevice::odin_reboot() -> bool {
    std::vector<unsigned char> rsp;
    if (!odin_command(0x67, 0x01, nullptr, 0, rsp, USB_TIMEOUT_CONTROL)) {
        return false;
    }
    return odin_fail_check(rsp, "Reboot", false);
}

auto UsbDevice::odin_set_total_bytes(uint64_t total_bytes) -> bool {
    std::vector<unsigned char> rsp;
    uint64_t le_total = h_to_le64(total_bytes);
    if (!odin_command(0x64, 0x02, &le_total, sizeof(le_total), rsp, USB_TIMEOUT_CONTROL)) {
        return false;
    }
    return odin_fail_check(rsp, "SetTotalBytes", false);
}

auto UsbDevice::odin_reset_flash_count() -> bool {
    std::vector<unsigned char> rsp;
    if (!odin_command(0x64, 0x01, nullptr, 0, rsp, USB_TIMEOUT_CONTROL)) {
        return false;
    }
    return odin_fail_check(rsp, "ResetFlashCount", false);
}

auto UsbDevice::odin_request_file_flash() -> bool {
    std::vector<unsigned char> rsp;
    if (!odin_command(0x66, 0x00, nullptr, 0, rsp, USB_TIMEOUT_CONTROL)) {
        return false;
    }
    return odin_fail_check(rsp, "RequestFileFlash", false);
}

auto UsbDevice::odin_request_sequence_flash(uint32_t aligned_size) -> bool {
    std::vector<unsigned char> rsp;
    uint32_t le_sz = h_to_le32(aligned_size);
    if (!odin_command(0x66, 0x02, &le_sz, sizeof(le_sz), rsp, USB_TIMEOUT_CONTROL)) {
        return false;
    }
    return odin_fail_check(rsp, "RequestSequenceFlash", false);
}

auto UsbDevice::odin_send_file_part_and_ack(const unsigned char* data, size_t size, uint32_t expected_index) -> bool {
    if (!bulk_write_all(data, size, odin_flash_timeout_ms)) {
        return false;
    }

    std::vector<unsigned char> rsp(8, 0);
    int actual = 0;
    if (!bulk_read_once(rsp.data(), rsp.size(), &actual, odin_flash_timeout_ms)) {
        return false;
    }
    if (actual != 8) {
        return false;
    }
    if (!odin_fail_check(rsp, "SendFilePart", false)) {
        return false;
    }

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

auto UsbDevice::odin_end_sequence_flash(const PitEntry& pit_entry, uint32_t real_size, uint32_t is_last) -> bool {
    std::vector<unsigned char> rsp;
    std::vector<unsigned char> payload(64, 0);

    auto w32 = [&](size_t off, uint32_t v) {
        uint32_t le = h_to_le32(v);
        std::memcpy(payload.data() + off, &le, sizeof(le));
    };

    if (pit_entry.binary_type == 1) {
        w32(0, 0x01);
        w32(4, real_size);
        w32(8, 0U);
        w32(12, pit_entry.device_type);
        w32(16, (is_last != 0U) ? 1U : 0U);
    } else {
        w32(0, 0x00);
        w32(4, real_size);
        w32(8, 0U);
        w32(12, pit_entry.device_type);
        w32(16, pit_entry.identifier);
        w32(20, (is_last != 0U) ? 1U : 0U);
        w32(24, 0U);
        w32(28, 0U);
    }

    if (!odin_command(0x66, 0x03, payload.data(), 32, rsp, odin_flash_timeout_ms)) {
        return false;
    }
    return odin_fail_check(rsp, "EndSequenceFlash", true);
}

auto UsbDevice::odin_dump_pit(std::vector<unsigned char>& pit_out) -> bool {
    std::vector<unsigned char> rsp;
    if (!odin_command(0x65, 0x01, nullptr, 0, rsp, 5000)) {
        return false;
    }
    if (!odin_fail_check(rsp, "RequestPitDump", false)) {
        return false;
    }

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
        if (!odin_command(0x65, 0x02, &le_i, sizeof(le_i), rsp, 5000)) {
            return false;
        }
        if (!odin_fail_check(rsp, "PitDumpBlock", false)) {
            return false;
        }

        size_t off = static_cast<size_t>(i) * block;
        size_t copy = std::min({rsp.size(), pit_out.size() - off, static_cast<size_t>(block)});
        std::memcpy(pit_out.data() + off, rsp.data(), copy);
    }

    if (!odin_command(0x65, 0x03, nullptr, 0, rsp, 5000)) {
        return false;
    }
    return odin_fail_check(rsp, "EndPitDump", false);
}

auto UsbDevice::flash_partition_stream(std::istream& stream, uint64_t size, const PitEntry& pit_entry,
                                       bool large_partition) -> bool {
    // Flash a partition from an input stream using the active device protocol.
    // High-level flow: initialize protocol transfer state, send data in protocol-defined
    // packet/sequence units, validate acknowledgements, then finalize the flash operation.
    (void) large_partition;

    // Odin legacy mode uses a request/sequence-based transfer model.
    // We first request file flash mode, then derive how many transfer sequences are needed
    // from the negotiated packet size and packets-per-sequence values.
    if (protocol_mode == ProtocolMode::OdinLegacy) {
        if (!odin_request_file_flash()) {
            return false;
        }

        // Bytes transferred per sequence = packet_size * packet_count.
        // A zero value would indicate invalid negotiation/configuration and would lead
        // to division by zero below, so fail fast.
        const uint64_t sequence_bytes =
            static_cast<uint64_t>(odin_flash_packet_size) * static_cast<uint64_t>(odin_flash_sequence_count);
        if (sequence_bytes == 0) {
            return false;
        }

        // Round up to include the final partial sequence when size is not aligned.
        const uint64_t sequences64 = (size + sequence_bytes - 1) / sequence_bytes;
        if (sequences64 == 0 || sequences64 > 0xFFFFFFFFULL) {
            log_error("Too many legacy sequences for size: " + std::to_string(size));
            return false;
        }
        const auto sequences = static_cast<uint32_t>(sequences64);

        uint64_t last_sequence64 = size - static_cast<uint64_t>(sequences - 1) * sequence_bytes;
        if (last_sequence64 == 0) {
            last_sequence64 = sequence_bytes;
        }
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

            if (!odin_request_sequence_flash(aligned_size)) {
                return false;
            }

            const uint32_t parts = aligned_size / static_cast<uint32_t>(odin_flash_packet_size);
            for (uint32_t j = 0; j < parts; ++j) {
                std::fill(part.begin(), part.end(), 0);

                uint64_t remaining_file_bytes = 0;
                if (total_sent < size) {
                    remaining_file_bytes = size - total_sent;
                }
                const size_t to_read = static_cast<size_t>(std::min<uint64_t>(remaining_file_bytes, part.size()));

                if (to_read > 0) {
                    stream.read(reinterpret_cast<char*>(part.data()), static_cast<std::streamsize>(to_read));
                    if (static_cast<size_t>(stream.gcount()) != to_read) {
                        return false;
                    }
                }

                if (!odin_send_file_part_and_ack(part.data(), part.size(), expected_index++)) {
                    return false;
                }
                total_sent += static_cast<uint64_t>(to_read);
            }

            if (!odin_end_sequence_flash(pit_entry, real_size, last ? 1U : 0U)) {
                return false;
            }
        }

        return odin_reset_flash_count();
    }

    if (!send_file_part_header(size)) {
        return false;
    }

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
        if (!send_file_part_chunk(buf.data(), to_read, chunk_index, large_partition)) {
            return false;
        }
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