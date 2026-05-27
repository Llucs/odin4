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
}

static auto retry_backoff_ms(int attempt) -> int {
    int ms = 100;
    for (int i = 0; i < attempt; ++i) {
        ms *= 2;
        if (ms > 1500) return 1500;
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
            if (to_send > max_chunk_bytes) to_send = max_chunk_bytes;
            int err = libusb_bulk_transfer(handle, endpoint_out, const_cast<unsigned char*>(ptr + offset),
                                           clamp_size_to_int(to_send), &actual_length, timeout_ms);
            if (actual_length > 0) offset += static_cast<size_t>(actual_length);
            if (err != 0) {
                if (err == LIBUSB_ERROR_NO_DEVICE) return false;
                if (err == LIBUSB_ERROR_PIPE) (void) libusb_clear_halt(handle, endpoint_out);
                if (err == LIBUSB_ERROR_PIPE || err == LIBUSB_ERROR_TIMEOUT) max_chunk_bytes = 0x4000;
                break;
            }
            if (actual_length <= 0) break;
        }
        if (offset == size) {
            if (odin_supports_zlp && endpoint_out_max_packet != 0 && (size % endpoint_out_max_packet) == 0) {
                if (!send_zlp(timeout_ms)) odin_supports_zlp = false;
            }
            return true;
        }
        if (attempt < USB_RETRY_COUNT - 1)
            std::this_thread::sleep_for(std::chrono::milliseconds(retry_backoff_ms(attempt)));
    }
    return false;
}

auto UsbDevice::send_zlp(int timeout_ms) -> bool {
    int actual = 0;
    return libusb_bulk_transfer(handle, endpoint_out, nullptr, 0, &actual, timeout_ms) == 0;
}

auto UsbDevice::bulk_read_once(void* data, size_t size, int* actual_length, int timeout_ms) -> bool {
    for (int attempt = 0; attempt < USB_RETRY_COUNT; ++attempt) {
        int err = libusb_bulk_transfer(handle, endpoint_in, static_cast<unsigned char*>(data), clamp_size_to_int(size),
                                       actual_length, timeout_ms);
        if (err == 0) return true;
        if (err == LIBUSB_ERROR_NO_DEVICE) return false;
        if (err == LIBUSB_ERROR_PIPE) (void) libusb_clear_halt(handle, endpoint_in);
        log_error(std::format("USB bulk read failed (error: {})", static_cast<int>(err)));
        if (attempt < USB_RETRY_COUNT - 1)
            std::this_thread::sleep_for(std::chrono::milliseconds(retry_backoff_ms(attempt)));
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
    int alt_setting = -1;
    uint8_t ep_in = 0;
    uint8_t ep_out = 0;
    uint16_t ep_out_mps = 0;
    uint8_t interface_class = 0;
    uint8_t num_endpoints = 0;
};

static auto find_best_interface(libusb_device* dev, const UsbSelectionCriteria& criteria) -> InterfaceCandidate {
    InterfaceCandidate best;
    libusb_config_descriptor* config = nullptr;
    if (libusb_get_active_config_descriptor(dev, &config) != 0 || (config == nullptr)) return best;

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
                if ((ep->bEndpointAddress & 0x80) != 0)
                    ep_in = ep->bEndpointAddress;
                else {
                    ep_out = ep->bEndpointAddress;
                    ep_out_mps = ep->wMaxPacketSize;
                }
            }

            if ((ep_in == 0U) || (ep_out == 0U)) continue;

            int score = 0;
            if (id->bInterfaceClass == 0x0A && id->bNumEndpoints == 2) score += 100;
            score += 50;
            if (bulk_endpoints == 2) score += 10;

            if (score > best.score) {
                best = {score, id->bInterfaceNumber, id->bAlternateSetting, ep_in, ep_out, ep_out_mps, id->bInterfaceClass, id->bNumEndpoints};
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
    last_open_error = UsbOpenError::None;
    last_open_libusb_err = 0;

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

    if (!ensure_libusb_initialized()) {
        last_open_error = UsbOpenError::Other;
        last_open_libusb_err = LIBUSB_ERROR_OTHER;
        log_error(std::format("Failed to enumerate USB devices (error: {})", static_cast<int>(LIBUSB_ERROR_OTHER)));
        return false;
    }

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

        if (!criteria.has_pid && !criteria.has_vid) {
            if (!pid_known && !cdc_data) continue;
        }

        int score = cand.score;
        if (pid_known) score += 20;
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
    if (chosen_if.ep_out_mps != 0) endpoint_out_max_packet = chosen_if.ep_out_mps;
    interface_number = chosen_if.interface_number;
    alt_setting = chosen_if.alt_setting;
    kernel_driver_detached = false;

    const int open_err = libusb_open(target, &handle);
    if (open_err < 0 || (handle == nullptr)) {
        last_open_libusb_err = open_err;
        if (open_err == LIBUSB_ERROR_ACCESS)
            last_open_error = UsbOpenError::AccessDenied;
        else if (open_err == LIBUSB_ERROR_BUSY)
            last_open_error = UsbOpenError::Busy;
        else
            last_open_error = UsbOpenError::Other;
        log_error("Failed to open USB device", open_err);
        return false;
    }

    const int kernel_driver_state = libusb_kernel_driver_active(handle, interface_number);
    if (kernel_driver_state < 0) {
        last_open_libusb_err = kernel_driver_state;
        last_open_error = (kernel_driver_state == LIBUSB_ERROR_ACCESS) ? UsbOpenError::AccessDenied : UsbOpenError::Other;
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
    if (claim_err == 0 && alt_setting >= 0) {
        int alt_err = libusb_set_interface_alt_setting(handle, interface_number, alt_setting);
        if (alt_err < 0) {
            last_open_libusb_err = alt_err;
            last_open_error = UsbOpenError::Other;
            log_error("Failed to set USB interface alt setting", alt_err);
            libusb_release_interface(handle, interface_number);
            if (kernel_driver_detached) {
                (void) libusb_attach_kernel_driver(handle, interface_number);
                kernel_driver_detached = false;
            }
            libusb_close(handle);
            handle = nullptr;
            return false;
        }
    }
    if (claim_err < 0) {
        last_open_libusb_err = claim_err;
        if (claim_err == LIBUSB_ERROR_ACCESS)
            last_open_error = UsbOpenError::AccessDenied;
        else
            last_open_error = UsbOpenError::Other;
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
    if (!bulk_write_all(data, size, timeout)) return false;
    if (is_control) log_hexdump("Packet Sent (Control)", data, size);
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
                if (received >= required_min) break;
                if (chunk <= 0) break;
                continue;
            }

            if (err == LIBUSB_ERROR_PIPE) (void) libusb_clear_halt(handle, endpoint_in);
            if (err == LIBUSB_ERROR_TIMEOUT) {
                if (timeout_override_ms > 0 || attempt == USB_RETRY_COUNT - 1) return false;
                break;
            }
            log_error("USB packet receive failed (attempt " + std::to_string(attempt + 1) + ")", err);
            if (err == LIBUSB_ERROR_NO_DEVICE) return false;
            break;
        }

        if (received >= required_min && received <= size) {
            if (is_control) log_hexdump("Packet Received (Control)", data, received);
            return true;
        }

        log_error("Incorrect receive size (attempt " + std::to_string(attempt + 1) + "): expected min " +
                  std::to_string(required_min) + ", max " + std::to_string(size) + ", received " +
                  std::to_string(received));

        if (attempt < USB_RETRY_COUNT - 1)
            std::this_thread::sleep_for(std::chrono::milliseconds(retry_backoff_ms(attempt)));
    }

    return false;
}

auto UsbDevice::handshake() -> bool {
    log_info("Starting handshake");
    return odin_handshake();
}

auto UsbDevice::request_device_type() -> bool {
    if (!odin_request_device_type(device_type_str)) {
        log_warn("Device type query failed; continuing without type info.");
        device_type_str.clear();
        return true;
    }
    return true;
}

auto UsbDevice::list_download_devices() -> std::vector<std::string> {
    UsbSelectionCriteria criteria;
    return list_download_devices(criteria);
}

auto UsbDevice::list_download_devices(const UsbSelectionCriteria& criteria) -> std::vector<std::string> {
    std::vector<std::string> result;
    libusb_device** list = nullptr;
    if (!ensure_libusb_initialized()) return result;
    const ssize_t cnt = libusb_get_device_list(g_libusb_ctx, &list);
    if (cnt < 0) return result;

    struct Cleanup {
        libusb_device** l;
        explicit Cleanup(libusb_device** ptr) : l(ptr) {}
        ~Cleanup() { if (l != nullptr) libusb_free_device_list(l, 1); }
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

// Protocol and flash operations are in odin_protocol.cpp
