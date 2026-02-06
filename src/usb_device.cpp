#include "usb_device.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <thread>
#include <chrono>
#include <cstring>

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

bool UsbDevice::open_device(const std::string& specific_path) {
    ssize_t cnt = libusb_get_device_list(NULL, &device_list);
    if (cnt < 0) {
        log_error("Failed to get USB device list", (int)cnt);
        return false;
    }

    libusb_device *target_device = nullptr;
    for (ssize_t i = 0; i < cnt; i++) {
        libusb_device_descriptor desc;
        if (libusb_get_device_descriptor(device_list[i], &desc) < 0) continue;

        if (desc.idVendor == SAMSUNG_VID) {
            if (!specific_path.empty()) {
                std::stringstream path_ss;
                path_ss << "/dev/bus/usb/" 
                        << std::setfill('0') << std::setw(3) << (int)libusb_get_bus_number(device_list[i]) << "/" 
                        << std::setfill('0') << std::setw(3) << (int)libusb_get_device_address(device_list[i]);
                if (path_ss.str() != specific_path) continue;
            }
            for (uint16_t pid : DOWNLOAD_PIDS) {
                if (desc.idProduct == pid) {
                    target_device = device_list[i];
                    break;
                }
            }
        }
        if (target_device) break;
    }

    if (!target_device) {
        log_info("No Samsung device in download mode found.");
        return false;
    }

    // Discover endpoints
    libusb_config_descriptor *config;
    if (libusb_get_active_config_descriptor(target_device, &config) == 0) {
        bool found = false;
        for (int i = 0; i < config->bNumInterfaces; i++) {
            const libusb_interface *inter = &config->interface[i];
            for (int j = 0; j < inter->num_altsetting; j++) {
                const libusb_interface_descriptor *inter_desc = &inter->altsetting[j];
                uint8_t ep_in = 0, ep_out = 0;
                for (int k = 0; k < inter_desc->bNumEndpoints; k++) {
                    const libusb_endpoint_descriptor *ep_desc = &inter_desc->endpoint[k];
                    if ((ep_desc->bmAttributes & 0x03) == LIBUSB_TRANSFER_TYPE_BULK) {
                        if (ep_desc->bEndpointAddress & 0x80) ep_in = ep_desc->bEndpointAddress;
                        else ep_out = ep_desc->bEndpointAddress;
                    }
                }
                if (ep_in && ep_out) {
                    endpoint_in = ep_in;
                    endpoint_out = ep_out;
                    interface_number = inter_desc->bInterfaceNumber;
                    found = true;
                    break;
                }
            }
            if (found) break;
        }
        if (!found) {
            log_info("Endpoints not found in config descriptor. Using defaults (0x01/0x81).");
        }
        libusb_free_config_descriptor(config);
    } else {
        log_info("Failed to get config descriptor. Using defaults (0x01/0x81).");
    }

    int err = libusb_open(target_device, &handle);
    if (err < 0) {
        log_error("Failed to open USB device", err);
        return false;
    }

    if (libusb_kernel_driver_active(handle, interface_number) == 1) {
        int detach_err = libusb_detach_kernel_driver(handle, interface_number);
        if (detach_err < 0) {
            log_error("Failed to detach kernel driver", detach_err);
            return false;
        }
    }

    err = libusb_claim_interface(handle, interface_number);
    if (err < 0) {
        log_error("Failed to claim USB interface", err);
        return false;
    }
    
    log_info("USB device opened. Interface: " + std::to_string(interface_number) + 
             ", EP IN: 0x" + std::to_string(endpoint_in) + 
             ", EP OUT: 0x" + std::to_string(endpoint_out));
    return true;
}

bool UsbDevice::send_packet(const void *data, size_t size, bool is_control) {
    int actual_length;
    int err = 0;
    int timeout = is_control ? USB_TIMEOUT_CONTROL : USB_TIMEOUT_BULK;
    
    for (int attempt = 0; attempt < USB_RETRY_COUNT; ++attempt) {
        err = libusb_bulk_transfer(handle, endpoint_out, (unsigned char*)data, size, &actual_length, timeout);
        
        if (err == 0 && actual_length == (int)size) {
            if (is_control) log_hexdump("Packet Sent (Control)", data, size);
            return true;
        }
        
        if (err != 0) {
            log_error("USB packet send failed (attempt " + std::to_string(attempt + 1) + ")", err);
        } else {
            log_error("Incorrect send size (attempt " + std::to_string(attempt + 1) + "): expected " + std::to_string(size) + ", sent " + std::to_string(actual_length));
        }
        
        if (attempt < USB_RETRY_COUNT - 1) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    
    return false;
}

bool UsbDevice::receive_packet(void *data, size_t size, int *actual_length, bool is_control) {
    int err = 0;
    int timeout = is_control ? USB_TIMEOUT_CONTROL : 300000;
    
    for (int attempt = 0; attempt < USB_RETRY_COUNT; ++attempt) {
        err = libusb_bulk_transfer(handle, endpoint_in, (unsigned char*)data, size, actual_length, timeout);
        
        if (err == 0 && *actual_length == (int)size) {
            if (is_control) log_hexdump("Packet Received (Control)", data, *actual_length);
            return true;
        }
        
        if (err != 0) {
            log_error("USB packet receive failed (attempt " + std::to_string(attempt + 1) + ")", err);
        } else {
            log_error("Incorrect receive size (attempt " + std::to_string(attempt + 1) + "): expected " + std::to_string(size) + ", received " + std::to_string(*actual_length));
        }
        
        if (attempt < USB_RETRY_COUNT - 1) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    
    return false;
}

bool UsbDevice::handshake() {
    log_info("Starting handshake...");
    ThorHandshakePacket pkt = {};
    pkt.header.packet_size = h_to_le32(sizeof(ThorHandshakePacket));
    pkt.header.packet_type = h_to_le16(THOR_PACKET_HANDSHAKE);
    pkt.header.packet_flags = 0;
    pkt.magic = h_to_le32(0x4F44494E); // 'ODIN'
    pkt.version = h_to_le32(0x00010000);
    pkt.packet_size = h_to_le32(sizeof(ThorHandshakePacket));

    if (!send_packet(&pkt, sizeof(pkt), true)) return false;

    ThorResponsePacket response = {};
    int actual_length;
    if (!receive_packet(&response, sizeof(response), &actual_length, true)) return false;
    
    if (le16toh(response.header.packet_type) != THOR_PACKET_RESPONSE || le32toh(response.response_code) != 0) {
        log_error("Handshake failed. Response code: " + std::to_string(le32toh(response.response_code)));
        
        log_info("Attempting to clear USB halt and retry handshake...");
        libusb_clear_halt(handle, endpoint_in);
        
        if (!send_packet(&pkt, sizeof(pkt), true)) return false;
        if (!receive_packet(&response, sizeof(response), &actual_length, true)) return false;
        
        if (le16toh(response.header.packet_type) != THOR_PACKET_RESPONSE || le32toh(response.response_code) != 0) {
            log_error("Handshake failed after retry. Response code: " + std::to_string(le32toh(response.response_code)));
            return false;
        }
    }
    log_info("Handshake successful.");
    return true;
}

bool UsbDevice::request_device_type() {
    log_info("Requesting device type...");
    ThorPacketHeader pkt = {};
    pkt.packet_size = h_to_le32(sizeof(ThorPacketHeader));
    pkt.packet_type = h_to_le16(THOR_PACKET_DEVICE_TYPE);
    pkt.packet_flags = 0;

    if (!send_packet(&pkt, sizeof(pkt), true)) return false;

    ThorDeviceTypePacket response = {};
    int actual_length;
    if (!receive_packet(&response, sizeof(response), &actual_length, true)) return false;

    if (le16toh(response.header.packet_type) != THOR_PACKET_DEVICE_TYPE) {
        log_error("Device type request failed. Unexpected packet type: " + std::to_string(le16toh(response.header.packet_type)));
        return false;
    }
    log_info("Device type received.");
    return true;
}

bool UsbDevice::begin_session() {
    log_info("Beginning session...");
    ThorBeginSessionPacket pkt = {};
    pkt.header.packet_size = h_to_le32(sizeof(ThorBeginSessionPacket));
    pkt.header.packet_type = h_to_le16(THOR_PACKET_BEGIN_SESSION);
    pkt.header.packet_flags = 0;
    pkt.unknown1 = 0;
    pkt.unknown2 = 0;

    if (!send_packet(&pkt, sizeof(pkt), true)) return false;

    ThorResponsePacket response = {};
    int actual_length;
    if (!receive_packet(&response, sizeof(response), &actual_length, true)) return false;

    if (le16toh(response.header.packet_type) != THOR_PACKET_RESPONSE || le32toh(response.response_code) != 0) {
        log_error("Session begin failed. Response code: " + std::to_string(le32toh(response.response_code)));
        return false;
    }
    log_info("Session started successfully.");
    return true;
}

bool UsbDevice::end_session() {
    log_info("Ending session...");
    ThorEndSessionPacket pkt = {};
    pkt.header.packet_size = h_to_le32(sizeof(ThorEndSessionPacket));
    pkt.header.packet_type = h_to_le16(THOR_PACKET_END_SESSION);
    pkt.header.packet_flags = 0;

    if (!send_packet(&pkt, sizeof(pkt), true)) return false;

    ThorResponsePacket response = {};
    int actual_length;
    if (!receive_packet(&response, sizeof(response), &actual_length, true)) return false;

    if (le16toh(response.header.packet_type) != THOR_PACKET_RESPONSE || le32toh(response.response_code) != 0) {
        log_error("Session end failed. Response code: " + std::to_string(le32toh(response.response_code)));
        return false;
    }
    log_info("Session ended successfully.");
    return true;
}

bool UsbDevice::request_pit() {
    log_info("Requesting PIT...");
    ThorPacketHeader pkt = {};
    pkt.packet_size = h_to_le32(sizeof(ThorPacketHeader));
    pkt.packet_type = h_to_le16(THOR_PACKET_PIT_FILE);
    pkt.packet_flags = 0;

    if (!send_packet(&pkt, sizeof(pkt), true)) return false;

    ThorPitFilePacket response = {};
    int actual_length;
    if (!receive_packet(&response, sizeof(response), &actual_length, true)) return false;

    if (le16toh(response.header.packet_type) != THOR_PACKET_PIT_FILE) {
        log_error("PIT request failed. Unexpected packet type: " + std::to_string(le16toh(response.header.packet_type)));
        return false;
    }
    log_info("PIT size packet received.");
    return true;
}

bool UsbDevice::receive_pit_table(PitTable& pit_table) {
    ThorPitFilePacket pit_size_pkt = {};
    int actual_length;
    if (!receive_packet(&pit_size_pkt, sizeof(pit_size_pkt), &actual_length, true)) return false;

    uint32_t pit_data_size = le32_to_h(pit_size_pkt.pit_file_size);
    if (pit_data_size == 0 || pit_data_size > 1048576) {
        log_error("Invalid or too large PIT size: " + std::to_string(pit_data_size));
        return false;
    }

    log_info("PIT size: " + std::to_string(pit_data_size) + " bytes.");
    
    std::vector<unsigned char> pit_data(pit_data_size);
    if (!receive_packet(pit_data.data(), pit_data_size, &actual_length)) {
        log_error("Failed to receive PIT data.");
        return false;
    }

    if (pit_data_size < 8) {
        log_error("Received PIT size too small.");
        return false;
    }

    uint32_t raw_val;
    std::memcpy(&raw_val, &pit_data[0], 4);
    pit_table.header_size = le32_to_h(raw_val);
    std::memcpy(&raw_val, &pit_data[4], 4);
    pit_table.entry_count = le32_to_h(raw_val);

    if (pit_table.entry_count > 512) {
        log_error("Invalid or excessive PIT entry count: " + std::to_string(pit_table.entry_count));
        return false;
    }
    
    size_t entry_size = 132; 
    size_t expected_min_size = pit_table.header_size + (pit_table.entry_count * entry_size);
    if (pit_data_size < expected_min_size) {
        entry_size = 128;
        expected_min_size = pit_table.header_size + (pit_table.entry_count * entry_size);
        if (pit_data_size < expected_min_size) {
            log_error("Received PIT size (" + std::to_string(pit_data_size) + ") is smaller than expected.");
            return false;
        }
    }

    if (pit_table.entry_count == 0 || pit_table.entry_count > 512) {
        log_error("Invalid or excessive PIT entry count: " + std::to_string(pit_table.entry_count));
        return false;
    }
    pit_table.entries.clear();
    pit_table.entries.reserve(pit_table.entry_count);
    log_info("Parsing " + std::to_string(pit_table.entry_count) + " PIT entries (entry size: " + std::to_string(entry_size) + ").");

    for (uint32_t i = 0; i < pit_table.entry_count; ++i) {
        size_t offset = pit_table.header_size + (i * entry_size);
        
        if (offset + sizeof(PitEntry) > pit_data_size) {
            log_error("Out of bounds access reading PIT entry " + std::to_string(i) + ".");
            return false;
        }

        PitEntry entry = {};
        uint32_t raw_val;
        
        std::memcpy(&raw_val, &pit_data[offset + 0], 4);
        entry.identifier = le32_to_h(raw_val);
        
        std::memcpy(&raw_val, &pit_data[offset + 8], 4);
        entry.flash_type = le32_to_h(raw_val);
        
        std::memcpy(&raw_val, &pit_data[offset + 12], 4);
        entry.file_size = le32_to_h(raw_val);
        
        std::memcpy(&raw_val, &pit_data[offset + 16], 4);
        entry.block_size = le32_to_h(raw_val);
        
        std::memcpy(entry.partition_name, &pit_data[offset + 32], 32);
        entry.partition_name[31] = '\0';
        
        std::memcpy(entry.file_name, &pit_data[offset + 64], 32);
        entry.file_name[31] = '\0';
        
        pit_table.entries.push_back(entry);
    }
    log_info("PIT parsed successfully.");
    return true;
}

bool UsbDevice::send_file_part_chunk(const void* data, size_t size, bool large_partition) {
    int actual_length;
    int err = 0;
    int timeout = large_partition ? 300000 : USB_TIMEOUT_BULK;
    
    for (int attempt = 0; attempt < USB_RETRY_COUNT; ++attempt) {
        err = libusb_bulk_transfer(handle, endpoint_out, (unsigned char*)data, size, &actual_length, timeout);
        if (err == 0 && actual_length == (int)size) return true;
        
        log_error("USB chunk send failed (attempt " + std::to_string(attempt + 1) + ")", err);
        if (attempt < USB_RETRY_COUNT - 1) std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return false;
}

bool UsbDevice::send_file_part_header(uint64_t total_size) {
    ThorFilePartSizePacket size_pkt = {};
    size_pkt.header.packet_size = h_to_le32(sizeof(ThorFilePartSizePacket));
    size_pkt.header.packet_type = h_to_le16(THOR_PACKET_FILE_PART_SIZE);
    size_pkt.header.packet_flags = 0;
    size_pkt.file_part_size = htole64(total_size);

    if (!send_packet(&size_pkt, sizeof(size_pkt), true)) return false;

    ThorResponsePacket response = {};
    int actual_length;
    if (!receive_packet(&response, sizeof(response), &actual_length, true)) return false;

    if (le16toh(response.header.packet_type) != THOR_PACKET_RESPONSE || le32toh(response.response_code) != 0) {
        log_error("Unexpected response sending file part size. Code: " + std::to_string(le32toh(response.response_code)));
        return false;
    }
    return true;
}

bool UsbDevice::end_file_transfer(uint32_t partition_id) {
    log_info("Finalizing file transfer for partition ID: " + std::to_string(partition_id));
    ThorEndFileTransferPacket pkt = {};
    pkt.header.packet_size = h_to_le32(sizeof(ThorEndFileTransferPacket));
    pkt.header.packet_type = h_to_le16(THOR_PACKET_END_FILE_TRANSFER);
    pkt.header.packet_flags = 0;
    pkt.partition_id = h_to_le32(partition_id);

    if (!send_packet(&pkt, sizeof(pkt), true)) return false;

    ThorResponsePacket response = {};
    int actual_length;
    if (!receive_packet(&response, sizeof(response), &actual_length, true)) return false;

    if (le16toh(response.header.packet_type) != THOR_PACKET_RESPONSE || le32toh(response.response_code) != 0) {
        log_error("File transfer finalization failed. Code: " + std::to_string(le32toh(response.response_code)));
        return false;
    }
    log_info("File transfer finalized.");
    return true;
}

bool UsbDevice::send_control(uint32_t control_type) {
    log_info("Sending control command: " + std::to_string(control_type));
    ThorControlPacket pkt = {};
    pkt.header.packet_size = h_to_le32(sizeof(ThorControlPacket));
    pkt.header.packet_type = h_to_le16(THOR_PACKET_CONTROL);
    pkt.header.packet_flags = 0;
    pkt.control_type = h_to_le32(control_type);

    if (!send_packet(&pkt, sizeof(pkt), true)) return false;

    ThorResponsePacket response = {};
    int actual_length;
    if (!receive_packet(&response, sizeof(response), &actual_length, true)) return false;

    if (le16toh(response.header.packet_type) != THOR_PACKET_RESPONSE || le32toh(response.response_code) != 0) {
        log_error("Control command failed. Code: " + std::to_string(le32toh(response.response_code)));
        return false;
    }
    log_info("Control command successful.");
    return true;
}
