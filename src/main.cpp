// ============================================================================
// odin4 - Samsung Device Flashing Tool
// Version: 3.0.0-648f483
// Protocol: Thor USB Communication
// Developer: Llucs
// ============================================================================

#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <cstring>
#include <map>
#include <algorithm>
#include <libusb.h>
#include <lz4.h>
#include <stdexcept>
#include <iomanip>
#include <thread>
#include <chrono>
#include <cmath>
#include <sstream>
#include <endian.h>

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>
#include <cryptopp/hex.h>

// Constants & Definitions

#define ODIN4_VERSION "3.0.0-648f483"
#define SAMSUNG_VID 0x04E8
#define USB_RETRY_COUNT 3
#define USB_TIMEOUT_BULK 60000 // 60000 ms (60 seconds)
#define USB_TIMEOUT_CONTROL 5000 // 5000 ms (5 seconds)

// Utilities


void log_info(const std::string& msg) {
    std::cout << "[INFO] " << msg << std::endl;
}

void log_error(const std::string& msg, int libusb_err = 0) {
    std::cerr << "[ERROR] " << msg;
    if (libusb_err != 0) {
        std::cerr << " (libusb: " << libusb_error_name(libusb_err) << ")";
    }
    std::cerr << std::endl;
}

void log_hexdump(const std::string& title, const void* data, size_t size) {
    if (size == 0) return;
    const unsigned char* bytes = static_cast<const unsigned char*>(data);
    
    // Save current cout state
    std::ios_base::fmtflags f(std::cout.flags());
    char fill = std::cout.fill();
    std::streamsize old_width = std::cout.width();
    
    std::cout << "[DEBUG] " << title << " (" << size << " bytes):" << std::endl;
    std::cout << std::hex << std::setfill('0');
    for (size_t i = 0; i < size; ++i) {
        std::cout << std::setw(2) << (unsigned int)bytes[i] << " ";
        if ((i + 1) % 16 == 0) std::cout << std::endl;
    }
    if (size % 16 != 0) std::cout << std::endl;
    
    // Restore cout state
    std::cout.flags(f);
    std::cout.fill(fill);
    std::cout.width(old_width);
}


uint32_t le32_to_h(uint32_t val) { return le32toh(val); }
uint32_t h_to_le32(uint32_t val) { return htole32(val); }
uint16_t h_to_le16(uint16_t val) { return htole16(val); }

std::string sanitize_filename(const std::string& filename) {
    std::string sanitized = filename;
    size_t last_dot = sanitized.find_last_of('.');
    while (last_dot != std::string::npos) {
        std::string ext = sanitized.substr(last_dot);
        if (ext == ".lz4" || ext == ".ext4" || ext == ".img" || ext == ".bin") {
            sanitized = sanitized.substr(0, last_dot);
            last_dot = sanitized.find_last_of('.');
        } else {
            break;
        }
    }
    return sanitized;
}

bool check_md5_signature(const std::string& file_path) {
    if (file_path.size() < 8 || file_path.substr(file_path.size() - 8) != ".tar.md5") {
        return true; 
    }

    log_info("Verifying MD5 signature for " + file_path);
    std::ifstream file(file_path, std::ios::binary | std::ios::ate);
    if (!file) {
        log_error("Could not open file for MD5 verification: " + file_path);
        return false;
    }

    std::streampos file_size = file.tellg();
    if (file_size < 32) {
        log_error("File too small to contain MD5 signature.");
        return false;
    }

    file.seekg((std::streamoff)file_size - 32);
    char expected_md5_hex[33];
    file.read(expected_md5_hex, 32);
    if (file.gcount() != 32) {
        log_error("Incomplete MD5 signature read from file.");
        return false;
    }
    expected_md5_hex[32] = '\0';
    std::string expected_md5(expected_md5_hex);

    log_info("Expected MD5: " + expected_md5);

    file.seekg(0);
    size_t content_size = (size_t)((long long)file_size - 32);

    CryptoPP::Weak::MD5 hash;
    std::vector<unsigned char> digest(hash.DigestSize());
    size_t buffer_size = (content_size > 1024 * 1024 * 1024) ? (32 * 1024 * 1024) : 1048576;
    std::vector<char> buffer(buffer_size);
    size_t total_read = 0;
    int last_progress = -1;

    while (total_read < content_size) {
        size_t to_read = std::min((size_t)buffer.size(), content_size - total_read);
        file.read(buffer.data(), (std::streamsize)to_read);
        size_t read_count = (size_t)file.gcount();

        if (read_count == 0) {
            if (total_read < content_size) {
                log_error("Premature read error during MD5 check.");
                return false;
            }
            break;
        }

        hash.Update((const unsigned char*)buffer.data(), read_count);
        total_read += read_count;

        int progress = (int)((double)total_read / content_size * 100);
        if (progress != last_progress) {
            std::cout << "\r[MD5] Verifying integrity... " << progress << "%" << std::flush;
            last_progress = progress;
        }
    }
    std::cout << std::endl;

    if (total_read != content_size) {
        log_error("Failed to read full file content for MD5 check. Read " + std::to_string(total_read) + " of " + std::to_string(content_size));
        return false;
    }

    hash.Final(digest.data());

    std::string calculated_md5;
    CryptoPP::HexEncoder encoder;
    encoder.Attach(new CryptoPP::StringSink(calculated_md5));
    encoder.Put(digest.data(), digest.size());
    encoder.MessageEnd();

    auto to_lower = [](std::string s) {
        std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return static_cast<char>(::tolower(static_cast<unsigned char>(c))); });
        return s;
    };

    std::string calculated_md5_lower = to_lower(calculated_md5);
    std::string expected_md5_lower = to_lower(expected_md5);

    log_info("Calculated MD5: " + calculated_md5_lower);

    if (calculated_md5_lower == expected_md5_lower) {
        log_info("MD5 verification successful.");
        return true;
    } else {
        log_error("MD5 verification failed! Expected: " + expected_md5_lower + " | Calculated: " + calculated_md5_lower);
        return false;
    }
}

// ============================================================================
// CONFIGURATION STRUCTURES
// ============================================================================

struct OdinConfig {
    std::string bootloader;
    std::string ap;
    std::string cp;
    std::string csc;
    std::string ums;
    std::string device_path;
    bool nand_erase = false;
    bool validation = false;
    bool reboot = false;
    bool redownload = false;
    bool show_license = false;
    bool list_devices = false;
};

// ============================================================================
// THOR PROTOCOL - PACKET STRUCTURES
// ============================================================================

#pragma pack(push, 1)

// --- Thor Packet Header ---
struct ThorPacketHeader {
    uint32_t packet_size;
    uint16_t packet_type;
    uint16_t packet_flags;
};

// --- Thor Packet Types ---
enum ThorPacketType {
    THOR_PACKET_HANDSHAKE = 0x0001,
    THOR_PACKET_DEVICE_TYPE = 0x0002,
    THOR_PACKET_FILE_PART = 0x0003,
    THOR_PACKET_END_FILE_TRANSFER = 0x0004,
    THOR_PACKET_END_SESSION = 0x0005,
    THOR_PACKET_RESPONSE = 0x0006,
    THOR_PACKET_PIT_FILE = 0x0007,
    THOR_PACKET_BEGIN_SESSION = 0x0008,
    THOR_PACKET_FILE_PART_SIZE = 0x0009,
    THOR_PACKET_RECEIVE_FILE_PART = 0x000A,
    THOR_PACKET_CONTROL = 0x000B,
};

// --- Thor Control Types ---
enum ThorControlType {
    THOR_CONTROL_REBOOT = 0x0001,
    THOR_CONTROL_REDOWNLOAD = 0x0002,
};

// --- Handshake Packet ---
struct ThorHandshakePacket {
    ThorPacketHeader header;
    uint32_t magic;
    uint32_t version;
    uint32_t packet_size;
};

// --- Device Type Packet ---
struct ThorDeviceTypePacket {
    ThorPacketHeader header;
    char device_type[128];
};

// --- Begin Session Packet ---
struct ThorBeginSessionPacket {
    ThorPacketHeader header;
    uint32_t unknown1;
    uint32_t unknown2;
};

// --- PIT File Packet ---
struct ThorPitFilePacket {
    ThorPacketHeader header;
    uint32_t pit_file_size;
};

// --- File Part Size Packet ---
struct ThorFilePartSizePacket {
    ThorPacketHeader header;
    uint64_t file_part_size;
};

// --- File Part Packet ---
struct ThorFilePartPacket {
    ThorPacketHeader header;
    uint32_t file_part_index;
    uint32_t file_part_size;
};

// --- End File Transfer Packet ---
struct ThorEndFileTransferPacket {
    ThorPacketHeader header;
    uint32_t partition_id;
};

// --- End Session Packet ---
struct ThorEndSessionPacket {
    ThorPacketHeader header;
};

// --- Control Packet ---
struct ThorControlPacket {
    ThorPacketHeader header;
    uint32_t control_type;
};

// --- Response Packet ---
struct ThorResponsePacket {
    ThorPacketHeader header;
    uint32_t response_code;
};

#pragma pack(pop)

// ============================================================================
// PARTITION INFORMATION TABLE (PIT)
// ============================================================================

#pragma pack(push, 1)
struct PitEntry {
    uint32_t identifier;
    uint32_t flash_type;
    uint32_t file_size;
    uint32_t block_size;
    char partition_name[32];
    char file_name[32];
};
#pragma pack(pop)

struct PitTable {
    uint32_t header_size;
    uint32_t entry_count;
    std::vector<PitEntry> entries;
};

// ============================================================================
// USB DEVICE COMMUNICATION CLASS
// ============================================================================

class UsbDevice {
private:
    libusb_device_handle *handle = nullptr;
    libusb_device **device_list = nullptr;
    const std::vector<uint16_t> DOWNLOAD_PIDS = {0x685D, 0x6600, 0x6860, 0x6861, 0x6862};
    
    uint8_t endpoint_out = 0x01;
    uint8_t endpoint_in = 0x81;
    int interface_number = 0;

public:
    UsbDevice() = default;
    ~UsbDevice() {
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

    bool open_device(const std::string& specific_path = "") {
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

    bool send_packet(const void *data, size_t size, bool is_control = false) {
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

    bool receive_packet(void *data, size_t size, int *actual_length, bool is_control = false) {
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

    bool handshake() {
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
            libusb_clear_halt(handle, LIBUSB_ENDPOINT_IN);
            
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

    bool request_device_type() {
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

    bool begin_session() {
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

    bool end_session() {
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

    bool request_pit() {
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

    bool receive_pit_table(PitTable& pit_table) {
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

    bool send_file_part_chunk(const void* data, size_t size, bool large_partition = false) {
        int actual_length;
        int err = 0;
        int timeout = large_partition ? 300000 : USB_TIMEOUT_BULK;
        
        for (int attempt = 0; attempt < USB_RETRY_COUNT; ++attempt) {
            err = libusb_bulk_transfer(handle, LIBUSB_ENDPOINT_OUT, (unsigned char*)data, size, &actual_length, timeout);
            if (err == 0 && actual_length == (int)size) return true;
            
            log_error("USB chunk send failed (attempt " + std::to_string(attempt + 1) + ")", err);
            if (attempt < USB_RETRY_COUNT - 1) std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        return false;
    }

    bool send_file_part_header(uint64_t total_size) {
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

    bool end_file_transfer(uint32_t partition_id) {
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

    bool send_control(uint32_t control_type) {
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
};

// ============================================================================
// COMPRESSION & FILE PROCESSING
// ============================================================================

#include <lz4frame.h>

bool process_lz4_streaming(std::ifstream& file, uint64_t compressed_size, UsbDevice& usb_device, const std::string& filename, bool large_partition = false) {
    LZ4F_decompressionContext_t dctx;
    LZ4F_errorCode_t err = LZ4F_createDecompressionContext(&dctx, LZ4F_VERSION);
    if (LZ4F_isError(err)) {
        log_error("Failed to create LZ4 decompression context: " + std::string(LZ4F_getErrorName(err)));
        return false;
    }

    struct DctxCleanup {
        LZ4F_decompressionContext_t ctx;
        DctxCleanup(LZ4F_decompressionContext_t c) : ctx(c) {}
        ~DctxCleanup() { LZ4F_freeDecompressionContext(ctx); }
    } cleanup(dctx);

    size_t in_buf_size = 1024 * 1024;
    size_t out_buf_size = 4 * 1024 * 1024;
    if (compressed_size > 1024 * 1024 * 1024) {
        in_buf_size = 8 * 1024 * 1024;
        out_buf_size = 16 * 1024 * 1024;
    }
    std::vector<unsigned char> in_buf(in_buf_size);
    std::vector<unsigned char> out_buf(out_buf_size);

    uint64_t remaining_compressed = compressed_size;
    uint64_t total_uncompressed_sent = 0;

    // Read frame header to get content size
    std::streampos start_pos = file.tellg();
    size_t header_read_size = std::min((size_t)1024, (size_t)compressed_size);
    std::vector<unsigned char> header_buf(header_read_size);
    file.read((char*)header_buf.data(), header_read_size);
    if ((size_t)file.gcount() != header_read_size) {
        log_error("Failed to read LZ4 header for " + filename);
        return false;
    }
    file.seekg(start_pos);

    LZ4F_frameInfo_t frame_info;
    size_t consumed = header_read_size;
    err = LZ4F_getFrameInfo(dctx, &frame_info, header_buf.data(), &consumed);
    if (LZ4F_isError(err)) {
        log_error("Failed to get LZ4 frame info for " + filename + ": " + std::string(LZ4F_getErrorName(err)));
        return false;
    }

    uint64_t uncompressed_size = frame_info.contentSize;
    if (uncompressed_size == 0) {
        log_info("LZ4 frame for " + filename + " does not contain uncompressed size. Calculating LZ4 size (this may take a while)...");
        LZ4F_decompressionContext_t scan_dctx;
        LZ4F_createDecompressionContext(&scan_dctx, LZ4F_VERSION);
        
        uint64_t scan_remaining = compressed_size;
        while (scan_remaining > 0) {
            size_t to_read = std::min(in_buf_size, (size_t)scan_remaining);
            file.read((char*)in_buf.data(), to_read);
            size_t read = (size_t)file.gcount();
            if (read == 0) break;
            
            size_t src_off = 0;
            while (src_off < read) {
                size_t dst_sz = out_buf_size;
                size_t src_sz = read - src_off;
                LZ4F_decompress(scan_dctx, out_buf.data(), &dst_sz, in_buf.data() + src_off, &src_sz, nullptr);
                uncompressed_size += dst_sz;
                src_off += src_sz;
            }
            scan_remaining -= read;
        }
        LZ4F_freeDecompressionContext(scan_dctx);
        file.seekg(start_pos);
        remaining_compressed = compressed_size;
        log_info("Pre-scan complete. Uncompressed size: " + std::to_string(uncompressed_size));
    }

    if (!usb_device.send_file_part_header(uncompressed_size)) return false;

    size_t src_offset = 0;
    size_t src_size = 0;
    
    while (remaining_compressed > 0 || src_size > 0) {
        if (src_size == 0 && remaining_compressed > 0) {
            size_t to_read = std::min(in_buf_size, (size_t)remaining_compressed);
            file.read((char*)in_buf.data(), to_read);
            src_size = (size_t)file.gcount();
            if (src_size == 0) break;
            remaining_compressed -= src_size;
            src_offset = 0;
        }

        while (src_size > 0) {
            size_t dst_size = out_buf_size;
            size_t src_consumed = src_size;
            err = LZ4F_decompress(dctx, out_buf.data(), &dst_size, in_buf.data() + src_offset, &src_consumed, nullptr);
            
            if (LZ4F_isError(err)) {
                log_error("LZ4 decompression error for " + filename + ": " + std::string(LZ4F_getErrorName(err)));
                return false;
            }

            if (dst_size > 0) {
                if (!usb_device.send_file_part_chunk(out_buf.data(), dst_size, large_partition)) return false;
                total_uncompressed_sent += dst_size;
            }

            src_offset += src_consumed;
            src_size -= src_consumed;
            if (err == 0) break; 
        }
        if (err == 0) break;
    }

    if (total_uncompressed_sent != uncompressed_size) {
        log_error("Decompressed size mismatch for " + filename + ": expected " + std::to_string(uncompressed_size) + ", got " + std::to_string(total_uncompressed_sent));
        return false;
    }

    return true;
}

bool process_tar_file(const std::string& tar_path, UsbDevice& usb_device, const PitTable& pit_table) {
    log_info("Processing TAR file: " + tar_path);
    
    if (!check_md5_signature(tar_path)) return false;

    std::ifstream file(tar_path, std::ios::binary);
    if (!file) {
        log_error("Could not open TAR file: " + tar_path);
        return false;
    }

    file.seekg(0, std::ios::end);
    std::streampos file_size = file.tellg();
    file.seekg(0);
    uint64_t max_read_pos = (uint64_t)file_size;

    if (tar_path.size() >= 8 && tar_path.substr(tar_path.size() - 8) == ".tar.md5") {
        max_read_pos -= 32;
    }

    char header[512];
    size_t chunk_size = 1048576;

    while ((uint64_t)file.tellg() < max_read_pos) {
        if (!file.read(header, 512)) break;

        std::string filename_str(header, 100);
        std::string filename = filename_str.c_str();

        if (filename.empty()) {
            bool all_zeros = true;
            for (int k = 0; k < 512; ++k) if (header[k] != 0) { all_zeros = false; break; }
            if (all_zeros) break;
            continue;
        }

        std::string size_str(header + 124, 12);
        uint64_t data_size = 0;
        try { data_size = std::stoull(size_str, nullptr, 8); } catch (...) { 
            log_error("Invalid file size in TAR header for " + filename);
            break; 
        }

        log_info("Found file in TAR: " + filename + " (" + std::to_string(data_size) + " bytes)");

        uint32_t partition_id = 0;
        std::string partition_name = "";
        std::string base_name = sanitize_filename(filename);
        bool is_lz4 = filename.find(".lz4") != std::string::npos;

        for (const auto& entry : pit_table.entries) {
            std::string pit_file_sanitized = sanitize_filename(entry.file_name);
            std::string pit_name_sanitized = sanitize_filename(entry.partition_name);
            if (pit_file_sanitized == base_name || pit_name_sanitized == base_name || std::string(entry.file_name) == filename) {
                partition_id = entry.identifier;
                partition_name = entry.partition_name;
                log_info("Partition found in PIT: " + partition_name + " (ID: " + std::to_string(partition_id) + ")");
                break;
            }
        }

        bool is_large = (partition_name == "SYSTEM" || partition_name == "USERDATA" || partition_name == "SUPER");

        if (partition_id == 0) {
            log_info("File " + filename + " ignored: Partition not found in PIT.");
            file.ignore((std::streamsize)(data_size + (512 - (data_size % 512)) % 512));
            continue;
        }

        if (is_lz4) {
            if (!process_lz4_streaming(file, data_size, usb_device, filename, is_large)) return false;
        } else {
            if (!usb_device.send_file_part_header(data_size)) return false;

            uint64_t remaining_size = data_size;
            size_t current_chunk_size = chunk_size;
            if (data_size > 1024 * 1024 * 1024) {
                current_chunk_size = 16 * 1024 * 1024;
            }
            std::vector<unsigned char> buffer(current_chunk_size);

            while (remaining_size > 0) {
                size_t to_read = std::min((uint64_t)current_chunk_size, remaining_size);
                file.read((char*)buffer.data(), to_read);
                size_t read_count = (size_t)file.gcount();

                if (read_count == 0) {
                    log_error("Unexpected read error in TAR file.");
                    return false;
                }

                if (!usb_device.send_file_part_chunk(buffer.data(), read_count, is_large)) return false;
                remaining_size -= read_count;
            }
        }

        size_t padding = (512 - (data_size % 512)) % 512;
        file.ignore((std::streamsize)padding);

        if (!usb_device.end_file_transfer(partition_id)) return false;
    }

    return true;
}


void print_usage() {
    std::cout << "Usage: odin4 [args...]" << std::endl;
    std::cout << "Odin4 downloader. Version: " << ODIN4_VERSION << std::endl;
    std::cout << " -v        Show version" << std::endl;
    std::cout << " -w        Show license" << std::endl;
    std::cout << " -b        Add Bootloader file" << std::endl;
    std::cout << " -a        Add AP image file" << std::endl;
    std::cout << " -c        Add CP image file" << std::endl;
    std::cout << " -s        Add CSC file" << std::endl;
    std::cout << " -u        Add UMS file" << std::endl;
    std::cout << " -e        Set Nand erase option" << std::endl;
    std::cout << " -V        Home binary validation check with PIT file" << std::endl;
    std::cout << " --reboot  Reboot into normal mode" << std::endl;
    
    std::cout << " --redownload   Reboot into download mode if possible" << std::endl;
    std::cout << " -d        Set a device path (detect automatically without this option)" << std::endl;
    std::cout << " -l        Show downloadable devices path" << std::endl;
    std::cout << std::endl;
    std::cout << "IMPORTANT: You must set up your system to detect your device on LINUX host." << std::endl;
    std::cout << "Create this file: /etc/udev/rules.d/51-android.rules" << std::endl;
    std::cout << "Add this line to the file:" << std::endl;
    std::cout << "SUBSYSTEM==\"usb\", ATTR{idVendor}==\"04e8\", MODE=\"0666\", GROUP=\"plugdev\"" << std::endl;
    std::cout << std::endl;
    std::cout << "Example:" << std::endl;
    std::cout << "$ odin4 -b BL_XXXX.tar.md5 -a AP_XXXX.tar.md5 -c CP_XXXX.tar.md5 -s CSC_XXXX.tar.md5" << std::endl;
    std::cout << "Example (Select One Device):" << std::endl;
    std::cout << "$ odin4 -l" << std::endl;
    std::cout << "$ odin4 -b BL_XXXX.tar.md5 -a AP_XXXX.tar.md5 -c CP_XXXX.tar.md5 -s CSC_XXXX.tar.md5 -d /dev/bus/usb/001/002" << std::endl;
    std::cout << std::endl;
    std::cout << "Odin Repository: https://github.com/Llucs/odin4" << std::endl;
}


void print_version() {
    std::cout << "odin4 version " << ODIN4_VERSION << std::endl;
}


void print_license() {
    std::cout << "Odin4 — Open Odin Reimplementation" << std::endl;
    std::cout << std::endl;
    std::cout << "Copyright (c) 2026 Llucs" << std::endl;
    std::cout << std::endl;
    std::cout << "Licensed under the Apache License, Version 2.0 (the \"License\");" << std::endl;
    std::cout << "you may not use this software except in compliance with the License." << std::endl;
    std::cout << "You may obtain a copy of the License at:" << std::endl;
    std::cout << std::endl;
    std::cout << "  http://www.apache.org/licenses/LICENSE-2.0" << std::endl;
    std::cout << std::endl;
    std::cout << "This software is provided \"AS IS\", WITHOUT WARRANTIES OR CONDITIONS" << std::endl;
    std::cout << "OF ANY KIND, either express or implied." << std::endl;
}


void list_devices() {
    libusb_device **list;
    ssize_t cnt = libusb_get_device_list(NULL, &list);
    if (cnt < 0) return;


    struct ListCleanup {
        libusb_device **list;
        ListCleanup(libusb_device **l) : list(l) {}
        ~ListCleanup() { if (list) libusb_free_device_list(list, 1); }
    } list_cleanup(list);

    bool found = false;
    for (ssize_t i = 0; i < cnt; i++) {
        libusb_device_descriptor desc;
        if (libusb_get_device_descriptor(list[i], &desc) < 0) continue;

        if (desc.idVendor == SAMSUNG_VID) {
            const std::vector<uint16_t> DOWNLOAD_PIDS = {0x685D, 0x6600, 0x6860, 0x6861, 0x6862};
            for (uint16_t pid : DOWNLOAD_PIDS) {
                if (desc.idProduct == pid) {
                    std::cout << "/dev/bus/usb/" << std::setfill('0') << std::setw(3) << (int)libusb_get_bus_number(list[i]) << "/" << std::setfill('0') << std::setw(3) << (int)libusb_get_device_address(list[i]) << std::endl;
                    found = true;
                }
            }
        }
    }

    if (!found) {
        std::cout << "No Samsung devices found in download mode." << std::endl;
    }
}

// ============================================================================
// FLASHING LOGIC
// ============================================================================

int run_flash_logic(const OdinConfig& config) {
    UsbDevice usb_device;
    if (!usb_device.open_device(config.device_path)) {
        log_error("The device could not be found or the connection established.");
        return 1;
    }

    if (!usb_device.handshake()) {
        log_error("Handshake failed.");
        return 1;
    }

    if (!usb_device.request_device_type()) {
        log_error("The device type request failed.");
        return 1;
    }

    if (!usb_device.begin_session()) {
        log_error("Session begin failed.");
        return 1;
    }

    if (!usb_device.request_pit()) {
        log_error("PIT request failed.");
        return 1;
    }

    PitTable pit_table;
    if (!usb_device.receive_pit_table(pit_table)) {
        log_error("PIT receipt failed.");
        return 1;
    }

    std::vector<std::pair<std::string, std::string>> files = {
        {"BL", config.bootloader}, 
        {"AP", config.ap}, 
        {"CP", config.cp}, 
        {"CSC", config.csc},
        {"UMS", config.ums}
    };

    bool success = true;
    for (const auto& f : files) {
        if (!f.second.empty()) {
            if (!process_tar_file(f.second, usb_device, pit_table)) {
                log_error("Flash failed during file processing: " + f.first);
                success = false;
                break;
            }
        }
    }

    if (!success) {
        usb_device.end_session();
        return 1;
    }

    if (config.reboot) {
        if (!usb_device.send_control(THOR_CONTROL_REBOOT)) {
            log_error("The reboot command failed.");
            return 1;
        }
    }

    if (config.redownload) {
        if (!usb_device.send_control(THOR_CONTROL_REDOWNLOAD)) {
            log_error("The redownload command failed.");
            return 1;
        }
    }

    if (!usb_device.end_session()) {
        log_error("Session closure failed.");
        return 1;
    }

    log_info("Flash process completed successfully.");
    return 0;
}

int process_arguments_and_run(int argc, char** argv) {
    OdinConfig config;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "-h") { 
            print_usage(); 
            return 0; 
        }
        if (arg == "-v") { 
            print_version(); 
            return 0; 
        }
        if (arg == "-w") { 
            print_license(); 
            return 0; 
        }
        if (arg == "-l") { 
            list_devices(); 
            return 0; 
        }
        if (arg == "--reboot") { 
            config.reboot = true; 
            continue; 
        }
        if (arg == "--redownload") { 
            config.redownload = true; 
            continue; 
        }
        if (arg == "-e") { 
            config.nand_erase = true; 
            continue; 
        }
        if (arg == "-V") { 
            config.validation = true; 
            continue; 
        }

        if (arg == "-b" || arg == "-a" || arg == "-c" || arg == "-s" || arg == "-u" || arg == "-d") {
            if (i + 1 >= argc) {
                std::cerr << "Error: Option '" << arg << "' requires an argument." << std::endl;
                return 1;
            }
            if (arg == "-b") config.bootloader = argv[++i];
            else if (arg == "-a") config.ap = argv[++i];
            else if (arg == "-c") config.cp = argv[++i];
            else if (arg == "-s") config.csc = argv[++i];
            else if (arg == "-u") config.ums = argv[++i];
            else if (arg == "-d") config.device_path = argv[++i];
        } else if (arg[0] == '-') {
            std::cerr << "odin4: illegal option -- '" << (arg.length() > 1 ? arg[1] : '?') << "'" << std::endl;
            return 1;
        }
    }

    if (config.bootloader.empty() && config.ap.empty() && config.cp.empty() && config.csc.empty() && config.ums.empty() && !config.reboot && !config.redownload) {
        print_usage();
        return 1;
    }

    return run_flash_logic(config);
}



int main(int argc, char** argv) {
    int err = libusb_init(NULL);
    if (err < 0) {
        std::cerr << "[ERROR] Failed to initialize libusb: " << libusb_error_name(err) << std::endl;
        return 1;
    }
    
    int result = process_arguments_and_run(argc, argv);
    
    libusb_exit(NULL);
    return result;
}
