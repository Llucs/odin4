// ============================================================================
// ODIN4 - Samsung Device Flashing Tool
// Version: 1.3.0 (4634111)
// Protocol: Thor USB Communication
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
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>
#include <cryptopp/hex.h>

// ============================================================================
// CONSTANTS & DEFINITIONS
// ============================================================================

#define ODIN4_VERSION "1.3.0 (4634111)"
#define SAMSUNG_VID 0x04E8
#define USB_RETRY_COUNT 3
#define USB_TIMEOUT_BULK 60000 // 60 
#define USB_TIMEOUT_CONTROL 5000 // 5 

// ============================================================================
// UTILITIES
// ============================================================================

// --- Logging ---
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
    std::cout << "[DEBUG] " << title << " (" << size << " bytes):" << std::endl;
    const unsigned char* bytes = static_cast<const unsigned char*>(data);
    for (size_t i = 0; i < size; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)bytes[i] << " ";
        if ((i + 1) % 16 == 0) std::cout << std::endl;
    }
    if (size % 16 != 0) std::cout << std::endl;
    std::cout << std::dec;
}

// --- Endianness Helper (Samsung protocol is Little Endian) ---
uint32_t le32_to_h(uint32_t le_val) {
    uint32_t host_val = 1;
    if (*(char*)&host_val == 1) { // Host is Little Endian
        return le_val;
    } else { // Host is Big Endian
        return (le_val >> 24) | 
               ((le_val >> 8) & 0x0000FF00) | 
               ((le_val << 8) & 0x00FF0000) | 
               (le_val << 24);
    }
}

// --- MD5 Validation ---
bool check_md5_signature(const std::string& file_path) {
    if (file_path.size() < 8 || file_path.substr(file_path.size() - 8) != ".tar.md5") {
        return true; 
    }

    log_info("Verificando assinatura MD5 para " + file_path);
    std::ifstream file(file_path, std::ios::binary | std::ios::ate);
    if (!file) {
        log_error("Não foi possível abrir o arquivo para verificação MD5: " + file_path);
        return false;
    }

    // Usamos long long para evitar ambiguidade com std::streampos
    long long file_size = file.tellg();
    if (file_size < 32) {
        log_error("Arquivo muito pequeno para conter assinatura MD5.");
        return false;
    }

    // 1. Ler a assinatura MD5 esperada (últimos 32 bytes)
    file.seekg(file_size - 32);
    char expected_md5_hex[33];
    file.read(expected_md5_hex, 32);
    expected_md5_hex[32] = '\0';
    std::string expected_md5(expected_md5_hex);

    log_info("MD5 Esperado: " + expected_md5);

    // 2. Calcular o MD5 do conteúdo
    file.seekg(0);
    size_t content_size = (size_t)(file_size - 32);

    CryptoPP::Weak::MD5 hash;
    std::vector<unsigned char> digest(hash.DigestSize());

    std::vector<char> buffer(1048576);

    size_t total_read = 0;

    while (total_read < content_size) {
        size_t to_read = std::min((size_t)buffer.size(), content_size - total_read);
        file.read(buffer.data(), (std::streamsize)to_read);
        size_t read_count = (size_t)file.gcount();

        if (read_count == 0) break;

        hash.Update((const unsigned char*)buffer.data(), read_count);
        total_read += read_count;
    }

    hash.Final(digest.data());

    // 3. Converter para hexadecimal
    std::string calculated_md5;
    CryptoPP::HexEncoder encoder;
    encoder.Attach(new CryptoPP::StringSink(calculated_md5));
    encoder.Put(digest.data(), digest.size());
    encoder.MessageEnd();

    // Converter para minúsculas para comparação
    std::transform(calculated_md5.begin(), calculated_md5.end(), calculated_md5.begin(), ::tolower);
    
    // Normalizar expected_md5 também
    std::string expected_md5_lower = expected_md5;
    std::transform(expected_md5_lower.begin(), expected_md5_lower.end(), expected_md5_lower.begin(), ::tolower);

    log_info("MD5 Calculado: " + calculated_md5);

    // 4. Comparar (Ignorar case - Samsung as vezes usa maiúsculas)
    if (calculated_md5 == expected_md5_lower) {
        log_info("Verificação MD5 bem-sucedida.");
        return true;
    } else {
        log_error("Verificação MD5 falhou! Esperado: " + expected_md5_lower + " | Calculado: " + calculated_md5);
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
    uint32_t file_part_size;
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

struct PitTable {
    uint32_t header_size;
    uint32_t entry_count;
    std::vector<PitEntry> entries;
};

#pragma pack(pop)

// ============================================================================
// USB DEVICE COMMUNICATION CLASS
// ============================================================================

class UsbDevice {
private:
    libusb_device_handle *handle = nullptr;
    libusb_device *device = nullptr;
    const std::vector<uint16_t> DOWNLOAD_PIDS = {0x685D, 0x6600, 0x6860, 0x6861, 0x6862};
    
    const uint8_t ENDPOINT_OUT = 0x01;
    const uint8_t ENDPOINT_IN = 0x81;

    // RAII wrapper para libusb_device_handle
    struct HandleCloser {
        libusb_device_handle *&h;
        HandleCloser(libusb_device_handle *&handle_ref) : h(handle_ref) {}
        ~HandleCloser() {
            if (h) {
                libusb_release_interface(h, 0);
                libusb_close(h);
                h = nullptr;
            }
        }
    };

public:
    UsbDevice() = default;
    ~UsbDevice() {
        // O destrutor da classe UsbDevice não precisa fazer nada,
        // pois o HandleCloser local em open_device e a refatoração
        // do open_device já garantem o cleanup.
    }

    // --- Device Detection & Connection ---
        bool open_device(const std::string& specific_path = "") {
        libusb_device **list = nullptr;
        ssize_t cnt = libusb_get_device_list(NULL, &list);
        if (cnt < 0) {
            log_error("Falha ao obter lista de dispositivos USB", (int)cnt);
            return false;
        }

        struct ListCleanup {
            libusb_device **list;
            ListCleanup(libusb_device **l) : list(l) {}
            ~ListCleanup() { if (list) libusb_free_device_list(list, 1); }
        } list_cleanup(list);

        for (ssize_t i = 0; i < cnt; i++) {
            libusb_device_descriptor desc;
            if (libusb_get_device_descriptor(list[i], &desc) < 0) continue;

            if (desc.idVendor == SAMSUNG_VID) {
                if (!specific_path.empty()) {
                    std::stringstream path_ss;
                    path_ss << "/dev/bus/usb/" << (int)libusb_get_bus_number(list[i]) << "/" << (int)libusb_get_device_address(list[i]);
                    if (path_ss.str() != specific_path) continue;
                }
                for (uint16_t pid : DOWNLOAD_PIDS) {
                    if (desc.idProduct == pid) {
                        device = list[i];
                        break;
                    }
                }
            }
            if (device) break;
        }

        if (!device) {
            log_info("Nenhum dispositivo Samsung em modo download encontrado.");
            return false;
        }

        int err = libusb_open(device, &handle);
        if (err < 0) {
            log_error("Falha ao abrir dispositivo USB", err);
            return false;
        }

        // RAII para garantir o fechamento do handle em caso de falha posterior
        HandleCloser closer(handle);

        if (libusb_kernel_driver_active(handle, 0) == 1) {
            int detach_err = libusb_detach_kernel_driver(handle, 0);
            if (detach_err < 0) {
                log_error("Falha ao desanexar driver do kernel", detach_err);
                return false;
            }
        }

        err = libusb_claim_interface(handle, 0);
        if (err < 0) {
            log_error("Falha ao reivindicar interface USB", err);
            return false;
        }
        
        // Se tudo deu certo, desativa o RAII local para que o handle seja gerenciado pelo UsbDevice
        closer.h = nullptr;
        return true;
    }

    // --- Low-level USB Communication ---
    bool send_packet(const void *data, size_t size, bool log_dump = false) {
        int actual_length;
        int err = 0;
        int timeout = log_dump ? USB_TIMEOUT_CONTROL : USB_TIMEOUT_BULK;
        
        for (int attempt = 0; attempt < USB_RETRY_COUNT; ++attempt) {
            err = libusb_bulk_transfer(handle, ENDPOINT_OUT, (unsigned char*)data, size, &actual_length, timeout);
            
            if (err == 0 && actual_length == (int)size) {
                if (log_dump) log_hexdump("Pacote Enviado (Controle)", data, size);
                return true; // Sucesso
            }
            
            if (err != 0) {
                log_error("Falha no envio de pacote USB (tentativa " + std::to_string(attempt + 1) + ")", err);
            } else {
                log_error("Tamanho de envio incorreto (tentativa " + std::to_string(attempt + 1) + "): esperado " + std::to_string(size) + ", enviado " + std::to_string(actual_length));
            }
            
            if (attempt < USB_RETRY_COUNT - 1) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100)); // Pequena pausa antes de tentar novamente
            }
        }
        
        return false; // Falha após todas as tentativas
    }

    bool receive_packet(void *data, size_t size, int *actual_length, bool log_dump = false) {
        int err = 0;
        int timeout = log_dump ? USB_TIMEOUT_CONTROL : USB_TIMEOUT_BULK;
        
        for (int attempt = 0; attempt < USB_RETRY_COUNT; ++attempt) {
            err = libusb_bulk_transfer(handle, ENDPOINT_IN, (unsigned char*)data, size, actual_length, timeout);
            
            if (err == 0) {
                if (log_dump) log_hexdump("Pacote Recebido (Controle)", data, *actual_length);
                return true; // Sucesso
            }
            
            log_error("Falha no recebimento de pacote USB (tentativa " + std::to_string(attempt + 1) + ")", err);
            
            if (attempt < USB_RETRY_COUNT - 1) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100)); // Pequena pausa antes de tentar novamente
            }
        }
        
        return false; // Falha após todas as tentativas
    }

    // --- Thor Protocol Handshake ---
    bool handshake() {
        log_info("Iniciando Handshake...");
        ThorHandshakePacket pkt;
        pkt.header.packet_size = sizeof(ThorHandshakePacket);
        pkt.header.packet_type = THOR_PACKET_HANDSHAKE;
        pkt.header.packet_flags = 0;
        pkt.magic = 0x00000001;
        pkt.version = 0x00000001;
        pkt.packet_size = 0x00400000;

        if (!send_packet(&pkt, sizeof(pkt), true)) return false;

        ThorResponsePacket response;
        int actual_length;
        if (!receive_packet(&response, sizeof(response), &actual_length, true)) return false;
        
        if (response.header.packet_type != THOR_PACKET_RESPONSE || response.response_code != 0) {
            log_error("Handshake falhou. Tipo de pacote: " + std::to_string(response.header.packet_type) + ", Código de resposta: " + std::to_string(response.response_code));
            
            // Tenta limpar o buffer de entrada USB e retentar o Handshake
            log_info("Tentando limpar o buffer de entrada USB e retentar o Handshake...");
            libusb_clear_halt(handle, ENDPOINT_IN);
            
            // Tenta o handshake novamente (retry manual)
            if (!send_packet(&pkt, sizeof(pkt), true)) return false;

            if (!receive_packet(&response, sizeof(response), &actual_length, true)) return false;
            
            if (response.header.packet_type != THOR_PACKET_RESPONSE || response.response_code != 0) {
                log_error("Handshake falhou após retry. Tipo de pacote: " + std::to_string(response.header.packet_type) + ", Código de resposta: " + std::to_string(response.response_code));
                return false;
            }
        }
        log_info("Handshake bem-sucedido.");
        return true;
    }

    // --- Device Type Request ---
    bool request_device_type() {
        log_info("Solicitando tipo de dispositivo...");
        ThorPacketHeader pkt;
        pkt.packet_size = sizeof(ThorPacketHeader);
        pkt.packet_type = THOR_PACKET_DEVICE_TYPE;
        pkt.packet_flags = 0;

        if (!send_packet(&pkt, sizeof(pkt), true)) return false;

        ThorDeviceTypePacket response;
        int actual_length;
        if (!receive_packet(&response, sizeof(response), &actual_length, true)) return false;

        if (response.header.packet_type != THOR_PACKET_DEVICE_TYPE) {
            log_error("Solicitação de tipo de dispositivo falhou. Tipo de pacote inesperado: " + std::to_string(response.header.packet_type));
            return false;
        }
        log_info("Tipo de dispositivo recebido.");
        return true;
    }

    // --- Session Management ---
    bool begin_session() {
        log_info("Iniciando sessão...");
        ThorBeginSessionPacket pkt;
        pkt.header.packet_size = sizeof(ThorBeginSessionPacket);
        pkt.header.packet_type = THOR_PACKET_BEGIN_SESSION;
        pkt.header.packet_flags = 0;
        pkt.unknown1 = 0;
        pkt.unknown2 = 0;

        if (!send_packet(&pkt, sizeof(pkt), true)) return false;

        ThorResponsePacket response;
        int actual_length;
        if (!receive_packet(&response, sizeof(response), &actual_length, true)) return false;

        if (response.header.packet_type != THOR_PACKET_RESPONSE || response.response_code != 0) {
            log_error("Início de sessão falhou. Código de resposta: " + std::to_string(response.response_code));
            return false;
        }
        log_info("Sessão iniciada com sucesso.");
        return true;
    }

    bool end_session() {
        log_info("Encerrando sessão...");
        ThorEndSessionPacket pkt;
        pkt.header.packet_size = sizeof(ThorEndSessionPacket);
        pkt.header.packet_type = THOR_PACKET_END_SESSION;
        pkt.header.packet_flags = 0;

        if (!send_packet(&pkt, sizeof(pkt), true)) return false;

        ThorResponsePacket response;
        int actual_length;
        if (!receive_packet(&response, sizeof(response), &actual_length, true)) return false;

        if (response.header.packet_type != THOR_PACKET_RESPONSE || response.response_code != 0) {
            log_error("Encerramento de sessão falhou. Código de resposta: " + std::to_string(response.response_code));
            return false;
        }
        log_info("Sessão encerrada com sucesso.");
        return true;
    }

    // --- PIT (Partition Information Table) Operations ---
    bool request_pit() {
        log_info("Solicitando PIT...");
        ThorPacketHeader pkt;
        pkt.packet_size = sizeof(ThorPacketHeader);
        pkt.packet_type = THOR_PACKET_PIT_FILE;
        pkt.packet_flags = 0;

        if (!send_packet(&pkt, sizeof(pkt), true)) return false;

        ThorPitFilePacket response;
        int actual_length;
        if (!receive_packet(&response, sizeof(response), &actual_length, true)) return false;

        if (response.header.packet_type != THOR_PACKET_PIT_FILE) {
            log_error("Solicitação de PIT falhou. Tipo de pacote inesperado: " + std::to_string(response.header.packet_type));
            return false;
        }
        log_info("Pacote de tamanho do PIT recebido.");
        return true;
    }

    bool receive_pit_table(PitTable& pit_table) {
        ThorPitFilePacket pit_size_pkt;
        int actual_length;
        if (!receive_packet(&pit_size_pkt, sizeof(pit_size_pkt), &actual_length, true)) return false;

        uint32_t pit_data_size = le32_to_h(pit_size_pkt.pit_file_size);
        if (pit_data_size == 0 || pit_data_size > 1048576) {
            log_error("Tamanho de PIT invalido ou muito grande.");
            return false;
        }

        log_info("Tamanho do PIT: " + std::to_string(pit_data_size) + " bytes.");
        
                    try {
                std::vector<unsigned char> compressed_data(data_size);
                file.read((char*)compressed_data.data(), data_size);
                
                std::vector<unsigned char> final_data = decompress_lz4_block(compressed_data, filename);
                std::vector<unsigned char>().swap(compressed_data); 

                if (final_data.empty()) {
                    file.ignore((512 - (data_size % 512)) % 512);
                    continue;
                }
                
                if (!usb_device.send_file_part_header(final_data.size())) return false;

                for (size_t i = 0; i < final_data.size(); i += CHUNK_SIZE) {
                    size_t to_send = std::min(CHUNK_SIZE, final_data.size() - i);
                    if (!usb_device.send_file_part_chunk(&final_data[i], to_send)) return false;
                }
            } catch (const std::bad_alloc& e) {
                log_error("Memoria insuficiente para descomprimir " + filename);
                return false;
            }
             char> pit_data(pit_data_size);
        if (!receive_packet(pit_data.data(), pit_data_size, &actual_length)) return false;

        // Validação de tamanho mínimo
        if (pit_data_size < 8) {
            log_error("Tamanho do PIT recebido muito pequeno.");
            return false;
        }

        // Endianness fix e validação de bounds
        pit_table.header_size = le32_to_h(*(uint32_t*)&pit_data[0]);
        pit_table.entry_count = le32_to_h(*(uint32_t*)&pit_data[4]);
        
        // Validação de tamanho total
        size_t expected_min_size = pit_table.header_size + (pit_table.entry_count * 128);
        if (pit_data_size < expected_min_size) {
            log_error("Tamanho do PIT recebido (" + std::to_string(pit_data_size) + ") é menor que o esperado (" + std::to_string(expected_min_size) + ").");
            return false;
        }

        pit_table.entries.resize(pit_table.entry_count);
        log_info("Lendo " + std::to_string(pit_table.entry_count) + " entradas PIT.");

        for (uint32_t i = 0; i < pit_table.entry_count; ++i) {
            size_t offset = pit_table.header_size + (i * 128);
            
            if (offset + 128 > pit_data_size) {
                log_error("Acesso fora dos limites ao ler a entrada PIT " + std::to_string(i) + ".");
                return false;
            }

            // Endianness fix aplicado
            pit_table.entries[i].identifier = le32_to_h(*(uint32_t*)&pit_data[offset + 0]);
            pit_table.entries[i].flash_type = le32_to_h(*(uint32_t*)&pit_data[offset + 8]);
            pit_table.entries[i].file_size = le32_to_h(*(uint32_t*)&pit_data[offset + 12]);
            pit_table.entries[i].block_size = le32_to_h(*(uint32_t*)&pit_data[offset + 16]);
            
            // Correção: Garante o terminador nulo (\0)
            strncpy(pit_table.entries[i].partition_name, (char*)&pit_data[offset + 32], 31);
            pit_table.entries[i].partition_name[31] = '\0';
            
            strncpy(pit_table.entries[i].file_name, (char*)&pit_data[offset + 64], 31);
            pit_table.entries[i].file_name[31] = '\0';
        }
        log_info("PIT lido com sucesso.");
        return true;
    }

    // --- File Transfer Operations ---
    bool send_file_part_chunk(const void* data, size_t size) {
        // Envia um chunk de dados. Não é idempotente, então não deve ter retry.
        int actual_length;
        int err = libusb_bulk_transfer(handle, ENDPOINT_OUT, (unsigned char*)data, size, &actual_length, USB_TIMEOUT_BULK);
        
        if (err != 0) {
            log_error("Falha no envio de chunk USB", err);
            return false;
        }
        if (actual_length != (int)size) {
            log_error("Tamanho de chunk enviado incorreto: esperado " + std::to_string(size) + ", enviado " + std::to_string(actual_length));
            return false;
        }
        return true;
    }

    bool send_file_part_header(size_t total_size) {
        ThorFilePartSizePacket size_pkt;
        size_pkt.header.packet_size = sizeof(ThorFilePartSizePacket);
        size_pkt.header.packet_type = THOR_PACKET_FILE_PART_SIZE;
        size_pkt.header.packet_flags = 0;
        size_pkt.file_part_size = total_size;

        if (!send_packet(&size_pkt, sizeof(size_pkt), true)) return false;

        ThorResponsePacket response;
        int actual_length;
        if (!receive_packet(&response, sizeof(response), &actual_length, true)) return false;

        if (response.header.packet_type != THOR_PACKET_RESPONSE || response.response_code != 0) {
            log_error("Resposta inesperada ao enviar tamanho da parte do arquivo. Código: " + std::to_string(response.response_code));
            return false;
        }
        return true;
    }

    bool end_file_transfer(uint32_t partition_id) {
        log_info("Finalizando transferência de arquivo para partição ID: " + std::to_string(partition_id));
        ThorEndFileTransferPacket pkt;
        pkt.header.packet_size = sizeof(ThorEndFileTransferPacket);
        pkt.header.packet_type = THOR_PACKET_END_FILE_TRANSFER;
        pkt.header.packet_flags = 0;
        pkt.partition_id = partition_id;

        if (!send_packet(&pkt, sizeof(pkt), true)) return false;

        ThorResponsePacket response;
        int actual_length;
        if (!receive_packet(&response, sizeof(response), &actual_length, true)) return false;

        if (response.header.packet_type != THOR_PACKET_RESPONSE || response.response_code != 0) {
            log_error("Finalização de transferência falhou. Código de resposta: " + std::to_string(response.response_code));
            return false;
        }
        log_info("Transferência finalizada com sucesso.");
        return true;
    }

    // --- Control Commands ---
    bool send_control(uint32_t control_type) {
        log_info("Enviando comando de controle: " + std::to_string(control_type));
        ThorControlPacket pkt;
        pkt.header.packet_size = sizeof(ThorControlPacket);
        pkt.header.packet_type = THOR_PACKET_CONTROL;
        pkt.header.packet_flags = 0;
        pkt.control_type = control_type;

        if (!send_packet(&pkt, sizeof(pkt), true)) return false;

        ThorResponsePacket response;
        int actual_length;
        if (!receive_packet(&response, sizeof(response), &actual_length, true)) return false;

        if (response.header.packet_type != THOR_PACKET_RESPONSE || response.response_code != 0) {
            log_error("Comando de controle falhou. Código de resposta: " + std::to_string(response.response_code));
            return false;
        }
        log_info("Comando de controle enviado com sucesso.");
        return true;
    }
};

// ============================================================================
// COMPRESSION & FILE PROCESSING
// ============================================================================

// --- LZ4 Decompression (Simplificada para streaming) ---
std::vector<unsigned char> decompress_lz4_block(const std::vector<unsigned char>& compressed, const std::string& filename) {
    // Tenta estimar o tamanho de saída com base no tamanho de entrada (x4)
    size_t estimated_size = compressed.size() * 4;
    std::vector<unsigned char> decompressed(estimated_size);

    int result = LZ4_decompress_safe((const char*)compressed.data(), (char*)decompressed.data(), compressed.size(), estimated_size);

    if (result < 0) {
        // Tenta com um buffer maior, se a estimativa inicial falhar
        log_info("Tentativa inicial de descompressão falhou. Tentando com buffer de 512MB.");
        decompressed.resize(512 * 1024 * 1024); // 512MB
        result = LZ4_decompress_safe((const char*)compressed.data(), (char*)decompressed.data(), compressed.size(), decompressed.size());
    }

    if (result <= 0) {
        log_error("Falha na descompressão LZ4 para o arquivo " + filename + ". Código de erro: " + std::to_string(result));
        return {};
    }
    decompressed.resize(result);
    return decompressed;
}

// --- TAR File Processing (Refatorado para Streaming) ---
bool process_tar_file(const std::string& tar_path, UsbDevice& usb_device, const PitTable& pit_table) {
    log_info("Processando arquivo TAR: " + tar_path);
    
    // 1. Verificação de MD5
    if (!check_md5_signature(tar_path)) {
        return false;
    }

    std::ifstream file(tar_path, std::ios::binary);
    if (!file) {
        log_error("Não foi possível abrir o arquivo TAR: " + tar_path);
        return false;
    }

    // Se for .tar.md5, ignora os últimos 32 bytes (assinatura MD5)
    if (tar_path.size() >= 8 && tar_path.substr(tar_path.size() - 8) == ".tar.md5") {
        std::streampos file_size = file.seekg(0, std::ios::end).tellg();
        file.seekg(0);
        // O loop de leitura do TAR deve parar 32 bytes antes do final do arquivo.
        // O loop `while (file.read(header, 512))` vai cuidar disso,
        // mas precisamos garantir que o `file.read` não leia o header
        // se estivermos nos últimos 32 bytes.
        // A lógica de parada será implícita, pois o `file.read(header, 512)` falhará
        // se houver menos de 512 bytes restantes, o que é o caso nos últimos 32 bytes.
    }

    char header[512];
    uint32_t part_index = 0;
    const size_t CHUNK_SIZE = 1048576; // 1MB para leitura/envio

        while (file.tellg() < max_read_pos && file.read(header, 512)) {
        std::string filename(header, 100);
        filename = filename.c_str();

        if (filename.empty()) break;

        std::string size_str(header + 124, 12);
        size_t data_size = 0;
        try { data_size = std::stoull(size_str, nullptr, 8); } catch (...) { break; }

        log_info("Encontrado arquivo no TAR: " + filename + " (tamanho: " + std::to_string(data_size) + " bytes)");

        // 2. Encontrar a partição no PIT
        uint32_t partition_id = 0;
        std::string base_name = filename;
        bool is_lz4 = base_name.find(".lz4") != std::string::npos;
        if (is_lz4) {
            base_name = base_name.substr(0, base_name.find(".lz4"));
        }

        for (const auto& entry : pit_table.entries) {
            if (std::string(entry.file_name) == base_name || std::string(entry.file_name) == filename) {
                partition_id = entry.identifier;
                log_info("Partição encontrada no PIT: " + std::string(entry.partition_name) + " (ID: " + std::to_string(partition_id) + ")");
                break;
            }
        }

        if (partition_id == 0) {
            log_info("Arquivo " + filename + " ignorado: Partição não encontrada no PIT.");
            file.ignore(data_size + (512 - (data_size % 512)) % 512);
            continue;
        }

        // 3. Lógica de Streaming
        if (is_lz4) {
            // Se for LZ4, precisamos ler o arquivo COMPRIMIDO inteiro para a memória
            // antes de descompactar, pois o LZ4 Frame é um bloco único.
            // Isso ainda é um problema de memória, mas é a limitação da API LZ4_decompress_safe.
            
            try {
                std::vector<unsigned char> compressed_data(data_size);
                file.read((char*)compressed_data.data(), data_size);
                
                std::vector<unsigned char> final_data = decompress_lz4_block(compressed_data, filename);
                std::vector<unsigned char>().swap(compressed_data); 

                if (final_data.empty()) {
                    file.ignore((512 - (data_size % 512)) % 512);
                    continue;
                }
                
                if (!usb_device.send_file_part_header(final_data.size())) return false;

                for (size_t i = 0; i < final_data.size(); i += CHUNK_SIZE) {
                    size_t to_send = std::min(CHUNK_SIZE, final_data.size() - i);
                    if (!usb_device.send_file_part_chunk(&final_data[i], to_send)) return false;
                }
            } catch (const std::bad_alloc& e) {
                log_error("Memoria insuficiente para descomprimir " + filename);
                return false;
            }
            
            // Envia o cabeçalho com o tamanho TOTAL DESCOMPRIMIDO
            if (!usb_device.send_file_part_header(final_data.size())) return false;

            // Envia em chunks de 1MB
            for (size_t i = 0; i < final_data.size(); i += CHUNK_SIZE) {
                size_t to_send = std::min(CHUNK_SIZE, final_data.size() - i);
                if (!usb_device.send_file_part_chunk(&final_data[i], to_send)) return false;
            }

        } else {
            // Arquivo normal (não comprimido) - Streaming direto
            if (!usb_device.send_file_part_header(data_size)) return false;

            size_t remaining_size = data_size;
            std::vector<unsigned char> buffer(CHUNK_SIZE);

            while (remaining_size > 0) {
                size_t to_read = std::min(CHUNK_SIZE, remaining_size);
                file.read((char*)buffer.data(), to_read);
                size_t read_count = file.gcount();

                if (read_count == 0) {
                    log_error("Erro de leitura inesperado no arquivo TAR.");
                    return false;
                }

                if (!usb_device.send_file_part_chunk(buffer.data(), read_count)) return false;
                remaining_size -= read_count;
            }
        }

        // 4. Ignorar padding e finalizar transferência
        size_t padding = (512 - (data_size % 512)) % 512;
        file.ignore(padding);

        if (!usb_device.end_file_transfer(partition_id)) return false;
        part_index++;
    }

    return true;
}

// ============================================================================
// USER INTERFACE & HELP MENU
// ============================================================================

// --- Help Menu ---
void print_usage() {
    std::cout << "Usage : odin4 [args...]" << std::endl;
    std::cout << "Odin4 downloader. odin4 version " << ODIN4_VERSION << std::endl;
    std::cout << " -v        SHOW VERSION" << std::endl;
    std::cout << " -w        Show License" << std::endl;
    std::cout << " -b        Add Bootloader file" << std::endl;
    std::cout << " -a        Add AP image file" << std::endl;
    std::cout << " -c        Add CP image file" << std::endl;
    std::cout << " -s        Add CSC file" << std::endl;
    std::cout << " -u        Add UMS file" << std::endl;
    std::cout << " -e        Set Nand erase option" << std::endl;
    std::cout << " -V        Home binary validation check with pit file" << std::endl;
    std::cout << " --reboot  Reboot into normal mode" << std::endl;
    std::cout << " --redownload   Reboot into download mode if it possible (not working in normal case)" << std::endl;
    std::cout << " -d        Set a device path (detect automatically without this option)" << std::endl;
    std::cout << " -l        Show downloadable devices path" << std::endl;
    std::cout << std::endl;
    std::cout << "IMPORTANT : You must set up your system to detect your device on LINUX host." << std::endl;
    std::cout << " create this file: /etc/udev/rules.d/51-android.rules" << std::endl;
    std::cout << " to add a line to the file:" << std::endl;
    std::cout << " SUBSYSTEM==\"usb\", ATTR{idVendor}==\"04e8\", MODE=\"0666\", GROUP=\"plugdev\"" << std::endl;
    std::cout << "   (http://developer.android.com/tools/device.html)" << std::endl;
    std::cout << " And you maybe need to unload a module cdc_acm before downloading. (This is only needed for older kernels.)" << std::endl;
    std::cout << "   $sudo rmmod cdc_acm" << std::endl;
    std::cout << " OR" << std::endl;
    std::cout << "   echo \"blacklist cdc_acm\" > /etc/modprobe.d/cdc_acm-blacklist.conf" << std::endl;
    std::cout << std::endl;
    std::cout << "Example :" << std::endl;
    std::cout << "$odin4 -b BL_XXXX.tar.md5 -a AP_XXXX.tar.md5 -c CP_XXXX.tar.md5 -s CSC_XXXX.tar.md5" << std::endl;
    std::cout << "Example (Select One Device):" << std::endl;
    std::cout << "$odin4 -l" << std::endl;
    std::cout << "PATH_OF_DEVICE_A" << std::endl;
    std::cout << "PATH_OF_DEVICE_B" << std::endl;
    std::cout << "$odin4 -b BL_XXXX.tar.md5 -a AP_XXXX.tar.md5 -c CP_XXXX.tar.md5 -s CSC_XXXX.tar.md5 -d PATH_OF_DEVICE_A" << std::endl;
    std::cout << std::endl;
    std::cout << "Odin Repository: https://github.com/Llucs/odin4" << std::endl;
}

// --- Version Info ---
void print_version() {
    std::cout << "odin4 version " << ODIN4_VERSION << std::endl;
}

// --- License Info ---
void print_license() {
    std::cout << "Odin4 — Open Odin Reimplementation" << std::endl;
    std::cout << std::endl;
    std::cout << "Copyright (c) 2026 Leandro Lucas Mendes de Souza"
              << std::endl;
    std::cout << std::endl;
    std::cout << "Licensed under the Apache License, Version 2.0 (the \"License\");"
              << std::endl;
    std::cout << "you may not use this software except in compliance with the License."
              << std::endl;
    std::cout << "You may obtain a copy of the License at:"
              << std::endl;
    std::cout << std::endl;
    std::cout << "  http://www.apache.org/licenses/LICENSE-2.0"
              << std::endl;
    std::cout << std::endl;
    std::cout << "This software is provided \"AS IS\", WITHOUT WARRANTIES OR CONDITIONS"
              << std::endl;
    std::cout << "OF ANY KIND, either express or implied."
              << std::endl;
}

// --- List Connected Devices ---
void list_devices() {
    libusb_device **list;
    ssize_t cnt = libusb_get_device_list(NULL, &list);
    if (cnt < 0) return;

    // RAII-like cleanup for device list
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
                    std::cout << "/dev/bus/usb/" << libusb_get_bus_number(list[i]) << "/" << libusb_get_device_address(list[i]) << std::endl;
                    found = true;
                    break;
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
        log_error("Login failed.");
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
                log_error("Flash failed during file processing. " + f.first + ".");
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

// ============================================================================
// ARGUMENT PARSING & MAIN
// ============================================================================

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

        if ((arg == "-b" || arg == "-a" || arg == "-c" || arg == "-s" || arg == "-u" || arg == "-d") && i + 1 < argc) {
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

// ============================================================================
// ENTRY POINT
// ============================================================================

int main(int argc, char** argv) {
    libusb_init(NULL);
    int result = process_arguments_and_run(argc, argv);
    libusb_exit(NULL);
    return result;
}

// ============================================================================
// END OF ODIN4
// ============================================================================
