# Thor Protocol Technical Report

**Author**: Llucs

## 1. Introduction

The Thor protocol, also known as Odin, is a proprietary USB communication protocol developed by Samsung. It is primarily utilized by Samsung devices when operating in Download Mode for various firmware management operations, including reading, writing, and overall firmware handling. This report provides a comprehensive technical overview of the Thor protocol, detailing its communication layers, packet structures, command sets, Partition Information Table (PIT) management, and file transfer mechanisms.

## 2. Transport Layer and Handshake

Communication within the Thor protocol is established over USB using Bulk Transfers. The target USB interface typically belongs to the `0x0A` (CDC Data) class and features two endpoints (one IN and one OUT). Samsung's standard Vendor ID (VID) is `0x04E8`, with common Product IDs (PID) in Download Mode including `0x6601`, `0x685D`, and `0x68C3`.

### 2.1. Initial Handshake

Before any operational data transfer, an initial handshake procedure is performed to confirm the presence and readiness of the device's bootloader (LOKE).

*   **Host to Device**: The host initiates the handshake by sending the ASCII string `ODIN` (4 bytes).
*   **Device to Host**: The device is expected to respond with the ASCII string `LOKE` (4 bytes).

In more recent implementations of the Thor protocol, the host may send the string `THOR`, with the device still responding with `LOKE`.

## 3. Packet Structure

Subsequent to the handshake, all communication is conducted using binary packets. With the exception of raw data transfers, every packet adheres to a standard header format.

### 3.1. Packet Header (ThorPacketHeader)

The packet header is 8 bytes in length and specifies the total size and type of the packet.

| Field         | Size    | Type                        | Description                                     |
| :------------ | :------ | :-------------------------- | :---------------------------------------------- |
| `packet_size` | 4 bytes | 32-bit Integer (Little-Endian) | Total size of the packet, including the header. |
| `packet_type` | 2 bytes | 16-bit Integer (Little-Endian) | Identifier for the packet type.                 |
| `packet_flags`| 2 bytes | 16-bit Integer (Little-Endian) | Additional flags (typically `0x0000`).          |

### 3.2. Known Packet Types

The following table lists the identified packet types used within the Thor protocol:

| Name                       | Value (`packet_type`) | Description                                     |
| :------------------------- | :-------------------- | :---------------------------------------------- |
| `THOR_PACKET_HANDSHAKE`    | `0x0001`              | Extended handshake packet.                      |
| `THOR_PACKET_DEVICE_TYPE`  | `0x0002`              | Request for device type.                        |
| `THOR_PACKET_FILE_PART`    | `0x0003`              | Transfer of a file part.                        |
| `THOR_PACKET_END_FILE_TRANSFER` | `0x0004`              | End of file transfer.                           |
| `THOR_PACKET_END_SESSION`  | `0x0005`              | Session termination.                            |
| `THOR_PACKET_RESPONSE`     | `0x0006`              | Generic device response.                        |
| `THOR_PACKET_PIT_FILE`     | `0x0007`              | PIT file transfer.                              |
| `THOR_PACKET_BEGIN_SESSION`| `0x0008`              | Session initiation.                             |
| `THOR_PACKET_FILE_PART_SIZE`| `0x0009`              | Definition of file part size.                   |
| `THOR_PACKET_RECEIVE_FILE_PART` | `0x000A`              | Acknowledgment of file part reception.          |
| `THOR_PACKET_CONTROL`      | `0x000B`              | Control commands (e.g., Reboot).                |

## 4. Session Management

Session management within the Thor protocol involves initiating and terminating communication sessions, negotiating protocol versions, and configuring transfer parameters.

### 4.1. Session Initiation (`0x64`)

The session initiation command is crucial for negotiating the protocol version and establishing transfer parameters between the host and the device.

**Request Structure:**

| Value         | Type         | Description                                     |
| :------------ | :----------- | :---------------------------------------------- |
| `0x64`        | 32-bit Integer | Packet type (Session).                          |
| `0x00`        | 32-bit Integer | Command (Initiate).                             |
| Dynamic       | 32-bit Integer | Requested protocol version (e.g., `0x00`, `0x03`, `0x04`, `0x05`, or `0x7FFFFFFF` for catch-all). |

**Response Structure:**

| Value         | Type         | Description                                     |
| :------------ | :----------- | :---------------------------------------------- |
| `0x64`        | 32-bit Integer | Packet type (`0xFF` in case of failure).        |
| Dynamic       | 32-bit Integer | Modified protocol version returned by the device. |

The modified protocol version returned by the device dictates the following standard parameters:

*   If the requested version is `0`, the device returns `0x20000`.
*   If the requested version is less than the bootloader's version, it returns `(<Requested Version> << 16) | 0x0`.
*   Otherwise, it returns `(<Bootloader Version> << 16) | 0x0`.

Based on the negotiated version, default transfer parameters are set:

*   **Version 0 or 1**: 30,000 ms (30s) timeout, 131,072 bytes (128 KiB) packet size, maximum sequence of 240 packets.
*   **Version >= 2**: 120,000 ms (2 min) timeout, 1,048,576 bytes (1 MiB) packet size, maximum sequence of 30 packets.

### 4.2. Total Size Configuration (`0x64`, Command `0x02`)

This command informs the device about the total size of the data that will be transferred during the session.

**Request Structure:**

| Value         | Type         | Description                                     |
| :------------ | :----------- | :---------------------------------------------- |
| `0x64`        | 32-bit Integer | Packet type.                                    |
| `0x02`        | 32-bit Integer | Command (Set Total Bytes).                      |
| Dynamic       | 64-bit Integer | Total size in bytes.                            |

**Response Structure:**

| Value         | Type         | Description                                     |
| :------------ | :----------- | :---------------------------------------------- |
| `0x64`        | 32-bit Integer | Packet type.                                    |
| `0x00`        | 32-bit Integer | Status code (0 = Success).                      |

### 4.3. Other Session Commands (`0x64`)

*   **Reset Flash Count (`0x01`)**: Resets the device's flash counter.
*   **Set File Part Size (`0x05`)**: Defines the size of a file part (32-bit argument).
*   **Erase Userdata (`0x07`)**: Erases the user data partition (equivalent to a Factory Reset).
*   **Enable T-Flash (`0x08`)**: Enables T-Flash mode.
*   **Set Region Code (`0x09`)**: Changes the device's region code (3-byte string argument).

### 4.4. Session Termination and Control (`0x67`)

**Base Request Structure:**

| Value         | Type         | Description                                     |
| :------------ | :----------- | :---------------------------------------------- |
| `0x67`        | 32-bit Integer | Packet type.                                    |
| Command       | 32-bit Integer | Control command.                                |

**Available Commands:**

*   `0x00`: End Session (Terminates the current session).
*   `0x01`: Reboot (Reboots the device normally).
*   `0x02`: Reboot to Odin (Reboots the device back into Download Mode).
*   `0x03`: Shutdown (Powers off the device).

**Response Structure:**

| Value         | Type         | Description                                     |
| :------------ | :----------- | :---------------------------------------------- |
| `0x67`        | 32-bit Integer | Packet type.                                    |
| `0x00`        | 32-bit Integer | Status code (0 = Success).                      |

## 5. Partition Information Table (PIT)

The Partition Information Table (PIT) file is a critical component that describes the storage layout of the device, defining partitions and their attributes.

### 5.1. PIT File Structure

A PIT file begins with a 28-byte header, followed by a variable number of 132-byte entries, each describing a specific partition.

**Header (28 bytes):**

| Offset | Size    | Type         | Description                                     |
| :----- | :------ | :----------- | :---------------------------------------------- |
| `0x00` | 4 bytes | 32-bit Integer | Magic Number (`0x12349876`).                    |
| `0x04` | 4 bytes | 32-bit Integer | Entry Count (Number of partition entries).      |
| `0x08` | 4 bytes | 32-bit Integer | Unknown 1.                                      |
| `0x0C` | 4 bytes | 32-bit Integer | Unknown 2.                                      |
| `0x10` | 2 bytes | 16-bit Integer | Unknown 3.                                      |
| `0x12` | 2 bytes | 16-bit Integer | Unknown 4.                                      |
| `0x14` | 2 bytes | 16-bit Integer | Unknown 5.                                      |
| `0x16` | 2 bytes | 16-bit Integer | Unknown 6.                                      |
| `0x18` | 2 bytes | 16-bit Integer | Unknown 7.                                      |
| `0x1A` | 2 bytes | 16-bit Integer | Unknown 8.                                      |

**PIT Entry (132 bytes):**

| Offset | Size    | Type         | Description                                     |
| :----- | :------ | :----------- | :---------------------------------------------- |
| `0x00` | 4 bytes | 32-bit Integer | Binary Type (0 = AP, 1 = CP).                   |
| `0x04` | 4 bytes | 32-bit Integer | Device Type (0 = OneNAND, 1 = FAT, 2 = MMC).    |
| `0x08` | 4 bytes | 32-bit Integer | Partition Identifier.                           |
| `0x0C` | 4 bytes | 32-bit Integer | Attributes (1 = Write, 2 = STL).                |
| `0x10` | 4 bytes | 32-bit Integer | Update Attributes (1 = FOTA, 2 = Secure).       |
| `0x14` | 4 bytes | 32-bit Integer | Block Size or Offset.                           |
| `0x18` | 4 bytes | 32-bit Integer | Block Count.                                    |
| `0x1C` | 4 bytes | 32-bit Integer | File Offset (Obsolete).                         |
| `0x20` | 4 bytes | 32-bit Integer | File Size (Obsolete).                           |
| `0x24` | 32 bytes | ASCII String | Partition Name.                                 |
| `0x44` | 32 bytes | ASCII String | Flash Filename.                                 |
| `0x64` | 32 bytes | ASCII String | FOTA Filename.                                  |

### 5.2. PIT Operations (`0x65`)

**Dumping (Reading PIT from Device):**

1.  **Request PIT Dump**: The host sends `0x65` with command `0x01`. The device responds with the total size of the PIT data.
2.  **Dump PIT Block**: The host requests 500-byte blocks by sending `0x65`, command `0x02`, and the block index. The device responds with the raw data for that block.
3.  **End PIT Dump**: The host sends `0x65` with command `0x03` to signal the end of the dump operation.

**Flashing (Writing PIT to Device):**

1.  **Request PIT Flash**: The host sends `0x65` with command `0x00`.
2.  **Begin PIT Flash**: The host sends `0x65`, command `0x02`, and the size of the PIT in bytes.
3.  **Send PIT Data**: The raw buffer of the PIT file is transferred to the device.
4.  **End PIT Flash**: The host sends `0x65` with command `0x03` to signal the completion of the flash operation.

## 6. File Transfer (Flashing)

Firmware file transfers (`0x66`) are structured into sequences, with each sequence further divided into smaller parts.

### 6.1. Request File Flash

This command initiates a file flash operation, specifying whether the data is compressed.

**Request Structure:**

| Value         | Type         | Description                                     |
| :------------ | :----------- | :---------------------------------------------- |
| `0x66`        | 32-bit Integer | Packet type.                                    |
| `0x00` or `0x05` | 32-bit Integer | Command (`0x00` for uncompressed data, `0x05` for LZ4 compressed data). |

**Response Structure:**

| Value         | Type         | Description                                     |
| :------------ | :----------- | :---------------------------------------------- |
| `0x66`        | 32-bit Integer | Packet type.                                    |
| `0x00`        | 32-bit Integer | Status code.                                    |

### 6.2. Begin File Sequence Flash

This command signals the start of a file sequence transfer and provides the aligned size of the sequence.

**Request Structure:**

| Value         | Type         | Description                                     |
| :------------ | :----------- | :---------------------------------------------- |
| `0x66`        | 32-bit Integer | Packet type.                                    |
| `0x02` or `0x06` | 32-bit Integer | Command (`0x02` for uncompressed, `0x06` for compressed). |
| Dynamic       | 32-bit Integer | Aligned size of the sequence in bytes.          |

**Response Structure:**

| Value         | Type         | Description                                     |
| :------------ | :----------- | :---------------------------------------------- |
| `0x66`        | 32-bit Integer | Packet type.                                    |
| `0x00`        | 32-bit Integer | Status code.                                    |

### 6.3. Flash File Part

Raw data blocks are sent, corresponding to the negotiated packet size (e.g., 1 MiB).

**Request**: Raw byte buffer.

**Response Structure:**

| Value         | Type         | Description                                     |
| :------------ | :----------- | :---------------------------------------------- |
| `0x66`        | 32-bit Integer | Packet type.                                    |
| Dynamic       | 32-bit Integer | Current file part index on the device side.     |

### 6.4. End File Sequence Flash

After all parts of a sequence have been transferred, the host must signal the end of that sequence. The format of this command varies depending on whether the file is intended for the Modem (CP) or Phone (AP).

**For Modem (CP):**

| Value         | Type         | Description                                     |
| :------------ | :----------- | :---------------------------------------------- |
| `0x66`        | 32-bit Integer | Packet type.                                    |
| `0x03` or `0x07` | 32-bit Integer | Command (`0x03` for uncompressed, `0x07` for compressed). |
| `0x01`        | 32-bit Integer | Modem/CP Identifier.                            |
| Dynamic       | 32-bit Integer | Actual size of the sequence in bytes.           |
| Dynamic       | 32-bit Integer | Binary Type (from PIT).                         |
| Dynamic       | 32-bit Integer | Device Type (from PIT).                         |
| Dynamic       | 32-bit Integer | Flag indicating if it is the last sequence (1 = Yes, 0 = No). |

**For Phone (AP):**

| Value         | Type         | Description                                     |
| :------------ | :----------- | :---------------------------------------------- |
| `0x66`        | 32-bit Integer | Packet type.                                    |
| `0x03` or `0x07` | 32-bit Integer | Command (`0x03` for uncompressed, `0x07` for compressed). |
| `0x00`        | 32-bit Integer | Phone/AP Identifier.                            |
| Dynamic       | 32-bit Integer | Actual size of the sequence in bytes.           |
| Dynamic       | 32-bit Integer | Binary Type (from PIT).                         |
| Dynamic       | 32-bit Integer | Device Type (from PIT).                         |
| Dynamic       | 32-bit Integer | Partition Identifier (from PIT).                |
| Dynamic       | 32-bit Integer | Flag indicating if it is the last sequence (1 = Yes, 0 = No). |
| Dynamic       | 32-bit Integer | EFS Clear Flag (1 = Yes, 0 = No).               |
| Dynamic       | 32-bit Integer | Bootloader Update Flag (1 = Yes, 0 = No).       |

**Response Structure:**

| Value         | Type         | Description                                     |
| :------------ | :----------- | :---------------------------------------------- |
| `0x66`        | 32-bit Integer | Packet type.                                    |
| `0x00`        | 32-bit Integer | Status code.                                    |

## 7. Device Information

The Thor protocol facilitates the extraction of detailed device information (`0x69`).

### 7.1. Information Structure

Device information is structured with a header followed by arrays of location and data structures.

**Header:**

*   Magic Number: `0x12345678` (32-bit)
*   Count: Number of items (32-bit)
*   Array of Location Structures
*   Array of Data Structures

**Location Structure:**

*   DevInfo Type (32-bit)
*   Offset in bytes (32-bit)
*   Size in bytes (32-bit)

**Data Structure:**

*   DevInfo Type (32-bit)
*   Size in bytes (32-bit)
*   Raw data buffer

**Known DevInfo Types:**

*   `0x00`: Model Name
*   `0x01`: Serial Code
*   `0x02`: Region Code (OMCSALESCODE)
*   `0x03`: Carrier ID

### 7.2. Extraction Commands (`0x69`)

*   **Dump Device Info (`0x00`)**: Requests the size of the device information. The device responds with the size (typically 500 bytes).
*   **Dump Block (`0x01`)**: Requests a 500-byte block by passing the block index. The device responds with the raw data for that block.
*   **End Dump (`0x02`)**: Terminates the information extraction process.

## 8. Error Handling

In the event of an error during any operation, the device signals the failure by setting the first byte of its response to `0xFF`. The specific error code is then provided as a 32-bit integer at offset 4 of the response.

**Known Error Codes during End File Sequence Flash:**

*   `-2`: Write Protection (WP) Error.
*   `-3`: Erase Error.
*   `-4`: Write Error.
*   `-5`: Authentication (Auth) Error.
*   `-6`: Size Error.
*   `-7`: File System (Ext4) Error.

## 9. References

[1] Documentação Técnica do Protocolo Thor (User Provided Document)
[2] Gabriel2392/brokkr-flash: Odin but better (and open-source). https://github.com/Gabriel2392/brokkr-flash
[3] Llucs/odin4: odin4 is a flash tool for Samsung devices. https://github.com/Llucs/odin4
[4] Benjamin-Dobell/Heimdall: Heimdall is a cross-platform open-source tool suite used to flash firmware (aka ROMs) onto Samsung Galaxy devices. https://github.com/Benjamin-Dobell/Heimdall
[5] Samsung-Loki/Thor: An alternative to Heimdall. https://github.com/Samsung-Loki/Thor
