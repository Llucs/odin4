# Odin Protocol Reference

**Author**: Llucs

## 1. Introduction

The Odin protocol is a proprietary USB communication protocol developed by Samsung, used by devices in Download Mode for firmware management operations. This document describes the wire protocol as implemented by odin4, covering packet structures, command sets, Partition Information Table (PIT) management, file transfer mechanisms, and compressed data support.

## 2. Transport Layer and Handshake

Communication is established over USB using Bulk Transfers. The target USB interface typically belongs to the `0x0A` (CDC Data) class and features two bulk endpoints (one IN, one OUT). Samsung's standard Vendor ID (VID) is `0x04E8`, with known Download Mode Product IDs (PID) including `0x6601`, `0x685D`, `0x68C3`, `0x68EF`, `0x4EEE`, and `0x4EEF`.

### 2.1. Initial Handshake

Before any data transfer, the host performs a handshake to confirm the device bootloader is ready.

*   **Host to Device**: Sends the ASCII string `ODIN` (4 bytes).
*   **Device to Host**: Responds with the ASCII string `LOKE` (4 bytes).

## 3. Packet Structures

After the handshake, all command communication uses two fixed-size structures: the request box and the response box. Raw data transfers bypass this structure and use the negotiated packet size directly.

### 3.1. Request Box (OdinRequestBox)

The request is a 1024-byte structure sent from host to device for all commands.

| Field      | Offset | Size    | Description                                           |
| :--------- | :----- | :------ | :---------------------------------------------------- |
| `id`       | 0x000  | 4 bytes | Command type (`0x64`, `0x65`, `0x66`, or `0x67`).    |
| `data`     | 0x004  | 4 bytes | Command parameter (subcommand).                       |
| `intData`  | 0x008  | 36 bytes| Integer argument array (9 x 32-bit).                  |
| `charData` | 0x02C  | 128 bytes| Character argument buffer.                           |
| `md5`      | 0x0AC  | 32 bytes | MD5 hash field (reserved).                            |
| `dummy`    | 0x0CC  | 820 bytes| Padding to 1024 bytes.                                |

All multi-byte fields are little-endian.

### 3.2. Response Box (OdinResponseBox)

The response is an 8-byte structure returned by the device after each command.

| Field  | Offset | Size    | Description                                                   |
| :----- | :----- | :------ | :------------------------------------------------------------ |
| `id`   | 0x000  | 4 bytes | Echo of command type, or `0xFFFFFFFF` on failure.             |
| `ack`  | 0x004  | 4 bytes | Status code (0 = success, negative values indicate progress or error). |

### 3.3. Failure Detection

The bootloader signals failure by setting `id` to `0xFFFFFFFF` (`BOOTLOADER_FAIL`). The `ack` field contains a specific error code. An `ack` value of `INT32_MIN` is also treated as failure.

### 3.4. Zero-Length Packets (ZLP)

After bulk writes that are multiples of the endpoint's `wMaxPacketSize`, the host sends a zero-length packet (ZLP) to signal transfer completion. If the device does not support ZLP, the feature is disabled for the remainder of the session.

## 4. Session Management

Session management involves initiating and terminating communication, negotiating protocol version, and configuring transfer parameters.

### 4.1. Command Type `0x64` (Session)

#### 4.1.1. Session Initiation (Command `0x00`)

Negotiates protocol version and detects device capabilities.

**Request:**

| Field    | Value      | Description                        |
| :------- | :--------- | :--------------------------------- |
| `id`     | `0x64`     | Session command type.              |
| `data`   | `0x00`     | Initiate subcommand.               |
| `intData[0]` | `0x7FFFFFFF` | Requested protocol version (catch-all). |

**Response (`id` = `0x64`):**

| Field  | Description                                              |
| :----- | :------------------------------------------------------- |
| `ack`  | Upper 16 bits encode the bootloader version; bit 15 (0x8000) indicates compressed download support. Lower 16 bits are reserved. |

**Version-based Parameters:**

*   **Version 0 or 1**: 30,000 ms timeout, 131,072 bytes (128 KiB) packet size, maximum 240 packets per sequence.
*   **Version >= 2**: 120,000 ms timeout, 1,048,576 bytes (1 MiB) packet size, maximum 30 packets per sequence. Additionally, the host sends `0x64`, command `0x05`, to set the file part size.

#### 4.1.2. Device Type Query (Command `0x01`)

Requests the device model identifier.

**Request:** `id` = `0x64`, `data` = `0x01`

**Response:** `ack` contains an integer model code. The host formats it as `"SM-<code>"`.

#### 4.1.3. Total Size Configuration (Command `0x02`)

Informs the device of the total firmware size to be transferred.

**Request:** `id` = `0x64`, `data` = `0x02`, `intData[0..1]` = 64-bit total size in bytes (little-endian).

**Response:** `id` = `0x64`, `ack` = `0x00` on success.

#### 4.1.4. Set File Part Size (Command `0x05`)

Defines the file part size for the session. Sent when protocol version >= 2.

**Request:** `id` = `0x64`, `data` = `0x05`, `intData[0]` = part size in bytes.

**Response:** `id` = `0x64`, `ack` = `0x00` on success.

### 4.2. Command Type `0x67` (Close)

Controls session termination and device reboot.

**Commands:**

| `data`  | Description                                                  |
| :------ | :----------------------------------------------------------- |
| `0x00`  | End Session — terminates the current session gracefully.     |
| `0x01`  | Reboot — reboots the device normally.                        |
| `0x02`  | Reboot to Odin — reboots the device back into Download Mode. |

**Response:** `id` = `0x67`, `ack` = `0x00` on success.

## 5. Partition Information Table (PIT)

The PIT describes the device storage layout and is required for safe firmware flashing.

### 5.1. PIT File Structure

A PIT file begins with a 28-byte header followed by a variable number of 132-byte entries.

**Header (28 bytes):**

| Offset | Size    | Type            | Description                                          |
| :----- | :------ | :-------------- | :--------------------------------------------------- |
| `0x00` | 4 bytes | 32-bit Integer  | Magic number (`0x12349876`).                         |
| `0x04` | 4 bytes | 32-bit Integer  | Entry count (number of partition entries).           |
| `0x08` | 8 bytes | Raw             | `com_tar2` field.                                    |
| `0x10` | 8 bytes | Raw             | `cpu_bl_id` field.                                   |
| `0x18` | 2 bytes | 16-bit Integer  | `lu_count`.                                          |
| `0x1A` | 2 bytes | 16-bit Integer  | Reserved.                                            |

**PIT Entry (132 bytes):**

| Offset | Size    | Type            | Description                                          |
| :----- | :------ | :-------------- | :--------------------------------------------------- |
| `0x00` | 4 bytes | 32-bit Integer  | Binary type (0 = AP, 1 = CP).                        |
| `0x04` | 4 bytes | 32-bit Integer  | Device type (0 = OneNAND, 1 = FAT, 2 = MMC).         |
| `0x08` | 4 bytes | 32-bit Integer  | Partition identifier.                                |
| `0x0C` | 4 bytes | 32-bit Integer  | Attributes.                                          |
| `0x10` | 4 bytes | 32-bit Integer  | Update attributes.                                   |
| `0x14` | 4 bytes | 32-bit Integer  | Block size or offset.                                |
| `0x18` | 4 bytes | 32-bit Integer  | Block count.                                         |
| `0x1C` | 4 bytes | 32-bit Integer  | File offset (obsolete).                              |
| `0x20` | 4 bytes | 32-bit Integer  | File size (obsolete).                                |
| `0x24` | 32 bytes | ASCII String   | Partition name.                                      |
| `0x44` | 32 bytes | ASCII String   | Flash filename.                                      |
| `0x64` | 32 bytes | ASCII String   | FOTA filename.                                       |

### 5.2. PIT Operations (`0x65`)

#### Dumping (Reading PIT from Device)

1. **Request PIT Size** (`0x65`, command `0x01`): The device responds with the total PIT data size in `ack`.
2. **Read PIT Block** (`0x65`, command `0x02`, `intData[0]` = block index): Requests a 500-byte block of PIT data. The device responds with raw data.
3. **End PIT Dump** (`0x65`, command `0x03`): Signals completion of the dump.

#### Flashing (Writing PIT to Device)

1. **Request PIT Flash** (`0x65`, command `0x00`): Prepares the device to receive a PIT.
2. **Send PIT Data** (`0x65`, command `0x01`, `intData[0]` = PIT size): Raw PIT buffer is transferred.
3. **End PIT Flash** (`0x65`, command `0x02`, `intData[0]` = PIT size): Completes the PIT write.

#### Validation

The host validates:
- Magic number matches `0x12349876`.
- Entry count is between 1 and 512.
- Entry identifier is non-zero and unique.
- Partition names contain only printable ASCII (0x20–0x7E), excluding `/` and `\`.
- Block size/count multiplication does not overflow.

## 6. File Transfer (Flashing)

Firmware file transfers (`0x66`) are divided into sequences, each further divided into packets of the negotiated size.

### 6.1. Request File Flash (Command `0x00`)

Initiates a file flash operation for uncompressed data.

**Request:** `id` = `0x66`, `data` = `0x00`

**Response:** `id` = `0x66`, `ack` = `0x00` on success.

### 6.2. Request Sequence Flash (Command `0x02`)

Begins a new sequence and provides the aligned packet-aligned size.

**Request:** `id` = `0x66`, `data` = `0x02`, `intData[0]` = aligned sequence size in bytes.

**Response:** `id` = `0x66`, `ack` = `0x00` on success.

### 6.3. Send File Part

Raw data blocks are sent at the negotiated packet size (128 KiB or 1 MiB). After each block the device responds with the current part index, which is validated against the sender's expected index.

**Request:** Raw byte buffer (negotiated packet size).

**Response:** `id` = `0x66`, `ack` = current file part index (device-side).

### 6.4. End Sequence Flash (Command `0x03`)

Signals the end of a sequence. Payload varies by partition type (CP/modem vs AP/phone).

**For CP (binary_type = 1), 32 bytes:**

| Offset | Size    | Description                                         |
| :----- | :------ | :-------------------------------------------------- |
| 0x00   | 4 bytes | Modem identifier (`0x01`).                          |
| 0x04   | 4 bytes | Actual size of the sequence in bytes.               |
| 0x08   | 4 bytes | Binary type (from PIT).                             |
| 0x0C   | 4 bytes | Device type (from PIT).                             |
| 0x10   | 4 bytes | Reserved (`0`).                                     |
| 0x14   | 4 bytes | Last sequence flag (`1` = yes, `0` = no).           |
| 0x18   | 4 bytes | Reserved (`0`).                                     |
| 0x1C   | 4 bytes | Reserved (`0`).                                     |

**For AP (binary_type = 0), 32 bytes:**

| Offset | Size    | Description                                         |
| :----- | :------ | :-------------------------------------------------- |
| 0x00   | 4 bytes | Phone identifier (`0x00`).                          |
| 0x04   | 4 bytes | Actual size of the sequence in bytes.               |
| 0x08   | 4 bytes | Binary type (from PIT).                             |
| 0x0C   | 4 bytes | Device type (from PIT).                             |
| 0x10   | 4 bytes | Partition identifier (from PIT).                    |
| 0x14   | 4 bytes | Last sequence flag (`1` = yes, `0` = no).           |
| 0x18   | 4 bytes | EFS clear flag (`1` = yes, `0` = no).               |
| 0x1C   | 4 bytes | Bootloader update flag (`1` = yes, `0` = no).       |

Before the end-sequence command, the host sends an empty bulk transfer (USB ZLP). After the command, it drains any unexpected response bytes.

### 6.5. Large Partitions

Partitions named `SYSTEM`, `USERDATA`, or `SUPER` have their real sizes rounded up to the next 512-byte boundary for the end-sequence reporting.

### 6.6. Compressed Transfers

If the device supports compressed downloads (detected during session initiation), LZ4-compressed firmware can be streamed directly.

#### 6.6.1. Request Compressed Flash (Command `0x05`)

Initiates a compressed flash operation.

**Request:** `id` = `0x66`, `data` = `0x05`

**Response:** `id` = `0x66`, `ack` = `0x00` on success.

#### 6.6.2. Request Compressed Sequence (Command `0x06`)

Begins a new compressed sequence.

**Request:** `id` = `0x66`, `data` = `0x06`, `intData[0]` = compressed sequence size in bytes.

**Response:** `id` = `0x66`, `ack` = `0x00` on success.

#### 6.6.3. End Compressed Sequence (Command `0x07`)

Same payload layout as the uncompressed end-sequence (command `0x03`), but with command value `0x07`. The size field reports the *decompressed* size of the sequence.

#### 6.6.4. LZ4 Frame Requirements

The host validates LZ4 frames before transfer:
- Frame version must be 1.
- Content size must be present.
- Block independence must be enabled.
- Block checksum must be disabled.
- No dictionary ID.
- Maximum block size ≤ 1 MiB.

If compressed transfer fails or is unsupported, the host falls back to decompressing to a temporary file and flashing the uncompressed data.

### 6.7. Reset Flash Count

After each file transfer, the host sends `0x64`, command `0x01` to reset the device flash counter.

### 6.8. Retry Behavior

USB bulk transfers include up to 5 retries with exponential backoff (100 ms initial, doubling per attempt, capped at 1500 ms). Pipe errors trigger a clear-halt on the endpoint. Timeout or pipe errors on writes reduce the chunk size to 16 KiB for the remainder of the transfer.

## 7. Device Information

The device type is queried via `0x64`, command `0x01`. The response code is formatted as `"SM-<code>"` for display purposes.

## 8. Error Handling

When an operation fails, the device sets `id` to `0xFFFFFFFF` in the response. Negative `ack` values indicate specific conditions during end-sequence operations:

| Code | Name      | Description                    |
| :--- | :-------- | :----------------------------- |
| `-2` | WP        | Write protection error.        |
| `-3` | Erase     | Erase error.                   |
| `-4` | Write     | Write error.                   |
| `-5` | Auth      | Authentication error.          |
| `-6` | Size      | Size error.                    |
| `-7` | Ext4      | File system (Ext4) error.      |

During end-sequence flash, negative codes in this range are treated as progress indicators (non-fatal).

## 9. References

[1] Llucs/odin4: odin4 is a flash tool for Samsung devices. https://github.com/Llucs/odin4
[2] Benjamin-Dobell/Heimdall: Cross-platform open-source tool suite for flashing firmware onto Samsung Galaxy devices. https://github.com/Benjamin-Dobell/Heimdall
[3] Gabriel2392/brokkr-flash: Odin reimplementation. https://github.com/Gabriel2392/brokkr-flash
[4] Samsung-Loki/Thor: Alternative to Heimdall. https://github.com/Samsung-Loki/Thor
