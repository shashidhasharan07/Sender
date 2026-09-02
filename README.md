import struct
import sys
import os
import csv
from datetime import datetime, timezone
from io import BytesIO
from collections import defaultdict


# ============================================================
# USER CONFIGURATION
# ============================================================

# Where is the opcode inside the SDR payload?
#
# If opcode is the first byte:
OPCODE_OFFSET = 0

# Opcode data type.
#
# "<B"  = unsigned 1 byte
# "<H"  = unsigned 2 bytes
# "<I"  = unsigned 4 bytes
# "<h"  = signed 2 bytes
# "<i"  = signed 4 bytes
# "<f"  = 4 byte float
# "<d"  = 8 byte double
#
# Change this if your ICD uses another format.
OPCODE_FORMAT = "<B"


# ------------------------------------------------------------
# If every SDR message has a fixed header before opcode,
# change OPCODE_OFFSET.
#
# Example:
#
# 28-byte header + opcode:
#
# OPCODE_OFFSET = 28
#
# ------------------------------------------------------------


# ============================================================
# SDR OPCODE DEFINITIONS
# ============================================================
#
# IMPORTANT:
#
# Replace these examples with your ACTUAL ICD definitions.
#
# Format:
#
# opcode:
# {
#     "name": "Opcode name",
#     "target_count_offset": None,
#     "target_count_format": None,
#     "target_size": number of bytes,
#     "fields": [
#         (name, format),
#         (name, format),
#     ]
# }
#
# The fields are relative to the beginning of EACH target.
#
# ------------------------------------------------------------

OPCODE_DEFINITIONS = {

    # --------------------------------------------------------
    # EXAMPLE OPCODE 101
    # --------------------------------------------------------

    101: {
        "name": "Example_Target_Data",

        # If one packet contains multiple targets and the
        # number of targets is stored in the packet:
        #
        # Example:
        # target_count_offset = 1
        # target_count_format = "<B"
        #
        # If there is only one target, use None.

        "target_count_offset": None,
        "target_count_format": None,

        # Total bytes occupied by ONE target.
        #
        # Example below:
        # rssi       2 bytes
        # frequency  4 bytes
        # snr        4 bytes
        # azimuth    4 bytes
        # range      4 bytes
        #
        # Total = 18 bytes
        #
        "target_size": 18,

        "fields": [
            ("rssi", "<h"),
            ("frequency", "<f"),
            ("snr", "<f"),
            ("azimuth", "<f"),
            ("range", "<f"),
        ]
    },


    # --------------------------------------------------------
    # EXAMPLE OPCODE 104
    # --------------------------------------------------------

    104: {
        "name": "Example_Track_Data",

        "target_count_offset": None,
        "target_count_format": None,

        "target_size": 17,

        "fields": [
            ("target_id", "<B"),
            ("velocity", "<f"),
            ("heading", "<f"),
            ("altitude", "<f"),
            ("status_flag", "<B"),
        ]
    },


    # --------------------------------------------------------
    # ADD YOUR OTHER OPCODES HERE
    # --------------------------------------------------------
    #
    # Example:
    #
    # 107: {
    #     "name": "Your_Opcode_107",
    #     "target_count_offset": 1,
    #     "target_count_format": "<B",
    #     "target_size": 20,
    #     "fields": [
    #         ("parameter1", "<H"),
    #         ("parameter2", "<I"),
    #         ("parameter3", "<f"),
    #         ("parameter4", "<f"),
    #     ]
    # },
    #
}


# ============================================================
# ERROR LOG
# ============================================================

ERROR_FILE = "errors.log"


def log_error(message):

    with open(ERROR_FILE, "a", encoding="utf-8") as f:
        f.write(message + "\n")


# ============================================================
# SAFE STRUCT UNPACK
# ============================================================

def unpack_value(data, offset, fmt):

    try:

        size = struct.calcsize(fmt)

        if offset < 0:
            return None, size

        if offset + size > len(data):
            return None, size

        value = struct.unpack_from(fmt, data, offset)[0]

        return value, size

    except Exception:

        return None, 0


# ============================================================
# TIMESTAMP
# ============================================================

def timestamp_to_string(timestamp_raw, resolution):

    try:

        seconds = timestamp_raw * resolution

        dt = datetime.fromtimestamp(
            seconds,
            timezone.utc
        )

        return dt.isoformat()

    except Exception:

        return ""


# ============================================================
# MAC ADDRESS
# ============================================================

def mac_address(data):

    if len(data) != 6:
        return ""

    return ":".join(
        f"{x:02X}" for x in data
    )


# ============================================================
# IPv4 ADDRESS
# ============================================================

def ipv4_address(data):

    if len(data) != 4:
        return ""

    return ".".join(
        str(x) for x in data
    )


# ============================================================
# IPv6 ADDRESS
# ============================================================

def ipv6_address(data):

    if len(data) != 16:
        return ""

    values = []

    for i in range(0, 16, 2):

        values.append(
            f"{data[i]:02X}{data[i + 1]:02X}"
        )

    return ":".join(values)


# ============================================================
# EXTRACT NETWORK PAYLOAD
# ============================================================

def extract_sdr_payload(packet):

    result = {
        "source": "",
        "destination": "",
        "source_port": "",
        "destination_port": "",
        "protocol": "",
        "payload": b""
    }

    # --------------------------------------------------------
    # Ethernet
    # --------------------------------------------------------

    if len(packet) < 14:

        # Do not drop packet.
        # Treat entire packet as custom payload.

        result["protocol"] = "UNKNOWN"
        result["payload"] = packet

        return result

    result["destination"] = mac_address(
        packet[0:6]
    )

    result["source"] = mac_address(
        packet[6:12]
    )

    ether_type = struct.unpack(
        ">H",
        packet[12:14]
    )[0]

    pos = 14


    # --------------------------------------------------------
    # VLAN
    # --------------------------------------------------------

    while ether_type in (
        0x8100,
        0x88A8,
        0x9100
    ):

        if len(packet) < pos + 4:

            result["protocol"] = "VLAN"
            result["payload"] = packet[pos:]

            return result

        ether_type = struct.unpack(
            ">H",
            packet[pos + 2:pos + 4]
        )[0]

        pos += 4


    # ========================================================
    # IPv4
    # ========================================================

    if ether_type == 0x0800:

        if len(packet) < pos + 20:

            result["protocol"] = "IPv4"
            result["payload"] = packet[pos:]

            return result

        version_ihl = packet[pos]

        ihl = (
            version_ihl & 0x0F
        ) * 4

        if len(packet) < pos + ihl:

            result["protocol"] = "IPv4"
            result["payload"] = packet[pos:]

            return result

        result["source"] = ipv4_address(
            packet[pos + 12:pos + 16]
        )

        result["destination"] = ipv4_address(
            packet[pos + 16:pos + 20]
        )

        protocol_number = packet[pos + 9]

        transport = pos + ihl


        # ----------------------------------------------------
        # UDP
        # ----------------------------------------------------

        if protocol_number == 17:

            result["protocol"] = "UDP"

            if len(packet) < transport + 8:

                result["payload"] = packet[transport:]

                return result

            result["source_port"] = struct.unpack(
                ">H",
                packet[transport:transport + 2]
            )[0]

            result["destination_port"] = struct.unpack(
                ">H",
                packet[transport + 2:transport + 4]
            )[0]

            udp_length = struct.unpack(
                ">H",
                packet[transport + 4:transport + 6]
            )[0]

            payload_start = transport + 8

            payload_end = len(packet)

            if udp_length >= 8:

                calculated_end = (
                    transport + udp_length
                )

                if calculated_end < payload_end:
                    payload_end = calculated_end

            result["payload"] = packet[
                payload_start:payload_end
            ]

            return result


        # ----------------------------------------------------
        # TCP
        # ----------------------------------------------------

        elif protocol_number == 6:

            result["protocol"] = "TCP"

            if len(packet) < transport + 20:

                result["payload"] = packet[transport:]

                return result

            result["source_port"] = struct.unpack(
                ">H",
                packet[transport:transport + 2]
            )[0]

            result["destination_port"] = struct.unpack(
                ">H",
                packet[transport + 2:transport + 4]
            )[0]

            data_offset = (
                (packet[transport + 12] >> 4)
                * 4
            )

            payload_start = (
                transport + data_offset
            )

            result["payload"] = packet[
                payload_start:
            ]

            return result


        # ----------------------------------------------------
        # Other IPv4 protocol
        # ----------------------------------------------------

        else:

            result["protocol"] = (
                f"IP({protocol_number})"
            )

            result["payload"] = packet[
                transport:
            ]

            return result


    # ========================================================
    # IPv6
    # ========================================================

    elif ether_type == 0x86DD:

        if len(packet) < pos + 40:

            result["protocol"] = "IPv6"
            result["payload"] = packet[pos:]

            return result

        result["source"] = ipv6_address(
            packet[pos + 8:pos + 24]
        )

        result["destination"] = ipv6_address(
            packet[pos + 24:pos + 40]
        )

        next_header = packet[pos + 6]

        transport = pos + 40


        # UDP
        if next_header == 17:

            result["protocol"] = "UDP"

            if len(packet) < transport + 8:

                result["payload"] = packet[transport:]

                return result

            result["source_port"] = struct.unpack(
                ">H",
                packet[transport:transport + 2]
            )[0]

            result["destination_port"] = struct.unpack(
                ">H",
                packet[transport + 2:transport + 4]
            )[0]

            result["payload"] = packet[
                transport + 8:
            ]

            return result


        # TCP
        elif next_header == 6:

            result["protocol"] = "TCP"

            if len(packet) < transport + 20:

                result["payload"] = packet[transport:]

                return result

            result["source_port"] = struct.unpack(
                ">H",
                packet[transport:transport + 2]
            )[0]

            result["destination_port"] = struct.unpack(
                ">H",
                packet[transport + 2:transport + 4]
            )[0]

            data_offset = (
                (packet[transport + 12] >> 4)
                * 4
            )

            result["payload"] = packet[
                transport + data_offset:
            ]

            return result


        else:

            result["protocol"] = (
                f"IPv6({next_header})"
            )

            result["payload"] = packet[
                transport:
            ]

            return result


    # ========================================================
    # Non-IP Ethernet
    # ========================================================

    else:

        result["protocol"] = (
            f"EtherType_0x{ether_type:04X}"
        )

        result["payload"] = packet[pos:]

        return result


# ============================================================
# GET OPCODE
# ============================================================

def get_opcode(payload):

    try:

        value = struct.unpack_from(
            OPCODE_FORMAT,
            payload,
            OPCODE_OFFSET
        )[0]

        return value

    except Exception:

        return None


# ============================================================
# DECODE UNKNOWN OPCODE
# ============================================================

def decode_unknown(payload):

    result = {}

    start = OPCODE_OFFSET + struct.calcsize(
        OPCODE_FORMAT
    )

    remaining = payload[start:]

    # --------------------------------------------------------
    # Keep every remaining byte.
    #
    # Divide into individual bytes so no data disappears.
    # --------------------------------------------------------

    for i, value in enumerate(
        remaining,
        1
    ):

        result[f"param_{i}"] = (
            f"0x{value:02X}"
        )

    return [result]


# ============================================================
# DECODE KNOWN OPCODE
# ============================================================

def decode_known_opcode(
    payload,
    opcode,
    definition
):

    fields = definition.get(
        "fields",
        []
    )

    target_size = definition.get(
        "target_size"
    )

    target_count_offset = definition.get(
        "target_count_offset"
    )

    target_count_format = definition.get(
        "target_count_format"
    )


    # --------------------------------------------------------
    # Determine target count
    # --------------------------------------------------------

    if (
        target_count_offset is not None
        and target_count_format is not None
    ):

        count, size = unpack_value(
            payload,
            OPCODE_OFFSET + target_count_offset,
            target_count_format
        )

        if count is None or count < 1:

            target_count = 1

        else:

            target_count = int(count)

    else:

        # If no target count is defined,
        # calculate number of targets from payload size.

        data_start = (
            OPCODE_OFFSET
            + struct.calcsize(OPCODE_FORMAT)
        )

        available = len(payload) - data_start

        if target_size and target_size > 0:

            target_count = (
                available // target_size
            )

            if target_count < 1:
                target_count = 1

        else:

            target_count = 1


    # --------------------------------------------------------
    # Starting position of target data
    # --------------------------------------------------------

    data_start = (
        OPCODE_OFFSET
        + struct.calcsize(OPCODE_FORMAT)
    )

    rows = []


    # ========================================================
    # Decode each target separately
    # ========================================================

    for target_index in range(
        target_count
    ):

        if target_size:

            target_start = (
                data_start
                + target_index * target_size
            )

            target_end = (
                target_start + target_size
            )

        else:

            target_start = data_start
            target_end = len(payload)


        target_data = payload[
            target_start:target_end
        ]

        row = {}

        current_offset = 0


        # ----------------------------------------------------
        # Decode every configured field
        # ----------------------------------------------------

        for field_name, fmt in fields:

            size = struct.calcsize(fmt)

            value, actual_size = unpack_value(
                target_data,
                current_offset,
                fmt
            )

            if value is None:

                row[field_name] = ""

                log_error(
                    f"Opcode {opcode}, "
                    f"target {target_index + 1}: "
                    f"could not decode field "
                    f"{field_name}"
                )

            else:

                row[field_name] = value

            current_offset += size


        # ----------------------------------------------------
        # If target contains bytes not described by ICD,
        # preserve them as param_N fields.
        # ----------------------------------------------------

        remaining = target_data[
            current_offset:
        ]

        for i, value in enumerate(
            remaining,
            1
        ):

            row[
                f"param_{i}"
            ] = f"0x{value:02X}"


        rows.append(row)


    return rows


# ============================================================
# DECODE SDR PAYLOAD
# ============================================================

def decode_sdr(payload):

    opcode = get_opcode(payload)

    if opcode is None:

        return (
            None,
            "UNKNOWN",
            [
                {
                    "param_1":
                    "Unable to read opcode"
                }
            ]
        )


    definition = OPCODE_DEFINITIONS.get(
        opcode
    )


    if definition is None:

        return (
            opcode,
            f"Opcode_{opcode}",
            decode_unknown(payload)
        )


    try:

        rows = decode_known_opcode(
            payload,
            opcode,
            definition
        )

        return (
            opcode,
            definition.get(
                "name",
                f"Opcode_{opcode}"
            ),
            rows
        )

    except Exception as e:

        log_error(
            f"Opcode {opcode} decoding error: {e}"
        )

        return (
            opcode,
            definition.get(
                "name",
                f"Opcode_{opcode}"
            ),
            decode_unknown(payload)
        )


# ============================================================
# PCAPNG OPTION PARSER
# ============================================================

def parse_options(data, endian):

    options = {}

    pos = 0

    while pos + 4 <= len(data):

        try:

            code = struct.unpack_from(
                endian + "H",
                data,
                pos
            )[0]

            length = struct.unpack_from(
                endian + "H",
                data,
                pos + 2
            )[0]

        except Exception:

            break

        pos += 4

        if code == 0:
            break

        if pos + length > len(data):
            break

        value = data[
            pos:pos + length
        ]

        options[code] = value

        padded_length = (
            (length + 3) // 4
        ) * 4

        pos += padded_length

    return options


# ============================================================
# PCAPNG CONVERTER
# ============================================================

def parse_pcapng(filename):

    packets = []

    interfaces = {}

    with open(filename, "rb") as f:

        data = f.read()


    pos = 0

    endian = "<"

    section_number = 0


    while pos + 12 <= len(data):

        try:

            # ------------------------------------------------
            # Block type
            # ------------------------------------------------

            block_type = struct.unpack_from(
                endian + "I",
                data,
                pos
            )[0]


            # ------------------------------------------------
            # Section Header Block
            # ------------------------------------------------

            if (
                block_type
                == 0x0A0D0D0A
            ):

                if pos + 12 > len(data):

                    log_error(
                        f"Truncated Section Header at {pos}"
                    )

                    break


                magic = data[
                    pos + 8:
                    pos + 12
                ]


                if magic == b"\x4D\x3C\x2B\x1A":

                    endian = "<"

                elif magic == b"\x1A\x2B\x3C\x4D":

                    endian = ">"

                else:

                    log_error(
                        f"Invalid byte-order magic at {pos}"
                    )

                    # Try little endian and continue
                    endian = "<"


                block_length = struct.unpack_from(
                    endian + "I",
                    data,
                    pos + 4
                )[0]


                if (
                    block_length < 28
                    or
                    pos + block_length > len(data)
                ):

                    log_error(
                        f"Invalid Section Header "
                        f"length at {pos}"
                    )

                    break


                section_number += 1

                interfaces = {}

                pos += block_length

                continue


            # ------------------------------------------------
            # Read block length
            # ------------------------------------------------

            block_length = struct.unpack_from(
                endian + "I",
                data,
                pos + 4
            )[0]


            if block_length < 12:

                log_error(
                    f"Invalid block length at {pos}"
                )

                break


            if (
                pos + block_length
                > len(data)
            ):

                log_error(
                    f"Truncated block at {pos}"
                )

                break


            block = data[
                pos:
                pos + block_length
            ]


            # =================================================
            # Interface Description Block
            # =================================================

            if block_type == 0x00000001:

                if len(block) >= 20:

                    interface_id = len(
                        interfaces
                    )

                    link_type = struct.unpack_from(
                        endian + "H",
                        block,
                        8
                    )[0]

                    snaplen = struct.unpack_from(
                        endian + "I",
                        block,
                        12
                    )[0]


                    # Parse options
                    options = {}

                    if len(block) > 16:

                        options = parse_options(
                            block[16:-4],
                            endian
                        )


                    # Default PCAPNG timestamp
                    # resolution is 10^-6 seconds.
                    timestamp_resolution = 1e-6


                    # if_tsresol option = 9
                    if 9 in options:

                        value = options[9]

                        if len(value) >= 1:

                            raw = value[0]

                            if raw & 0x80:

                                # Base 2
                                timestamp_resolution = (
                                    2 ** -(raw & 0x7F)
                                )

                            else:

                                # Base 10
                                timestamp_resolution = (
                                    10 ** (-raw)
                                )


                    interfaces[
                        interface_id
                    ] = {
                        "link_type": link_type,
                        "snaplen": snaplen,
                        "timestamp_resolution":
                            timestamp_resolution
                    }


            # =================================================
            # Enhanced Packet Block
            # =================================================

            elif block_type == 0x00000006:

                if len(block) < 32:

                    log_error(
                        f"Malformed Enhanced Packet "
                        f"Block at {pos}"
                    )

                    # Do NOT drop packet structure silently

                else:

                    interface_id = struct.unpack_from(
                        endian + "I",
                        block,
                        8
                    )[0]

                    timestamp_high = struct.unpack_from(
                        endian + "I",
                        block,
                        12
                    )[0]

                    timestamp_low = struct.unpack_from(
                        endian + "I",
                        block,
                        16
                    )[0]

                    captured_length = struct.unpack_from(
                        endian + "I",
                        block,
                        20
                    )[0]

                    original_length = struct.unpack_from(
                        endian + "I",
                        block,
                        24
                    )[0]


                    packet_start = 28

                    packet_end = (
                        packet_start
                        + captured_length
                    )


                    if (
                        packet_start <= len(block)
                        and
                        packet_end <= len(block) - 4
                    ):

                        packet = block[
                            packet_start:
                            packet_end
                        ]

                        timestamp_raw = (
                            (timestamp_high << 32)
                            |
                            timestamp_low
                        )

                        interface = interfaces.get(
                            interface_id,
                            {}
                        )

                        resolution = interface.get(
                            "timestamp_resolution",
                            1e-6
                        )

                        timestamp = (
                            timestamp_to_string(
                                timestamp_raw,
                                resolution
                            )
                        )

                        packets.append({
                            "timestamp":
                                timestamp,
                            "timestamp_raw":
                                timestamp_raw,
                            "interface_id":
                                interface_id,
                            "captured_length":
                                captured_length,
                            "original_length":
                                original_length,
                            "packet":
                                packet
                        })

                    else:

                        log_error(
                            f"Invalid packet boundaries "
                            f"at block {pos}"
                        )


            # =================================================
            # Simple Packet Block
            # =================================================

            elif block_type == 0x00000003:

                if len(block) >= 16:

                    original_length = struct.unpack_from(
                        endian + "I",
                        block,
                        8
                    )[0]

                    packet = block[
                        12:-4
                    ]

                    packets.append({
                        "timestamp": "",
                        "timestamp_raw": 0,
                        "interface_id": 0,
                        "captured_length":
                            len(packet),
                        "original_length":
                            original_length,
                        "packet":
                            packet
                    })


            # =================================================
            # Legacy Packet Block
            # =================================================

            elif block_type == 0x00000002:

                if len(block) >= 32:

                    interface_id = struct.unpack_from(
                        endian + "H",
                        block,
                        8
                    )[0]

                    timestamp_high = struct.unpack_from(
                        endian + "H",
                        block,
                        12
                    )[0]

                    timestamp_low = struct.unpack_from(
                        endian + "I",
                        block,
                        16
                    )[0]

                    captured_length = struct.unpack_from(
                        endian + "I",
                        block,
                        20
                    )[0]

                    original_length = struct.unpack_from(
                        endian + "I",
                        block,
                        24
                    )[0]

                    packet_start = 28

                    packet_end = (
                        packet_start
                        + captured_length
                    )

                    if (
                        packet_end <= len(block) - 4
                    ):

                        packet = block[
                            packet_start:
                            packet_end
                        ]

                        timestamp_raw = (
                            (timestamp_high << 32)
                            |
                            timestamp_low
                        )

                        interface = interfaces.get(
                            interface_id,
                            {}
                        )

                        resolution = interface.get(
                            "timestamp_resolution",
                            1e-6
                        )

                        timestamp = (
                            timestamp_to_string(
                                timestamp_raw,
                                resolution
                            )
                        )

                        packets.append({
                            "timestamp":
                                timestamp,
                            "timestamp_raw":
                                timestamp_raw,
                            "interface_id":
                                interface_id,
                            "captured_length":
                                captured_length,
                            "original_length":
                                original_length,
                            "packet":
                                packet
                        })


            # Move to next block
            pos += block_length


        except Exception as e:

            log_error(
                f"PCAPNG parsing error at offset "
                f"{pos}: {e}"
            )

            # Attempt to move forward instead of crashing.
            pos += 4


    return packets


# ============================================================
# COLLECT ALL CSV COLUMNS
# ============================================================

def collect_columns(rows):

    columns = [
        "packet_number",
        "capture_timestamp",
        "opcode",
        "opcode_name",
        "target_index"
    ]

    for row in rows:

        for key in row.keys():

            if key not in columns:

                columns.append(key)

    return columns


# ============================================================
# WRITE CSV
# ============================================================

def write_csv(filename, rows, columns):

    with open(
        filename,
        "w",
        newline="",
        encoding="utf-8"
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=columns,
            extrasaction="ignore"
        )

        writer.writeheader()

        for row in rows:

            writer.writerow(row)


# ============================================================
# MAIN CONVERSION
# ============================================================

def convert(filename):

    # Clear old error file
    with open(
        ERROR_FILE,
        "w",
        encoding="utf-8"
    ) as f:
        f.write("PCAPNG conversion errors\n")
        f.write("=" * 60 + "\n")


    print()
    print("=" * 60)
    print("PURE PYTHON SDR PCAPNG -> CSV")
    print("=" * 60)

    print()
    print("Reading:")
    print(filename)

    packets = parse_pcapng(
        filename
    )

    print()
    print(
        "PCAPNG packets found:",
        len(packets)
    )


    all_rows = []

    opcode_rows = defaultdict(list)

    opcode_set = set()


    # ========================================================
    # Process every packet
    # ========================================================

    for packet_number, item in enumerate(
        packets,
        1
    ):

        try:

            raw_packet = item[
                "packet"
            ]


            # ------------------------------------------------
            # Extract network/application payload
            # ------------------------------------------------

            network = extract_sdr_payload(
                raw_packet
            )

            payload = network[
                "payload"
            ]


            # ------------------------------------------------
            # Decode opcode
            # ------------------------------------------------

            opcode, opcode_name, decoded_targets = (
                decode_sdr(payload)
            )


            if opcode is not None:

                opcode_set.add(
                    opcode
                )


            # ------------------------------------------------
            # If decoder somehow returns no rows,
            # preserve the packet.
            # ------------------------------------------------

            if not decoded_targets:

                decoded_targets = [
                    {}
                ]


            # =================================================
            # ONE TARGET = ONE CSV ROW
            # =================================================

            for target_index, decoded in enumerate(
                decoded_targets,
                1
            ):

                row = {

                    "packet_number":
                        packet_number,

                    "capture_timestamp":
                        item.get(
                            "timestamp",
                            ""
                        ),

                    "opcode":
                        opcode
                        if opcode is not None
                        else "",

                    "opcode_name":
                        opcode_name,

                    "target_index":
                        target_index
                }


                # --------------------------------------------
                # Add ONLY decoded SDR parameters
                # --------------------------------------------

                for key, value in decoded.items():

                    row[key] = value


                # --------------------------------------------
                # Combined CSV
                # --------------------------------------------

                all_rows.append(
                    row
                )


                # --------------------------------------------
                # Per-opcode CSV
                # --------------------------------------------

                opcode_key = (
                    opcode
                    if opcode is not None
                    else "unknown"
                )

                opcode_rows[
                    opcode_key
                ].append(row)


        except Exception as e:

            # ------------------------------------------------
            # NEVER crash the whole conversion because of
            # one packet.
            # ------------------------------------------------

            log_error(
                f"Packet {packet_number}: {e}"
            )

            # Preserve packet as a CSV row.
            all_rows.append({
                "packet_number":
                    packet_number,

                "capture_timestamp":
                    item.get(
                        "timestamp",
                        ""
                    ),

                "opcode": "",

                "opcode_name":
                    "DECODE_ERROR",

                "target_index": 1
            })


    # ========================================================
    # Combined CSV
    # ========================================================

    if all_rows:

        combined_columns = collect_columns(
            all_rows
        )

        output_dir = os.path.dirname(
            os.path.abspath(filename)
        )

        combined_file = os.path.join(
            output_dir,
            "telemetry_combined.csv"
        )

        write_csv(
            combined_file,
            all_rows,
            combined_columns
        )

    else:

        combined_file = ""


    # ========================================================
    # Per opcode CSV
    # ========================================================

    output_dir = os.path.dirname(
        os.path.abspath(filename)
    )


    per_opcode_counts = {}


    for opcode, rows in opcode_rows.items():

        # ----------------------------------------------------
        # Sort by capture timestamp
        # ----------------------------------------------------

        rows.sort(
            key=lambda x:
            x.get(
                "capture_timestamp",
                ""
            )
        )


        if opcode == "unknown":

            filename_opcode = "opcode_unknown.csv"

        else:

            filename_opcode = (
                f"opcode_{opcode}.csv"
            )


        output_file = os.path.join(
            output_dir,
            filename_opcode
        )


        # ----------------------------------------------------
        # Determine columns.
        #
        # Keep only parameters relevant to this opcode.
        # ----------------------------------------------------

        columns = [
            "packet_number",
            "capture_timestamp",
            "opcode",
            "opcode_name",
            "target_index"
        ]


        for row in rows:

            for key in row.keys():

                if key not in columns:

                    columns.append(key)


        write_csv(
            output_file,
            rows,
            columns
        )


        per_opcode_counts[
            opcode
        ] = len(rows)


    # ========================================================
    # SUMMARY
    # ========================================================

    print()
    print("=" * 60)
    print("CONVERSION COMPLETED")
    print("=" * 60)

    print(
        "Total packets processed:",
        len(packets)
    )

    print(
        "Total CSV rows:",
        len(all_rows)
    )

    print(
        "Total different opcodes:",
        len(opcode_set)
    )

    print()

    print("Rows written per opcode:")

    for opcode in sorted(
        per_opcode_counts,
        key=lambda x: str(x)
    ):

        print(
            f"  Opcode {opcode}: "
            f"{per_opcode_counts[opcode]} rows"
        )

    print()

    if combined_file:

        print(
            "Combined CSV:",
            combined_file
        )

    print(
        "Error log:",
        os.path.abspath(
            ERROR_FILE
        )
    )

    print()


# ============================================================
# PROGRAM START
# ============================================================

def main():

    # --------------------------------------------------------
    # Usage:
    #
    # python3 script.py capture.pcapng
    #
    # --------------------------------------------------------

    if len(sys.argv) >= 2:

        filename = sys.argv[1]

    else:

        filename = input(
            "Enter PCAPNG file path: "
        ).strip().strip('"')


    if not filename:

        print(
            "ERROR: No PCAPNG file specified."
        )

        return


    if not os.path.isfile(filename):

        print(
            "ERROR: File not found:"
        )

        print(filename)

        return


    if not filename.lower().endswith(
        ".pcapng"
    ):

        print(
            "WARNING: File does not have "
            "a .pcapng extension."
        )


    try:

        convert(filename)

    except Exception as e:

        log_error(
            f"Fatal error: {e}"
        )

        print()
        print(
            "ERROR:",
            e
        )

        print(
            "See errors.log for details."
        )


if __name__ == "__main__":

    main()
