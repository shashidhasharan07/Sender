import struct
import csv
import os
from datetime import datetime, timezone


# ============================================================
# CONFIGURATION
# ============================================================

# Your protocol is assumed to use big-endian payload values.
PAYLOAD_BYTEORDER = "big"

# One complete target message
MESSAGE_SIZE = 130

# Header inside one message
HEADER_SIZE = 28

# First byte of the application message is assumed to be Opcode
OPCODE_OFFSET = 0

# Number of targets is assumed to be the second byte.
TARGET_COUNT_OFFSET = 1

# ------------------------------------------------------------
# Current generic target layout
#
# IMPORTANT:
# The uploaded file does NOT contain the actual protocol
# definition for the 28-byte header / 102-byte parameter area.
#
# Therefore these are only safe generic fields.
# ------------------------------------------------------------

GENERIC_TARGET_FIELDS = [
    "GlobalID",
    "Latitude",
    "Longitude",
    "Altitude",
    "Bitfield",
    "Enum"
]


# ============================================================
# BYTE ORDER HELPERS
# ============================================================

def normalize_byteorder(byteorder):
    """
    Converts Python/struct style endian values into
    'big' or 'little'.
    """

    if byteorder in ("big", ">","!"):
        return "big"

    if byteorder in ("little", "<"):
        return "little"

    raise ValueError(
        f"Invalid byteorder {byteorder!r}. "
        "Expected big, little, >, < or !"
    )


def read_u8(data, pos):
    if pos < 0 or pos + 1 > len(data):
        raise ValueError(f"Cannot read u8 at offset {pos}")

    return data[pos]


def read_u16(data, pos, byteorder="big"):
    byteorder = normalize_byteorder(byteorder)

    if pos < 0 or pos + 2 > len(data):
        raise ValueError(f"Cannot read u16 at offset {pos}")

    return int.from_bytes(
        data[pos:pos + 2],
        byteorder=byteorder,
        signed=False
    )


def read_u32(data, pos, byteorder="big"):
    byteorder = normalize_byteorder(byteorder)

    if pos < 0 or pos + 4 > len(data):
        raise ValueError(f"Cannot read u32 at offset {pos}")

    return int.from_bytes(
        data[pos:pos + 4],
        byteorder=byteorder,
        signed=False
    )


def read_i32(data, pos, byteorder="big"):
    byteorder = normalize_byteorder(byteorder)

    if pos < 0 or pos + 4 > len(data):
        raise ValueError(f"Cannot read i32 at offset {pos}")

    return int.from_bytes(
        data[pos:pos + 4],
        byteorder=byteorder,
        signed=True
    )


# ============================================================
# GENERIC VALUE DECODERS
# ============================================================

def decode_uint(data, byteorder):
    if len(data) == 0:
        return ""

    return int.from_bytes(
        data,
        byteorder=normalize_byteorder(byteorder),
        signed=False
    )


def decode_int(data, byteorder):
    if len(data) == 0:
        return ""

    return int.from_bytes(
        data,
        byteorder=normalize_byteorder(byteorder),
        signed=True
    )


def decode_value(data, byteorder="big", signed=False):
    """
    Generic decoder.

    1 byte  -> integer
    2 bytes -> integer
    4 bytes -> integer
    8 bytes -> integer

    Other lengths are returned as a decimal integer too.
    """

    if not data:
        return ""

    if signed:
        return decode_int(data, byteorder)

    return decode_uint(data, byteorder)


# ============================================================
# NETWORK PACKET EXTRACTION
# ============================================================

def extract_application_payload(packet):
    """
    Extract application payload from:

        Ethernet
        VLAN (optional)
        IPv4 / IPv6
        TCP / UDP

    Only returns application payload.

    No network information is written to CSV.
    """

    if not packet:
        return b""

    # --------------------------------------------------------
    # Ethernet
    # --------------------------------------------------------

    if len(packet) < 14:
        return b""

    ether_type = int.from_bytes(
        packet[12:14],
        byteorder="big"
    )

    pos = 14

    # --------------------------------------------------------
    # VLAN
    # --------------------------------------------------------

    while ether_type in (0x8100, 0x88A8, 0x9100):

        if len(packet) < pos + 4:
            return b""

        ether_type = int.from_bytes(
            packet[pos + 2:pos + 4],
            byteorder="big"
        )

        pos += 4

    # --------------------------------------------------------
    # IPv4
    # --------------------------------------------------------

    if ether_type == 0x0800:

        if len(packet) < pos + 20:
            return b""

        version_ihl = packet[pos]

        version = version_ihl >> 4

        if version != 4:
            return b""

        ihl = (version_ihl & 0x0F) * 4

        if ihl < 20:
            return b""

        if len(packet) < pos + ihl:
            return b""

        protocol = packet[pos + 9]

        transport_pos = pos + ihl

        # ----------------------------------------------------
        # TCP
        # ----------------------------------------------------

        if protocol == 6:

            if len(packet) < transport_pos + 20:
                return b""

            tcp_data_offset = (
                packet[transport_pos + 12] >> 4
            ) * 4

            if tcp_data_offset < 20:
                return b""

            payload_pos = (
                transport_pos + tcp_data_offset
            )

            if payload_pos > len(packet):
                return b""

            return packet[payload_pos:]

        # ----------------------------------------------------
        # UDP
        # ----------------------------------------------------

        if protocol == 17:

            if len(packet) < transport_pos + 8:
                return b""

            payload_pos = transport_pos + 8

            if payload_pos > len(packet):
                return b""

            return packet[payload_pos:]

        return packet[transport_pos:]

    # --------------------------------------------------------
    # IPv6
    # --------------------------------------------------------

    elif ether_type == 0x86DD:

        if len(packet) < pos + 40:
            return b""

        next_header = packet[pos + 6]

        transport_pos = pos + 40

        # Basic IPv6 extension-header handling
        while next_header in (
            0,
            43,
            44,
            50,
            51,
            60
        ):

            if next_header == 44:
                # Fragment header = 8 bytes
                if len(packet) < transport_pos + 8:
                    return b""

                next_header = packet[
                    transport_pos
                ]

                transport_pos += 8

            elif next_header == 50:
                # ESP.
                # Cannot reliably locate application payload.
                return b""

            elif next_header == 51:
                # Authentication header.
                if len(packet) < transport_pos + 2:
                    return b""

                next_header_value = packet[
                    transport_pos
                ]

                payload_len_units = packet[
                    transport_pos + 1
                ]

                header_len = (
                    (payload_len_units + 2) * 4
                )

                if len(packet) < transport_pos + header_len:
                    return b""

                next_header = next_header_value

                transport_pos += header_len

            else:
                # Hop-by-hop, routing, destination options
                if len(packet) < transport_pos + 2:
                    return b""

                next_header_value = packet[
                    transport_pos
                ]

                ext_len = (
                    packet[transport_pos + 1] + 1
                ) * 8

                if len(packet) < transport_pos + ext_len:
                    return b""

                next_header = next_header_value

                transport_pos += ext_len

        # ----------------------------------------------------
        # IPv6 TCP
        # ----------------------------------------------------

        if next_header == 6:

            if len(packet) < transport_pos + 20:
                return b""

            tcp_header_len = (
                packet[transport_pos + 12] >> 4
            ) * 4

            if tcp_header_len < 20:
                return b""

            payload_pos = (
                transport_pos + tcp_header_len
            )

            if payload_pos > len(packet):
                return b""

            return packet[payload_pos:]

        # ----------------------------------------------------
        # IPv6 UDP
        # ----------------------------------------------------

        if next_header == 17:

            if len(packet) < transport_pos + 8:
                return b""

            payload_pos = transport_pos + 8

            if payload_pos > len(packet):
                return b""

            return packet[payload_pos:]

        return packet[transport_pos:]

    # --------------------------------------------------------
    # Non-IP
    # --------------------------------------------------------

    return b""


# ============================================================
# APPLICATION MESSAGE DECODER
# ============================================================

def decode_single_message(message):
    """
    Decode one 130-byte application message.

    Current known information:
        message size = 130
        header       = 28

    Opcode:
        byte 0

    Target count:
        byte 1

    The remaining protocol-specific structure is NOT present
    in the uploaded Python file, so the decoder does not invent
    parameter names/types.
    """

    result = {
        "Opcode": "",
        "Target_Count": "",
        "Parameters": {},
        "Targets": []
    }

    if not message:
        return result

    if len(message) < 2:
        return result

    # --------------------------------------------------------
    # Opcode
    # --------------------------------------------------------

    result["Opcode"] = message[OPCODE_OFFSET]

    # --------------------------------------------------------
    # Target count
    # --------------------------------------------------------

    result["Target_Count"] = message[
        TARGET_COUNT_OFFSET
    ]

    target_count = result["Target_Count"]

    # --------------------------------------------------------
    # Header
    # --------------------------------------------------------

    header_end = min(
        HEADER_SIZE,
        len(message)
    )

    header = message[:header_end]

    # --------------------------------------------------------
    # Parameter area
    # --------------------------------------------------------

    parameter_area = message[header_end:]

    # --------------------------------------------------------
    # IMPORTANT
    #
    # We cannot safely invent the parameter names here.
    #
    # The uploaded file only contained the old guessed fields:
    # GlobalID, Latitude, Longitude, Altitude, Bitfield, Enum.
    #
    # Instead of generating fake parameter names/values,
    # preserve the parameter area internally.
    # --------------------------------------------------------

    # If there is no target information, treat this as a
    # generic opcode message.
    if target_count == 0:
        result["Parameters"] = decode_generic_parameters(
            parameter_area
        )

        return result

    # --------------------------------------------------------
    # Target messages
    #
    # 130-byte message
    # 28-byte header
    # leaves 102 bytes.
    #
    # We cannot know the exact target size without the protocol
    # definition.
    #
    # For now, if target count divides 102, divide equally.
    # --------------------------------------------------------

    if target_count > 0:

        remaining_size = len(parameter_area)

        if remaining_size % target_count == 0:

            target_size = (
                remaining_size // target_count
            )

            for index in range(target_count):

                start = (
                    index * target_size
                )

                end = (
                    start + target_size
                )

                target_data = parameter_area[
                    start:end
                ]

                target = decode_generic_target(
                    target_data
                )

                result["Targets"].append(
                    target
                )

        else:

            # Cannot safely divide the parameter area.
            # Keep it as one generic target.
            result["Targets"].append(
                decode_generic_target(
                    parameter_area
                )
            )

    return result


# ============================================================
# GENERIC PARAMETER DECODER
# ============================================================

def decode_generic_parameters(data):
    """
    Generic decoder used only when there are no targets.

    It does NOT claim to know protocol parameter names.

    Splits data into 4-byte unsigned integers where possible.
    """

    parameters = {}

    if not data:
        return parameters

    full_words = len(data) // 4

    for index in range(full_words):

        start = index * 4

        end = start + 4

        value = decode_value(
            data[start:end],
            PAYLOAD_BYTEORDER,
            signed=False
        )

        parameters[
            f"Parameter_{index + 1}"
        ] = value

    remainder_start = full_words * 4

    if remainder_start < len(data):

        remainder = data[
            remainder_start:
        ]

        parameters[
            f"Parameter_{full_words + 1}"
        ] = decode_value(
            remainder,
            PAYLOAD_BYTEORDER,
            signed=False
        )

    return parameters


# ============================================================
# GENERIC TARGET DECODER
# ============================================================

def decode_generic_target(data):
    """
    Generic target decoder.

    This is intentionally conservative because the actual
    protocol parameter definition is not present in the
    uploaded Python file.
    """

    target = {}

    length = len(data)

    # --------------------------------------------------------
    # If target has at least 4 bytes
    # --------------------------------------------------------

    if length >= 4:

        target["GlobalID"] = decode_uint(
            data[0:4],
            PAYLOAD_BYTEORDER
        )

    # --------------------------------------------------------
    # If target has at least 8 bytes
    # --------------------------------------------------------

    if length >= 8:

        raw_latitude = decode_int(
            data[4:8],
            PAYLOAD_BYTEORDER
        )

        target["Latitude"] = (
            raw_latitude / 10000000.0
        )

    # --------------------------------------------------------
    # If target has at least 12 bytes
    # --------------------------------------------------------

    if length >= 12:

        raw_longitude = decode_int(
            data[8:12],
            PAYLOAD_BYTEORDER
        )

        target["Longitude"] = (
            raw_longitude / 10000000.0
        )

    # --------------------------------------------------------
    # If target has at least 16 bytes
    # --------------------------------------------------------

    if length >= 16:

        raw_altitude = decode_int(
            data[12:16],
            PAYLOAD_BYTEORDER
        )

        target["Altitude"] = (
            raw_altitude / 1000.0
        )

    # --------------------------------------------------------
    # Generic bitfield
    # --------------------------------------------------------

    if length >= 17:

        bitfield = data[16]

        target["Bitfield"] = bitfield

        for bit in range(8):

            target[
                f"Bit{bit}"
            ] = (
                (bitfield >> bit) & 1
            )

    # --------------------------------------------------------
    # Generic enum
    # --------------------------------------------------------

    if length >= 18:

        target["Enum"] = data[17]

    # --------------------------------------------------------
    # Remaining target parameters
    # --------------------------------------------------------

    if length > 18:

        remaining = data[18:]

        full_words = len(remaining) // 4

        for index in range(full_words):

            start = index * 4

            end = start + 4

            target[
                f"Parameter_{index + 1}"
            ] = decode_uint(
                remaining[start:end],
                PAYLOAD_BYTEORDER
            )

        remainder_start = full_words * 4

        if remainder_start < len(remaining):

            target[
                f"Parameter_{full_words + 1}"
            ] = decode_uint(
                remaining[remainder_start:],
                PAYLOAD_BYTEORDER
            )

    return target


# ============================================================
# SPLIT APPLICATION PAYLOAD INTO 130-BYTE MESSAGES
# ============================================================

def split_messages(payload):
    """
    Splits application payload into 130-byte messages.

    If payload contains:

        130 bytes  -> 1 message
        260 bytes  -> 2 messages
        390 bytes  -> 3 messages
        ...

    Any incomplete trailing bytes are ignored.
    """

    messages = []

    if not payload:
        return messages

    position = 0

    while position + MESSAGE_SIZE <= len(payload):

        message = payload[
            position:
            position + MESSAGE_SIZE
        ]

        messages.append(message)

        position += MESSAGE_SIZE

    return messages


# ============================================================
# CSV COLUMN NAME
# ============================================================

def target_column(parameter_name, target_number):
    """
    Creates:

        Parameter[1]
        Parameter[2]
        Parameter[3]

    Only for target parameters.
    """

    return f"{parameter_name}[{target_number}]"


# ============================================================
# PCAPNG CONVERTER
# ============================================================

def convert_pcapng(input_file, output_file):

    print()
    print("Reading PCAPNG file...")
    print()

    with open(input_file, "rb") as f:
        data = f.read()

    print(
        "PCAPNG size:",
        len(data),
        "bytes"
    )

    position = 0

    endian = "little"

    packet_number = 0

    rows = []

    all_columns = set()

    max_targets = 0

    # --------------------------------------------------------
    # Process one network packet
    # --------------------------------------------------------

    def process_packet(packet):

        nonlocal packet_number
        nonlocal max_targets

        application_payload = (
            extract_application_payload(packet)
        )

        if not application_payload:
            return

        messages = split_messages(
            application_payload
        )

        # If application payload is smaller than 130,
        # try treating the complete payload as one message.
        if not messages:

            if len(application_payload) >= 2:

                messages = [
                    application_payload
                ]

            else:

                return

        for message in messages:

            decoded = decode_single_message(
                message
            )

            packet_number += 1

            row = {
                "Packet_No": packet_number,
                "Opcode": decoded["Opcode"],
                "Target_Count": decoded["Target_Count"]
            }

            # ------------------------------------------------
            # Non-target parameters
            # ------------------------------------------------

            for name, value in decoded[
                "Parameters"
            ].items():

                row[name] = value

                all_columns.add(name)

            # ------------------------------------------------
            # Target parameters
            # ------------------------------------------------

            targets = decoded["Targets"]

            if len(targets) > max_targets:

                max_targets = len(targets)

            for target_index, target in enumerate(
                targets,
                start=1
            ):

                for name, value in target.items():

                    column = target_column(
                        name,
                        target_index
                    )

                    row[column] = value

                    all_columns.add(column)

            rows.append(row)

    # ========================================================
    # PCAPNG BLOCK LOOP
    # ========================================================

    while position + 12 <= len(data):

        # ----------------------------------------------------
        # Block type
        # ----------------------------------------------------

        raw_block_type = data[
            position:
            position + 4
        ]

        # Section Header Block has special byte pattern.
        if raw_block_type == b"\x0A\x0D\x0D\x0A":

            if position + 12 > len(data):
                break

            byte_order_magic = data[
                position + 8:
                position + 12
            ]

            if byte_order_magic == b"\x1A\x2B\x3C\x4D":

                endian = "big"

            elif byte_order_magic == b"\x4D\x3C\x2B\x1A":

                endian = "little"

            else:

                print(
                    "WARNING: Invalid PCAPNG byte-order magic."
                )

                position += 4

                continue

            block_length = read_u32(
                data,
                position + 4,
                endian
            )

            if block_length < 28:
                print(
                    "WARNING: Invalid Section Header Block."
                )
                break

            if (
                position + block_length
                > len(data)
            ):
                print(
                    "WARNING: Truncated Section Header Block."
                )
                break

            position += block_length

            continue

        # ----------------------------------------------------
        # Normal block
        # ----------------------------------------------------

        try:

            block_type = read_u32(
                data,
                position,
                endian
            )

            block_length = read_u32(
                data,
                position + 4,
                endian
            )

        except ValueError:

            break

        if block_length < 12:

            print(
                "WARNING: Invalid block length:",
                block_length
            )

            break

        if (
            position + block_length
            > len(data)
        ):

            print(
                "WARNING: Truncated PCAPNG block."
            )

            break

        block = data[
            position:
            position + block_length
        ]

        # ----------------------------------------------------
        # Interface Description Block
        #
        # Type = 1
        # ----------------------------------------------------

        if block_type == 0x00000001:

            pass

        # ----------------------------------------------------
        # Legacy Packet Block
        #
        # Type = 2
        # ----------------------------------------------------

        elif block_type == 0x00000002:

            if len(block) >= 28:

                try:

                    captured_length = read_u32(
                        block,
                        20,
                        endian
                    )

                    packet_start = 28

                    packet_end = (
                        packet_start
                        + captured_length
                    )

                    # Last 4 bytes = block total
                    # length, so packet must finish
                    # before them.

                    if (
                        packet_end
                        <= len(block) - 4
                    ):

                        packet = block[
                            packet_start:
                            packet_end
                        ]

                        process_packet(packet)

                except Exception as e:

                    print(
                        "WARNING: Error in legacy packet:",
                        e
                    )

        # ----------------------------------------------------
        # Enhanced Packet Block
        #
        # Type = 6
        # ----------------------------------------------------

        elif block_type == 0x00000006:

            if len(block) >= 32:

                try:

                    captured_length = read_u32(
                        block,
                        20,
                        endian
                    )

                    packet_start = 28

                    packet_end = (
                        packet_start
                        + captured_length
                    )

                    if (
                        packet_end
                        <= len(block) - 4
                    ):

                        packet = block[
                            packet_start:
                            packet_end
                        ]

                        process_packet(packet)

                except Exception as e:

                    print(
                        "WARNING: Error in enhanced packet:",
                        e
                    )

        position += block_length

    # ========================================================
    # CREATE CSV HEADER
    # ========================================================

    base_columns = [
        "Packet_No",
        "Opcode",
        "Target_Count"
    ]

    # Separate normal columns and target columns.
    normal_columns = []

    target_columns = []

    for column in all_columns:

        if "[" in column and column.endswith("]"):

            target_columns.append(column)

        else:

            normal_columns.append(column)

    # Sort normal parameter columns.
    normal_columns.sort()

    # --------------------------------------------------------
    # Sort target columns naturally:
    #
    # GlobalID[1]
    # Latitude[1]
    # ...
    # GlobalID[2]
    # Latitude[2]
    # ...
    # --------------------------------------------------------

    import re

    def target_sort_key(column):

        match = re.match(
            r"^(.*)\[(\d+)\]$",
            column
        )

        if not match:
            return (
                999999,
                column
            )

        name = match.group(1)

        number = int(
            match.group(2)
        )

        return (
            number,
            name
        )

    target_columns.sort(
        key=target_sort_key
    )

    full_header = (
        base_columns
        + normal_columns
        + target_columns
    )

    # ========================================================
    # WRITE CSV
    # ========================================================

    try:

        with open(
            output_file,
            "w",
            newline="",
            encoding="utf-8"
        ) as f:

            writer = csv.DictWriter(
                f,
                fieldnames=full_header,
                extrasaction="ignore"
            )

            writer.writeheader()

            for row in rows:

                writer.writerow(row)

    except PermissionError:

        base, extension = os.path.splitext(
            output_file
        )

        fallback = (
            base
            + "_"
            + datetime.now().strftime(
                "%Y%m%d_%H%M%S"
            )
            + extension
        )

        print()
        print(
            "WARNING: CSV is locked."
        )

        print(
            "Writing to:",
            fallback
        )

        with open(
            fallback,
            "w",
            newline="",
            encoding="utf-8"
        ) as f:

            writer = csv.DictWriter(
                f,
                fieldnames=full_header,
                extrasaction="ignore"
            )

            writer.writeheader()

            for row in rows:

                writer.writerow(row)

        output_file = fallback

    # ========================================================
    # RESULT
    # ========================================================

    print()
    print("=" * 70)
    print("CONVERSION COMPLETED")
    print("=" * 70)

    print(
        "Packets/messages decoded:",
        packet_number
    )

    print(
        "Maximum targets:",
        max_targets
    )

    print(
        "CSV columns:",
        len(full_header)
    )

    print(
        "CSV file:",
        output_file
    )

    print("=" * 70)

    return packet_number, output_file


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 70)
    print("PCAPNG TO CSV CONVERTER")
    print("=" * 70)
    print()
    print("Message size :", MESSAGE_SIZE)
    print("Header size  :", HEADER_SIZE)
    print()

    # --------------------------------------------------------
    # PCAPNG input
    # --------------------------------------------------------

    pcapng_file = input(
        "Enter the full path of your PCAPNG file: "
    ).strip().strip('"')

    if not os.path.isfile(pcapng_file):

        print()
        print(
            "ERROR: PCAPNG file not found:"
        )

        print(pcapng_file)

        input(
            "\nPress Enter to exit..."
        )

        return

    # --------------------------------------------------------
    # Output filename
    # --------------------------------------------------------

    default_csv = (
        os.path.splitext(
            pcapng_file
        )[0]
        + ".csv"
    )

    print()

    csv_input = input(
        f"CSV output path [{default_csv}]: "
    ).strip().strip('"')

    if csv_input:

        csv_file = csv_input

    else:

        csv_file = default_csv

    print()
    print("Starting conversion...")
    print()

    try:

        convert_pcapng(
            pcapng_file,
            csv_file
        )

    except KeyboardInterrupt:

        print()
        print(
            "Conversion cancelled."
        )

    except Exception as e:

        print()
        print("=" * 70)
        print("ERROR")
        print("=" * 70)

        print(
            type(e).__name__,
            ":",
            str(e)
        )

        import traceback

        traceback.print_exc()

        print("=" * 70)

    input(
        "\nPress Enter to exit..."
    )


# ============================================================
# PROGRAM START
# ============================================================

if __name__ == "__main__":
    main()
