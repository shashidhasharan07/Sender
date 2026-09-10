import csv
import os
import struct
from datetime import datetime


# ============================================================
# CONFIGURATION
# ============================================================

# ------------------------------------------------------------
# YOUR CUSTOM HEADER
# ------------------------------------------------------------

HEADER_SIZE = 16

# 10th byte of custom header
#
# Byte 1  -> index 0
# Byte 10 -> index 9
#
OPCODE_OFFSET = 9


# ============================================================
# SIZE FIELD IN YOUR 16-BYTE HEADER
# ============================================================
#
# Current assumption:
#
# Byte 1  - 4  : Other header data
# Byte 5  - 8  : Other header data
# Byte 9       : Other header data
# Byte 10      : OPCODE
# Byte 11 - 12 : Other header data
# Byte 13 - 16 : PACKET SIZE
#
# Therefore:
#
# SIZE_OFFSET = 12
# SIZE_LENGTH = 4
#
# Change these according to your actual header.
# ============================================================

SIZE_OFFSET = 12
SIZE_LENGTH = 4

# "big"    -> most significant byte first
# "little" -> least significant byte first

SIZE_ENDIAN = "big"


# ------------------------------------------------------------
# If True:
#
#     packet_size = header + payload
#
# payload_size = packet_size - 16
#
# If False:
#
#     packet_size = payload size
# ------------------------------------------------------------

SIZE_INCLUDES_HEADER = True


# ============================================================
# ICD DEFINITIONS
# ============================================================
#
# The decoder supports:
#
# Primitive:
#   uint8
#   int8
#   uint16
#   int16
#   uint32
#   int32
#   uint64
#   int64
#   float32
#   float64
#   bytes
#
# Containers:
#   struct
#   array
#   dynamic_array
#   mixed
#
# Arrays can contain:
#
#   primitive
#   struct
#   array
#   mixed
#
# Structs can contain:
#
#   primitive
#   struct
#   array
#   mixed
#
# Therefore arbitrary nesting is supported.
#
# ============================================================


ICDS = {

    # ========================================================
    # OPCODE 104
    #
    # Simple structure
    # ========================================================

    104: {
        "type": "struct",

        "fields": [

            {
                "name": "target_id",
                "type": "uint8"
            },

            {
                "name": "latitude",
                "type": "int32",
                "scale": 0.000001
            },

            {
                "name": "longitude",
                "type": "int32",
                "scale": 0.000001
            }
        ]
    },


    # ========================================================
    # OPCODE 105
    #
    # Example:
    #
    # struct
    # |
    # +-- num_targets
    # |
    # +-- Target[num_targets]
    #       |
    #       +-- id
    #       +-- range
    #       +-- num_tracks
    #       |
    #       +-- Track[num_tracks]
    #               |
    #               +-- velocity
    #               +-- status
    #
    # ========================================================

    105: {
        "type": "struct",

        "fields": [

            # ------------------------------------------------
            # Number of targets
            # ------------------------------------------------

            {
                "name": "num_targets",
                "type": "uint8"
            },

            # ------------------------------------------------
            # Target array
            # ------------------------------------------------

            {
                "name": "Target",
                "type": "array",

                "count_from": "num_targets",
                "max_count": 5,

                "element": {

                    "type": "struct",

                    "fields": [

                        # ------------------------------------
                        # Target ID
                        # ------------------------------------

                        {
                            "name": "id",
                            "type": "uint8"
                        },

                        # ------------------------------------
                        # Range
                        # ------------------------------------

                        {
                            "name": "range",
                            "type": "uint16",
                            "scale": 0.5
                        },

                        # ------------------------------------
                        # Number of tracks
                        # ------------------------------------

                        {
                            "name": "num_tracks",
                            "type": "uint8"
                        },

                        # ------------------------------------
                        # Track array
                        # ------------------------------------

                        {
                            "name": "Track",
                            "type": "array",

                            "count_from": "num_tracks",
                            "max_count": 3,

                            "element": {

                                "type": "struct",

                                "fields": [

                                    {
                                        "name": "velocity",
                                        "type": "float32"
                                    },

                                    {
                                        "name": "status",
                                        "type": "uint8",

                                        "enum": {
                                            0: "FREE",
                                            1: "LOCKED"
                                        }
                                    }
                                ]
                            }
                        }
                    ]
                }
            }
        ]
    },


    # ========================================================
    # OPCODE 106
    #
    # STRUCT -> STRUCT
    # ========================================================

    106: {
        "type": "struct",

        "fields": [

            {
                "name": "message_id",
                "type": "uint8"
            },

            {
                "name": "position",
                "type": "struct",

                "fields": [

                    {
                        "name": "latitude",
                        "type": "int32",
                        "scale": 0.000001
                    },

                    {
                        "name": "longitude",
                        "type": "int32",
                        "scale": 0.000001
                    }
                ]
            }
        ]
    },


    # ========================================================
    # OPCODE 107
    #
    # ARRAY -> STRUCT
    # ========================================================

    107: {
        "type": "array",

        "name": "Target",

        "count": 3,

        "element": {

            "type": "struct",

            "fields": [

                {
                    "name": "id",
                    "type": "uint8"
                },

                {
                    "name": "value",
                    "type": "uint16"
                }
            ]
        }
    },


    # ========================================================
    # OPCODE 108
    #
    # ARRAY -> ARRAY -> STRUCT
    # ========================================================

    108: {
        "type": "array",

        "name": "Group",

        "count": 2,

        "element": {

            "type": "array",

            "name": "Target",

            "count": 3,

            "element": {

                "type": "struct",

                "fields": [

                    {
                        "name": "id",
                        "type": "uint8"
                    },

                    {
                        "name": "value",
                        "type": "float32"
                    }
                ]
            }
        }
    },


    # ========================================================
    # OPCODE 109
    #
    # MIXED
    #
    # STRUCT -> ARRAY -> STRUCT
    # ========================================================

    109: {
        "type": "mixed",

        "blocks": [

            {
                "type": "struct",

                "fields": [

                    {
                        "name": "message_id",
                        "type": "uint8"
                    },

                    {
                        "name": "count",
                        "type": "uint8"
                    }
                ]
            },

            {
                "name": "values",

                "type": "array",

                "count_from": "count",
                "max_count": 5,

                "element": {

                    "type": "struct",

                    "fields": [

                        {
                            "name": "id",
                            "type": "uint8"
                        },

                        {
                            "name": "value",
                            "type": "uint16"
                        }
                    ]
                }
            }
        ]
    },


    # ========================================================
    # OPCODE 120
    #
    # Simple example
    # ========================================================

    120: {
        "type": "struct",

        "fields": [

            {
                "name": "message_id",
                "type": "uint8"
            },

            {
                "name": "status",
                "type": "uint32"
            },

            {
                "name": "health",
                "type": "uint8"
            }
        ]
    }
}


# ============================================================
# DATA TYPES
# ============================================================

TYPE_INFO = {

    "uint8":  (1, "B"),
    "int8":   (1, "b"),

    "uint16": (2, "H"),
    "int16":  (2, "h"),

    "uint32": (4, "I"),
    "int32":  (4, "i"),

    "uint64": (8, "Q"),
    "int64":  (8, "q"),

    "float32": (4, "f"),
    "float64": (8, "d")
}


# ============================================================
# READ INTEGER
# ============================================================

def read_integer(
    data,
    offset,
    length,
    endian
):

    if offset + length > len(data):

        raise ValueError(
            "Integer extends beyond available data"
        )

    return int.from_bytes(
        data[
            offset:
            offset + length
        ],
        byteorder=endian,
        signed=False
    )


# ============================================================
# READ PCAP
# ============================================================

def read_pcap(
    file_path
):

    packets = []

    with open(
        file_path,
        "rb"
    ) as file:

        global_header = file.read(24)

        if len(global_header) != 24:

            raise ValueError(
                "Invalid PCAP global header"
            )

        magic = global_header[
            0:4
        ]

        # ----------------------------------------------------
        # Determine endian and timestamp resolution
        # ----------------------------------------------------

        if magic == b"\xd4\xc3\xb2\xa1":

            endian = "<"
            timestamp_divisor = 1000000

        elif magic == b"\xa1\xb2\xc3\xd4":

            endian = ">"
            timestamp_divisor = 1000000

        elif magic == b"\x4d\x3c\xb2\xa1":

            endian = "<"
            timestamp_divisor = 1000000000

        elif magic == b"\xa1\xb2\x3c\x4d":

            endian = ">"
            timestamp_divisor = 1000000000

        else:

            raise ValueError(
                "Not a valid PCAP file"
            )

        # ----------------------------------------------------
        # Read packet records
        # ----------------------------------------------------

        while True:

            packet_header = file.read(16)

            if not packet_header:

                break

            if len(packet_header) != 16:

                raise ValueError(
                    "Incomplete PCAP packet header"
                )

            (
                ts_sec,
                ts_fraction,
                incl_len,
                orig_len
            ) = struct.unpack(
                endian + "IIII",
                packet_header
            )

            packet_data = file.read(
                incl_len
            )

            if len(packet_data) != incl_len:

                raise ValueError(
                    "Incomplete PCAP packet data"
                )

            timestamp = (
                ts_sec +
                ts_fraction / timestamp_divisor
            )

            packets.append(
                {
                    "timestamp": timestamp,
                    "data": packet_data
                }
            )

    return packets


# ============================================================
# READ PCAPNG
# ============================================================

def read_pcapng(
    file_path
):

    packets = []

    interfaces = {}

    endian = None

    with open(
        file_path,
        "rb"
    ) as file:

        while True:

            block_type_bytes = file.read(4)

            if not block_type_bytes:

                break

            if len(block_type_bytes) != 4:

                raise ValueError(
                    "Incomplete PCAPNG block type"
                )

            # =================================================
            # SECTION HEADER BLOCK
            # =================================================

            if block_type_bytes == b"\x0a\x0d\x0d\x0a":

                block_length_bytes = file.read(4)

                if len(block_length_bytes) != 4:

                    raise ValueError(
                        "Invalid PCAPNG section header"
                    )

                remaining = file.read(8)

                if len(remaining) != 8:

                    raise ValueError(
                        "Incomplete PCAPNG section header"
                    )

                bom = remaining[
                    0:4
                ]

                if bom == b"\x4d\x3c\x2b\x1a":

                    endian = "<"

                elif bom == b"\x1a\x2b\x3c\x4d":

                    endian = ">"

                else:

                    raise ValueError(
                        "Invalid PCAPNG byte-order magic"
                    )

                block_length = struct.unpack(
                    endian + "I",
                    block_length_bytes
                )[0]

                remaining_length = (
                    block_length -
                    12
                )

                if remaining_length < 0:

                    raise ValueError(
                        "Invalid PCAPNG block length"
                    )

                rest = file.read(
                    remaining_length
                )

                if len(rest) != remaining_length:

                    raise ValueError(
                        "Incomplete PCAPNG section"
                    )

                continue

            # =================================================
            # CHECK ENDIANNESS
            # =================================================

            if endian is None:

                raise ValueError(
                    "PCAPNG section header not found"
                )

            # =================================================
            # BLOCK LENGTH
            # =================================================

            block_length_bytes = file.read(4)

            if len(block_length_bytes) != 4:

                raise ValueError(
                    "Incomplete PCAPNG block length"
                )

            block_length = struct.unpack(
                endian + "I",
                block_length_bytes
            )[0]

            if block_length < 12:

                raise ValueError(
                    "Invalid PCAPNG block length"
                )

            block_data = file.read(
                block_length - 8
            )

            if len(block_data) != (
                block_length - 8
            ):

                raise ValueError(
                    "Incomplete PCAPNG block"
                )

            body = block_data[
                :-4
            ]

            block_type = struct.unpack(
                endian + "I",
                block_type_bytes
            )[0]

            # =================================================
            # INTERFACE DESCRIPTION BLOCK
            # =================================================

            if block_type == 0x00000001:

                if len(body) < 8:

                    continue

                (
                    link_type,
                    reserved,
                    snaplen
                ) = struct.unpack(
                    endian + "HHI",
                    body[:8]
                )

                ts_resolution = 1000000

                options = body[
                    8:
                ]

                option_offset = 0

                while (
                    option_offset + 4
                    <= len(options)
                ):

                    (
                        option_code,
                        option_length
                    ) = struct.unpack_from(
                        endian + "HH",
                        options,
                        option_offset
                    )

                    option_offset += 4

                    if option_code == 0:

                        break

                    option_value = options[
                        option_offset:
                        option_offset +
                        option_length
                    ]

                    # ----------------------------------------
                    # if_tsresol
                    # ----------------------------------------

                    if option_code == 9:

                        if len(
                            option_value
                        ) >= 1:

                            value = (
                                option_value[0]
                            )

                            if value & 0x80:

                                ts_resolution = (
                                    2 **
                                    (value & 0x7F)
                                )

                            else:

                                ts_resolution = (
                                    10 **
                                    value
                                )

                    padded_length = (
                        (
                            option_length +
                            3
                        ) // 4
                    ) * 4

                    option_offset += (
                        padded_length
                    )

                interface_id = len(
                    interfaces
                )

                interfaces[
                    interface_id
                ] = {

                    "link_type":
                        link_type,

                    "ts_resolution":
                        ts_resolution
                }

            # =================================================
            # ENHANCED PACKET BLOCK
            # =================================================

            elif block_type == 0x00000006:

                if len(body) < 20:

                    continue

                (
                    interface_id,
                    ts_high,
                    ts_low,
                    captured_length,
                    original_length
                ) = struct.unpack(
                    endian + "IIIII",
                    body[:20]
                )

                packet_start = 20

                packet_end = (
                    packet_start +
                    captured_length
                )

                packet_data = body[
                    packet_start:
                    packet_end
                ]

                interface_info = interfaces.get(
                    interface_id,
                    {
                        "ts_resolution":
                            1000000
                    }
                )

                ts_resolution = (
                    interface_info[
                        "ts_resolution"
                    ]
                )

                timestamp_value = (
                    (ts_high << 32) |
                    ts_low
                )

                timestamp = (
                    timestamp_value /
                    ts_resolution
                )

                packets.append(
                    {
                        "timestamp":
                            timestamp,

                        "data":
                            packet_data
                    }
                )

            # =================================================
            # SIMPLE PACKET BLOCK
            # =================================================

            elif block_type == 0x00000003:

                if len(body) < 4:

                    continue

                packet_data = body[
                    4:
                ]

                packets.append(
                    {
                        "timestamp":
                            None,

                        "data":
                            packet_data
                    }
                )

            # =================================================
            # LEGACY PACKET BLOCK
            # =================================================

            elif block_type == 0x00000002:

                if len(body) < 20:

                    continue

                (
                    interface_id,
                    drops_count,
                    ts_high,
                    ts_low,
                    captured_length,
                    original_length
                ) = struct.unpack(
                    endian + "HHIIII",
                    body[:20]
                )

                packet_start = 20

                packet_end = (
                    packet_start +
                    captured_length
                )

                packet_data = body[
                    packet_start:
                    packet_end
                ]

                interface_info = interfaces.get(
                    interface_id,
                    {
                        "ts_resolution":
                            1000000
                    }
                )

                ts_resolution = (
                    interface_info[
                        "ts_resolution"
                    ]
                )

                timestamp_value = (
                    (ts_high << 32) |
                    ts_low
                )

                timestamp = (
                    timestamp_value /
                    ts_resolution
                )

                packets.append(
                    {
                        "timestamp":
                            timestamp,

                        "data":
                            packet_data
                    }
                )

    return packets


# ============================================================
# DETERMINE PCAP OR PCAPNG
# ============================================================

def read_saved_capture(
    file_path
):

    with open(
        file_path,
        "rb"
    ) as file:

        magic = file.read(4)

    # --------------------------------------------------------
    # PCAPNG
    # --------------------------------------------------------

    if magic == b"\x0a\x0d\x0d\x0a":

        print(
            "Capture format: PCAPNG"
        )

        return read_pcapng(
            file_path
        )

    # --------------------------------------------------------
    # PCAP
    # --------------------------------------------------------

    pcap_magics = [

        b"\xd4\xc3\xb2\xa1",
        b"\xa1\xb2\xc3\xd4",
        b"\x4d\x3c\xb2\xa1",
        b"\xa1\xb2\x3c\x4d"
    ]

    if magic in pcap_magics:

        print(
            "Capture format: PCAP"
        )

        return read_pcap(
            file_path
        )

    raise ValueError(
        "File is not recognized as "
        "PCAP or PCAPNG"
    )


# ============================================================
# EXTRACT CUSTOM DATA
# ============================================================

def extract_custom_data(
    packet_bytes
):

    # --------------------------------------------------------
    # Ethernet
    # --------------------------------------------------------

    if len(packet_bytes) < 14:

        raise ValueError(
            "Ethernet frame is shorter than 14 bytes"
        )

    ether_type = struct.unpack(
        ">H",
        packet_bytes[
            12:14
        ]
    )[0]

    offset = 14

    # --------------------------------------------------------
    # VLAN
    # --------------------------------------------------------

    while ether_type in (
        0x8100,
        0x88A8
    ):

        if len(packet_bytes) < (
            offset + 4
        ):

            raise ValueError(
                "Incomplete VLAN header"
            )

        ether_type = struct.unpack(
            ">H",
            packet_bytes[
                offset + 2:
                offset + 4
            ]
        )[0]

        offset += 4

    # ========================================================
    # IPv4
    # ========================================================

    if ether_type == 0x0800:

        if len(packet_bytes) < (
            offset + 20
        ):

            raise ValueError(
                "Incomplete IPv4 header"
            )

        first_byte = packet_bytes[
            offset
        ]

        version = (
            first_byte >> 4
        )

        if version != 4:

            raise ValueError(
                "Invalid IPv4 packet"
            )

        ihl = (
            first_byte & 0x0F
        ) * 4

        if ihl < 20:

            raise ValueError(
                "Invalid IPv4 header length"
            )

        if len(packet_bytes) < (
            offset + ihl
        ):

            raise ValueError(
                "Incomplete IPv4 header"
            )

        protocol = packet_bytes[
            offset + 9
        ]

        transport_offset = (
            offset + ihl
        )

    # ========================================================
    # IPv6
    # ========================================================

    elif ether_type == 0x86DD:

        if len(packet_bytes) < (
            offset + 40
        ):

            raise ValueError(
                "Incomplete IPv6 header"
            )

        version = (
            packet_bytes[offset] >> 4
        )

        if version != 6:

            raise ValueError(
                "Invalid IPv6 packet"
            )

        protocol = packet_bytes[
            offset + 6
        ]

        transport_offset = (
            offset + 40
        )

    else:

        raise ValueError(
            f"Unsupported EtherType: "
            f"0x{ether_type:04X}"
        )

    # ========================================================
    # UDP
    # ========================================================

    if protocol == 17:

        if len(packet_bytes) < (
            transport_offset + 8
        ):

            raise ValueError(
                "Incomplete UDP header"
            )

        udp_length = struct.unpack(
            ">H",
            packet_bytes[
                transport_offset + 4:
                transport_offset + 6
            ]
        )[0]

        payload_start = (
            transport_offset + 8
        )

        if udp_length >= 8:

            payload_length = (
                udp_length - 8
            )

            payload_end = (
                payload_start +
                payload_length
            )

            payload_end = min(
                payload_end,
                len(packet_bytes)
            )

            return packet_bytes[
                payload_start:
                payload_end
            ]

        return packet_bytes[
            payload_start:
        ]

    # ========================================================
    # TCP
    # ========================================================

    if protocol == 6:

        if len(packet_bytes) < (
            transport_offset + 20
        ):

            raise ValueError(
                "Incomplete TCP header"
            )

        tcp_data_offset = (
            packet_bytes[
                transport_offset + 12
            ] >> 4
        ) * 4

        if tcp_data_offset < 20:

            raise ValueError(
                "Invalid TCP header length"
            )

        payload_start = (
            transport_offset +
            tcp_data_offset
        )

        if payload_start > len(
            packet_bytes
        ):

            raise ValueError(
                "TCP payload is outside packet"
            )

        return packet_bytes[
            payload_start:
        ]

    raise ValueError(
        f"Unsupported IP protocol: "
        f"{protocol}"
    )


# ============================================================
# PARSE CUSTOM HEADER
# ============================================================

def parse_header(
    custom_data
):

    if len(custom_data) < HEADER_SIZE:

        raise ValueError(
            f"Custom data has only "
            f"{len(custom_data)} bytes. "
            f"16-byte header required."
        )

    # --------------------------------------------------------
    # First 16 bytes = header
    # --------------------------------------------------------

    header = custom_data[
        :HEADER_SIZE
    ]

    # --------------------------------------------------------
    # Opcode
    # --------------------------------------------------------

    opcode = header[
        OPCODE_OFFSET
    ]

    # --------------------------------------------------------
    # Packet size
    # --------------------------------------------------------

    packet_size = read_integer(
        header,
        SIZE_OFFSET,
        SIZE_LENGTH,
        SIZE_ENDIAN
    )

    # --------------------------------------------------------
    # Payload size
    # --------------------------------------------------------

    if SIZE_INCLUDES_HEADER:

        payload_size = (
            packet_size -
            HEADER_SIZE
        )

    else:

        payload_size = packet_size

    if payload_size < 0:

        raise ValueError(
            f"Invalid payload size: "
            f"{payload_size}"
        )

    return (
        header,
        opcode,
        packet_size,
        payload_size
    )


# ============================================================
# DECODE PRIMITIVE
# ============================================================

def decode_primitive(
    payload,
    offset,
    field
):

    field_name = field.get(
        "name",
        ""
    )

    field_type = field.get(
        "type"
    )

    # ========================================================
    # RAW BYTES
    # ========================================================

    if field_type == "bytes":

        count = int(
            field.get(
                "count",
                1
            )
        )

        if offset + count > len(payload):

            raise ValueError(
                f"Not enough bytes for "
                f"field '{field_name}'"
            )

        value = payload[
            offset:
            offset + count
        ]

        return (
            value.hex(),
            offset + count
        )

    # ========================================================
    # CHECK DATA TYPE
    # ========================================================

    if field_type not in TYPE_INFO:

        raise ValueError(
            f"Unknown ICD type "
            f"'{field_type}'"
        )

    size, fmt = TYPE_INFO[
        field_type
    ]

    # --------------------------------------------------------
    # ICD byte order
    # --------------------------------------------------------

    endian_prefix = (
        ">"
        if SIZE_ENDIAN == "big"
        else "<"
    )

    count = int(
        field.get(
            "count",
            1
        )
    )

    values = []

    # ========================================================
    # READ VALUES
    # ========================================================

    for index in range(count):

        if offset + size > len(payload):

            raise ValueError(
                f"Not enough payload bytes "
                f"for '{field_name}'"
            )

        value = struct.unpack_from(
            endian_prefix + fmt,
            payload,
            offset
        )[0]

        offset += size

        # ----------------------------------------------------
        # SCALE
        # ----------------------------------------------------

        if "scale" in field:

            value *= field[
                "scale"
            ]

        # ----------------------------------------------------
        # OFFSET
        # ----------------------------------------------------

        if "offset" in field:

            value += field[
                "offset"
            ]

        # ----------------------------------------------------
        # ENUM
        # ----------------------------------------------------

        if "enum" in field:

            enum_table = field[
                "enum"
            ]

            if value in enum_table:

                value = enum_table[
                    value
                ]

        values.append(
            value
        )

    # ========================================================
    # SINGLE VALUE
    # ========================================================

    if count == 1:

        return (
            values[0],
            offset
        )

    # ========================================================
    # ARRAY OF PRIMITIVES
    # ========================================================

    return (
        values,
        offset
    )


# ============================================================
# DECODE STRUCT
# ============================================================

def decode_struct(
    node,
    payload,
    offset,
    prefix,
    context
):

    decoded = {}

    fields = node.get(
        "fields",
        []
    )

    # ========================================================
    # DECODE EACH FIELD
    # ========================================================

    for field in fields:

        field_type = field.get(
            "type"
        )

        field_name = field.get(
            "name",
            ""
        )

        # ----------------------------------------------------
        # PRIMITIVE FIELD
        # ----------------------------------------------------

        if (
            field_type in TYPE_INFO
            or field_type == "bytes"
        ):

            value, offset = decode_primitive(
                payload,
                offset,
                field
            )

            full_name = (
                f"{prefix}.{field_name}"
                if prefix
                else field_name
            )

            decoded[
                full_name
            ] = value

            # ------------------------------------------------
            # Store context.
            #
            # This allows:
            #
            # count_from = "num_targets"
            #
            # count_from = "num_tracks"
            # ------------------------------------------------

            if field_type in TYPE_INFO:

                context[
                    field_name
                ] = value

            continue

        # ----------------------------------------------------
        # NESTED NODE
        # ----------------------------------------------------

        if field_type in (
            "struct",
            "array",
            "dynamic_array",
            "mixed"
        ):

            child_prefix = (
                f"{prefix}.{field_name}"
                if prefix and field_name
                else field_name
                if field_name
                else prefix
            )

            child_result, offset = decode_node(
                field,
                payload,
                offset,
                child_prefix,
                context
            )

            decoded.update(
                child_result
            )

            continue

        raise ValueError(
            f"Unsupported field type "
            f"'{field_type}' "
            f"for '{field_name}'"
        )

    return (
        decoded,
        offset
    )


# ============================================================
# DECODE ARRAY
# ============================================================

def decode_array(
    node,
    payload,
    offset,
    prefix,
    context
):

    # ========================================================
    # DETERMINE ARRAY COUNT
    # ========================================================

    if "count_from" in node:

        count_name = node[
            "count_from"
        ]

        if count_name not in context:

            raise ValueError(
                f"Array '{prefix}' requires "
                f"count_from='{count_name}', "
                f"but that field has not "
                f"been decoded yet"
            )

        count = int(
            context[
                count_name
            ]
        )

    elif "count" in node:

        count = int(
            node[
                "count"
            ]
        )

    else:

        raise ValueError(
            f"Array '{prefix}' has no "
            f"'count' or 'count_from'"
        )

    # ========================================================
    # VALIDATE COUNT
    # ========================================================

    if count < 0:

        raise ValueError(
            f"Negative array count "
            f"for '{prefix}'"
        )

    # ========================================================
    # MAX COUNT
    # ========================================================

    if "max_count" in node:

        max_count = int(
            node[
                "max_count"
            ]
        )

        if count > max_count:

            raise ValueError(
                f"Array '{prefix}' count "
                f"{count} exceeds max_count "
                f"{max_count}"
            )

    # ========================================================
    # ELEMENT
    # ========================================================

    if "element" not in node:

        raise ValueError(
            f"Array '{prefix}' has no "
            f"'element' definition"
        )

    element = node[
        "element"
    ]

    decoded = {}

    # ========================================================
    # DECODE EACH ELEMENT
    # ========================================================

    for index in range(count):

        element_prefix = (
            f"{prefix}[{index + 1}]"
            if prefix
            else f"[{index + 1}]"
        )

        element_result, offset = decode_node(
            element,
            payload,
            offset,
            element_prefix,
            context
        )

        decoded.update(
            element_result
        )

    return (
        decoded,
        offset
    )


# ============================================================
# DECODE MIXED
# ============================================================

def decode_mixed(
    node,
    payload,
    offset,
    prefix,
    context
):

    decoded = {}

    blocks = node.get(
        "blocks",
        []
    )

    # ========================================================
    # DECODE BLOCKS SEQUENTIALLY
    # ========================================================
    #
    # Example:
    #
    # mixed
    #   |
    #   +-- struct
    #   |
    #   +-- array
    #   |
    #   +-- struct
    #   |
    #   +-- array
    #
    # ========================================================

    for block in blocks:

        block_name = block.get(
            "name"
        )

        if block_name:

            block_prefix = (
                f"{prefix}.{block_name}"
                if prefix
                else block_name
            )

        else:

            block_prefix = prefix

        block_result, offset = decode_node(
            block,
            payload,
            offset,
            block_prefix,
            context
        )

        decoded.update(
            block_result
        )

    return (
        decoded,
        offset
    )


# ============================================================
# DECODE ANY ICD NODE
# ============================================================

def decode_node(
    node,
    payload,
    offset,
    prefix,
    context
):

    node_type = node.get(
        "type"
    )

    # ========================================================
    # PRIMITIVE
    # ========================================================

    if (
        node_type in TYPE_INFO
        or node_type == "bytes"
    ):

        value, offset = decode_primitive(
            payload,
            offset,
            node
        )

        name = node.get(
            "name"
        )

        if name:

            full_name = (
                f"{prefix}.{name}"
                if prefix
                else name
            )

        else:

            full_name = prefix

        return (
            {
                full_name: value
            },
            offset
        )

    # ========================================================
    # STRUCT
    # ========================================================

    if node_type == "struct":

        return decode_struct(
            node,
            payload,
            offset,
            prefix,
            context
        )

    # ========================================================
    # ARRAY
    # ========================================================

    if (
        node_type == "array"
        or node_type == "dynamic_array"
    ):

        return decode_array(
            node,
            payload,
            offset,
            prefix,
            context
        )

    # ========================================================
    # MIXED
    # ========================================================

    if node_type == "mixed":

        return decode_mixed(
            node,
            payload,
            offset,
            prefix,
            context
        )

    raise ValueError(
        f"Unsupported ICD node type "
        f"'{node_type}'"
    )


# ============================================================
# DECODE PAYLOAD
# ============================================================

def decode_payload(
    opcode,
    payload
):

    # ========================================================
    # UNKNOWN OPCODE
    # ========================================================

    if opcode not in ICDS:

        return {

            "decode_status":
                "UNKNOWN_OPCODE",

            "raw_payload":
                payload.hex()
        }

    decoded = {

        "decode_status":
            "OK"
    }

    icd = ICDS[
        opcode
    ]

    # ========================================================
    # CONTEXT
    # ========================================================
    #
    # Context stores values that can be used by:
    #
    # count_from
    #
    # Example:
    #
    # num_targets = 2
    #
    # Target count becomes 2.
    #
    # ========================================================

    context = {}

    offset = 0

    try:

        # ----------------------------------------------------
        # Backward compatibility:
        #
        # Old format:
        #
        # 104: [
        #     {...},
        #     {...}
        # ]
        #
        # Automatically convert to struct.
        # ----------------------------------------------------

        if isinstance(
            icd,
            list
        ):

            icd = {

                "type": "struct",

                "fields": icd
            }

        # ----------------------------------------------------
        # Decode root node
        # ----------------------------------------------------

        decoded_values, offset = decode_node(
            icd,
            payload,
            offset,
            "",
            context
        )

        decoded.update(
            decoded_values
        )

        # ====================================================
        # REMAINING BYTES
        # ====================================================

        if offset < len(
            payload
        ):

            decoded[
                "remaining_bytes"
            ] = payload[
                offset:
            ].hex()

        else:

            decoded[
                "remaining_bytes"
            ] = ""

    except Exception as exc:

        decoded[
            "decode_status"
        ] = "DECODE_ERROR"

        decoded[
            "decode_error"
        ] = str(exc)

    return decoded


# ============================================================
# FORMAT TIMESTAMP
# ============================================================

def format_timestamp(
    timestamp
):

    if timestamp is None:

        return ""

    try:

        return datetime.fromtimestamp(
            timestamp
        ).strftime(
            "%Y-%m-%d %H:%M:%S.%f"
        )

    except Exception:

        return ""


# ============================================================
# PROCESS ONE PACKET
# ============================================================

def process_packet(
    packet_number,
    packet_info
):

    raw_packet = packet_info[
        "data"
    ]

    timestamp = packet_info[
        "timestamp"
    ]

    result = {

        "packet_number":
            packet_number,

        "timestamp":
            format_timestamp(
                timestamp
            ),

        "pcap_packet_size":
            len(raw_packet)
    }

    try:

        # ====================================================
        # EXTRACT APPLICATION DATA
        # ====================================================

        custom_data = (
            extract_custom_data(
                raw_packet
            )
        )

        result[
            "custom_data_size"
        ] = len(custom_data)

        # ====================================================
        # PARSE 16-BYTE HEADER
        # ====================================================

        (
            header,
            opcode,
            packet_size,
            payload_size
        ) = parse_header(
            custom_data
        )

        # ====================================================
        # HEADER INFORMATION
        # ====================================================

        result[
            "header_hex"
        ] = header.hex()

        result[
            "opcode"
        ] = opcode

        result[
            "packet_size"
        ] = packet_size

        result[
            "payload_size"
        ] = payload_size

        # ====================================================
        # CHECK COMPLETE PACKET
        # ====================================================

        required_size = (
            HEADER_SIZE +
            payload_size
        )

        if len(custom_data) < (
            required_size
        ):

            result[
                "decode_status"
            ] = "INCOMPLETE_PACKET"

            result[
                "error"
            ] = (
                f"Header says packet requires "
                f"{required_size} bytes, "
                f"but only "
                f"{len(custom_data)} bytes "
                f"were saved."
            )

            return result

        # ====================================================
        # EXTRACT PAYLOAD
        # ====================================================

        payload_start = (
            HEADER_SIZE
        )

        payload_end = (
            HEADER_SIZE +
            payload_size
        )

        payload = custom_data[
            payload_start:
            payload_end
        ]

        result[
            "payload_hex"
        ] = payload.hex()

        # ====================================================
        # DECODE USING ICD
        # ====================================================

        decoded = decode_payload(
            opcode,
            payload
        )

        result.update(
            decoded
        )

        return result

    except Exception as exc:

        result[
            "decode_status"
        ] = "ERROR"

        result[
            "error"
        ] = str(exc)

        return result


# ============================================================
# WRITE CSV
# ============================================================

def write_csv(
    results,
    csv_path
):

    # ========================================================
    # FIND ALL COLUMNS
    # ========================================================

    columns = []

    for result in results:

        for key in result:

            if key not in columns:

                columns.append(
                    key
                )

    # ========================================================
    # CREATE DIRECTORY
    # ========================================================

    directory = os.path.dirname(
        os.path.abspath(
            csv_path
        )
    )

    if directory:

        os.makedirs(
            directory,
            exist_ok=True
        )

    # ========================================================
    # WRITE CSV
    # ========================================================

    with open(
        csv_path,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=columns
        )

        writer.writeheader()

        for result in results:

            row = {}

            for column in columns:

                value = result.get(
                    column,
                    ""
                )

                # ------------------------------------------------
                # Convert arrays/lists to CSV text
                # ------------------------------------------------

                if isinstance(
                    value,
                    list
                ):

                    value = ",".join(
                        str(item)
                        for item in value
                    )

                row[
                    column
                ] = value

            writer.writerow(
                row
            )


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print("=" * 70)

    print(
        "OFFLINE PCAP / PCAPNG -> "
        "RECURSIVE ICD -> CSV"
    )

    print("=" * 70)

    # ========================================================
    # INPUT PCAP
    # ========================================================

    pcap_path = input(
        "\nEnter saved PCAP/PCAPNG file path: "
    ).strip()

    pcap_path = (
        pcap_path
        .strip('"')
        .strip("'")
    )

    # ========================================================
    # CHECK FILE
    # ========================================================

    if not os.path.isfile(
        pcap_path
    ):

        print()
        print(
            "ERROR: Input file does not exist."
        )

        return

    # ========================================================
    # OUTPUT CSV
    # ========================================================

    csv_path = input(
        "Enter CSV output file path: "
    ).strip()

    csv_path = (
        csv_path
        .strip('"')
        .strip("'")
    )

    if not csv_path:

        print()
        print(
            "ERROR: CSV path cannot be empty."
        )

        return

    # ========================================================
    # READ CAPTURE
    # ========================================================

    print()
    print(
        "Reading saved capture..."
    )

    try:

        packets = read_saved_capture(
            pcap_path
        )

    except Exception as exc:

        print()
        print(
            "ERROR reading capture:"
        )

        print(
            exc
        )

        return

    print(
        f"Packets found: "
        f"{len(packets)}"
    )

    # ========================================================
    # PROCESS PACKETS
    # ========================================================

    results = []

    successful = 0
    failed = 0

    print()
    print(
        "Extracting packets and "
        "decoding ICD..."
    )

    print(
        "-" * 70
    )

    for packet_number, packet_info in enumerate(
        packets,
        start=1
    ):

        result = process_packet(
            packet_number,
            packet_info
        )

        results.append(
            result
        )

        status = result.get(
            "decode_status",
            "ERROR"
        )

        opcode = result.get(
            "opcode",
            ""
        )

        payload_size = result.get(
            "payload_size",
            ""
        )

        # ====================================================
        # DISPLAY RESULT
        # ====================================================

        if status == "OK":

            successful += 1

            print(
                f"Packet {packet_number}: "
                f"Opcode={opcode}, "
                f"Payload={payload_size} bytes, "
                f"OK"
            )

        else:

            failed += 1

            print(
                f"Packet {packet_number}: "
                f"Opcode={opcode}, "
                f"Status={status}"
            )

            error = result.get(
                "decode_error"
            )

            if error:

                print(
                    f"    Error: {error}"
                )

            error = result.get(
                "error"
            )

            if error:

                print(
                    f"    Error: {error}"
                )

    # ========================================================
    # WRITE CSV
    # ========================================================

    print()
    print(
        "Writing CSV..."
    )

    try:

        write_csv(
            results,
            csv_path
        )

    except Exception as exc:

        print()
        print(
            "ERROR writing CSV:"
        )

        print(
            exc
        )

        return

    # ========================================================
    # SUMMARY
    # ========================================================

    print()
    print("=" * 70)

    print(
        "PROCESSING COMPLETE"
    )

    print("=" * 70)

    print(
        f"Input file : {pcap_path}"
    )

    print(
        f"Total      : {len(packets)}"
    )

    print(
        f"Decoded    : {successful}"
    )

    print(
        f"Failed     : {failed}"
    )

    print(
        f"CSV file   : {csv_path}"
    )

    print("=" * 70)


# ============================================================
# PROGRAM START
# ============================================================

if __name__ == "__main__":

    main()
