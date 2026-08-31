import struct
import csv
import os
from datetime import datetime, timezone


def read_u16(data, pos, endian):
    return struct.unpack(endian + "H", data[pos:pos + 2])[0]


def read_u32(data, pos, endian):
    return struct.unpack(endian + "I", data[pos:pos + 4])[0]


def mac_address(data):
    if len(data) < 6:
        return ""
    return ":".join(f"{x:02X}" for x in data[:6])


def ipv4_address(data):
    if len(data) < 4:
        return ""
    return ".".join(str(x) for x in data[:4])


def ipv6_address(data):
    if len(data) < 16:
        return ""
    parts = []
    for i in range(0, 16, 2):
        parts.append(f"{data[i]:02X}{data[i + 1]:02X}")
    return ":".join(parts)


def decode_packet(packet):
    result = {
        "Source_MAC": "",
        "Destination_MAC": "",
        "Source_IP": "",
        "Destination_IP": "",
        "Protocol": "",
        "Source_Port": "",
        "Destination_Port": "",
        "TCP_Flags": "",
        "Payload_Hex": ""
    }

    if len(packet) < 14:
        result["Payload_Hex"] = packet.hex()
        return result

    # Ethernet
    dst_mac = packet[0:6]
    src_mac = packet[6:12]

    result["Destination_MAC"] = mac_address(dst_mac)
    result["Source_MAC"] = mac_address(src_mac)

    ether_type = struct.unpack(">H", packet[12:14])[0]
    pos = 14

    # VLAN tags
    while ether_type in (0x8100, 0x88A8, 0x9100):

        if len(packet) < pos + 4:
            result["Payload_Hex"] = packet[pos:].hex()
            return result

        ether_type = struct.unpack(
            ">H", packet[pos + 2:pos + 4]
        )[0]

        pos += 4

    # IPv4
    if ether_type == 0x0800:

        if len(packet) >= pos + 20:

            version_ihl = packet[pos]
            ihl = (version_ihl & 0x0F) * 4

            if len(packet) >= pos + ihl:

                result["Source_IP"] = ipv4_address(
                    packet[pos + 12:pos + 16]
                )

                result["Destination_IP"] = ipv4_address(
                    packet[pos + 16:pos + 20]
                )

                protocol = packet[pos + 9]

                protocol_names = {
                    1: "ICMP",
                    6: "TCP",
                    17: "UDP"
                }

                result["Protocol"] = protocol_names.get(
                    protocol,
                    f"IP({protocol})"
                )

                transport = pos + ihl

                # TCP
                if protocol == 6 and len(packet) >= transport + 20:

                    src_port = struct.unpack(
                        ">H", packet[transport:transport + 2]
                    )[0]

                    dst_port = struct.unpack(
                        ">H", packet[transport + 2:transport + 4]
                    )[0]

                    result["Source_Port"] = src_port
                    result["Destination_Port"] = dst_port

                    flags = struct.unpack(
                        ">H", packet[transport + 12:transport + 14]
                    )[0] & 0x01FF

                    result["TCP_Flags"] = f"0x{flags:03X}"

                    data_offset = (
                        (packet[transport + 12] >> 4) * 4
                    )

                    payload_start = transport + data_offset

                    result["Payload_Hex"] = packet[
                        payload_start:
                    ].hex()

                    return result

                # UDP
                elif protocol == 17 and len(packet) >= transport + 8:

                    src_port = struct.unpack(
                        ">H", packet[transport:transport + 2]
                    )[0]

                    dst_port = struct.unpack(
                        ">H", packet[transport + 2:transport + 4]
                    )[0]

                    result["Source_Port"] = src_port
                    result["Destination_Port"] = dst_port

                    result["Payload_Hex"] = packet[
                        transport + 8:
                    ].hex()

                    return result

                else:

                    result["Payload_Hex"] = packet[
                        transport:
                    ].hex()

                    return result

    # IPv6
    elif ether_type == 0x86DD:

        if len(packet) >= pos + 40:

            result["Source_IP"] = ipv6_address(
                packet[pos + 8:pos + 24]
            )

            result["Destination_IP"] = ipv6_address(
                packet[pos + 24:pos + 40]
            )

            next_header = packet[pos + 6]

            protocol_names = {
                6: "TCP",
                17: "UDP",
                58: "ICMPv6"
            }

            result["Protocol"] = protocol_names.get(
                next_header,
                f"IPv6({next_header})"
            )

            transport = pos + 40

            # TCP
            if next_header == 6 and len(packet) >= transport + 20:

                result["Source_Port"] = struct.unpack(
                    ">H", packet[transport:transport + 2]
                )[0]

                result["Destination_Port"] = struct.unpack(
                    ">H", packet[transport + 2:transport + 4]
                )[0]

                data_offset = (
                    (packet[transport + 12] >> 4) * 4
                )

                result["TCP_Flags"] = (
                    f"0x{struct.unpack('>H', packet[transport+12:transport+14])[0] & 0x01FF:03X}"
                )

                result["Payload_Hex"] = packet[
                    transport + data_offset:
                ].hex()

                return result

            # UDP
            elif next_header == 17 and len(packet) >= transport + 8:

                result["Source_Port"] = struct.unpack(
                    ">H", packet[transport:transport + 2]
                )[0]

                result["Destination_Port"] = struct.unpack(
                    ">H", packet[transport + 2:transport + 4]
                )[0]

                result["Payload_Hex"] = packet[
                    transport + 8:
                ].hex()

                return result

            else:

                result["Payload_Hex"] = packet[
                    transport:
                ].hex()

                return result

    # Unknown/non-IP packet
    else:

        result["Protocol"] = f"EtherType(0x{ether_type:04X})"

        result["Payload_Hex"] = packet[pos:].hex()

        return result


def convert_pcapng(filename, output_file):

    with open(filename, "rb") as f:
        data = f.read()

    pos = 0

    endian = "<"

    interfaces = {}

    packet_number = 0

    rows = []

    while pos + 12 <= len(data):

        # Read block type first.
        raw_type = data[pos:pos + 4]

        if len(raw_type) < 4:
            break

        block_type_le = struct.unpack(
            "<I", raw_type
        )[0]

        block_type_be = struct.unpack(
            ">I", raw_type
        )[0]

        # Section Header Block
        if block_type_le == 0x0A0D0D0A:

            if pos + 12 > len(data):
                break

            magic = data[pos + 8:pos + 12]

            if magic == b"\x1A\x2B\x3C\x4D":
                endian = ">"

            elif magic == b"\x4D\x3C\x2B\x1A":
                endian = "<"

            else:
                pos += 4
                continue

            block_length = read_u32(
                data, pos + 4, endian
            )

            if block_length < 28:
                break

            if pos + block_length > len(data):
                break

            pos += block_length
            continue

        # Read block length
        block_length = read_u32(
            data, pos + 4, endian
        )

        if block_length < 12:
            break

        if pos + block_length > len(data):
            break

        block = data[pos:pos + block_length]

        # Interface Description Block
        if block_type_le == 0x00000001:

            interface_id = len(interfaces)

            link_type = read_u16(
                block, 8, endian
            )

            snaplen = read_u32(
                block, 12, endian
            )

            interfaces[interface_id] = {
                "link_type": link_type,
                "snaplen": snaplen
            }

        # Enhanced Packet Block
        elif block_type_le == 0x00000006:

            if len(block) >= 32:

                interface_id = read_u32(
                    block, 8, endian
                )

                timestamp_high = read_u32(
                    block, 12, endian
                )

                timestamp_low = read_u32(
                    block, 16, endian
                )

                captured_length = read_u32(
                    block, 20, endian
                )

                original_length = read_u32(
                    block, 24, endian
                )

                packet_start = 28

                packet_end = packet_start + captured_length

                if packet_end <= len(block) - 4:

                    packet = block[
                        packet_start:packet_end
                    ]

                    timestamp_value = (
                        (timestamp_high << 32)
                        | timestamp_low
                    )

                    # PCAPNG default timestamp resolution
                    timestamp_seconds = (
                        timestamp_value / 1_000_000
                    )

                    try:
                        timestamp = datetime.fromtimestamp(
                            timestamp_seconds,
                            timezone.utc
                        ).isoformat()
                    except Exception:
                        timestamp = str(timestamp_value)

                    decoded = decode_packet(packet)

                    packet_number += 1

                    rows.append([
                        packet_number,
                        interface_id,
                        timestamp,
                        captured_length,
                        original_length,
                        decoded["Source_MAC"],
                        decoded["Destination_MAC"],
                        decoded["Source_IP"],
                        decoded["Destination_IP"],
                        decoded["Protocol"],
                        decoded["Source_Port"],
                        decoded["Destination_Port"],
                        decoded["TCP_Flags"],
                        decoded["Payload_Hex"],
                        packet.hex()
                    ])

        # Legacy Packet Block
        elif block_type_le == 0x00000002:

            if len(block) >= 28:

                interface_id = read_u16(
                    block, 8, endian
                )

                timestamp_high = read_u32(
                    block, 12, endian
                )

                timestamp_low = read_u32(
                    block, 16, endian
                )

                captured_length = read_u32(
                    block, 20, endian
                )

                original_length = read_u32(
                    block, 24, endian
                )

                packet_start = 28

                packet_end = packet_start + captured_length

                if packet_end <= len(block) - 4:

                    packet = block[
                        packet_start:packet_end
                    ]

                    timestamp_value = (
                        (timestamp_high << 32)
                        | timestamp_low
                    )

                    timestamp_seconds = (
                        timestamp_value / 1_000_000
                    )

                    try:
                        timestamp = datetime.fromtimestamp(
                            timestamp_seconds,
                            timezone.utc
                        ).isoformat()
                    except Exception:
                        timestamp = str(timestamp_value)

                    decoded = decode_packet(packet)

                    packet_number += 1

                    rows.append([
                        packet_number,
                        interface_id,
                        timestamp,
                        captured_length,
                        original_length,
                        decoded["Source_MAC"],
                        decoded["Destination_MAC"],
                        decoded["Source_IP"],
                        decoded["Destination_IP"],
                        decoded["Protocol"],
                        decoded["Source_Port"],
                        decoded["Destination_Port"],
                        decoded["TCP_Flags"],
                        decoded["Payload_Hex"],
                        packet.hex()
                    ])

        pos += block_length

    # Write CSV
    with open(
        output_file,
        "w",
        newline="",
        encoding="utf-8"
    ) as f:

        writer = csv.writer(f)

        writer.writerow([
            "Packet_No",
            "Interface_ID",
            "Timestamp",
            "Captured_Length",
            "Original_Length",
            "Source_MAC",
            "Destination_MAC",
            "Source_IP",
            "Destination_IP",
            "Protocol",
            "Source_Port",
            "Destination_Port",
            "TCP_Flags",
            "Payload_Hex",
            "Complete_Packet_Hex"
        ])

        writer.writerows(rows)

    return packet_number


# =========================================================
# MAIN PROGRAM
# =========================================================

print("=" * 60)
print("PCAPNG TO CSV CONVERTER")
print("No external libraries required")
print("=" * 60)

pcapng_file = input(
    "\nEnter the full path of your PCAPNG file: "
).strip().strip('"')

if not os.path.isfile(pcapng_file):

    print("\nERROR: File not found.")
    input("\nPress Enter to exit...")
    raise SystemExit

default_csv = os.path.splitext(pcapng_file)[0] + ".csv"

answer = input(
    f"\nCSV output path [{default_csv}]: "
).strip().strip('"')

if answer:
    csv_file = answer
else:
    csv_file = default_csv

print("\nReading PCAPNG...")
print("Please wait...")

try:

    count = convert_pcapng(
        pcapng_file,
        csv_file
    )

    print("\n" + "=" * 60)
    print("CONVERSION COMPLETED")
    print("=" * 60)
    print("Packets captured :", count)
    print("CSV file         :", csv_file)

except Exception as e:

    print("\nERROR:")
    print(e)

input("\nPress Enter to exit...")
