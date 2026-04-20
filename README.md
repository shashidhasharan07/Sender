# Sender
import socket
import struct
import time
import random

GROUP = "239.1.1.1"
PORT = 5005

HEADER_FMT = "!BBBBIQB3x"

sock = socket.socket(
    socket.AF_INET,
    socket.SOCK_DGRAM,
    socket.IPPROTO_UDP
)

sock.setsockopt(
    socket.IPPROTO_IP,
    socket.IP_MULTICAST_TTL,
    1
)

sock.setsockopt(
    socket.IPPROTO_IP,
    socket.IP_MULTICAST_LOOP,
    1
)

counter = 0

print("Sender 101 → Multicast 5005")

while True:

    value = random.uniform(0, 100)

    payload = struct.pack(
        "!f",
        value
    )

    header = struct.pack(
        HEADER_FMT,
        counter & 0xFF,
        101,
        1,
        0,
        len(payload),
        int(time.time() * 1e6),
        1
    )

    sock.sendto(
        header + payload,
        (GROUP, PORT)
    )

    counter += 1

    time.sleep(0.02)
