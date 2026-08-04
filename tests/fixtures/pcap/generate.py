#!/usr/bin/env python3
"""Generate the pcap fixtures used by the Phase 1 decode and replay tests.

    python3 tests/fixtures/pcap/generate.py

Deterministic: fixed timestamps, fixed addresses, no randomness. Re-running it
must reproduce the committed files byte for byte, so a diff means someone
changed the test data on purpose.

Why Python rather than Rust: these files are *test data*, and half of them are
deliberately malformed. Building them here keeps packet-crafting code — and in
particular code that writes wrong length fields on purpose — out of the shipped
crates, where every parser is written to reject exactly this.

`normal.pcap` holds five well-formed conversations plus an ARP frame:

    1. TCP  192.0.2.10:51000 -> 198.51.100.20:80   full open, request,
       response, and a clean FIN teardown (7 packets)
    2. UDP  192.0.2.10:53124 -> 198.51.100.53:53   DNS query and reply
    3. ICMP 192.0.2.10       -> 198.51.100.20      echo request and reply
    4. TCP over IPv6, SYN only, left open
    5. TCP inside VLAN 100, SYN only, left open
    plus one ARP frame, which is ordinary traffic and starts no flow

`malformed.pcap` holds one frame per decoder anomaly. Every frame in it should
produce at least one anomaly and none should crash or hang the decoder.
"""

import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent

# A fixed, obviously-synthetic instant: 2024-01-01T00:00:00Z.
BASE_TIME = 1_704_067_200

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_ARP = 0x0806
ETHERTYPE_VLAN = 0x8100

CLIENT_MAC = bytes.fromhex("020000000001")
SERVER_MAC = bytes.fromhex("020000000002")

CLIENT_V4 = bytes([192, 0, 2, 10])
SERVER_V4 = bytes([198, 51, 100, 20])
DNS_V4 = bytes([198, 51, 100, 53])

CLIENT_V6 = bytes.fromhex("20010db8" + "00" * 11 + "10")
SERVER_V6 = bytes.fromhex("20010db8" + "00" * 11 + "20")

FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10


def checksum(data: bytes) -> int:
    """Standard 16-bit one's-complement checksum."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ethernet(dst: bytes, src: bytes, ethertype: int, payload: bytes) -> bytes:
    return dst + src + struct.pack("!H", ethertype) + payload


def vlan(vlan_id: int, inner_ethertype: int, payload: bytes) -> bytes:
    return struct.pack("!HH", vlan_id, inner_ethertype) + payload


def ipv4(
    src: bytes,
    dst: bytes,
    protocol: int,
    payload: bytes,
    *,
    total_len: int | None = None,
    ihl: int = 5,
    version: int = 4,
    break_checksum: bool = False,
    ident: int = 0x1234,
    flags_offset: int = 0,
) -> bytes:
    header = bytearray(20)
    header[0] = (version << 4) | ihl
    header[2:4] = struct.pack("!H", 20 + len(payload) if total_len is None else total_len)
    header[4:6] = struct.pack("!H", ident)
    header[6:8] = struct.pack("!H", flags_offset)
    header[8] = 64
    header[9] = protocol
    header[12:16] = src
    header[16:20] = dst
    value = checksum(bytes(header))
    if break_checksum:
        value ^= 0xFFFF
    header[10:12] = struct.pack("!H", value)
    return bytes(header) + payload


def ipv6(src: bytes, dst: bytes, next_header: int, payload: bytes) -> bytes:
    header = bytearray(40)
    header[0] = 0x60
    header[4:6] = struct.pack("!H", len(payload))
    header[6] = next_header
    header[7] = 64
    header[8:24] = src
    header[24:40] = dst
    return bytes(header) + payload


def tcp(
    sport: int,
    dport: int,
    seq: int,
    ack: int,
    flags: int,
    payload: bytes = b"",
    *,
    data_offset: int = 5,
) -> bytes:
    header = bytearray(20)
    header[0:2] = struct.pack("!H", sport)
    header[2:4] = struct.pack("!H", dport)
    header[4:8] = struct.pack("!I", seq)
    header[8:12] = struct.pack("!I", ack)
    header[12] = data_offset << 4
    header[13] = flags
    header[14:16] = struct.pack("!H", 64240)
    return bytes(header) + payload


def udp(sport: int, dport: int, payload: bytes, *, length: int | None = None) -> bytes:
    header = struct.pack(
        "!HHHH", sport, dport, 8 + len(payload) if length is None else length, 0
    )
    return header + payload


def icmp(icmp_type: int, code: int, payload: bytes) -> bytes:
    body = struct.pack("!BBHHH", icmp_type, code, 0, 0x0001, 0x0001) + payload
    value = checksum(body)
    return body[:2] + struct.pack("!H", value) + body[4:]


def arp() -> bytes:
    return struct.pack("!HHBBH", 1, ETHERTYPE_IPV4, 6, 4, 1) + (
        CLIENT_MAC + CLIENT_V4 + b"\x00" * 6 + SERVER_V4
    )


def write_pcap(path: Path, frames: list[tuple[float, bytes]], snaplen: int = 65535) -> None:
    """Write a little-endian, microsecond-resolution pcap savefile."""
    out = bytearray()
    out += struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, 1)
    for offset, frame in frames:
        seconds = BASE_TIME + int(offset)
        micros = int(round((offset - int(offset)) * 1_000_000))
        out += struct.pack("<IIII", seconds, micros, len(frame), len(frame))
        out += frame
    path.write_bytes(bytes(out))
    print(f"{path.name}: {len(frames)} frames, {len(out)} bytes")


def build_normal() -> list[tuple[float, bytes]]:
    frames: list[tuple[float, bytes]] = []

    def to_server(payload: bytes, ethertype: int = ETHERTYPE_IPV4) -> bytes:
        return ethernet(SERVER_MAC, CLIENT_MAC, ethertype, payload)

    def to_client(payload: bytes, ethertype: int = ETHERTYPE_IPV4) -> bytes:
        return ethernet(CLIENT_MAC, SERVER_MAC, ethertype, payload)

    # --- flow 1: a complete HTTP exchange over TCP -------------------------
    frames.append((0.0, to_server(ipv4(CLIENT_V4, SERVER_V4, 6, tcp(51000, 80, 1000, 0, SYN)))))
    frames.append((0.1, to_client(ipv4(SERVER_V4, CLIENT_V4, 6, tcp(80, 51000, 5000, 1001, SYN | ACK)))))
    frames.append((0.2, to_server(ipv4(CLIENT_V4, SERVER_V4, 6, tcp(51000, 80, 1001, 5001, ACK)))))

    request = b"GET /index.html HTTP/1.1\r\nHost: example.invalid\r\n\r\n"
    frames.append(
        (0.3, to_server(ipv4(CLIENT_V4, SERVER_V4, 6, tcp(51000, 80, 1001, 5001, PSH | ACK, request))))
    )
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"
    frames.append(
        (
            0.4,
            to_client(
                ipv4(SERVER_V4, CLIENT_V4, 6, tcp(80, 51000, 5001, 1001 + len(request), PSH | ACK, response))
            ),
        )
    )
    frames.append((0.5, to_server(ipv4(CLIENT_V4, SERVER_V4, 6, tcp(51000, 80, 1051, 5041, FIN | ACK)))))
    frames.append((0.6, to_client(ipv4(SERVER_V4, CLIENT_V4, 6, tcp(80, 51000, 5041, 1052, FIN | ACK)))))

    # --- flow 2: a DNS query and its reply ---------------------------------
    query = bytes.fromhex("abcd0100000100000000000003777777076578616d706c6507696e76616c696400000100 01")
    frames.append((1.0, ethernet(SERVER_MAC, CLIENT_MAC, ETHERTYPE_IPV4, ipv4(CLIENT_V4, DNS_V4, 17, udp(53124, 53, query)))))
    reply = query + bytes.fromhex("c00c000100010000003c0004c6336414")
    frames.append((1.1, ethernet(CLIENT_MAC, SERVER_MAC, ETHERTYPE_IPV4, ipv4(DNS_V4, CLIENT_V4, 17, udp(53, 53124, reply)))))

    # --- flow 3: ICMP echo, which has no ports -----------------------------
    frames.append((2.0, to_server(ipv4(CLIENT_V4, SERVER_V4, 1, icmp(8, 0, b"cybersentinel-ping")))))
    frames.append((2.1, to_client(ipv4(SERVER_V4, CLIENT_V4, 1, icmp(0, 0, b"cybersentinel-ping")))))

    # --- flow 4: TCP over IPv6, left open ----------------------------------
    frames.append(
        (3.0, to_server(ipv6(CLIENT_V6, SERVER_V6, 6, tcp(51001, 443, 1, 0, SYN)), ETHERTYPE_IPV6))
    )

    # --- flow 5: TCP inside VLAN 100, left open ----------------------------
    frames.append(
        (
            4.0,
            ethernet(
                SERVER_MAC,
                CLIENT_MAC,
                ETHERTYPE_VLAN,
                vlan(100, ETHERTYPE_IPV4, ipv4(CLIENT_V4, SERVER_V4, 6, tcp(51002, 8080, 1, 0, SYN))),
            ),
        )
    )

    # --- not a flow at all: ARP is ordinary traffic ------------------------
    frames.append((5.0, ethernet(b"\xff" * 6, CLIENT_MAC, ETHERTYPE_ARP, arp())))

    return frames


def build_malformed() -> list[tuple[float, bytes]]:
    frames: list[tuple[float, bytes]] = []

    def to_server(payload: bytes, ethertype: int = ETHERTYPE_IPV4) -> bytes:
        return ethernet(SERVER_MAC, CLIENT_MAC, ethertype, payload)

    good_tcp = tcp(51000, 80, 1, 0, SYN, b"payload")

    # 1. an empty frame
    frames.append((0.0, b""))
    # 2. an Ethernet header cut in half
    frames.append((0.1, b"\x02\x00\x00\x00\x00\x01\x02\x00"))
    # 3. IP version 7
    frames.append((0.2, to_server(ipv4(CLIENT_V4, SERVER_V4, 6, good_tcp, version=7))))
    # 4. IHL below the 5-word minimum
    frames.append((0.3, to_server(ipv4(CLIENT_V4, SERVER_V4, 6, good_tcp, ihl=3))))
    # 5. total_len shorter than the header it sits in
    frames.append((0.4, to_server(ipv4(CLIENT_V4, SERVER_V4, 6, good_tcp, total_len=12))))
    # 6. total_len overrunning a frame that was captured whole
    frames.append((0.5, to_server(ipv4(CLIENT_V4, SERVER_V4, 6, good_tcp, total_len=9000))))
    # 7. a header checksum that does not verify
    frames.append((0.6, to_server(ipv4(CLIENT_V4, SERVER_V4, 6, good_tcp, break_checksum=True))))
    # 8. a TCP data offset below the 5-word minimum
    frames.append(
        (0.7, to_server(ipv4(CLIENT_V4, SERVER_V4, 6, tcp(51000, 80, 1, 0, SYN, data_offset=0))))
    )
    # 9. a TCP data offset pointing past the end of the frame
    frames.append(
        (0.8, to_server(ipv4(CLIENT_V4, SERVER_V4, 6, tcp(51000, 80, 1, 0, SYN, data_offset=15))))
    )
    # 10. a TCP header cut short
    frames.append((0.9, to_server(ipv4(CLIENT_V4, SERVER_V4, 6, b"\x00" * 10))))
    # 11. a UDP length below its own header size
    frames.append((1.0, to_server(ipv4(CLIENT_V4, DNS_V4, 17, udp(53124, 53, b"payload", length=3)))))
    # 12. a UDP length overrunning a frame that was captured whole
    frames.append((1.1, to_server(ipv4(CLIENT_V4, DNS_V4, 17, udp(53124, 53, b"payload", length=4000)))))
    # 13. three stacked VLAN tags, one past QinQ
    frames.append(
        (
            1.2,
            ethernet(
                SERVER_MAC,
                CLIENT_MAC,
                ETHERTYPE_VLAN,
                vlan(1, ETHERTYPE_VLAN, vlan(2, ETHERTYPE_VLAN, vlan(3, ETHERTYPE_IPV4, ipv4(CLIENT_V4, SERVER_V4, 6, good_tcp)))),
            ),
        )
    )
    # 14. an IPv6 header cut short
    frames.append((1.3, to_server(b"\x60\x00\x00\x00\x00\x14\x06", ETHERTYPE_IPV6)))

    return frames


def main() -> None:
    write_pcap(HERE / "normal.pcap", build_normal())
    write_pcap(HERE / "malformed.pcap", build_malformed())


if __name__ == "__main__":
    main()
