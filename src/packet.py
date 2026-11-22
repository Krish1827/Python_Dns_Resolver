import random
import socket
import struct
from dataclasses import dataclass
from typing import List, Tuple

RECORD_TYPES = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "MX": 15,
    "AAAA": 28,
}

TYPE_NAMES = {v: k for k, v in RECORD_TYPES.items()}

RCODE_MESSAGES = {
    0: "NOERROR",
    1: "FORMERR (Format Error)",
    2: "SERVFAIL (Server Failure)",
    3: "NXDOMAIN (Non-Existent Domain)",
    4: "NOTIMP (Not Implemented)",
    5: "REFUSED (Query Refused)",
}


@dataclass
class DNSRecord:
    name: str
    rtype: str
    rclass: int
    ttl: int
    data: str


@dataclass
class DNSResponse:
    transaction_id: int
    flags: int
    rcode: int
    truncated: bool
    answers: List[DNSRecord]
    authorities: List[DNSRecord]
    additionals: List[DNSRecord]


def encode_domain_name(domain: str) -> bytes:
    """Encodes a domain name into RFC 1035 length-prefixed labels terminated by 0x00."""
    domain = domain.strip().rstrip(".")
    if not domain:
        return b"\x00"
    parts = domain.split(".")
    encoded = bytearray()
    for label in parts:
        raw = label.encode("ascii")
        if len(raw) > 63:
            raise ValueError(f"DNS label exceeds 63 bytes: {label}")
        encoded.append(len(raw))
        encoded.extend(raw)
    encoded.append(0)
    return bytes(encoded)


def decode_domain_name(packet: bytes, offset: int) -> Tuple[str, int]:
    """Decodes a domain name from a DNS packet, following RFC 1035 compression pointers."""
    labels: List[str] = []
    jumped = False
    original_next_offset = offset
    visited_offsets = set()

    while True:
        if offset >= len(packet):
            raise ValueError("Malformed DNS packet: unexpected end of name")
        if offset in visited_offsets:
            raise ValueError("Malformed DNS packet: compression pointer loop detected")
        visited_offsets.add(offset)

        length = packet[offset]

        # Check top 2 bits for compression pointer (0b11000000 == 0xC0)
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(packet):
                raise ValueError("Malformed DNS packet: truncated compression pointer")
            pointer = ((length & 0x3F) << 8) | packet[offset + 1]
            if not jumped:
                original_next_offset = offset + 2
            offset = pointer
            jumped = True
            continue

        if length == 0:
            if not jumped:
                original_next_offset = offset + 1
            break

        offset += 1
        if offset + length > len(packet):
            raise ValueError("Malformed DNS packet: label extends past packet boundary")
        labels.append(packet[offset : offset + length].decode("ascii", errors="replace"))
        offset += length

    return ".".join(labels), original_next_offset


def build_query(domain: str, qtype_name: str, transaction_id: int | None = None) -> Tuple[int, bytes]:
    """Constructs a binary RFC 1035 DNS query packet with Recursion Desired (RD=1)."""
    qtype_upper = qtype_name.upper()
    if qtype_upper not in RECORD_TYPES:
        raise ValueError(f"Unsupported record type: {qtype_name}")

    tx_id = transaction_id if transaction_id is not None else random.randint(0, 65535)
    flags = 0x0100  # Standard query + Recursion Desired (RD)
    header = struct.pack("!HHHHHH", tx_id, flags, 1, 0, 0, 0)
    question = encode_domain_name(domain) + struct.pack("!HH", RECORD_TYPES[qtype_upper], 1)  # QCLASS=1 (IN)
    return tx_id, header + question


def _parse_rdata(packet: bytes, rtype_code: int, rdata_offset: int, rdlength: int) -> str:
    rdata = packet[rdata_offset : rdata_offset + rdlength]
    if rtype_code == 1 and rdlength == 4:  # A
        return socket.inet_ntop(socket.AF_INET, rdata)
    if rtype_code == 28 and rdlength == 16:  # AAAA
        return socket.inet_ntop(socket.AF_INET6, rdata)
    if rtype_code in (2, 5):  # NS, CNAME
        target, _ = decode_domain_name(packet, rdata_offset)
        return target
    if rtype_code == 15:  # MX
        if rdlength < 3:
            raise ValueError("Malformed MX record")
        preference = struct.unpack("!H", rdata[:2])[0]
        exchange, _ = decode_domain_name(packet, rdata_offset + 2)
        return f"{preference} {exchange}"
    return rdata.hex()


def _parse_records(packet: bytes, offset: int, count: int) -> Tuple[List[DNSRecord], int]:
    records: List[DNSRecord] = []
    for _ in range(count):
        name, offset = decode_domain_name(packet, offset)
        if offset + 10 > len(packet):
            raise ValueError("Malformed DNS resource record header")
        rtype_code, rclass, ttl, rdlength = struct.unpack("!HHIH", packet[offset : offset + 10])
        offset += 10
        if offset + rdlength > len(packet):
            raise ValueError("Malformed DNS resource record RDATA")
        rtype_name = TYPE_NAMES.get(rtype_code, f"TYPE{rtype_code}")
        data_str = _parse_rdata(packet, rtype_code, offset, rdlength)
        offset += rdlength
        records.append(DNSRecord(name=name, rtype=rtype_name, rclass=rclass, ttl=ttl, data=data_str))
    return records, offset


def parse_response(packet: bytes, expected_tx_id: int | None = None) -> DNSResponse:
    """Parses a binary DNS response packet into structured resource records."""
    if len(packet) < 12:
        raise ValueError("DNS response shorter than 12-byte header")

    tx_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", packet[:12])
    if expected_tx_id is not None and tx_id != expected_tx_id:
        raise ValueError(f"Transaction ID mismatch: expected {expected_tx_id}, got {tx_id}")

    qr = (flags >> 15) & 0x1
    if qr != 1:
        raise ValueError("Packet is not a DNS response (QR=0)")

    truncated = bool((flags >> 9) & 0x1)
    rcode = flags & 0x000F

    offset = 12
    for _ in range(qdcount):
        _, offset = decode_domain_name(packet, offset)
        offset += 4  # QTYPE (2) + QCLASS (2)

    answers, offset = _parse_records(packet, offset, ancount)
    authorities, offset = _parse_records(packet, offset, nscount)
    additionals, offset = _parse_records(packet, offset, arcount)

    return DNSResponse(
        transaction_id=tx_id,
        flags=flags,
        rcode=rcode,
        truncated=truncated,
        answers=answers,
        authorities=authorities,
        additionals=additionals,
    )
