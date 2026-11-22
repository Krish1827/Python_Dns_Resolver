import socket
import struct
import time
import unittest
from unittest.mock import patch

from src.cache import DNSCache
from src.packet import (
    DNSRecord,
    build_query,
    decode_domain_name,
    encode_domain_name,
    parse_response,
)
from src.resolver import DNSResolutionError, DNSResolver


class TestDNSPacketAndCache(unittest.TestCase):
    def test_encode_and_decode_domain_name(self):
        encoded = encode_domain_name("www.google.com")
        self.assertEqual(encoded, b"\x03www\x06google\x03com\x00")
        decoded, next_offset = decode_domain_name(encoded, 0)
        self.assertEqual(decoded, "www.google.com")
        self.assertEqual(next_offset, len(encoded))

    def test_decode_compression_pointer(self):
        # Packet with "google.com" at offset 12 and pointer (0xC00C) at offset 24
        header = b"\x00" * 12
        name_bytes = b"\x06google\x03com\x00"  # length 12 (offsets 12..23)
        pointer_bytes = b"\x03www\xc0\x0c"
        packet = header + name_bytes + pointer_bytes
        decoded, next_offset = decode_domain_name(packet, 24)
        self.assertEqual(decoded, "www.google.com")
        self.assertEqual(next_offset, 30)

    def test_build_and_parse_a_record_response(self):
        tx_id, query = build_query("example.com", "A", transaction_id=0x1234)
        self.assertEqual(tx_id, 0x1234)

        # Construct mock response: Header (QR=1, RD=1, RA=1, QD=1, AN=1) + Question + Answer
        resp_header = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
        question = query[12:]
        # Answer: pointer to offset 12 (0xC00C), TYPE A (1), CLASS IN (1), TTL 300, RDLENGTH 4, IP 93.184.216.34
        answer = struct.pack("!HHHIH", 0xC00C, 1, 1, 300, 4) + socket.inet_aton("93.184.216.34")
        raw_resp = resp_header + question + answer

        parsed = parse_response(raw_resp, expected_tx_id=0x1234)
        self.assertEqual(parsed.rcode, 0)
        self.assertFalse(parsed.truncated)
        self.assertEqual(len(parsed.answers), 1)
        self.assertEqual(parsed.answers[0].name, "example.com")
        self.assertEqual(parsed.answers[0].rtype, "A")
        self.assertEqual(parsed.answers[0].ttl, 300)
        self.assertEqual(parsed.answers[0].data, "93.184.216.34")

    def test_ttl_cache_hit_and_expiration(self):
        cache = DNSCache()
        rec = DNSRecord(name="example.com", rtype="A", rclass=1, ttl=1, data="93.184.216.34")
        cache.set("example.com", "A", [rec])

        hit = cache.get("EXAMPLE.COM", "a")
        self.assertIsNotNone(hit)
        self.assertEqual(hit[0].data, "93.184.216.34")

        time.sleep(1.05)
        expired = cache.get("example.com", "A")
        self.assertIsNone(expired)

    def test_timeout_handling(self):
        resolver = DNSResolver(servers=["192.0.2.1"], timeout=0.1)
        with patch.object(resolver, "_send_udp", side_effect=socket.timeout("timed out")):
            with self.assertRaises(DNSResolutionError) as ctx:
                resolver.resolve("example.com", "A", use_cache=False)
            self.assertIn("Timeout", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
