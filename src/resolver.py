import socket
import struct
from dataclasses import dataclass
from typing import Dict, List, Optional
from .cache import DNSCache
from .packet import (
    DNSRecord,
    RCODE_MESSAGES,
    RECORD_TYPES,
    build_query,
    parse_response,
)


class DNSResolutionError(Exception):
    """Raised when DNS resolution fails due to network timeout, socket error, or RCODE error."""


@dataclass
class QueryOutcome:
    domain: str
    rtype: str
    records: List[DNSRecord]
    from_cache: bool
    transport: str
    server: str


class DNSResolver:
    """UDP/TCP DNS Resolver with TTL caching, CNAME following, and timeout failover."""

    def __init__(
        self,
        servers: Optional[List[str]] = None,
        port: int = 53,
        timeout: float = 2.5,
        cache: Optional[DNSCache] = None,
    ) -> None:
        self.servers = servers or ["8.8.8.8", "1.1.1.1"]
        self.port = port
        self.timeout = timeout
        self.cache = cache if cache is not None else DNSCache()

    def _send_udp(self, query_bytes: bytes, server: str) -> bytes:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(self.timeout)
            sock.sendto(query_bytes, (server, self.port))
            data, _ = sock.recvfrom(4096)
            return data

    def _send_tcp(self, query_bytes: bytes, server: str) -> bytes:
        framed = struct.pack("!H", len(query_bytes)) + query_bytes
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.timeout)
            sock.connect((server, self.port))
            sock.sendall(framed)

            length_prefix = self._recv_exact(sock, 2)
            resp_len = struct.unpack("!H", length_prefix)[0]
            return self._recv_exact(sock, resp_len)

    @staticmethod
    def _recv_exact(sock: socket.socket, num_bytes: int) -> bytes:
        buf = bytearray()
        while len(buf) < num_bytes:
            chunk = sock.recv(num_bytes - len(buf))
            if not chunk:
                raise ConnectionError("TCP connection closed prematurely by DNS server")
            buf.extend(chunk)
        return bytes(buf)

    def resolve(self, domain: str, rtype: str = "A", use_cache: bool = True) -> QueryOutcome:
        clean_domain = domain.strip().rstrip(".")
        qtype = rtype.upper()
        if not clean_domain:
            raise DNSResolutionError("Domain name cannot be empty.")
        if qtype not in RECORD_TYPES:
            raise DNSResolutionError(f"Unsupported record type '{qtype}'. Supported: {', '.join(RECORD_TYPES)}")

        if use_cache:
            cached_records = self.cache.get(clean_domain, qtype)
            if cached_records is not None:
                return QueryOutcome(
                    domain=clean_domain,
                    rtype=qtype,
                    records=cached_records,
                    from_cache=True,
                    transport="CACHE",
                    server="local-cache",
                )

        tx_id, query_bytes = build_query(clean_domain, qtype)
        last_error: Optional[Exception] = None

        for server in self.servers:
            try:
                transport = "UDP"
                raw_response = self._send_udp(query_bytes, server)
                parsed = parse_response(raw_response, expected_tx_id=tx_id)

                # RFC 1035: If truncated over UDP (TC=1), retry over TCP
                if parsed.truncated:
                    transport = "TCP"
                    raw_response = self._send_tcp(query_bytes, server)
                    parsed = parse_response(raw_response, expected_tx_id=tx_id)

                if parsed.rcode != 0:
                    rc_msg = RCODE_MESSAGES.get(parsed.rcode, f"RCODE {parsed.rcode}")
                    raise DNSResolutionError(f"DNS server {server} returned error: {rc_msg}")

                if use_cache and parsed.answers:
                    self.cache.set(clean_domain, qtype, parsed.answers)

                return QueryOutcome(
                    domain=clean_domain,
                    rtype=qtype,
                    records=parsed.answers,
                    from_cache=False,
                    transport=transport,
                    server=server,
                )
            except (socket.timeout, TimeoutError) as exc:
                last_error = DNSResolutionError(f"Timeout ({self.timeout}s) querying {server}")
            except OSError as exc:
                last_error = DNSResolutionError(f"Network error querying {server}: {exc}")
            except DNSResolutionError as exc:
                # Propagate authoritative NXDOMAIN immediately instead of failing over
                if "NXDOMAIN" in str(exc):
                    raise
                last_error = exc

        raise last_error or DNSResolutionError("All upstream DNS servers failed.")

    def resolve_all(self, domain: str, use_cache: bool = True) -> Dict[str, QueryOutcome]:
        """Queries A, AAAA, CNAME, MX, and NS records for a domain."""
        results: Dict[str, QueryOutcome] = {}
        for qtype in ("A", "AAAA", "CNAME", "MX", "NS"):
            results[qtype] = self.resolve(domain, qtype, use_cache=use_cache)
        return results
