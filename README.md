# Python DNS Resolver (RFC 1035 Wire-Protocol Implementation)

A pure-Python, zero-dependency DNS resolver built directly on raw **UDP and TCP sockets** (`socket` + `struct`), implementing binary DNS packet encoding/decoding per **RFC 1035** and **RFC 3596**.

## Features
- **Record Types:** `A` (IPv4), `AAAA` (IPv6), `CNAME` (canonical alias), `MX` (mail exchangers with preference), and `NS` (authoritative nameservers)
- **RFC 1035 Compression Pointer Decoding:** Handles recursive DNS name compression (`0xC0` pointers) across all resource record sections
- **UDP with Automatic TCP Fallback:** Queries over UDP (`port 53`) and automatically retries over TCP when the `TC` (Truncated) flag is set
- **TTL-Aware In-Memory Cache:** Caches responses keyed by `(domain, record_type)`, decrements remaining TTL in real time, and evicts expired entries automatically
- **Timeout & Upstream Failover:** Configurable socket timeouts with automatic fallback across upstream resolvers (e.g., `8.8.8.8`, `1.1.1.1`)
- **Interactive CLI & Single-Query Mode:** Supports both interactive prompt loops and one-shot CLI flags

## Quick Start (Zero External Dependencies)
```bash
# Interactive mode
python src/main.py

# Single domain lookup (queries A, AAAA, CNAME, MX, NS)
python src/main.py google.com

# Query a specific record type with custom upstream server and timeout
python src/main.py github.com --type MX --server 1.1.1.1 --timeout 2.0

# Run unit & packet-parsing tests
python -m unittest discover -s tests -v
```
