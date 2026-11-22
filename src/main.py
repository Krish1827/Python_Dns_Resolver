import argparse
import os
import sys

# Support running `python src/main.py` directly from project root
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.packet import RECORD_TYPES
from src.resolver import DNSResolutionError, DNSResolver


def print_summary(domain: str, resolver: DNSResolver, bypass_cache: bool = False) -> None:
    try:
        outcomes = resolver.resolve_all(domain, use_cache=not bypass_cache)
    except DNSResolutionError as exc:
        print(f"\nResolution failed for '{domain}': {exc}\n")
        return

    ipv4 = [r for r in outcomes["A"].records if r.rtype == "A"]
    ipv6 = [r for r in outcomes["AAAA"].records if r.rtype == "AAAA"]
    cnames = [
        r for outcome in outcomes.values() for r in outcome.records if r.rtype == "CNAME"
    ]
    # Deduplicate CNAME records across queries
    seen_cnames = set()
    unique_cnames = []
    for c in cnames:
        if c.data not in seen_cnames:
            seen_cnames.add(c.data)
            unique_cnames.append(c)

    mx_records = outcomes["MX"].records
    ns_records = outcomes["NS"].records

    print("\nDNS Resolution Results")
    print("=" * 42)
    print(f"Domain: {domain}")

    if ipv4:
        for rec in ipv4:
            src = "CACHE" if outcomes["A"].from_cache else f"{outcomes['A'].transport}@{outcomes['A'].server}"
            print(f"IPv4:   {rec.data} (Record Type: A, TTL: {rec.ttl}s) [{src}]")
    else:
        print("IPv4:   None found")

    if ipv6:
        for rec in ipv6:
            src = "CACHE" if outcomes["AAAA"].from_cache else f"{outcomes['AAAA'].transport}@{outcomes['AAAA'].server}"
            print(f"IPv6:   {rec.data} (Record Type: AAAA, TTL: {rec.ttl}s) [{src}]")
    else:
        print("IPv6:   None found")

    if unique_cnames:
        for rec in unique_cnames:
            print(f"CNAME:  {rec.name} -> {rec.data} (TTL: {rec.ttl}s)")

    if mx_records:
        for rec in mx_records:
            print(f"MX:     {rec.data} (TTL: {rec.ttl}s)")

    if ns_records:
        for rec in ns_records:
            print(f"NS:     {rec.data} (TTL: {rec.ttl}s)")

    print("\nResolution successful.\n")


def print_single_type(domain: str, rtype: str, resolver: DNSResolver, bypass_cache: bool = False) -> None:
    try:
        outcome = resolver.resolve(domain, rtype=rtype, use_cache=not bypass_cache)
    except DNSResolutionError as exc:
        print(f"Resolution failed for '{domain}' ({rtype}): {exc}\n")
        return

    src = "CACHE" if outcome.from_cache else f"{outcome.transport}@{outcome.server}"
    print("\nDNS Resolution Results")
    print("=" * 42)
    print(f"Domain:      {outcome.domain}")
    print(f"Record Type: {outcome.rtype}")
    print(f"Source:      {src}")

    if not outcome.records:
        print("Records:     No records returned")
    else:
        for rec in outcome.records:
            print(f"  -> [{rec.rtype}] {rec.data} (TTL: {rec.ttl} seconds)")

    print("\nResolution successful.\n")


def interactive_loop(resolver: DNSResolver) -> None:
    print("Python DNS Resolver (RFC 1035 UDP/TCP)")
    print("Commands: enter a domain (e.g., google.com), 'stats' for cache stats, 'clear' to flush cache, or 'exit'\n")

    while True:
        try:
            raw = input("Enter domain: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break

        if not raw:
            continue
        if raw.lower() in ("exit", "quit", "q"):
            break
        if raw.lower() == "stats":
            print(f"Cache Stats: {resolver.cache.stats()}\n")
            continue
        if raw.lower() == "clear":
            resolver.cache.clear()
            print("DNS cache cleared.\n")
            continue

        parts = raw.split()
        domain = parts[0]
        if len(parts) > 1 and parts[1].upper() in RECORD_TYPES:
            print_single_type(domain, parts[1].upper(), resolver)
        else:
            print_summary(domain, resolver)


def main() -> None:
    parser = argparse.ArgumentParser(description="RFC 1035 DNS Resolver in Python")
    parser.add_argument("domain", nargs="?", help="Domain name to resolve (omit for interactive mode)")
    parser.add_argument(
        "-t", "--type",
        choices=list(RECORD_TYPES.keys()),
        help="Query a specific record type (A, AAAA, CNAME, MX, NS)",
    )
    parser.add_argument(
        "-s", "--server",
        default="8.8.8.8",
        help="Primary upstream DNS server IP (default: 8.8.8.8)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=2.5,
        help="Socket timeout in seconds (default: 2.5)",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Bypass the local TTL cache",
    )
    args = parser.parse_args()

    servers = [args.server] if args.server != "8.8.8.8" else ["8.8.8.8", "1.1.1.1"]
    resolver = DNSResolver(servers=servers, timeout=args.timeout)

    if args.domain:
        if args.type:
            print_single_type(args.domain, args.type, resolver, bypass_cache=args.no_cache)
        else:
            print_summary(args.domain, resolver, bypass_cache=args.no_cache)
    else:
        interactive_loop(resolver)


if __name__ == "__main__":
    main()
