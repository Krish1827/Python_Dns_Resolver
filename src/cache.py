import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from .packet import DNSRecord


@dataclass
class CacheEntry:
    records: List[DNSRecord]
    expires_at: float


class DNSCache:
    """In-memory TTL-aware DNS record cache."""

    def __init__(self) -> None:
        self._store: Dict[Tuple[str, str], CacheEntry] = {}
        self.hits = 0
        self.misses = 0

    @staticmethod
    def _key(domain: str, rtype: str) -> Tuple[str, str]:
        return (domain.strip().rstrip(".").lower(), rtype.upper())

    def get(self, domain: str, rtype: str) -> Optional[List[DNSRecord]]:
        key = self._key(domain, rtype)
        entry = self._store.get(key)
        if entry is None:
            self.misses += 1
            return None

        now = time.monotonic()
        if now >= entry.expires_at:
            del self._store[key]
            self.misses += 1
            return None

        self.hits += 1
        remaining_ttl = max(1, int(entry.expires_at - now))
        return [
            DNSRecord(
                name=rec.name,
                rtype=rec.rtype,
                rclass=rec.rclass,
                ttl=remaining_ttl,
                data=rec.data,
            )
            for rec in entry.records
        ]

    def set(self, domain: str, rtype: str, records: List[DNSRecord]) -> None:
        if not records:
            return
        min_ttl = min(rec.ttl for rec in records)
        if min_ttl <= 0:
            return
        key = self._key(domain, rtype)
        self._store[key] = CacheEntry(
            records=list(records),
            expires_at=time.monotonic() + min_ttl,
        )

    def clear(self) -> None:
        self._store.clear()

    def stats(self) -> Dict[str, int]:
        # Purge expired items before reporting size
        now = time.monotonic()
        expired = [k for k, v in self._store.items() if now >= v.expires_at]
        for k in expired:
            del self._store[k]
        return {
            "entries": len(self._store),
            "hits": self.hits,
            "misses": self.misses,
        }
