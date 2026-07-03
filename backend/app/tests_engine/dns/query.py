from __future__ import annotations

from typing import Any
import dns.asyncresolver
import dns.asyncquery
import dns.resolver
import dns.name
import dns.exception


class DNSQueryClient:
    def __init__(self, nameserver: str | None = None) -> None:
        self.resolver = dns.asyncresolver.Resolver()
        if nameserver:
            self.resolver.nameservers = [nameserver]

    async def query(self, domain: str, record_type: str) -> list[Any]:
        try:
            answer = await self.resolver.resolve(domain, record_type)
            return [rdata for rdata in answer]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
            return []

    async def query_dnssec(self, domain: str) -> bool:
        try:
            response = await self.resolver.resolve(domain, "DNSKEY")
            return bool(response)
        except Exception:
            return False

    async def zone_transfer_allowed(self, domain: str) -> bool:
        try:
            name = dns.name.from_text(domain)
            answer = await dns.asyncquery.xfr(self.resolver.nameservers[0], name)
            return bool(answer)
        except Exception:
            return False
