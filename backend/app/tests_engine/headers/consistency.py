from __future__ import annotations

from .base import HeaderSecurityTest, TestResult
from ..registry import registry


class NoDuplicateHeaders(HeaderSecurityTest):
    id = "headers.no_duplicate_headers"
    severity = "low"

    async def run(self, target: object) -> TestResult:
        raw_headers = await self.fetch_raw_headers(target)
        dupes: dict[str, int] = {}
        for name, _value in raw_headers:
            dupes[name] = dupes.get(name, 0) + 1
        duplicates = [name for name, count in dupes.items() if count > 1]
        if not duplicates:
            return TestResult(id=self.id, status="pass", evidence="No duplicate headers detected", severity=self.severity)
        return TestResult(id=self.id, status="warning", evidence=f"Duplicate headers found: {', '.join(duplicates)}", recommendation="Remove duplicate response headers", severity=self.severity)


class HeaderConsistencyHTTPHTTPS(HeaderSecurityTest):
    id = "headers.consistency.http_https"
    severity = "info"

    async def run(self, target: object) -> TestResult:
        http_headers = await self.fetch_headers(target, scheme="http")
        https_headers = await self.fetch_headers(target, scheme="https")
        differences = [name for name in set(http_headers) | set(https_headers) if http_headers.get(name) != https_headers.get(name)]
        if not differences:
            return TestResult(id=self.id, status="pass", evidence="Security headers consistent between HTTP and HTTPS", severity=self.severity)
        return TestResult(id=self.id, status="warning", evidence="Security headers differ between HTTP and HTTPS", recommendation="Ensure header consistency across protocols", severity=self.severity)


registry.register(NoDuplicateHeaders())
registry.register(HeaderConsistencyHTTPHTTPS())
