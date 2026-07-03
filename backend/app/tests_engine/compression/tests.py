from __future__ import annotations

from typing import Any

from .base import CompressionSecurityTest, parse_vary_header, is_unsafe_etag
from ..registry import registry
from ..base import ScanContext, TestResult


class BREACHIndicator(CompressionSecurityTest):
    id = "compression.breach_indicator"
    severity = "high"

    async def run(self, target: ScanContext) -> TestResult:
        response = await self.get_response(target)
        if "content-encoding" in response.headers and "gzip" in response.headers["content-encoding"].lower():
            return TestResult(id=self.id, status="warning", evidence="Compression enabled on response", recommendation="Review BREACH risk for reflected content", severity=self.severity)
        return TestResult(id=self.id, status="pass", evidence="Compression not enabled or not gzip", severity=self.severity)


class CompressionConfig(CompressionSecurityTest):
    id = "compression.config"
    severity = "medium"

    async def run(self, target: ScanContext) -> TestResult:
        response = await self.get_response(target)
        encoding = response.headers.get("content-encoding", "").lower()
        if encoding in {"gzip", "br"}:
            return TestResult(id=self.id, status="pass", evidence=f"Compression enabled via {encoding}", severity=self.severity)
        return TestResult(id=self.id, status="warning", evidence="Compression not enabled", recommendation="Enable gzip or brotli compression where appropriate", severity=self.severity)


class CachePoisoning(CompressionSecurityTest):
    id = "cache.poisoning"
    severity = "medium"

    async def run(self, target: ScanContext) -> TestResult:
        response = await self.get_response(target)
        vary = response.headers.get("vary", "")
        if "accept-encoding" not in vary.lower():
            return TestResult(id=self.id, status="warning", evidence="Vary header missing Accept-Encoding", recommendation="Include Accept-Encoding in Vary header", severity=self.severity)
        return TestResult(id=self.id, status="pass", evidence="Vary header includes Accept-Encoding", severity=self.severity)


class VaryHeaderConfigured(CompressionSecurityTest):
    id = "cache.vary"
    severity = "low"

    async def run(self, target: ScanContext) -> TestResult:
        response = await self.get_response(target)
        if "vary" in response.headers:
            return TestResult(id=self.id, status="pass", evidence="Vary header present", severity=self.severity)
        return TestResult(id=self.id, status="warning", evidence="Vary header missing", recommendation="Add Vary header", severity=self.severity)


class ETagSafe(CompressionSecurityTest):
    id = "cache.etag"
    severity = "low"

    async def run(self, target: ScanContext) -> TestResult:
        response = await self.get_response(target)
        etag = response.headers.get("etag", "")
        if etag and not is_unsafe_etag(etag):
            return TestResult(id=self.id, status="pass", evidence="ETag appears safe", severity=self.severity)
        return TestResult(id=self.id, status="warning", evidence="ETag may expose file version info", recommendation="Use opaque ETag values", severity=self.severity)


class StaleWhileRevalidate(CompressionSecurityTest):
    id = "cache.stale_while_revalidate"
    severity = "low"

    async def run(self, target: ScanContext) -> TestResult:
        response = await self.get_response(target)
        cache_control = response.headers.get("cache-control", "").lower()
        if "stale-while-revalidate" in cache_control:
            return TestResult(id=self.id, status="pass", evidence="stale-while-revalidate configured", severity=self.severity)
        return TestResult(id=self.id, status="warning", evidence="stale-while-revalidate not configured", recommendation="Consider setting stale-while-revalidate", severity=self.severity)


class ApiNoSensitiveCache(CompressionSecurityTest):
    id = "cache.api_sensitive"
    severity = "high"

    async def run(self, target: ScanContext) -> TestResult:
        response = await self.get_response(target)
        cache_control = response.headers.get("cache-control", "").lower()
        if "no-store" in cache_control or "private" in cache_control:
            return TestResult(id=self.id, status="pass", evidence="Sensitive API cache-control set", severity=self.severity)
        return TestResult(id=self.id, status="warning", evidence="Sensitive API response may be cached", recommendation="Use no-store or private for sensitive endpoints", severity=self.severity)


class CDNNoSensitiveCache(CompressionSecurityTest):
    id = "cache.cdn_sensitive"
    severity = "low"

    async def run(self, target: ScanContext) -> TestResult:
        response = await self.get_response(target)
        cache_control = response.headers.get("cache-control", "").lower()
        if "no-store" in cache_control or "private" in cache_control:
            return TestResult(id=self.id, status="pass", evidence="Sensitive content not cached publicly", severity=self.severity)
        return TestResult(id=self.id, status="warning", evidence="CDN may cache sensitive content", recommendation="Use no-store/private for sensitive resources", severity=self.severity)


registry.register(BREACHIndicator())
registry.register(CompressionConfig())
registry.register(CachePoisoning())
registry.register(VaryHeaderConfigured())
registry.register(ETagSafe())
registry.register(StaleWhileRevalidate())
registry.register(ApiNoSensitiveCache())
registry.register(CDNNoSensitiveCache())
