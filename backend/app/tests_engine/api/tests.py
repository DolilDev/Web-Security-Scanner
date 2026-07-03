from __future__ import annotations

import httpx

from ..base import ScanContext, SecurityTest, TestResult
from ..registry import registry


class APISecurityTest(SecurityTest):
    category = "CORS and API Security"

    async def request(self, url: str, method: str = "GET", headers: dict[str, str] | None = None) -> httpx.Response:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            return await client.request(method, url, headers=headers or {})


class CORSAllowAll(APISecurityTest):
    id = "api.cors_allow_all"
    severity = "high"

    async def run(self, target: ScanContext) -> TestResult:
        response = await self.request(target.target)
        origin = response.headers.get("access-control-allow-origin", "")
        if origin == "*":
            return TestResult(id=self.id, status="fail", evidence="CORS Access-Control-Allow-Origin is set to '*'", recommendation="Restrict allowed origins", severity=self.severity)
        return TestResult(id=self.id, status="pass", evidence="CORS origin is not wildcard or is absent", severity=self.severity)


class CORSAllowCredentialsWithWildcard(APISecurityTest):
    id = "api.cors_credentials_wildcard"
    severity = "high"

    async def run(self, target: ScanContext) -> TestResult:
        response = await self.request(target.target)
        origin = response.headers.get("access-control-allow-origin", "")
        credentials = response.headers.get("access-control-allow-credentials", "").lower()
        if origin == "*" and credentials == "true":
            return TestResult(id=self.id, status="fail", evidence="CORS allows credentials with wildcard origin", recommendation="Do not combine Access-Control-Allow-Origin '*' with credentials", severity=self.severity)
        return TestResult(id=self.id, status="pass", evidence="CORS credential usage appears acceptable", severity=self.severity)


class CORSAllowPrivateNetwork(APISecurityTest):
    id = "api.cors_private_network"
    severity = "medium"

    async def run(self, target: ScanContext) -> TestResult:
        response = await self.request(target.target)
        if "access-control-request-private-network" in response.headers:
            return TestResult(id=self.id, status="warning", evidence="Access-Control-Request-Private-Network header present", recommendation="Review CORS private network handling", severity=self.severity)
        return TestResult(id=self.id, status="pass", evidence="No private network CORS header observed", severity=self.severity)


class CORSPreflightCache(APISecurityTest):
    id = "api.cors_preflight_cache"
    severity = "low"

    async def run(self, target: ScanContext) -> TestResult:
        response = await self.request(target.target, method="OPTIONS", headers={"Origin": "https://example.com", "Access-Control-Request-Method": "GET"})
        max_age = response.headers.get("access-control-max-age")
        if max_age is not None and max_age.isdigit() and int(max_age) > 0:
            return TestResult(id=self.id, status="pass", evidence=f"CORS preflight caching enabled ({max_age}s)", severity=self.severity)
        return TestResult(id=self.id, status="info", evidence="CORS preflight caching not configured or unsupported", severity=self.severity)


class JSONContentTypeStrict(APISecurityTest):
    id = "api.json_content_type"
    severity = "medium"

    async def run(self, target: ScanContext) -> TestResult:
        response = await self.request(target.target)
        content_type = response.headers.get("content-type", "").lower()
        if "application/json" in content_type:
            return TestResult(id=self.id, status="pass", evidence="Response content-type indicates JSON", severity=self.severity)
        return TestResult(id=self.id, status="warning", evidence="Response content-type is not JSON", recommendation="Use explicit application/json for APIs", severity=self.severity)


class APIErrorLeakage(APISecurityTest):
    id = "api.error_leakage"
    severity = "medium"

    async def run(self, target: ScanContext) -> TestResult:
        response = await self.request(target.target)
        body = response.text.lower()
        if "stack trace" in body or "exception" in body or "traceback" in body:
            return TestResult(id=self.id, status="warning", evidence="Potential server error information disclosed", recommendation="Avoid leaking internal error details", severity=self.severity)
        return TestResult(id=self.id, status="pass", evidence="No obvious server error details leaked", severity=self.severity)


registry.register(CORSAllowAll())
registry.register(CORSAllowCredentialsWithWildcard())
registry.register(CORSAllowPrivateNetwork())
registry.register(CORSPreflightCache())
registry.register(JSONContentTypeStrict())
registry.register(APIErrorLeakage())
