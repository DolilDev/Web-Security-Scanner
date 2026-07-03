from __future__ import annotations

from .base import HeaderSecurityTest, TestResult, parse_directives
from ..registry import registry


class HSTSHeaderPresent(HeaderSecurityTest):
    id = "headers.hsts.present"
    severity = "high"

    async def run(self, target: object) -> TestResult:
        headers = await self.fetch_headers(target)
        if "strict-transport-security" in headers:
            return TestResult(id=self.id, status="pass", evidence="HSTS header present", severity=self.severity)
        return TestResult(id=self.id, status="fail", evidence="Missing Strict-Transport-Security header", recommendation="Add Strict-Transport-Security header", severity=self.severity)


class HSTSMaxAge(HeaderSecurityTest):
    id = "headers.hsts.max_age"
    severity = "high"

    async def run(self, target: object) -> TestResult:
        headers = await self.fetch_headers(target)
        value = headers.get("strict-transport-security", "")
        directives = parse_directives(value)
        max_age = directives.get("max-age")
        if max_age and max_age.isdigit() and int(max_age) >= 31536000:
            return TestResult(id=self.id, status="pass", evidence="HSTS max-age is at least 31536000", severity=self.severity)
        return TestResult(id=self.id, status="fail", evidence="HSTS max-age missing or too low", recommendation="Set max-age to at least 31536000", severity=self.severity)


class HSTSIncludeSubDomains(HeaderSecurityTest):
    id = "headers.hsts.include_subdomains"
    severity = "medium"

    async def run(self, target: object) -> TestResult:
        headers = await self.fetch_headers(target)
        value = headers.get("strict-transport-security", "")
        if "includesubdomains" in value.replace(" ", "").lower():
            return TestResult(id=self.id, status="pass", evidence="HSTS includesSubDomains present", severity=self.severity)
        return TestResult(id=self.id, status="warning", evidence="HSTS includeSubDomains missing", recommendation="Add includeSubDomains to HSTS", severity=self.severity)


class HSTSPreload(HeaderSecurityTest):
    id = "headers.hsts.preload"
    severity = "low"

    async def run(self, target: object) -> TestResult:
        headers = await self.fetch_headers(target)
        value = headers.get("strict-transport-security", "")
        if "preload" in value.lower():
            return TestResult(id=self.id, status="pass", evidence="HSTS preload present", severity=self.severity)
        return TestResult(id=self.id, status="warning", evidence="HSTS preload missing", recommendation="Consider adding preload to HSTS", severity=self.severity)


registry.register(HSTSHeaderPresent())
registry.register(HSTSMaxAge())
registry.register(HSTSIncludeSubDomains())
registry.register(HSTSPreload())
