from __future__ import annotations

from typing import Any

from .base import CookieSecurityTest, TestResult, parse_set_cookie
from ..registry import registry


class CookieFlagSecure(CookieSecurityTest):
    id = "cookies.secure"
    severity = "high"

    async def run(self, target: Any) -> TestResult:
        cookies = await self.fetch_cookies(target)
        if not cookies:
            return TestResult(id=self.id, status="skipped", evidence="No cookies found", severity=self.severity)
        failing = [cookie for cookie in cookies if "secure" not in cookie]
        if failing:
            return TestResult(id=self.id, status="fail", evidence=f"Cookies without Secure flag: {', '.join([c['name'] for c in failing])}", recommendation="Set Secure flag on cookies", severity=self.severity)
        return TestResult(id=self.id, status="pass", evidence="All cookies have Secure flag", severity=self.severity)


class CookieFlagHttpOnly(CookieSecurityTest):
    id = "cookies.httponly"
    severity = "high"

    async def run(self, target: Any) -> TestResult:
        cookies = await self.fetch_cookies(target)
        if not cookies:
            return TestResult(id=self.id, status="skipped", evidence="No cookies found", severity=self.severity)
        failing = [cookie for cookie in cookies if "httponly" not in cookie]
        if failing:
            return TestResult(id=self.id, status="fail", evidence=f"Cookies without HttpOnly flag: {', '.join([c['name'] for c in failing])}", recommendation="Set HttpOnly flag on cookies", severity=self.severity)
        return TestResult(id=self.id, status="pass", evidence="All cookies have HttpOnly flag", severity=self.severity)


class CookieSameSiteStrictOrLax(CookieSecurityTest):
    id = "cookies.same_site"
    severity = "high"

    async def run(self, target: Any) -> TestResult:
        cookies = await self.fetch_cookies(target)
        if not cookies:
            return TestResult(id=self.id, status="skipped", evidence="No cookies found", severity=self.severity)
        failing = [cookie for cookie in cookies if cookie.get("samesite", "").lower() not in {"strict", "lax"}]
        if failing:
            return TestResult(id=self.id, status="warning", evidence=f"Cookies with weak SameSite: {', '.join([c['name'] for c in failing])}", recommendation="Use SameSite=Strict or Lax", severity=self.severity)
        return TestResult(id=self.id, status="pass", evidence="All cookies use Strict or Lax SameSite", severity=self.severity)


class CookieSameSiteNoneSecure(CookieSecurityTest):
    id = "cookies.same_site_none_requires_secure"
    severity = "high"

    async def run(self, target: Any) -> TestResult:
        cookies = await self.fetch_cookies(target)
        if not cookies:
            return TestResult(id=self.id, status="skipped", evidence="No cookies found", severity=self.severity)
        failing = [cookie for cookie in cookies if cookie.get("samesite", "").lower() == "none" and "secure" not in cookie]
        if failing:
            return TestResult(id=self.id, status="fail", evidence=f"Cookies with SameSite=None missing Secure: {', '.join([c['name'] for c in failing])}", recommendation="Add Secure flag to SameSite=None cookies", severity=self.severity)
        return TestResult(id=self.id, status="pass", evidence="All SameSite=None cookies also have Secure flag", severity=self.severity)


class CookieSessionLifetime(CookieSecurityTest):
    id = "cookies.session_lifetime"
    severity = "medium"

    async def run(self, target: Any) -> TestResult:
        cookies = await self.fetch_cookies(target)
        if not cookies:
            return TestResult(id=self.id, status="skipped", evidence="No cookies found", severity=self.severity)
        failing = [cookie for cookie in cookies if cookie.get("expires") or cookie.get("max-age")]
        if failing:
            return TestResult(id=self.id, status="warning", evidence=f"Session cookies have persistent expiration: {', '.join([c['name'] for c in failing])}", recommendation="Avoid long-lived session cookie expiration", severity=self.severity)
        return TestResult(id=self.id, status="pass", evidence="Session cookies have no long-lived expiration", severity=self.severity)


class CookieSecurePrefix(CookieSecurityTest):
    id = "cookies.secure_prefix"
    severity = "low"

    async def run(self, target: Any) -> TestResult:
        cookies = await self.fetch_cookies(target)
        if not cookies:
            return TestResult(id=self.id, status="skipped", evidence="No cookies found", severity=self.severity)
        prefixed = [cookie for cookie in cookies if cookie["name"].startswith("__host-") or cookie["name"].startswith("__secure-")]
        if prefixed:
            return TestResult(id=self.id, status="pass", evidence=f"Cookies with secure prefix: {', '.join([c['name'] for c in prefixed])}", severity=self.severity)
        return TestResult(id=self.id, status="warning", evidence="No cookie prefixes __Host- or __Secure- found", recommendation="Use __Host- or __Secure- prefixes where applicable", severity=self.severity)


class CookieNameBackendFingerprint(CookieSecurityTest):
    id = "cookies.name_backend_fingerprint"
    severity = "medium"
    forbidden_names = {"phpsessid", "jsessionid", "aspnet_sessionid"}

    async def run(self, target: Any) -> TestResult:
        cookies = await self.fetch_cookies(target)
        if not cookies:
            return TestResult(id=self.id, status="skipped", evidence="No cookies found", severity=self.severity)
        leaking = [cookie for cookie in cookies if cookie["name"].lower() in self.forbidden_names]
        if leaking:
            return TestResult(id=self.id, status="warning", evidence=f"Cookies reveal backend type: {', '.join([c['name'] for c in leaking])}", recommendation="Avoid backend-identifying cookie names", severity=self.severity)
        return TestResult(id=self.id, status="pass", evidence="Cookie names do not expose backend technology", severity=self.severity)


class CookieDomainScope(CookieSecurityTest):
    id = "cookies.domain_scope"
    severity = "medium"

    async def run(self, target: Any) -> TestResult:
        cookies = await self.fetch_cookies(target)
        if not cookies:
            return TestResult(id=self.id, status="skipped", evidence="No cookies found", severity=self.severity)
        failing = [cookie for cookie in cookies if cookie.get("domain", "").startswith(".")]
        if failing:
            return TestResult(id=self.id, status="warning", evidence=f"Cookies have broad domain scope: {', '.join([c['name'] for c in failing])}", recommendation="Restrict cookie domain scope", severity=self.severity)
        return TestResult(id=self.id, status="pass", evidence="Cookie domain scope appears narrow", severity=self.severity)


class CookiePathScope(CookieSecurityTest):
    id = "cookies.path_scope"
    severity = "medium"

    async def run(self, target: Any) -> TestResult:
        cookies = await self.fetch_cookies(target)
        if not cookies:
            return TestResult(id=self.id, status="skipped", evidence="No cookies found", severity=self.severity)
        failing = [cookie for cookie in cookies if cookie.get("path", "/") == "/"]
        if failing:
            return TestResult(id=self.id, status="warning", evidence=f"Cookies use root path scope: {', '.join([c['name'] for c in failing])}", recommendation="Restrict cookie path scope", severity=self.severity)
        return TestResult(id=self.id, status="pass", evidence="Cookie path scope appears narrow", severity=self.severity)


class CookieSessionEntropy(CookieSecurityTest):
    id = "cookies.session_entropy"
    severity = "medium"

    async def run(self, target: Any) -> TestResult:
        cookies = await self.fetch_cookies(target)
        if not cookies:
            return TestResult(id=self.id, status="skipped", evidence="No cookies found", severity=self.severity)
        weak = [cookie for cookie in cookies if len(cookie.get("value", "")) < 16]
        if weak:
            return TestResult(id=self.id, status="warning", evidence=f"Cookies with low entropy value: {', '.join([c['name'] for c in weak])}", recommendation="Use longer random session identifiers", severity=self.severity)
        return TestResult(id=self.id, status="pass", evidence="Cookie values have sufficient length for entropy", severity=self.severity)


registry.register(CookieFlagSecure())
registry.register(CookieFlagHttpOnly())
registry.register(CookieSameSiteStrictOrLax())
registry.register(CookieSameSiteNoneSecure())
registry.register(CookieSessionLifetime())
registry.register(CookieSecurePrefix())
registry.register(CookieNameBackendFingerprint())
registry.register(CookieDomainScope())
registry.register(CookiePathScope())
registry.register(CookieSessionEntropy())
