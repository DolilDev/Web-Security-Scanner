from __future__ import annotations

import re

import httpx

from ..base import ScanContext, SecurityTest, TestResult
from ..registry import registry


class PrivacySecurityTest(SecurityTest):
    category = "Privacy and Compliance"

    async def request(self, url: str) -> httpx.Response:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            return await client.get(url)


class PrivacyPolicyPresent(PrivacySecurityTest):
    id = "privacy.policy_present"
    severity = "medium"

    async def run(self, target: ScanContext) -> TestResult:
        candidates = ["/privacy", "/privacy.html", "/privacy-policy", "/privacy-policy.html"]
        for path in candidates:
            url = target.target.rstrip("/") + path
            try:
                resp = await self.request(url)
                if resp.status_code == 200 and len(resp.text) > 100:
                    return TestResult(id=self.id, status="pass", evidence=f"Privacy policy found at {url}", severity=self.severity)
            except Exception:
                continue
        return TestResult(id=self.id, status="warning", evidence="Privacy policy not discovered on common paths", recommendation="Provide a privacy policy page", severity=self.severity)


class SecurityTxtPresent(PrivacySecurityTest):
    id = "privacy.security_txt"
    severity = "low"

    async def run(self, target: ScanContext) -> TestResult:
        url = target.target.rstrip("/") + "/.well-known/security.txt"
        try:
            resp = await self.request(url)
            if resp.status_code == 200 and "contact:" in resp.text.lower():
                return TestResult(id=self.id, status="pass", evidence="security.txt present", severity=self.severity)
            return TestResult(id=self.id, status="info", evidence="security.txt not present or incomplete", severity=self.severity)
        except Exception as exc:
            return TestResult(id=self.id, status="error", evidence=str(exc), severity=self.severity)


class CookieConsentBanner(PrivacySecurityTest):
    id = "privacy.cookie_consent"
    severity = "medium"

    async def run(self, target: ScanContext) -> TestResult:
        try:
            resp = await self.request(target.target)
            body = resp.text.lower()
            if "cookie" in body and ("consent" in body or "accept" in body or "reject" in body):
                return TestResult(id=self.id, status="pass", evidence="Cookie consent UI detected", severity=self.severity)
            return TestResult(id=self.id, status="warning", evidence="No clear cookie consent UI detected", recommendation="Implement explicit cookie consent for privacy compliance", severity=self.severity)
        except Exception as exc:
            return TestResult(id=self.id, status="error", evidence=str(exc), severity=self.severity)


class PIIExposure(PrivacySecurityTest):
    id = "privacy.pii_exposure"
    severity = "high"

    email_re = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")

    async def run(self, target: ScanContext) -> TestResult:
        try:
            resp = await self.request(target.target)
            emails = set(self.email_re.findall(resp.text))
            if emails:
                return TestResult(id=self.id, status="warning", evidence=f"Potential PII (email addresses) found: {', '.join(list(emails)[:5])}", recommendation="Avoid leaking PII in public pages", severity=self.severity)
            return TestResult(id=self.id, status="pass", evidence="No obvious PII detected on root page", severity=self.severity)
        except Exception as exc:
            return TestResult(id=self.id, status="error", evidence=str(exc), severity=self.severity)


class DataRetentionNotice(PrivacySecurityTest):
    id = "privacy.data_retention"
    severity = "info"

    async def run(self, target: ScanContext) -> TestResult:
        return TestResult(id=self.id, status="info", evidence="Data retention policy checks require manual verification", severity=self.severity)


registry.register(PrivacyPolicyPresent())
registry.register(SecurityTxtPresent())
registry.register(CookieConsentBanner())
registry.register(PIIExposure())
registry.register(DataRetentionNotice())
