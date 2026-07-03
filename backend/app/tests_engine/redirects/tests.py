from __future__ import annotations

from typing import Optional

import httpx

from ..base import ScanContext, SecurityTest, TestResult
from ..registry import registry


class RedirectSecurityTest(SecurityTest):
    category = "Redirects and Mixed Content"

    async def request(self, url: str, follow_redirects: bool = False) -> httpx.Response:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=follow_redirects) as client:
            response = await client.get(url)
            return response

    def find_hsts_header(self, response: httpx.Response) -> Optional[str]:
        return response.headers.get("strict-transport-security")


class HttpsOnlyRedirect(RedirectSecurityTest):
    id = "redirects.https_only"
    severity = "high"

    async def run(self, target: ScanContext) -> TestResult:
        try:
            response = await self.request(target.target, follow_redirects=False)
            location = response.headers.get("location", "")
            if response.status_code in {301, 302, 307, 308} and location.startswith("https://"):
                return TestResult(id=self.id, status="pass", evidence="HTTP redirects to HTTPS", severity=self.severity)
            return TestResult(id=self.id, status="fail", evidence="HTTP does not redirect to HTTPS", recommendation="Configure HTTP to redirect to HTTPS with permanent 301/308 status", severity=self.severity)
        except Exception as exc:
            return TestResult(id=self.id, status="error", evidence=str(exc), severity=self.severity)


class HstsHeaderPresent(RedirectSecurityTest):
    id = "redirects.hsts"
    severity = "high"

    async def run(self, target: ScanContext) -> TestResult:
        if not target.target.startswith("https://"):
            return TestResult(id=self.id, status="skipped", evidence="HSTS check requires HTTPS target", severity=self.severity)
        response = await self.request(target.target, follow_redirects=False)
        if self.find_hsts_header(response):
            return TestResult(id=self.id, status="pass", evidence="HSTS header present", severity=self.severity)
        return TestResult(id=self.id, status="fail", evidence="HSTS header missing", recommendation="Add Strict-Transport-Security header", severity=self.severity)


class MixedContentResources(RedirectSecurityTest):
    id = "redirects.mixed_content"
    severity = "medium"

    async def run(self, target: ScanContext) -> TestResult:
        try:
            response = await self.request(target.target, follow_redirects=True)
            if response.status_code != 200:
                return TestResult(id=self.id, status="info", evidence=f"Unable to verify mixed content: status {response.status_code}", severity=self.severity)
            html = response.text.lower()
            if "http://" in html and target.target.startswith("https://"):
                return TestResult(id=self.id, status="fail", evidence="Potential mixed content resources found", recommendation="Use HTTPS for all page resources", severity=self.severity)
            return TestResult(id=self.id, status="pass", evidence="No obvious mixed content in HTML body", severity=self.severity)
        except Exception as exc:
            return TestResult(id=self.id, status="error", evidence=str(exc), severity=self.severity)


registry.register(HttpsOnlyRedirect())
registry.register(HstsHeaderPresent())
registry.register(MixedContentResources())
