from __future__ import annotations

import re
from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup

from ..base import ScanContext, SecurityTest, TestResult
from ..registry import registry


class SupplyChainSecurityTest(SecurityTest):
    category = "Supply Chain and Third-Party"

    async def fetch(self, url: str) -> httpx.Response:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            return await client.get(url)


class ThirdPartyScripts(SupplyChainSecurityTest):
    id = "supplychain.third_party_scripts"
    severity = "medium"

    async def run(self, target: ScanContext) -> TestResult:
        try:
            resp = await self.fetch(target.target)
            soup = BeautifulSoup(resp.text, "html.parser")
            scripts = [s.get("src") for s in soup.find_all("script") if s.get("src")]
            origin = urlparse(target.target).netloc
            external = [s for s in scripts if s and urlparse(s).netloc and urlparse(s).netloc != origin]
            if external:
                return TestResult(id=self.id, status="warning", evidence=f"External script domains: {', '.join(set(urlparse(s).netloc for s in external))}", recommendation="Review third-party script trust and supply-chain risks", severity=self.severity)
            return TestResult(id=self.id, status="pass", evidence="No external scripts detected on the page", severity=self.severity)
        except Exception as exc:
            return TestResult(id=self.id, status="error", evidence=str(exc), severity=self.severity)


class MissingSRIForExternalScripts(SupplyChainSecurityTest):
    id = "supplychain.missing_sri"
    severity = "high"

    async def run(self, target: ScanContext) -> TestResult:
        try:
            resp = await self.fetch(target.target)
            soup = BeautifulSoup(resp.text, "html.parser")
            missing = []
            for s in soup.find_all("script"):
                src = s.get("src")
                if src and urlparse(src).netloc:
                    if not s.has_attr("integrity"):
                        missing.append(src)
            if missing:
                return TestResult(id=self.id, status="fail", evidence=f"External scripts without SRI: {', '.join(missing[:5])}", recommendation="Add Subresource Integrity (SRI) hashes to third-party scripts", severity=self.severity)
            return TestResult(id=self.id, status="pass", evidence="All external scripts include integrity attribute or none present", severity=self.severity)
        except Exception as exc:
            return TestResult(id=self.id, status="error", evidence=str(exc), severity=self.severity)


class ExposedDependencyManifests(SupplyChainSecurityTest):
    id = "supplychain.manifests_exposed"
    severity = "high"

    async def run(self, target: ScanContext) -> TestResult:
        candidates = ["/package.json", "/composer.json", "/requirements.txt", "/Pipfile", "/pyproject.toml"]
        found = []
        for path in candidates:
            try:
                resp = await self.fetch(target.target.rstrip("/") + path)
                if resp.status_code == 200 and len(resp.text) > 10:
                    found.append(path)
            except Exception:
                continue
        if found:
            return TestResult(id=self.id, status="fail", evidence=f"Dependency manifests exposed: {', '.join(found)}", recommendation="Remove or protect dependency manifests", severity=self.severity)
        return TestResult(id=self.id, status="pass", evidence="No common dependency manifests exposed", severity=self.severity)


class CSPScriptSrcLoose(SupplyChainSecurityTest):
    id = "supplychain.csp_loose"
    severity = "medium"

    async def run(self, target: ScanContext) -> TestResult:
        try:
            resp = await self.fetch(target.target)
            csp = resp.headers.get("content-security-policy", "")
            if not csp:
                return TestResult(id=self.id, status="warning", evidence="No CSP header present", recommendation="Consider adding a restrictive Content-Security-Policy", severity=self.severity)
            if "script-src 'unsafe-inline'" in csp or "script-src *" in csp:
                return TestResult(id=self.id, status="warning", evidence="CSP script-src allows unsafe or wildcard sources", recommendation="Tighten script-src directive", severity=self.severity)
            return TestResult(id=self.id, status="pass", evidence="CSP script-src appears restrictive or absent but acceptable", severity=self.severity)
        except Exception as exc:
            return TestResult(id=self.id, status="error", evidence=str(exc), severity=self.severity)


registry.register(ThirdPartyScripts())
registry.register(MissingSRIForExternalScripts())
registry.register(ExposedDependencyManifests())
registry.register(CSPScriptSrcLoose())
