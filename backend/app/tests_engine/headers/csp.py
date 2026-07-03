from __future__ import annotations

from typing import Any

from .base import HeaderSecurityTest, TestResult, parse_directives
from ..registry import registry


class CSPHeaderPresent(HeaderSecurityTest):
    id = "headers.csp.present"
    severity = "high"

    async def run(self, target: Any) -> TestResult:
        headers = await self.fetch_headers(target)
        if "content-security-policy" in headers:
            return TestResult(id=self.id, status="pass", evidence="CSP header present", severity=self.severity)
        return TestResult(id=self.id, status="fail", evidence="Missing Content-Security-Policy header", recommendation="Add a Content-Security-Policy header", severity=self.severity)


class CSPUnsafeInline(HeaderSecurityTest):
    id = "headers.csp.unsafe_inline"
    severity = "medium"

    async def run(self, target: Any) -> TestResult:
        headers = await self.fetch_headers(target)
        value = headers.get("content-security-policy", "")
        if "unsafe-inline" in value:
            return TestResult(id=self.id, status="fail", evidence="CSP contains unsafe-inline", recommendation="Remove unsafe-inline from CSP", severity=self.severity)
        return TestResult(id=self.id, status="pass", evidence="CSP does not contain unsafe-inline", severity=self.severity)


class CSPUnsafeEval(HeaderSecurityTest):
    id = "headers.csp.unsafe_eval"
    severity = "medium"

    async def run(self, target: Any) -> TestResult:
        headers = await self.fetch_headers(target)
        value = headers.get("content-security-policy", "")
        if "unsafe-eval" in value:
            return TestResult(id=self.id, status="fail", evidence="CSP contains unsafe-eval", recommendation="Remove unsafe-eval from CSP", severity=self.severity)
        return TestResult(id=self.id, status="pass", evidence="CSP does not contain unsafe-eval", severity=self.severity)


class CSPDirectiveDefined(HeaderSecurityTest):
    directive: str
    id: str
    severity = "medium"

    def __init__(self, directive: str) -> None:
        self.directive = directive
        self.id = f"headers.csp.{directive.replace('-', '_')}"

    async def run(self, target: Any) -> TestResult:
        headers = await self.fetch_headers(target)
        value = headers.get("content-security-policy", "")
        directives = parse_directives(value)
        if self.directive in directives:
            return TestResult(id=self.id, status="pass", evidence=f"CSP has {self.directive}", severity=self.severity)
        return TestResult(id=self.id, status="fail", evidence=f"CSP missing {self.directive}", recommendation=f"Add {self.directive} to CSP", severity=self.severity)


class CSPObjectSrcNone(HeaderSecurityTest):
    id = "headers.csp.object_src_none"
    severity = "medium"

    async def run(self, target: Any) -> TestResult:
        headers = await self.fetch_headers(target)
        value = headers.get("content-security-policy", "")
        directives = parse_directives(value)
        if directives.get("object-src", "").lower() == "none":
            return TestResult(id=self.id, status="pass", evidence="object-src set to none", severity=self.severity)
        return TestResult(id=self.id, status="fail", evidence="object-src missing or not none", recommendation="Set object-src 'none' in CSP", severity=self.severity)


class CSPReportTo(HeaderSecurityTest):
    id = "headers.csp.reporting"
    severity = "low"

    async def run(self, target: Any) -> TestResult:
        headers = await self.fetch_headers(target)
        value = headers.get("content-security-policy", "")
        directives = parse_directives(value)
        if "report-uri" in directives or "report-to" in directives:
            return TestResult(id=self.id, status="pass", evidence="CSP reporting configured", severity=self.severity)
        return TestResult(id=self.id, status="warning", evidence="CSP reporting not configured", recommendation="Consider adding report-uri or report-to", severity=self.severity)


registry.register(CSPHeaderPresent())
registry.register(CSPUnsafeInline())
registry.register(CSPUnsafeEval())
registry.register(CSPHasDirective(directive="default-src"))
registry.register(CSPHasDirective(directive="script-src"))
registry.register(CSPHasDirective(directive="style-src"))
registry.register(CSPHasDirective(directive="img-src"))
registry.register(CSPHasDirective(directive="connect-src"))
registry.register(CSPObjectSrcNone())
registry.register(CSPHasDirective(directive="frame-ancestors"))
registry.register(CSPHasDirective(directive="base-uri"))
registry.register(CSPHasDirective(directive="form-action"))
registry.register(CSPHasDirective(directive="upgrade-insecure-requests"))
registry.register(CSPHasDirective(directive="block-all-mixed-content"))
registry.register(CSPReportTo())
