from __future__ import annotations

from .base import HeaderSecurityTest, TestResult, has_sensitive_server_version, parse_permissions_policy
from ..registry import registry


class XFrameOptions(HeaderSecurityTest):
    id = "headers.x_frame_options"
    severity = "medium"

    async def run(self, target: object) -> TestResult:
        headers = await self.fetch_headers(target)
        value = headers.get("x-frame-options", "")
        if value.upper() in {"DENY", "SAMEORIGIN"}:
            return TestResult(id=self.id, status="pass", evidence=f"X-Frame-Options: {value}", severity=self.severity)
        if value:
            return TestResult(id=self.id, status="fail", evidence=f"Invalid X-Frame-Options: {value}", recommendation="Use DENY or SAMEORIGIN", severity=self.severity)
        return TestResult(id=self.id, status="fail", evidence="Missing X-Frame-Options header", recommendation="Add X-Frame-Options header", severity=self.severity)


class XContentTypeOptions(HeaderSecurityTest):
    id = "headers.x_content_type_options"
    severity = "medium"

    async def run(self, target: object) -> TestResult:
        headers = await self.fetch_headers(target)
        if headers.get("x-content-type-options", "").lower() == "nosniff":
            return TestResult(id=self.id, status="pass", evidence="X-Content-Type-Options is nosniff", severity=self.severity)
        return TestResult(id=self.id, status="fail", evidence="Missing or incorrect X-Content-Type-Options", recommendation="Set X-Content-Type-Options: nosniff", severity=self.severity)


class ReferrerPolicyPresent(HeaderSecurityTest):
    id = "headers.referrer_policy.present"
    severity = "low"

    async def run(self, target: object) -> TestResult:
        headers = await self.fetch_headers(target)
        if "referrer-policy" in headers:
            return TestResult(id=self.id, status="pass", evidence="Referrer-Policy header present", severity=self.severity)
        return TestResult(id=self.id, status="fail", evidence="Missing Referrer-Policy header", recommendation="Add Referrer-Policy header", severity=self.severity)


class ReferrerPolicyUnsafeUrl(HeaderSecurityTest):
    id = "headers.referrer_policy.unsafe_url"
    severity = "medium"

    async def run(self, target: object) -> TestResult:
        value = (await self.fetch_headers(target)).get("referrer-policy", "")
        if not value:
            return TestResult(id=self.id, status="fail", evidence="Missing Referrer-Policy header", recommendation="Add Referrer-Policy header", severity=self.severity)
        if value.lower() == "unsafe-url":
            return TestResult(id=self.id, status="fail", evidence="Referrer-Policy is unsafe-url", recommendation="Avoid unsafe-url value", severity=self.severity)
        return TestResult(id=self.id, status="pass", evidence=f"Referrer-Policy: {value}", severity=self.severity)


class PermissionsPolicyPresent(HeaderSecurityTest):
    id = "headers.permissions_policy.present"
    severity = "low"

    async def run(self, target: object) -> TestResult:
        headers = await self.fetch_headers(target)
        if "permissions-policy" in headers or "feature-policy" in headers:
            return TestResult(id=self.id, status="pass", evidence="Permissions-Policy present", severity=self.severity)
        return TestResult(id=self.id, status="fail", evidence="Missing Permissions-Policy header", recommendation="Add Permissions-Policy header", severity=self.severity)


class PermissionsPolicyRestrictsFeature(HeaderSecurityTest):
    feature: str
    id: str
    severity = "medium"

    def __init__(self, feature: str) -> None:
        self.feature = feature
        self.id = f"headers.permissions_policy.{feature.replace('-', '_')}"

    async def run(self, target: object) -> TestResult:
        headers = await self.fetch_headers(target)
        value = headers.get("permissions-policy", headers.get("feature-policy", ""))
        if not value:
            return TestResult(id=self.id, status="skipped", evidence="Permissions-Policy missing", severity=self.severity)
        policies = parse_permissions_policy(value)
        feature_policy = policies.get(self.feature, "").strip()
        if feature_policy and feature_policy not in {"*", "(self)"}:
            return TestResult(id=self.id, status="pass", evidence=f"{self.feature} restricted in Permissions-Policy", severity=self.severity)
        return TestResult(id=self.id, status="warning", evidence=f"{self.feature} not restricted in Permissions-Policy", recommendation=f"Restrict {self.feature} in Permissions-Policy", severity=self.severity)


class SecurityServerHeaderAbsent(HeaderSecurityTest):
    id = "headers.server_version_hidden"
    severity = "medium"

    async def run(self, target: object) -> TestResult:
        value = (await self.fetch_headers(target)).get("server", "")
        if not value:
            return TestResult(id=self.id, status="pass", evidence="Server header absent", severity=self.severity)
        if has_sensitive_server_version(value):
            return TestResult(id=self.id, status="fail", evidence=f"Server header reveals version: {value}", recommendation="Remove version info from Server header", severity=self.severity)
        return TestResult(id=self.id, status="pass", evidence="Server header present without version", severity=self.severity)


class XPoweredByAbsent(HeaderSecurityTest):
    id = "headers.x_powered_by_absent"
    severity = "medium"

    async def run(self, target: object) -> TestResult:
        headers = await self.fetch_headers(target)
        if "x-powered-by" not in headers:
            return TestResult(id=self.id, status="pass", evidence="X-Powered-By header absent", severity=self.severity)
        return TestResult(id=self.id, status="fail", evidence="X-Powered-By header present", recommendation="Remove X-Powered-By header", severity=self.severity)


class XAspNetVersionAbsent(HeaderSecurityTest):
    id = "headers.x_aspnet_version_absent"
    severity = "medium"

    async def run(self, target: object) -> TestResult:
        headers = await self.fetch_headers(target)
        for header_name in ["x-aspnet-version", "x-aspnetmvc-version"]:
            if header_name in headers:
                return TestResult(id=self.id, status="fail", evidence=f"{header_name} header present", recommendation=f"Remove {header_name} header", severity=self.severity)
        return TestResult(id=self.id, status="pass", evidence="ASP.NET version headers absent", severity=self.severity)


registry.register(XFrameOptions())
registry.register(XContentTypeOptions())
registry.register(ReferrerPolicyPresent())
registry.register(ReferrerPolicyUnsafeUrl())
registry.register(PermissionsPolicyPresent())
registry.register(PermissionsPolicyRestrictsFeature(feature="camera"))
registry.register(PermissionsPolicyRestrictsFeature(feature="microphone"))
registry.register(PermissionsPolicyRestrictsFeature(feature="geolocation"))
registry.register(PermissionsPolicyRestrictsFeature(feature="payment"))
registry.register(PermissionsPolicyRestrictsFeature(feature="usb"))
registry.register(PermissionsPolicyRestrictsFeature(feature="fullscreen"))
registry.register(PermissionsPolicyRestrictsFeature(feature="autoplay"))
registry.register(PermissionsPolicyRestrictsFeature(feature="accelerometer"))
registry.register(SecurityServerHeaderAbsent())
registry.register(XPoweredByAbsent())
registry.register(XAspNetVersionAbsent())
