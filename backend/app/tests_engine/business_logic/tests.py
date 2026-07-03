from __future__ import annotations

import httpx

from ..base import ScanContext, SecurityTest, TestResult
from ..registry import registry


class BusinessLogicSecurityTest(SecurityTest):
    category = "Business Logic and Authorization"

    async def request(self, url: str, method: str = "GET", headers: dict | None = None) -> httpx.Response:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            return await client.request(method, url, headers=headers or {})


class ObjectLevelAuthorization(BusinessLogicSecurityTest):
    id = "bizlogic.object_level_authz"
    severity = "high"

    async def run(self, target: ScanContext) -> TestResult:
        if not target.metadata.get("auth_credentials"):
            return TestResult(id=self.id, status="info", evidence="Test requires authenticated flows to validate object-level authorization", severity=self.severity)
        return TestResult(id=self.id, status="info", evidence="Object-level authorization checks are application-specific and require interaction", severity=self.severity)


class PrivilegeEscalation(BusinessLogicSecurityTest):
    id = "bizlogic.privilege_escalation"
    severity = "high"

    async def run(self, target: ScanContext) -> TestResult:
        return TestResult(id=self.id, status="info", evidence="Privilege escalation detection requires role-based test accounts", severity=self.severity)


class PredictableIdentifiers(BusinessLogicSecurityTest):
    id = "bizlogic.predictable_ids"
    severity = "medium"

    async def run(self, target: ScanContext) -> TestResult:
        # Passive check: look for numeric IDs in links on the landing page
        try:
            resp = await self.request(target.target)
            body = resp.text
            if "/api/" in body and any(f"/{i}/" in body for i in range(1, 6)):
                return TestResult(id=self.id, status="warning", evidence="Potential predictable numeric identifiers found in page content", recommendation="Use non-predictable identifiers and enforce authorization", severity=self.severity)
            return TestResult(id=self.id, status="pass", evidence="No obvious predictable identifiers discovered", severity=self.severity)
        except Exception as exc:
            return TestResult(id=self.id, status="error", evidence=str(exc), severity=self.severity)


class ExcessiveActions(BusinessLogicSecurityTest):
    id = "bizlogic.excessive_actions"
    severity = "medium"

    async def run(self, target: ScanContext) -> TestResult:
        return TestResult(id=self.id, status="info", evidence="Detecting excessive allowed business actions requires authenticated scenario testing", severity=self.severity)


registry.register(ObjectLevelAuthorization())
registry.register(PrivilegeEscalation())
registry.register(PredictableIdentifiers())
registry.register(ExcessiveActions())
