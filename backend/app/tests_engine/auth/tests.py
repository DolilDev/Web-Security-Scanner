from __future__ import annotations

from typing import Any

import httpx

from ..base import ScanContext, SecurityTest, TestResult
from ..registry import registry


class AuthSecurityTest(SecurityTest):
    category = "Authentication and Sessions"

    async def fetch_html(self, target: ScanContext) -> str:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            response = await client.get(target.target)
            return response.text

    async def run(self, target: ScanContext) -> TestResult:
        raise NotImplementedError


class SessionIdNotInUrl(AuthSecurityTest):
    id = "auth.session_id_not_in_url"
    severity = "high"

    async def run(self, target: ScanContext) -> TestResult:
        if "jsessionid=" in target.target.lower() or "phpsessid=" in target.target.lower():
            return TestResult(id=self.id, status="fail", evidence="Session ID present in URL", recommendation="Do not transmit session IDs in URLs", severity=self.severity)
        return TestResult(id=self.id, status="pass", evidence="Session ID not in URL", severity=self.severity)


class LoginRequiredForSessionFixation(AuthSecurityTest):
    id = "auth.session_fixation"
    severity = "high"

    async def run(self, target: ScanContext) -> TestResult:
        if not target.metadata.get("auth_credentials"):
            return TestResult(id=self.id, status="skipped", evidence="No test credentials provided", recommendation="Provide explicit login credentials to run this test", severity=self.severity)
        return TestResult(id=self.id, status="info", evidence="Session fixation test requires explicit credentials", severity=self.severity)


class LogoutInvalidatesSession(AuthSecurityTest):
    id = "auth.logout_invalidation"
    severity = "high"

    async def run(self, target: ScanContext) -> TestResult:
        if not target.metadata.get("auth_credentials"):
            return TestResult(id=self.id, status="skipped", evidence="No login data provided", recommendation="Provide credentials to verify logout invalidates session", severity=self.severity)
        return TestResult(id=self.id, status="info", evidence="Logout invalidation test requires authenticated session", severity=self.severity)


class SessionTimeoutConfigured(AuthSecurityTest):
    id = "auth.session_timeout"
    severity = "medium"

    async def run(self, target: ScanContext) -> TestResult:
        return TestResult(id=self.id, status="info", evidence="Session timeout configuration requires application-specific checks", severity=self.severity)


class AuthConcurrency(AuthSecurityTest):
    id = "auth.concurrent_sessions"
    severity = "low"

    async def run(self, target: ScanContext) -> TestResult:
        if not target.metadata.get("auth_credentials"):
            return TestResult(id=self.id, status="skipped", evidence="No credentials provided", recommendation="Provide credentials for concurrent session checks", severity=self.severity)
        return TestResult(id=self.id, status="info", evidence="Concurrent session test requires explicit credentials", severity=self.severity)


class PasswordResetTokenEntropy(AuthSecurityTest):
    id = "auth.reset_token_entropy"
    severity = "medium"

    async def run(self, target: ScanContext) -> TestResult:
        return TestResult(id=self.id, status="info", evidence="Password reset token checks require application-specific test data", severity=self.severity)


class PasswordResetTokenExpiry(AuthSecurityTest):
    id = "auth.reset_token_expiry"
    severity = "medium"

    async def run(self, target: ScanContext) -> TestResult:
        return TestResult(id=self.id, status="info", evidence="Password reset expiry detection requires test flow", severity=self.severity)


class RememberMeTokenSecure(AuthSecurityTest):
    id = "auth.remember_me_secure"
    severity = "low"

    async def run(self, target: ScanContext) -> TestResult:
        return TestResult(id=self.id, status="info", evidence="Remember-me token security requires explicit login flow", severity=self.severity)


class TwoFactorAvailability(AuthSecurityTest):
    id = "auth.2fa_available"
    severity = "info"

    async def run(self, target: ScanContext) -> TestResult:
        return TestResult(id=self.id, status="info", evidence="2FA availability is informational", severity=self.severity)


class AccountLockout(AuthSecurityTest):
    id = "auth.account_lockout"
    severity = "medium"

    async def run(self, target: ScanContext) -> TestResult:
        return TestResult(id=self.id, status="info", evidence="Account lockout detection requires explicit auth tests", severity=self.severity)


class LoginErrorMessages(AuthSecurityTest):
    id = "auth.login_error_messages"
    severity = "medium"

    async def run(self, target: ScanContext) -> TestResult:
        return TestResult(id=self.id, status="info", evidence="User enumeration error message checks require login form analysis", severity=self.severity)


class JWTNoneAlgorithm(AuthSecurityTest):
    id = "auth.jwt_none"
    severity = "high"

    async def run(self, target: ScanContext) -> TestResult:
        return TestResult(id=self.id, status="info", evidence="JWT algorithm validation requires API-specific checks", severity=self.severity)


class JWTWeakSecret(AuthSecurityTest):
    id = "auth.jwt_weak_secret"
    severity = "medium"

    async def run(self, target: ScanContext) -> TestResult:
        return TestResult(id=self.id, status="info", evidence="JWT secret strength detection requires token analysis", severity=self.severity)


class JWTExpPresent(AuthSecurityTest):
    id = "auth.jwt_exp"
    severity = "medium"

    async def run(self, target: ScanContext) -> TestResult:
        return TestResult(id=self.id, status="info", evidence="JWT exp presence requires token inspection", severity=self.severity)


class JWTIatPresent(AuthSecurityTest):
    id = "auth.jwt_iat"
    severity = "low"

    async def run(self, target: ScanContext) -> TestResult:
        return TestResult(id=self.id, status="info", evidence="JWT iat presence requires token inspection", severity=self.severity)


class JWTSignatureValidated(AuthSecurityTest):
    id = "auth.jwt_signature"
    severity = "high"

    async def run(self, target: ScanContext) -> TestResult:
        return TestResult(id=self.id, status="info", evidence="JWT signature validation requires token tests", severity=self.severity)


class PasswordPolicyVisible(AuthSecurityTest):
    id = "auth.password_policy"
    severity = "info"

    async def run(self, target: ScanContext) -> TestResult:
        return TestResult(id=self.id, status="info", evidence="Password policy visibility is informational", severity=self.severity)


registry.register(SessionIdNotInUrl())
registry.register(LoginRequiredForSessionFixation())
registry.register(LogoutInvalidatesSession())
registry.register(SessionTimeoutConfigured())
registry.register(AuthConcurrency())
registry.register(PasswordResetTokenEntropy())
registry.register(PasswordResetTokenExpiry())
registry.register(RememberMeTokenSecure())
registry.register(TwoFactorAvailability())
registry.register(AccountLockout())
registry.register(LoginErrorMessages())
registry.register(JWTNoneAlgorithm())
registry.register(JWTWeakSecret())
registry.register(JWTExpPresent())
registry.register(JWTIatPresent())
registry.register(JWTSignatureValidated())
registry.register(PasswordPolicyVisible())
