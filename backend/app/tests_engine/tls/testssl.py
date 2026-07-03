from __future__ import annotations

from typing import Any
from .base import TLSBase, TestResult


class TestSSLUnsupportedVersion(TLSBase):
    def __init__(self, version: str, id: str) -> None:
        super().__init__(id=id, severity="high")
        self.version = version

    def run_test(self, target: Any) -> str:
        raise NotImplementedError

    def interpret(self, result: dict[str, Any]) -> TestResult:
        supported = result.get("protocols", {}).get(self.version, {}).get("supported")
        if supported is False:
            return TestResult(id=self.id, status="pass", evidence=f"{self.version} disabled", severity=self.severity)
        return TestResult(id=self.id, status="fail", evidence=f"{self.version} enabled", recommendation=f"Disable {self.version}", severity=self.severity)


class TestSSLSupportedVersion(TLSBase):
    def __init__(self, version: str, id: str) -> None:
        super().__init__(id=id, severity="medium")
        self.version = version

    def run_test(self, target: Any) -> str:
        raise NotImplementedError

    def interpret(self, result: dict[str, Any]) -> TestResult:
        supported = result.get("protocols", {}).get(self.version, {}).get("supported")
        if supported is True:
            return TestResult(id=self.id, status="pass", evidence=f"{self.version} supported", severity=self.severity)
        return TestResult(id=self.id, status="fail", evidence=f"{self.version} not supported", recommendation=f"Enable {self.version}", severity=self.severity)


class TestSSLCipherUnavailable(TLSBase):
    def __init__(self, cipher: str, id: str) -> None:
        super().__init__(id=id, severity="high")
        self.cipher = cipher

    def run_test(self, target: Any) -> str:
        raise NotImplementedError

    def interpret(self, result: dict[str, Any]) -> TestResult:
        ciphers = result.get("ciphers", {}).get("accepted", [])
        if any(self.cipher.lower() in cipher.get("name", "").lower() for cipher in ciphers):
            return TestResult(id=self.id, status="fail", evidence=f"{self.cipher} cipher accepted", recommendation=f"Disable {self.cipher} ciphers", severity=self.severity)
        return TestResult(id=self.id, status="pass", evidence=f"{self.cipher} cipher not accepted", severity=self.severity)


class TestSSLHasForwardSecrecy(TLSBase):
    def __init__(self) -> None:
        super().__init__(id="tls.forward_secrecy", severity="high")

    def run_test(self, target: Any) -> str:
        raise NotImplementedError

    def interpret(self, result: dict[str, Any]) -> TestResult:
        ciphers = result.get("ciphers", {}).get("accepted", [])
        if any(cipher.get("key_exchange", "").startswith("ECDHE") or cipher.get("key_exchange", "").startswith("DHE") for cipher in ciphers):
            return TestResult(id=self.id, status="pass", evidence="Forward secrecy ciphers accepted", severity=self.severity)
        return TestResult(id=self.id, status="fail", evidence="No forward secrecy ciphers accepted", recommendation="Enable ECDHE or DHE ciphers", severity=self.severity)
