from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from dataclasses import dataclass

from ..base import ScanContext, SecurityTest, TestResult
from ..registry import registry


class TestSSLWrapper:
    def __init__(self, executable: str = "testssl.sh") -> None:
        self.executable = executable

    def is_available(self) -> bool:
        return Path(self.executable).exists() or Path("/usr/bin/testssl.sh").exists() or Path("/usr/local/bin/testssl.sh").exists()

    def parse_json(self, raw: str) -> dict[str, Any]:
        return json.loads(raw)


class TLSBase(SecurityTest):
    category = "TLS/SSL"

    def __init__(self, id: str, severity: str = "medium") -> None:
        self.id = id
        self.severity = severity

    async def run(self, target: ScanContext) -> TestResult:
        wrapper = TestSSLWrapper()
        if not wrapper.is_available():
            return TestResult(id=self.id, status="error", evidence="testssl.sh not installed", recommendation="Install testssl.sh or configure the wrapper", severity=self.severity)

        raw = self.run_test(target)
        try:
            parsed = wrapper.parse_json(raw)
        except json.JSONDecodeError as exc:
            return TestResult(id=self.id, status="error", evidence="Could not parse testssl.sh JSON output", recommendation=str(exc), severity=self.severity)

        return self.interpret(parsed)

    def run_test(self, target: ScanContext) -> str:
        raise NotImplementedError

    def interpret(self, result: dict[str, Any]) -> TestResult:
        raise NotImplementedError
