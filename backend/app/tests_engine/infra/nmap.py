from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any

from ..base import ScanContext, SecurityTest, TestResult
from ..registry import registry


class NmapWrapper:
    def __init__(self, executable: str = "nmap") -> None:
        self.executable = executable

    def is_available(self) -> bool:
        return shutil.which(self.executable) is not None

    def scan(self, target: str, args: list[str] | None = None, timeout: int = 60) -> dict[str, Any]:
        if not self.is_available():
            raise FileNotFoundError("nmap executable not found")

        args = args or ["-oJ", "-", "-Pn", "--top-ports", "1000", target]
        result = subprocess.run([self.executable, *args], capture_output=True, text=True, timeout=timeout)
        if result.returncode != 0:
            raise RuntimeError(result.stderr or result.stdout)
        return json.loads(result.stdout)


class NmapPortScan(SecurityTest):
    category = "Infrastructure and Ports"
    id = "infra.nmap.port_scan"
    severity = "info"

    async def run(self, target: ScanContext) -> TestResult:
        wrapper = NmapWrapper()
        if not wrapper.is_available():
            return TestResult(id=self.id, status="error", evidence="nmap not installed", recommendation="Install nmap", severity=self.severity)
        try:
            data = wrapper.scan(target.target)
            return TestResult(id=self.id, status="pass", evidence="Port scan completed", references=["nmap"], severity=self.severity)
        except Exception as exc:
            return TestResult(id=self.id, status="error", evidence=str(exc), severity=self.severity)


registry.register(NmapPortScan())
