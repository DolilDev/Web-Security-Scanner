from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any

from ..base import ScanContext, SecurityTest, TestResult
from ..registry import registry


class WhatWebWrapper:
    def __init__(self, executable: str = "whatweb") -> None:
        self.executable = executable

    def is_available(self) -> bool:
        return shutil.which(self.executable) is not None

    def scan(self, target: str, timeout: int = 60) -> dict[str, Any]:
        if not self.is_available():
            raise FileNotFoundError("whatweb executable not found")

        result = subprocess.run([self.executable, "--log-json", "-", target], capture_output=True, text=True, timeout=timeout)
        if result.returncode != 0:
            raise RuntimeError(result.stderr or result.stdout)

        return json.loads(result.stdout)


class WhatWebTechnologyDetection(SecurityTest):
    category = "Fingerprinting Technology"
    id = "fingerprint.whatweb"
    severity = "info"

    async def run(self, target: ScanContext) -> TestResult:
        wrapper = WhatWebWrapper()
        if not wrapper.is_available():
            return TestResult(id=self.id, status="error", evidence="whatweb not installed", recommendation="Install whatweb", severity=self.severity)

        try:
            result = wrapper.scan(target.target)
        except Exception as exc:
            return TestResult(id=self.id, status="error", evidence=str(exc), severity=self.severity)

        technologies = []
        for item in result.get("plugins", []):
            name = item.get("name")
            if name:
                technologies.append(name)

        evidence = "; ".join(technologies) or "No technologies detected"
        return TestResult(id=self.id, status="pass", evidence=evidence, severity=self.severity)


registry.register(WhatWebTechnologyDetection())
