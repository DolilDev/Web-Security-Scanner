from __future__ import annotations

import asyncio
from typing import Any

import httpx

from ..base import ScanContext, SecurityTest, TestResult
from ..registry import registry


class PathCheck(SecurityTest):
    category = "Infrastructure and Ports"
    id = "infra.http_paths"
    severity = "medium"

    async def run(self, target: ScanContext) -> TestResult:
        paths = [
            ".git/",
            ".svn/",
            ".env",
            ".DS_Store",
            "wp-admin/",
            "phpmyadmin/",
            "admin/",
            "security.txt",
            "humans.txt",
            "package.json",
            "package-lock.json",
        ]
        findings: list[str] = []
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
            for path in paths:
                url = target.target.rstrip("/") + "/" + path
                await asyncio.sleep(0.25)
                response = await client.get(url)
                if response.status_code == 200:
                    findings.append(path)
        if findings:
            return TestResult(id=self.id, status="warning", evidence=f"Publicly accessible paths: {', '.join(findings)}", recommendation="Restrict access to sensitive paths", severity=self.severity)
        return TestResult(id=self.id, status="pass", evidence="No common sensitive paths exposed", severity=self.severity)


registry.register(PathCheck())
