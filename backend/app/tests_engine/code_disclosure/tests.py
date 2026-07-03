from __future__ import annotations

from typing import Optional

import httpx

from ..base import ScanContext, SecurityTest, TestResult
from ..registry import registry


class CodeDisclosureSecurityTest(SecurityTest):
    category = "Code Disclosure"

    async def request(self, url: str) -> httpx.Response:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            response = await client.get(url)
            return response

    def contains_sensitive_file(self, body: str) -> bool:
        triggers = ["<!doctype html>", "require('fs')", "#!/bin/bash", "<html", "function ", "var ", "const "]
        return any(token in body.lower() for token in triggers)


class GitConfigExposed(CodeDisclosureSecurityTest):
    id = "code_disclosure.git_config"
    severity = "high"

    async def run(self, target: ScanContext) -> TestResult:
        candidate = target.target.rstrip("/") + "/.git/config"
        try:
            response = await self.request(candidate)
            if response.status_code == 200 and "[core]" in response.text:
                return TestResult(id=self.id, status="fail", evidence="Exposed .git/config file", recommendation="Restrict access to Git repository files", severity=self.severity)
            return TestResult(id=self.id, status="pass", evidence="No exposed .git/config discovered", severity=self.severity)
        except Exception as exc:
            return TestResult(id=self.id, status="error", evidence=str(exc), severity=self.severity)


class SVNEntriesExposed(CodeDisclosureSecurityTest):
    id = "code_disclosure.svn_entries"
    severity = "high"

    async def run(self, target: ScanContext) -> TestResult:
        candidate = target.target.rstrip("/") + "/.svn/entries"
        try:
            response = await self.request(candidate)
            if response.status_code == 200 and "svn:" in response.text.lower():
                return TestResult(id=self.id, status="fail", evidence="Exposed .svn/entries file", recommendation="Disable access to Subversion metadata", severity=self.severity)
            return TestResult(id=self.id, status="pass", evidence="No exposed .svn/entries discovered", severity=self.severity)
        except Exception as exc:
            return TestResult(id=self.id, status="error", evidence=str(exc), severity=self.severity)


class BackupFileDiscovery(CodeDisclosureSecurityTest):
    id = "code_disclosure.backup_files"
    severity = "medium"

    async def run(self, target: ScanContext) -> TestResult:
        candidates = ["/backup.zip", "/backup.tar.gz", "/db.sql", "/dump.sql", "/.env"]
        discovered = []
        for path in candidates:
            url = target.target.rstrip("/") + path
            try:
                response = await self.request(url)
                if response.status_code == 200 and len(response.text) > 100:
                    discovered.append(url)
            except Exception:
                continue
        if discovered:
            return TestResult(id=self.id, status="fail", evidence=f"Exposed backup or dump file(s): {', '.join(discovered)}", recommendation="Remove or restrict access to backup artifacts", severity=self.severity)
        return TestResult(id=self.id, status="pass", evidence="No obvious backup artifacts found", severity=self.severity)


class SourceFileLeakage(CodeDisclosureSecurityTest):
    id = "code_disclosure.source_files"
    severity = "medium"

    async def run(self, target: ScanContext) -> TestResult:
        candidates = ["/index.php", "/app.py", "/config.php", "/wp-config.php"]
        for path in candidates:
            url = target.target.rstrip("/") + path
            try:
                response = await self.request(url)
                if response.status_code == 200 and self.contains_sensitive_file(response.text):
                    return TestResult(id=self.id, status="fail", evidence=f"Source file may be exposed at {url}", recommendation="Ensure source files are not served as plain text", severity=self.severity)
            except Exception:
                continue
        return TestResult(id=self.id, status="pass", evidence="No obvious source file leakage discovered", severity=self.severity)


class DebugOrConfigLeak(CodeDisclosureSecurityTest):
    id = "code_disclosure.debug_info"
    severity = "medium"

    async def run(self, target: ScanContext) -> TestResult:
        candidate = target.target.rstrip("/") + "/.env"
        try:
            response = await self.request(candidate)
            if response.status_code == 200 and ("DB_USER" in response.text or "AWS_SECRET" in response.text or "SECRET_KEY" in response.text):
                return TestResult(id=self.id, status="fail", evidence="Sensitive configuration appears exposed", recommendation="Protect environment configuration files from web access", severity=self.severity)
            return TestResult(id=self.id, status="pass", evidence="No obvious debug/config exposure found", severity=self.severity)
        except Exception as exc:
            return TestResult(id=self.id, status="error", evidence=str(exc), severity=self.severity)


registry.register(GitConfigExposed())
registry.register(SVNEntriesExposed())
registry.register(BackupFileDiscovery())
registry.register(SourceFileLeakage())
registry.register(DebugOrConfigLeak())
