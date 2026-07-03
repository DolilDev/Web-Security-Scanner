from __future__ import annotations

import re
from typing import Any

import httpx
from bs4 import BeautifulSoup

from ..base import ScanContext, SecurityTest, TestResult
from ..registry import registry


def find_forms(html: str) -> list[Any]:
    soup = BeautifulSoup(html, "html.parser")
    return soup.find_all("form")


def extract_form_fields(form: Any) -> dict[str, Any]:
    fields = {}
    for element in form.find_all(["input", "textarea", "select"]):
        name = element.get("name")
        if not name:
            continue
        fields[name] = {
            "type": element.get("type", "text"),
            "autocomplete": element.get("autocomplete"),
            "value": element.get("value"),
        }
    return fields


class FormSecurityTest(SecurityTest):
    category = "Forms and Input Handling"

    async def fetch_html(self, target: ScanContext) -> str:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            response = await client.get(target.target)
            return response.text

    async def run(self, target: ScanContext) -> TestResult:
        raise NotImplementedError


class CSRFTokenPresent(FormSecurityTest):
    id = "forms.csrf_token"
    severity = "high"

    async def run(self, target: ScanContext) -> TestResult:
        html = await self.fetch_html(target)
        forms = find_forms(html)
        missing = []
        for form in forms:
            if not form.find("input", attrs={"name": re.compile(r"csrf|token", re.I)}):
                missing.append(str(form.get("action", "")))
        if missing:
            return TestResult(id=self.id, status="warning", evidence=f"Forms missing CSRF token: {', '.join(missing)}", recommendation="Add CSRF tokens to form submissions", severity=self.severity)
        return TestResult(id=self.id, status="pass", evidence="CSRF token present in forms", severity=self.severity)


class PasswordAutocompleteOff(FormSecurityTest):
    id = "forms.password_autocomplete"
    severity = "low"

    async def run(self, target: ScanContext) -> TestResult:
        html = await self.fetch_html(target)
        forms = find_forms(html)
        bad = []
        for form in forms:
            fields = extract_form_fields(form)
            for name, props in fields.items():
                if props["type"] == "password" and props["autocomplete"] != "off":
                    bad.append(name)
        if bad:
            return TestResult(id=self.id, status="warning", evidence=f"Password fields with autocomplete enabled: {', '.join(bad)}", recommendation="Set autocomplete=off on password fields", severity=self.severity)
        return TestResult(id=self.id, status="pass", evidence="Password autocomplete is off or not present", severity=self.severity)


class FormPostsOverHttps(FormSecurityTest):
    id = "forms.https_action"
    severity = "high"

    async def run(self, target: ScanContext) -> TestResult:
        html = await self.fetch_html(target)
        forms = find_forms(html)
        insecure = []
        for form in forms:
            action = form.get("action", "")
            if action and action.startswith("http://"):
                insecure.append(action)
        if insecure:
            return TestResult(id=self.id, status="fail", evidence=f"Forms post to HTTP endpoints: {', '.join(insecure)}", recommendation="Use HTTPS form actions", severity=self.severity)
        return TestResult(id=self.id, status="pass", evidence="Forms submit over HTTPS or relative paths", severity=self.severity)


registry.register(CSRFTokenPresent())
registry.register(PasswordAutocompleteOff())
registry.register(FormPostsOverHttps())
