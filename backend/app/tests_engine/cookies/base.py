from __future__ import annotations

import asyncio
from typing import Any
from urllib.parse import urlparse, urlunparse

import httpx

from ..base import ScanContext, SecurityTest, TestResult


def parse_set_cookie(header_value: str) -> dict[str, str]:
    parts = [part.strip() for part in header_value.split(";") if part.strip()]
    result: dict[str, str] = {}
    for idx, part in enumerate(parts):
        if idx == 0 and "=" in part:
            name, value = part.split("=", 1)
            result["name"] = name.strip()
            result["value"] = value.strip()
            continue
        if "=" in part:
            key, value = part.split("=", 1)
            result[key.lower()] = value.strip()
        else:
            result[part.lower()] = ""
    return result


def normalize_cookies(headers: dict[str, str]) -> list[dict[str, str]]:
    cookies: list[dict[str, str]] = []
    for name, value in headers.items():
        if name.lower() == "set-cookie":
            cookies.append(parse_set_cookie(value))
    return cookies


class CookieSecurityTest(SecurityTest):
    category = "Cookies"

    async def fetch_cookies(self, target: ScanContext) -> list[dict[str, str]]:
        if "cookies" in target.metadata:
            return target.metadata["cookies"]

        parsed = urlparse(target.target)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("Target URL must start with http:// or https://")

        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            response = await client.get(target.target)
            await asyncio.sleep(0.2)
            cookies = normalize_cookies({name.lower(): value for name, value in response.headers.items()})
            target.metadata["cookies"] = cookies
            return cookies

    async def run(self, target: ScanContext) -> TestResult:
        raise NotImplementedError
