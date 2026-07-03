from __future__ import annotations

import asyncio
from abc import abstractmethod
from typing import Any
from urllib.parse import urlparse, urlunparse

import httpx

from ..base import ScanContext, SecurityTest, TestResult


def normalize_headers(headers: dict[str, str]) -> dict[str, str]:
    return {name.lower(): value for name, value in headers.items()}


def parse_directives(header_value: str) -> dict[str, str]:
    directives: dict[str, str] = {}
    for part in header_value.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            key, _, value = part.partition("=")
            directives[key.strip().lower()] = value.strip()
        else:
            directives[part.strip().lower()] = ""
    return directives


def parse_permissions_policy(header_value: str) -> dict[str, str]:
    policies: dict[str, str] = {}
    for part in header_value.split(","):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            name, _, value = part.partition("=")
            policies[name.strip().lower()] = value.strip().strip("\"'")
        else:
            policies[part.strip().lower()] = ""
    return policies


def has_sensitive_server_version(value: str) -> bool:
    lowered = value.lower()
    if "/" in lowered:
        return True
    if any(token in lowered for token in ("apache", "nginx", "iis", "tomcat", "gunicorn", "uwsgi")) and any(char.isdigit() for char in lowered):
        return True
    return False


class HeaderSecurityTest(SecurityTest):
    category = "HTTP Security Headers"

    async def fetch_headers(self, target: ScanContext, scheme: str | None = None) -> dict[str, str]:
        metadata_key = f"headers_{scheme or 'default'}"
        if metadata_key in target.metadata:
            return target.metadata[metadata_key]

        headers, _ = await self._fetch_http_response(target, scheme=scheme)
        target.metadata[metadata_key] = headers
        return headers

    async def fetch_raw_headers(self, target: ScanContext, scheme: str | None = None) -> list[tuple[str, str]]:
        metadata_key = f"headers_raw_{scheme or 'default'}"
        if metadata_key in target.metadata:
            return target.metadata[metadata_key]

        _, raw_headers = await self._fetch_http_response(target, scheme=scheme)
        target.metadata[metadata_key] = raw_headers
        return raw_headers

    async def _fetch_http_response(self, target: ScanContext, scheme: str | None = None) -> tuple[dict[str, str], list[tuple[str, str]]]:
        url = target.target
        if scheme:
            parsed = urlparse(url)
            if parsed.scheme not in {"http", "https"}:
                raise ValueError("Target URL must start with http:// or https://")
            parsed = parsed._replace(scheme=scheme)
            url = urlunparse(parsed)

        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            response = await client.get(url)
            await asyncio.sleep(0.2)
            headers = normalize_headers(response.headers)
            raw_headers = [(name.lower(), value) for name, value in response.headers.multi_items()]
            return headers, raw_headers

    async def run(self, target: ScanContext) -> TestResult:
        raise NotImplementedError
