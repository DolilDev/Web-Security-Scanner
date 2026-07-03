from __future__ import annotations

from typing import Any

import httpx

from ..base import ScanContext, SecurityTest, TestResult


def parse_vary_header(value: str) -> set[str]:
    return {segment.strip().lower() for segment in value.split(",") if segment.strip()}


def is_unsafe_etag(value: str) -> bool:
    return any(token.isdigit() for token in value) and len(value) < 32


class CompressionSecurityTest(SecurityTest):
    category = "Compression and Cache"

    async def get_response(self, target: ScanContext, path: str = "") -> httpx.Response:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            return await client.get(target.target.rstrip("/") + path)

    async def run(self, target: ScanContext) -> TestResult:
        raise NotImplementedError
