from __future__ import annotations

import asyncio
from typing import Any

import httpx

from ..base import ScanContext, SecurityTest, TestResult
from ..registry import registry


class HTTPMethodSecurityTest(SecurityTest):
    category = "HTTP Methods and Protocol"

    async def request(self, url: str, method: str, client: httpx.AsyncClient) -> httpx.Response:
        return await client.request(method, url)

    async def run(self, target: ScanContext) -> TestResult:
        raise NotImplementedError


class TraceDisabled(HTTPMethodSecurityTest):
    id = "http.trace_disabled"
    severity = "high"

    async def run(self, target: ScanContext) -> TestResult:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
            response = await self.request(target.target, "TRACE", client)
            if response.status_code in {405, 501, 403, 400}:
                return TestResult(id=self.id, status="pass", evidence="TRACE method disabled", severity=self.severity)
            return TestResult(id=self.id, status="fail", evidence="TRACE method allowed", recommendation="Disable TRACE", severity=self.severity)


class PutProtected(HTTPMethodSecurityTest):
    id = "http.put_protected"
    severity = "medium"

    async def run(self, target: ScanContext) -> TestResult:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
            response = await self.request(target.target, "PUT", client)
            if response.status_code in {401, 403, 405}:
                return TestResult(id=self.id, status="pass", evidence="PUT method protected or disabled", severity=self.severity)
            return TestResult(id=self.id, status="warning", evidence="PUT method may be exposed", recommendation="Restrict or disable PUT", severity=self.severity)


class DeleteProtected(HTTPMethodSecurityTest):
    id = "http.delete_protected"
    severity = "medium"

    async def run(self, target: ScanContext) -> TestResult:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
            response = await self.request(target.target, "DELETE", client)
            if response.status_code in {401, 403, 405}:
                return TestResult(id=self.id, status="pass", evidence="DELETE method protected or disabled", severity=self.severity)
            return TestResult(id=self.id, status="warning", evidence="DELETE method may be exposed", recommendation="Restrict or disable DELETE", severity=self.severity)


class ConnectUnavailable(HTTPMethodSecurityTest):
    id = "http.connect_unavailable"
    severity = "medium"

    async def run(self, target: ScanContext) -> TestResult:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
            response = await self.request(target.target, "CONNECT", client)
            if response.status_code in {400, 405, 501}:
                return TestResult(id=self.id, status="pass", evidence="CONNECT method unavailable", severity=self.severity)
            return TestResult(id=self.id, status="warning", evidence="CONNECT method may be available", recommendation="Disable CONNECT", severity=self.severity)


class OptionsMethodsLimited(HTTPMethodSecurityTest):
    id = "http.options_methods"
    severity = "low"

    async def run(self, target: ScanContext) -> TestResult:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
            response = await client.request("OPTIONS", target.target)
            allowed = response.headers.get("allow", "")
            extra = [method for method in allowed.split(",") if method.strip() and method.strip() not in {"GET", "HEAD", "POST", "OPTIONS"}]
            if extra:
                return TestResult(id=self.id, status="warning", evidence=f"Overly permissive methods allowed: {', '.join(extra)}", recommendation="Limit allowed methods", severity=self.severity)
            return TestResult(id=self.id, status="pass", evidence="Allowed methods are reasonable", severity=self.severity)


class HTTP11Fallback(HTTPMethodSecurityTest):
    id = "http.http1_0_fallback"
    severity = "low"

    async def run(self, target: ScanContext) -> TestResult:
        async with httpx.AsyncClient(http2=False, timeout=10.0, follow_redirects=False) as client:
            response = await client.get(target.target, headers={"Connection": "close"})
            if response.http_version == "HTTP/1.0":
                return TestResult(id=self.id, status="pass", evidence="HTTP/1.0 fallback supported", severity=self.severity)
            return TestResult(id=self.id, status="warning", evidence="HTTP/1.0 fallback not supported", recommendation="Verify HTTP/1.0 compatibility", severity=self.severity)


class HTTP2Supported(HTTPMethodSecurityTest):
    id = "http.http2"
    severity = "low"

    async def run(self, target: ScanContext) -> TestResult:
        async with httpx.AsyncClient(http2=True, timeout=10.0, follow_redirects=False) as client:
            response = await client.get(target.target)
            if response.http_version == "HTTP/2":
                return TestResult(id=self.id, status="pass", evidence="HTTP/2 supported", severity=self.severity)
            return TestResult(id=self.id, status="warning", evidence="HTTP/2 not supported", recommendation="Check HTTP/2 support", severity=self.severity)


registry.register(TraceDisabled())
registry.register(PutProtected())
registry.register(DeleteProtected())
registry.register(ConnectUnavailable())
registry.register(OptionsMethodsLimited())
registry.register(HTTP11Fallback())
registry.register(HTTP2Supported())
