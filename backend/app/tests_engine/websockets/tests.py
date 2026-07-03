from __future__ import annotations

import ssl

import httpx

from ..base import ScanContext, SecurityTest, TestResult
from ..registry import registry


class WebSocketSecurityTest(SecurityTest):
    category = "WebSockets and Real-Time"

    async def request(self, url: str) -> httpx.Response:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=False) as client:
            return await client.get(url)


class WebSocketUpgradeHeader(WebSocketSecurityTest):
    id = "websockets.upgrade_header"
    severity = "medium"

    async def run(self, target: ScanContext) -> TestResult:
        response = await self.request(target.target)
        connection = response.headers.get("connection", "").lower()
        upgrade = response.headers.get("upgrade", "").lower()
        if "upgrade" in connection and upgrade == "websocket":
            return TestResult(id=self.id, status="pass", evidence="WebSocket upgrade headers present", severity=self.severity)
        return TestResult(id=self.id, status="info", evidence="No WebSocket upgrade headers detected", severity=self.severity)


class WSSOnlyUpgrade(WebSocketSecurityTest):
    id = "websockets.wss_only"
    severity = "high"

    async def run(self, target: ScanContext) -> TestResult:
        if target.target.startswith("ws://"):
            return TestResult(id=self.id, status="fail", evidence="Insecure WS endpoint detected", recommendation="Use WSS for secure WebSocket transport", severity=self.severity)
        return TestResult(id=self.id, status="pass", evidence="Target is not an insecure WS endpoint", severity=self.severity)


class WebSocketCORSLikeHeaders(WebSocketSecurityTest):
    id = "websockets.cross_origin"
    severity = "medium"

    async def run(self, target: ScanContext) -> TestResult:
        response = await self.request(target.target)
        if "access-control-allow-origin" in response.headers:
            return TestResult(id=self.id, status="warning", evidence="Access-Control-Allow-Origin observed on WebSocket endpoint", recommendation="Validate WebSocket cross-origin policies", severity=self.severity)
        return TestResult(id=self.id, status="pass", evidence="No WebSocket CORS-like headers present", severity=self.severity)


class WebSocketProtocolNegotiation(WebSocketSecurityTest):
    id = "websockets.protocol_negotiation"
    severity = "low"

    async def run(self, target: ScanContext) -> TestResult:
        response = await self.request(target.target)
        if response.headers.get("sec-websocket-protocol"):
            return TestResult(id=self.id, status="info", evidence="WebSocket protocol negotiation header present", severity=self.severity)
        return TestResult(id=self.id, status="info", evidence="No WebSocket subprotocol negotiation header observed", severity=self.severity)


class WebSocketOriginValidation(WebSocketSecurityTest):
    id = "websockets.origin_validation"
    severity = "medium"

    async def run(self, target: ScanContext) -> TestResult:
        response = await self.request(target.target)
        if response.headers.get("sec-websocket-origin") or response.headers.get("origin"):
            return TestResult(id=self.id, status="info", evidence="WebSocket origin header observed", severity=self.severity)
        return TestResult(id=self.id, status="info", evidence="No origin validation headers observed", severity=self.severity)


registry.register(WebSocketUpgradeHeader())
registry.register(WSSOnlyUpgrade())
registry.register(WebSocketCORSLikeHeaders())
registry.register(WebSocketProtocolNegotiation())
registry.register(WebSocketOriginValidation())
