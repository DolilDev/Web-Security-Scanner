import pytest

from backend.app.base import ScanContext
from backend.app.tests_engine.websockets.tests import WebSocketUpgradeHeader


@pytest.mark.asyncio
async def test_websocket_upgrade_header_results():
    result = await WebSocketUpgradeHeader().run(ScanContext("https://example.com"))
    assert result.id == "websockets.upgrade_header"
    assert result.status in {"pass", "info", "error"}
