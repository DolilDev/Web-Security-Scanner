import pytest
from unittest.mock import AsyncMock

from backend.app.tests_engine.infra.http_paths import PathCheck
from backend.app.base import ScanContext


@pytest.mark.asyncio
async def test_path_check_skips_public_paths(monkeypatch):
    client_mock = AsyncMock()
    response = type("R", (), {"status_code": 404})
    client_mock.get.return_value = response
    monkeypatch.setattr("httpx.AsyncClient", lambda *args, **kwargs: client_mock)

    test = PathCheck()
    result = await test.run(ScanContext("https://example.com"))

    assert result.status == "pass"
    assert "No common sensitive paths" in result.evidence
