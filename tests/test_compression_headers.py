import pytest
from unittest.mock import AsyncMock

from backend.app.tests_engine.compression.base import parse_vary_header, is_unsafe_etag
from backend.app.tests_engine.compression.tests import CachePoisoning, ETagSafe
from backend.app.base import ScanContext


def test_parse_vary_header():
    result = parse_vary_header("Accept-Encoding, User-Agent")
    assert result == {"accept-encoding", "user-agent"}


def test_is_unsafe_etag():
    assert is_unsafe_etag("12345")
    assert not is_unsafe_etag("\"abcde12345\"")


@pytest.mark.asyncio
async def test_cache_poisoning_pass(monkeypatch):
    response = type("R", (), {"headers": {"vary": "Accept-Encoding, User-Agent"}})
    monkeypatch.setattr("backend.app.tests_engine.compression.base.httpx.AsyncClient", lambda *args, **kwargs: AsyncMock(__aenter__=AsyncMock(return_value=type("C", (), {"get": AsyncMock(return_value=response)})), __aexit__=AsyncMock(return_value=None)))

    test = CachePoisoning()
    result = await test.run(ScanContext("https://example.com"))
    assert result.status == "pass"


@pytest.mark.asyncio
async def test_etag_safe_warning(monkeypatch):
    response = type("R", (), {"headers": {"etag": "12345"}})
    monkeypatch.setattr("backend.app.tests_engine.compression.base.httpx.AsyncClient", lambda *args, **kwargs: AsyncMock(__aenter__=AsyncMock(return_value=type("C", (), {"get": AsyncMock(return_value=response)})), __aexit__=AsyncMock(return_value=None)))

    test = ETagSafe()
    result = await test.run(ScanContext("https://example.com"))
    assert result.status == "warning"
