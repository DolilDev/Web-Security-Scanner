import pytest
from unittest.mock import AsyncMock

import dns.resolver

from backend.app.tests_engine.dns.query import DNSQueryClient


@pytest.mark.asyncio
async def test_query_returns_empty_on_no_answer(monkeypatch):
    client = DNSQueryClient()
    monkeypatch.setattr(client.resolver, "resolve", AsyncMock(side_effect=dns.resolver.NoAnswer()))

    result = await client.query("example.com", "TXT")

    assert result == []


@pytest.mark.asyncio
async def test_query_dnssec_false_on_error(monkeypatch):
    client = DNSQueryClient()
    monkeypatch.setattr(client.resolver, "resolve", AsyncMock(side_effect=Exception("dns failure")))

    assert await client.query_dnssec("example.com") is False


@pytest.mark.asyncio
async def test_zone_transfer_allowed_false_on_exception(monkeypatch):
    client = DNSQueryClient()
    monkeypatch.setattr("dns.asyncquery.xfr", AsyncMock(side_effect=Exception("xfr failure")))

    assert await client.zone_transfer_allowed("example.com") is False
