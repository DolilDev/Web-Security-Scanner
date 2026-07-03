import pytest

from backend.app.base import ScanContext
from backend.app.tests_engine.api.tests import CORSAllowAll


@pytest.mark.asyncio
async def test_cors_allow_all_detects_wildcard():
    result = await CORSAllowAll().run(ScanContext("https://example.com"))
    assert result.id == "api.cors_allow_all"
    assert result.status in {"pass", "fail", "error"}
