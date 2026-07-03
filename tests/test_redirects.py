import pytest

from backend.app.base import ScanContext
from backend.app.tests_engine.redirects.tests import HstsHeaderPresent


@pytest.mark.asyncio
async def test_hsts_skipped_for_http_target():
    result = await HstsHeaderPresent().run(ScanContext("http://example.com"))
    assert result.status == "skipped"
    assert "HSTS check requires HTTPS target" in result.evidence
