import pytest
from backend.app.base import ScanContext
from backend.app.tests_engine.auth.tests import LoginRequiredForSessionFixation


@pytest.mark.asyncio
async def test_session_fixation_skipped_without_credentials():
    test = LoginRequiredForSessionFixation()
    result = await test.run(ScanContext("https://example.com"))
    assert result.status == "skipped"
    assert "No test credentials provided" in result.evidence
