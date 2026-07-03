import pytest

from backend.app.base import ScanContext
from backend.app.tests_engine.privacy.tests import PrivacyPolicyPresent


@pytest.mark.asyncio
async def test_privacy_policy_smoke():
    result = await PrivacyPolicyPresent().run(ScanContext("https://example.com"))
    assert result.id == "privacy.policy_present"
    assert result.status in {"pass", "warning", "error"}
