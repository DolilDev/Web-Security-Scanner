import pytest

from backend.app.base import ScanContext
from backend.app.tests_engine.supply_chain.tests import ThirdPartyScripts


@pytest.mark.asyncio
async def test_third_party_scripts_smoke():
    result = await ThirdPartyScripts().run(ScanContext("https://example.com"))
    assert result.id == "supplychain.third_party_scripts"
    assert result.status in {"pass", "warning", "error"}
