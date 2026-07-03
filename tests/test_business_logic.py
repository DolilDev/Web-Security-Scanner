import pytest

from backend.app.base import ScanContext
from backend.app.tests_engine.business_logic.tests import PredictableIdentifiers


@pytest.mark.asyncio
async def test_predictable_identifiers_smoke():
    result = await PredictableIdentifiers().run(ScanContext("https://example.com"))
    assert result.id == "bizlogic.predictable_ids"
    assert result.status in {"pass", "warning", "error"}
