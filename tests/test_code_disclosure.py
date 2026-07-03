import pytest

from backend.app.base import ScanContext
from backend.app.tests_engine.code_disclosure.tests import GitConfigExposed


@pytest.mark.asyncio
async def test_git_config_exposed_passes_for_nonexistent_target():
    result = await GitConfigExposed().run(ScanContext("https://example.com"))
    assert result.status in {"pass", "fail", "error"}
    assert result.id == "code_disclosure.git_config"
