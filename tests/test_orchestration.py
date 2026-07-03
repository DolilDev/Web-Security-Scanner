import pytest

from backend.app.scan_runner import run_and_save


@pytest.mark.asyncio
async def test_orchestration_run_smoke():
    # run_and_save is synchronous wrapper; call directly
    report = run_and_save("https://example.com")
    assert isinstance(report, list)
    if report:
        assert "id" in report[0]
        assert "status" in report[0]
