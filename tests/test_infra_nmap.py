import json
from unittest.mock import patch

from backend.app.tests_engine.infra.nmap import NmapWrapper


def test_nmap_wrapper_reports_unavailable(monkeypatch):
    wrapper = NmapWrapper()
    monkeypatch.setattr(wrapper, "is_available", lambda: False)

    try:
        wrapper.scan("example.com")
    except FileNotFoundError as exc:
        assert "nmap executable not found" in str(exc)


def test_nmap_wrapper_parses_json(monkeypatch):
    sample = {"scan": {"1.1.1.1": {}}}
    with patch("subprocess.run") as mocked:
        mocked.return_value.returncode = 0
        mocked.return_value.stdout = json.dumps(sample)
        wrapper = NmapWrapper()
        monkeypatch.setattr(wrapper, "is_available", lambda: True)
        result = wrapper.scan("example.com")
        assert result["scan"]
