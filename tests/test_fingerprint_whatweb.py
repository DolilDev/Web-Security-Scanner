import json
from unittest.mock import patch

from backend.app.tests_engine.fingerprint.whatweb import WhatWebWrapper


def test_whatweb_parse_json_output(monkeypatch):
    sample = {"plugins": [{"name": "WordPress"}, {"name": "jQuery"}]}
    with patch("subprocess.run") as mocked:
        mocked.return_value.returncode = 0
        mocked.return_value.stdout = json.dumps(sample)
        wrapper = WhatWebWrapper()
        monkeypatch.setattr(wrapper, "is_available", lambda: True)
        result = wrapper.scan("https://example.com")
        assert result["plugins"][0]["name"] == "WordPress"
