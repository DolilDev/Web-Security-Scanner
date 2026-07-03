import json
from pathlib import Path

from backend.app.tests_engine.tls.base import TestSSLWrapper
from backend.app.tests_engine.tls.testssl import (
    TestSSLUnsupportedVersion,
    TestSSLSupportedVersion,
    TestSSLCipherUnavailable,
    TestSSLHasForwardSecrecy,
)
from backend.app.base import ScanContext


FIXTURE_PATH = Path(__file__).resolve().parent / "fixtures" / "testssl_sample.json"


def load_fixture() -> dict:
    return json.loads(FIXTURE_PATH.read_text())


class DummyTLSTest(TestSSLUnsupportedVersion):
    def __init__(self) -> None:
        super().__init__(version="SSLv2", id="tls.ssldisabled")

    def run_test(self, target: ScanContext) -> str:
        return "{}"

    def interpret(self, result: dict) -> object:
        return super().interpret(result)


def test_parse_testssl_json_fixture():
    fixture = load_fixture()
    wrapper = TestSSLWrapper()
    assert wrapper.parse_json(json.dumps(fixture))["protocols"]["TLSv1.2"]["supported"] is True


def test_forward_secrecy_interpretation():
    fixture = load_fixture()
    test = TestSSLHasForwardSecrecy()
    result = test.interpret(fixture)
    assert result.status == "pass"


def test_cipher_unavailable_interpretation():
    fixture = load_fixture()
    test = TestSSLCipherUnavailable(cipher="RC4", id="tls.cipher.rc4")
    result = test.interpret(fixture)
    assert result.status == "pass"


def test_tls_unsupported_version_interpretation():
    fixture = load_fixture()
    test = TestSSLUnsupportedVersion(version="SSLv3", id="tls.sslv3_disabled")
    result = test.interpret(fixture)
    assert result.status == "pass"


def test_tls_supported_version_interpretation():
    fixture = load_fixture()
    test = TestSSLSupportedVersion(version="TLSv1.3", id="tls.tls13_supported")
    result = test.interpret(fixture)
    assert result.status == "pass"
