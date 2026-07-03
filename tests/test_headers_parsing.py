import pytest

from backend.app.tests_engine.headers.base import parse_directives, parse_permissions_policy


def test_parse_directives_single_value():
    directives = parse_directives("default-src 'self'; script-src 'self' example.com")
    assert directives["default-src"] == "'self'"
    assert directives["script-src"] == "'self' example.com"


def test_parse_directives_flag_only():
    directives = parse_directives("upgrade-insecure-requests; block-all-mixed-content")
    assert directives["upgrade-insecure-requests"] == ""
    assert directives["block-all-mixed-content"] == ""


def test_parse_permissions_policy_simple():
    policies = parse_permissions_policy("geolocation=(self), microphone=()*")
    assert policies["geolocation"] == "(self)"
    assert policies["microphone"] == "()*"


def test_parse_permissions_policy_quote_stripping():
    policies = parse_permissions_policy("camera=\"none\", autoplay='self'")
    assert policies["camera"] == "none"
    assert policies["autoplay"] == "self"
