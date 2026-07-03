from backend.app.tests_engine.cookies.base import parse_set_cookie, normalize_cookies


def test_parse_set_cookie_flags_and_attributes():
    cookie = parse_set_cookie("sessionid=abc123; HttpOnly; Secure; Path=/; SameSite=Strict")
    assert cookie["name"] == "sessionid"
    assert cookie["value"] == "abc123"
    assert "httponly" in cookie
    assert "secure" in cookie
    assert cookie["path"] == "/"
    assert cookie["samesite"] == "Strict"


def test_normalize_cookies_extracts_set_cookie_headers():
    headers = {"set-cookie": "sessionid=abc123; Secure; HttpOnly"}
    cookies = normalize_cookies(headers)
    assert len(cookies) == 1
    assert cookies[0]["name"] == "sessionid"
    assert cookies[0]["secure"] == ""
    assert cookies[0]["httponly"] == ""
