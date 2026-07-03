import pytest

from backend.app.tests_engine.forms.tests import find_forms, extract_form_fields


def test_find_forms_returns_form_elements():
    html = "<html><body><form action='/login'><input name='username'/></form></body></html>"
    forms = find_forms(html)
    assert len(forms) == 1


def test_extract_form_fields_parses_input():
    html = "<form><input name='password' type='password' autocomplete='off'/></form>"
    forms = find_forms(html)
    fields = extract_form_fields(forms[0])
    assert fields["password"]["type"] == "password"
    assert fields["password"]["autocomplete"] == "off"
