from fastapi.testclient import TestClient

from backend.app.main import app


def test_list_reports():
    client = TestClient(app)
    resp = client.get('/dashboard/reports')
    assert resp.status_code == 200
    assert 'reports' in resp.json()
