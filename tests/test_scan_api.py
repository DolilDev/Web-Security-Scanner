from fastapi.testclient import TestClient

from backend.app.main import app


def test_scan_api_requires_target():
    client = TestClient(app)
    resp = client.post('/api/scan')
    assert resp.status_code == 422


def test_dashboard_reports_endpoint():
    client = TestClient(app)
    resp = client.get('/dashboard/reports')
    assert resp.status_code == 200
    assert isinstance(resp.json().get('reports'), list)
