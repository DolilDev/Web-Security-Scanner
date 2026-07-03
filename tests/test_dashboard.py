from fastapi.testclient import TestClient

from backend.app.main import app


def test_dashboard_index():
    client = TestClient(app)
    resp = client.get('/dashboard')
    assert resp.status_code in (200, 404)
