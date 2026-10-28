from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_health_works():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}

def test_predict_returns_label_and_confidence():
    r = client.post("/predict", json={"url": "https://www.google.com"})
    assert r.status_code == 200
    body = r.json()
    assert "label" in body
    assert "confidence" in body
    assert 0.0 <= body["confidence"] <= 1.0

def test_predict_rejects_too_long_input():
    long_url = "http://example.com/" + "a" * 3000
    r = client.post("/predict", json={"url": long_url})
    assert r.status_code == 422

def test_predict_rejects_empty_input():
    r = client.post("/predict", json={"url": ""})
    assert r.status_code == 422

def test_error_format_is_consistent():
    r = client.post("/predict", json={"url": ""})
    body = r.json()
    assert "error" in body
    assert "detail" in body