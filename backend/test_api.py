import pytest 
from fastapi.testclient import TestClient
from main import app 

client = TestClient(app)

def test_health_returns_ok():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}

def test_predict_returns_valid_shape():
    r = client.post(
        "/predict",
        json={"url": "http://paypal-secure-login.example.com/verify"},
    )
    assert r.status_code == 200 
    body = r.json()
    assert body["label"] in {"0", "1"}
    assert isinstance(body["confidence"], float)
    assert 0.0 <= body["confidence"] <= 1.0

def test_predict_returns_the_same_result():
    url = "http://paypal-secure-login.example.com/verify"
    r1 = client.post("/predict", json={"url": url})
    r2 = client.post("/predict", json={"url": url})
    assert r1.json()["label"] == r2.json()["label"]
   

def test_empty_url_is_rejected():
    r = client.post("/predict", json={"url": ""})
    assert r.status_code == 422

def test_url_longer_than_limit_is_rejected():
    r = client.post("/predict", json={"url": "http://example.com/" + "a" * 3000})
    assert r.status_code == 422

def test_missing_url_is_rejected():
    r = client.post("/predict", json={})
    assert r.status_code == 422

def test_validation_error_uses_shared_envelope():
    r = client.post("/predict", json={"url": ""})
    body = r.json()
    assert "error" in body 
    assert "detail" in body 

def test_validation_error_has_no_stack_trace():
    r = client.post("/predict", json={"url": ""})
    text = str(r.json()).lower()
    assert "traceback" not in text 
    assert "c:\\" not in text 
    assert "file " not in text 

