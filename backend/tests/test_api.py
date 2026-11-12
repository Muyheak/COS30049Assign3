"""Run from backend/:  python -m pytest -q"""
import asyncio

import pytest
from fastapi.testclient import TestClient

from app import config, model as model_mod
from app.main import app
from app.security.dos import InferenceGate, ServerBusy
from app.security.unicode_norm import skeletonise

FRONTEND = config.ALLOWED_ORIGINS[0]


@pytest.fixture(scope="module")
def client():
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


def error_shape(r, status, code):
    body = r.json()
    assert r.status_code == status
    assert body["error"]["status"] == status and body["error"]["code"] == code
    assert "Traceback" not in r.text


def test_check_returns_verdict(client):
    r = client.post("/api/v1/check", json={"url": "http://paypal.com.secure-login.tk/verify"})
    assert r.status_code == 200
    body = r.json()
    assert body["label"] in {"phishing", "legitimate"}
    assert 0.5 <= body["confidence"] <= 1
    assert len(body["features"]) == 16


@pytest.mark.parametrize("payload", [{"url": ""}, {"url": "   "}, {"url": "a" * 2049}, {"url": 5},
                                     {"url": "<script>alert(1)</script>"}, {"url": "a.com", "x": 1}, {}])
def test_invalid_input_is_422(client, payload):
    error_shape(client.post("/api/v1/check", json=payload), 422, "validation_error")


def test_malformed_json_is_422(client):
    r = client.post("/api/v1/check", content=b"{bad", headers={"content-type": "application/json"})
    error_shape(r, 422, "validation_error")


def test_unknown_path_and_method(client):
    error_shape(client.get("/nope"), 404, "not_found")
    error_shape(client.delete("/api/v1/check"), 405, "method_not_allowed")


def test_oversized_body_is_413(client):
    r = client.post("/api/v1/check", content=b"x" * (config.MAX_BODY_BYTES + 1),
                    headers={"content-type": "application/json"})
    error_shape(r, 413, "payload_too_large")


def test_unexpected_error_hides_details(client, monkeypatch):
    def boom(*_):
        raise RuntimeError("secret internal detail")
    monkeypatch.setattr("app.main.predict", boom)
    r = client.post("/api/v1/check", json={"url": "a.com"})
    error_shape(r, 500, "internal_error")
    assert "secret" not in r.text


def test_security_headers(client):
    r = client.get("/api/v1/health")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert "default-src 'none'" in r.headers["content-security-policy"]
    assert "server" not in r.headers


def test_cors_only_allows_frontend(client):
    pre = {"Access-Control-Request-Method": "POST"}
    ok = client.options("/api/v1/check", headers={"Origin": FRONTEND, **pre})
    bad = client.options("/api/v1/check", headers={"Origin": "https://evil.example", **pre})
    assert ok.headers.get("access-control-allow-origin") == FRONTEND
    assert "access-control-allow-origin" not in bad.headers


def test_model_hash_mismatch_refuses(monkeypatch):
    monkeypatch.setattr(config, "MODEL_SHA256", "0" * 64)
    with pytest.raises(model_mod.ModelIntegrityError):
        model_mod.load_model()


def test_gate_returns_busy_when_full():
    async def run():
        gate = InferenceGate(max_concurrent=1, wait_seconds=0.01)
        await gate._sem.acquire()           # occupy the only slot
        with pytest.raises(ServerBusy):
            await gate.run(lambda: None)
    asyncio.run(run())


@pytest.mark.parametrize("disguised", [
    "https://pаypаl.com/login",          # Cyrillic а
    "https://paypal.com/lo​gin",              # zero-width space
    "https://paypal．com/login",               # fullwidth dot
    "https://ｐａｙｐａｌ.com/login",  # fullwidth letters
    "https://xn--pypal-4ve.com/login",             # punycode of pаypal
    "https://p%D0%B0ypal.com/login",               # percent-encoded Cyrillic а
])
def test_skeleton_defeats_disguises(disguised):
    assert skeletonise(disguised) == "https://paypal.com/login"
