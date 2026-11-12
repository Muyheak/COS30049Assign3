"""Loads the model once at start-up and runs predictions.

joblib files are pickles, and unpickling can run arbitrary code, so the file's
SHA-256 is checked against MODEL_SHA256 *before* joblib.load is called.
"""
import hashlib
import logging

import joblib
import pandas as pd

from . import config
from .features import FEATURES, to_vector
from .security.unicode_norm import skeletonise

log = logging.getLogger("phishguard.model")


class ModelIntegrityError(RuntimeError):
    pass


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_model():
    if not config.MODEL_SHA256:
        raise ModelIntegrityError("MODEL_SHA256 is not set; refusing to unpickle an unverified model file")
    actual = _sha256(config.MODEL_PATH)
    if actual != config.MODEL_SHA256:
        raise ModelIntegrityError(f"Model hash mismatch for {config.MODEL_PATH.name}; refusing to load")
    model = joblib.load(config.MODEL_PATH)
    log.info("Model loaded and verified (%s)", actual[:12])
    return model


def predict(model, raw_url):
    """Return the result dict for one URL. Runs in a worker thread (see main.py)."""
    url = skeletonise(raw_url) if config.UNICODE_NORMALISATION else raw_url
    clean, row = to_vector(url)
    proba = float(model.predict_proba(pd.DataFrame([row], columns=FEATURES))[0][1])
    is_phishing = proba >= 0.5
    return {
        "label": "phishing" if is_phishing else "legitimate",
        "confidence": round(proba if is_phishing else 1 - proba, 4),
        "phishing_probability": round(proba, 4),
        "normalised_url": clean,
        "unicode_normalised": url != raw_url,
        "features": dict(zip(FEATURES, row)),
    }
