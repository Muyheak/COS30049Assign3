"""All settings come from environment variables (or a local .env file), never
from source code. See .env.example for every variable and its default."""
import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


def _bool(name, default):
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "on", "yes"}


def _int(name, default):
    return int(os.getenv(name, str(default)))


# CORS: exact front-end origin(s), comma-separated. Never "*".
ALLOWED_ORIGINS = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "http://localhost:5173").split(",") if o.strip()]

# Model file and its expected SHA-256 (the server refuses to start on a mismatch)
MODEL_PATH = Path(os.getenv("MODEL_PATH", BASE_DIR / "model" / "phishing_rf.joblib"))
MODEL_SHA256 = os.getenv("MODEL_SHA256", "").strip().lower()

# Hygiene size limit: the longest URL we accept (characters)
MAX_URL_LENGTH = _int("MAX_URL_LENGTH", 2048)

# Denial-of-service defence (section 2.7, Advanced)
MAX_BODY_BYTES = _int("MAX_BODY_BYTES", 4096)               # raw request body cap, enforced while streaming
MAX_INFLIGHT_CHECKS = _int("MAX_INFLIGHT_CHECKS", 32)            # /check requests handled at once; excess -> 503
MAX_CONCURRENT_INFERENCES = _int("MAX_CONCURRENT_INFERENCES", 4)  # model calls running at once
QUEUE_WAIT_SECONDS = float(os.getenv("QUEUE_WAIT_SECONDS", "0.5"))  # wait for a free slot, then 503

# Demo switches, so the video can show each attack with and without its defence.
# Both default to ON. Never ship with either set to off.
DOS_DEFENCE = _bool("DOS_DEFENCE", True)
UNICODE_NORMALISATION = _bool("UNICODE_NORMALISATION", True)
