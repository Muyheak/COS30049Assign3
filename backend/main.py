from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from fastapi.exceptions import RequestValidationError
import joblib
import os
import hashlib
from feature_extractor import extract_features

# ---- SlowAPI (rate limiting) ----
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

FRONTEND_ORIGIN = os.environ.get("FRONTEND_ORIGIN", "http://localhost:3000")
EXPECTED_HASH = None
if os.path.exists(".env"):
    with open(".env", "r") as f:
        for line in f:
            if line.startswith("MODEL_HASH="):
                EXPECTED_HASH = line.strip().split("=")[1]
                break
if not EXPECTED_HASH:
    EXPECTED_HASH = os.environ.get("MODEL_HASH")

app = FastAPI(title="Phishing URL Detector")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_ORIGIN],
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)

# ---- Rate limiter setup ----
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ---- Safe model loading: check hash BEFORE loading ----
def load_model_safely():
    if not EXPECTED_HASH:
        raise RuntimeError(
            "MODEL_HASH is not set in .env, refusing to load an unverified model"
        )
    with open("model.pkl", "rb") as f:
        actual_hash = hashlib.sha256(f.read()).hexdigest()
    if actual_hash != EXPECTED_HASH:
        raise RuntimeError(
            f"Model file hash does not match the recorded hash, refusing to load.\n"
            f"  expected: {EXPECTED_HASH}\n"
            f"  actual:   {actual_hash}"
        )
    return joblib.load("model.pkl")

MODEL = load_model_safely()


class URLRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)


class URLResponse(BaseModel):
    label: str
    confidence: float


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": "request failed", "detail": exc.detail},
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content={"error": "invalid input", "detail": exc.errors()},
    )

@app.exception_handler(Exception)
async def generic_handler(request: Request, exc: Exception):
    print(f"unexpected error: {type(exc).__name__}: {exc}")
    return JSONResponse(
        status_code=500,
        content={"error": "internal error", "detail": "please try again later"},
    )


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/predict", response_model=URLResponse)
@limiter.limit("10/minute")
def predict(req: URLRequest, request: Request):
    try:
        feats = extract_features(req.url)
        proba = MODEL.predict_proba([feats])[0]
        label = str(MODEL.classes_[proba.argmax()])
        return URLResponse(label=label, confidence=float(proba.max()))
    except Exception as e:
        print(f"prediction failed: {e}")
        raise HTTPException(status_code=400, detail="Could not analyse this URL")
