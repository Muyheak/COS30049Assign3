from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from fastapi.exceptions import RequestValidationError
import joblib
import os
import hashlib
from feature_extractor import extract_features
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

FRONTEND_ORIGIN = os.environ.get("FRONTEND_ORIGIN", "http://localhost:3000")
EXPECTED_HASH = os.environ.get("MODEL_HASH")


app = FastAPI(
    title="Phishing URL Detector",
    description=(
        "This takes a URL and extracts the features and returns the phishing result with confidence. Its rate is limited to 10 requests a minute per IP."
    ),
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_ORIGIN],
    allow_methods=["POST", "GET"],
    allow_headers=["Content-Type"],
)

#  The rate limiter is keyed by client IP, so no user accounts available 
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# This loads the model that's verified, and it raises an error message if the model file hash doesn't match the recorded hash
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

# It loads once during startup, if the hash is wrong, it exits before uvicorn accepts any request so that it prevents any risk from unverified models
MODEL = load_model_safely()


class URLRequest(BaseModel):
    url: str = Field(
        min_length=1, 
        max_length=2048,
        description="URL to classify:",
        )


class URLResponse(BaseModel):
    label: str = Field(description="'0' = benign, '1' = phishing")
    confidence: float = Field(description="Model confidence, 0.0 to 1.0")

# These three exception handlers are so every error returns the same shape:
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


@app.get(
        "/health",
        summary="Health check",
        description="Returns 'ok' when the API is up.",
    )
def health():
    return {"status": "ok"}


@app.post(
        "/predict", 
        response_model=URLResponse,
        summary="Predict if a user is phishing or benign",
        description=(
            "Extracts the 16 features from the URL and it returns a predict label and confidence. The rate is limited to 10 requests per minute per IP." 
        ),
        response_description="Label ('0' or '1') and confidence",
        )

# The limiter blocks flooding attacks by limiting requests to only 10 per minute, because thats 3-5x what a normal user submits. 
@limiter.limit("10/minute")

# We use regular def for this one because the model does the calculation, while FastAPI runs in the background and it doesn't freeze the other requests like/health
def predict(req: URLRequest, request: Request):
    try:
        feats = extract_features(req.url)
        proba = MODEL.predict_proba([feats])[0]
        label = str(MODEL.classes_[proba.argmax()])
        return URLResponse(label=label, confidence=float(proba.max()))
    except Exception as e:
        print(f"prediction failed: {e}")
        raise HTTPException(status_code=400, detail="This URL could not be analyzed")
