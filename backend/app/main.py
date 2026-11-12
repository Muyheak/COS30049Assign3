"""PhishGuard API: phishing URL detection behind a hardened FastAPI back end.

Run:  uvicorn app.main:app --port 8000 --no-server-header
Docs: http://localhost:8000/docs
"""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from . import config, errors
from .model import load_model, predict
from .schemas import CheckRequest, CheckResponse, ErrorResponse, Health, ModelInfo
from .security.dos import AdmissionControlMiddleware, BodySizeLimitMiddleware, InferenceGate
from .security.headers import SecurityHeadersMiddleware

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("phishguard")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Loaded ONCE at start-up (after its hash is verified), never per request
    app.state.model = load_model()
    app.state.gate = InferenceGate(config.MAX_CONCURRENT_INFERENCES, config.QUEUE_WAIT_SECONDS)
    for name, on in (("DoS defence", config.DOS_DEFENCE), ("Unicode normalisation", config.UNICODE_NORMALISATION)):
        (log.info if on else log.warning)("%s: %s", name, "ON" if on else "OFF (demo mode, do not deploy)")
    yield


app = FastAPI(
    title="PhishGuard API",
    version="1.0.0",
    description="Checks whether a URL is phishing or legitimate, with the model's confidence. "
                "Every error uses the same JSON shape: `{\"error\": {status, code, message, fields?}}`.",
    lifespan=lifespan,
    redoc_url=None,
)

# add_middleware wraps, so the LAST one added runs FIRST on the way in:
#   SecurityHeaders -> CORS -> AdmissionControl -> BodySizeLimit -> routes
# Headers and CORS sit outermost so even a 413/503 reaches the browser readable.
app.add_middleware(BodySizeLimitMiddleware, max_bytes=config.MAX_BODY_BYTES)
app.add_middleware(AdmissionControlMiddleware, max_inflight=config.MAX_INFLIGHT_CHECKS)
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.ALLOWED_ORIGINS,   # the front end's exact origin, never "*"
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
    allow_credentials=False,
    max_age=600,
)
app.add_middleware(SecurityHeadersMiddleware)
errors.register(app)

ERRORS = {
    413: {"model": ErrorResponse, "description": "Request body larger than MAX_BODY_BYTES",
          "content": {"application/json": {"example": {"error": {"status": 413, "code": "payload_too_large",
                                                                 "message": "Request body exceeds 4096 bytes."}}}}},
    422: {"model": ErrorResponse, "description": "Invalid input",
          "content": {"application/json": {"example": {"error": {
              "status": 422, "code": "validation_error", "message": "The request was not valid.",
              "fields": [{"field": "url", "message": "String should have at most 2048 characters"}]}}}}},
    500: {"model": ErrorResponse, "description": "Unexpected server error (no internal details)"},
    503: {"model": ErrorResponse, "description": "Too many checks running; retry after the Retry-After header",
          "content": {"application/json": {"example": {"error": {
              "status": 503, "code": "service_unavailable",
              "message": "The server is busy. Please try again shortly."}}}}},
}


@app.post("/api/v1/check", response_model=CheckResponse, responses=ERRORS, tags=["detection"],
          summary="Check one URL",
          description="Normalises the URL exactly as in training, extracts the 16 lexical features and "
                      "returns the model's verdict and confidence. Look-alike Unicode characters are "
                      "folded to ASCII first so they cannot hide words like `paypal` or `login`.")
async def check_url(body: CheckRequest, request: Request):
    return await request.app.state.gate.run(predict, request.app.state.model, body.url)


@app.get("/api/v1/model-info", response_model=ModelInfo, tags=["detection"],
         summary="Describe the model",
         description="Lists the features the model uses, so the front end can label its charts.")
async def model_info(request: Request):
    from .features import FEATURES
    return ModelInfo(model_type=type(request.app.state.model).__name__, features=FEATURES,
                     max_url_length=config.MAX_URL_LENGTH)


@app.get("/api/v1/health", response_model=Health, tags=["system"], summary="Liveness check",
         description="Answers immediately even while checks are running; used to show the server is responsive.")
async def health(request: Request):
    return Health(status="ok", model_loaded=getattr(request.app.state, "model", None) is not None)
