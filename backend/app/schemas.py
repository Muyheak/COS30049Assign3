"""Pydantic request/response models. Constraints here are the first back-end
check; front-end validation is only for usability."""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from . import config


class CheckRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", json_schema_extra={
        "examples": [{"url": "http://paypal.com.secure-login.tk/verify/account"}]})

    url: str = Field(..., min_length=1, max_length=config.MAX_URL_LENGTH,
                     description=f"The URL to check, 1-{config.MAX_URL_LENGTH} characters.")

    @field_validator("url")
    @classmethod
    def not_blank(cls, v):
        if not v.strip():
            raise ValueError("URL must not be blank")
        v = v.strip()
        if any(ord(c) < 32 or ord(c) == 127 for c in v):
            raise ValueError("URL must not contain control characters")
        # Characters RFC 3986 never allows unencoded in a URL; real links percent-encode them
        if any(c.isspace() or c in '<>"`' for c in v):
            raise ValueError('URL must not contain spaces or the characters < > " `')
        return v


class CheckResponse(BaseModel):
    label: Literal["phishing", "legitimate"]
    confidence: float = Field(..., ge=0, le=1, description="Probability of the predicted label")
    phishing_probability: float = Field(..., ge=0, le=1)
    normalised_url: str = Field(..., description="The URL as the model saw it, after normalisation")
    unicode_normalised: bool = Field(..., description="True if look-alike characters were folded to ASCII")
    features: dict[str, float] = Field(..., description="The 16 lexical features passed to the model")

    model_config = ConfigDict(json_schema_extra={"examples": [{
        "label": "phishing", "confidence": 0.9312, "phishing_probability": 0.9312,
        "normalised_url": "http://paypal.com.secure-login.tk/verify/account", "unicode_normalised": False,
        "features": {"url_length": 48, "host_length": 27, "suspicious_words": 3, "suspicious_tlds": 1},
    }]})


class ModelInfo(BaseModel):
    model_type: str
    features: list[str]
    max_url_length: int


class Health(BaseModel):
    status: Literal["ok"]
    model_loaded: bool


class ErrorDetail(BaseModel):
    status: int
    code: str
    message: str
    fields: list[dict] | None = None


class ErrorResponse(BaseModel):
    error: ErrorDetail
