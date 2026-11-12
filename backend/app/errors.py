"""One JSON error format for every failure, with no stack traces:
    {"error": {"status": 422, "code": "validation_error", "message": "...", "fields": [...]}}
"""
import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from .security.dos import ServerBusy

log = logging.getLogger("phishguard.errors")

_CODES = {400: "bad_request", 404: "not_found", 405: "method_not_allowed", 413: "payload_too_large",
          415: "unsupported_media_type", 429: "too_many_requests", 503: "service_unavailable"}


def _err(status, code, message, fields=None, headers=None):
    body = {"status": status, "code": code, "message": message}
    if fields:
        body["fields"] = fields
    return JSONResponse({"error": body}, status_code=status, headers=headers)


def register(app: FastAPI):
    @app.exception_handler(RequestValidationError)
    async def validation(_: Request, exc: RequestValidationError):
        # Report which field failed and why, but never echo the submitted value back
        fields = [{"field": "body" if e["type"] == "json_invalid"
                   else ".".join(str(p) for p in e["loc"] if p != "body") or "body",
                   "message": e["msg"]} for e in exc.errors()]
        return _err(422, "validation_error", "The request was not valid.", fields)

    @app.exception_handler(StarletteHTTPException)
    async def http_error(_: Request, exc: StarletteHTTPException):
        msg = exc.detail if isinstance(exc.detail, str) else "Request failed."
        return _err(exc.status_code, _CODES.get(exc.status_code, "http_error"), msg, headers=exc.headers)

    @app.exception_handler(ServerBusy)
    async def busy(_: Request, __: ServerBusy):
        return _err(503, "service_unavailable", "The server is busy. Please try again shortly.",
                    headers={"Retry-After": "1"})

    @app.exception_handler(Exception)
    async def unexpected(request: Request, exc: Exception):
        # Full details go to the server log only; the client gets a generic message
        log.exception("Unhandled error on %s %s", request.method, request.url.path)
        return _err(500, "internal_error", "Something went wrong on our side. Please try again.")
