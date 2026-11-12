"""Denial-of-service defence (section 2.7, Advanced).

Three mechanisms, each stopping a different way to make one request cost the
server far more than it costs the attacker:

1. BodySizeLimitMiddleware - refuses a body over MAX_BODY_BYTES *while it is
   still arriving*, before it is buffered or JSON-parsed. The Pydantic
   max_length on `url` only runs after the whole body has been read and
   parsed, so on its own it does not stop a 200 MB request. Counting streamed
   bytes (not just trusting Content-Length) also stops chunked uploads that
   send no Content-Length at all.

2. Inference off the event loop - the model call runs in a worker thread, so
   one slow call cannot freeze every other request (including /health).

3. AdmissionControlMiddleware - at most MAX_INFLIGHT_CHECKS /check requests
   are handled at once; the excess gets 503 + Retry-After before its body is
   even read, so a flood is turned away cheaply.

4. InferenceGate - at most MAX_CONCURRENT_INFERENCES model calls run at once,
   in worker threads. A request that cannot get a slot within
   QUEUE_WAIT_SECONDS gets 503 instead of joining an unbounded queue.
"""
import asyncio
import json

from starlette.concurrency import run_in_threadpool

from .. import config


def _error_body(status, code, message):
    return json.dumps({"error": {"status": status, "code": code, "message": message}}).encode()


class BodySizeLimitMiddleware:
    """Pure ASGI middleware so it can count bytes as they stream in."""

    def __init__(self, app, max_bytes):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not config.DOS_DEFENCE:
            return await self.app(scope, receive, send)

        headers = dict(scope.get("headers") or [])
        declared = headers.get(b"content-length")
        if declared is not None:
            try:
                too_big = int(declared) > self.max_bytes
            except ValueError:
                too_big = True
            if too_big:
                return await self._reject(send)

        received = 0
        rejected = False

        async def limited_receive():
            nonlocal received, rejected
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes and not rejected:
                    # Answer 413 now and stop reading. The app below sees an exception
                    # (FastAPI turns it into its own 400); guarded_send drops that reply.
                    rejected = True
                    await self._reject(send)
                    raise _BodyTooLarge()
            return message

        async def guarded_send(message):
            if not rejected:
                await send(message)

        try:
            await self.app(scope, limited_receive, guarded_send)
        except _BodyTooLarge:
            pass

    async def _reject(self, send):
        body = _error_body(413, "payload_too_large", f"Request body exceeds {self.max_bytes} bytes.")
        await send({"type": "http.response.start", "status": 413,
                    "headers": [(b"content-type", b"application/json"),
                                (b"content-length", str(len(body)).encode()),
                                (b"connection", b"close")]})
        await send({"type": "http.response.body", "body": body})


class _BodyTooLarge(Exception):
    pass


class AdmissionControlMiddleware:
    """Load shedding at the door: if MAX_INFLIGHT_CHECKS /check requests are already
    being handled, answer 503 straight away, before the body is read, parsed or
    routed. Rejecting early is what keeps a flood cheap; a 503 decided after
    reading and validating the body would still cost nearly as much as serving it.
    Other paths (/health, /docs) are not counted, so they stay responsive."""

    def __init__(self, app, max_inflight, paths=("/api/v1/check",)):
        self.app = app
        self.max_inflight = max_inflight
        self.paths = paths
        self.inflight = 0

    async def __call__(self, scope, receive, send):
        if (scope["type"] != "http" or not config.DOS_DEFENCE
                or scope["path"] not in self.paths or scope["method"] == "OPTIONS"):
            return await self.app(scope, receive, send)
        if self.inflight >= self.max_inflight:
            body = _error_body(503, "service_unavailable", "The server is busy. Please try again shortly.")
            await send({"type": "http.response.start", "status": 503,
                        "headers": [(b"content-type", b"application/json"), (b"retry-after", b"1"),
                                    (b"content-length", str(len(body)).encode())]})
            await send({"type": "http.response.body", "body": body})
            return
        self.inflight += 1          # single event loop: no lock needed for this counter
        try:
            await self.app(scope, receive, send)
        finally:
            self.inflight -= 1


class ServerBusy(Exception):
    """Raised when no inference slot frees up in time; mapped to 503 in errors.py."""


class InferenceGate:
    def __init__(self, max_concurrent, wait_seconds):
        self._sem = asyncio.Semaphore(max_concurrent)
        self._wait = wait_seconds

    async def run(self, fn, *args):
        if not config.DOS_DEFENCE:
            # UNDEFENDED path, kept only for the before/after demo:
            # the model runs directly on the event loop, blocking every other request.
            return fn(*args)
        try:
            await asyncio.wait_for(self._sem.acquire(), timeout=self._wait)
        except asyncio.TimeoutError:
            raise ServerBusy()
        try:
            return await run_in_threadpool(fn, *args)
        finally:
            self._sem.release()
