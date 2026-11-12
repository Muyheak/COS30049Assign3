"""Misconfiguration defence (section 2.7, Intermediate): security headers.

FastAPI/Starlette send none of these by default, and OWASP ZAP's baseline scan
flags every one that is missing. The API only ever returns JSON, so the policy
can be very strict; /docs is the one HTML page and needs the Swagger UI
assets from cdn.jsdelivr.net, so it gets its own narrower policy.

Written as pure ASGI middleware rather than Starlette's BaseHTTPMiddleware,
which adds noticeable per-request overhead under load.
"""

API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
DOCS_CSP = ("default-src 'none'; script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
            "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; img-src 'self' data: https://fastapi.tiangolo.com; "
            "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
DOCS_PATHS = {"/docs", "/docs/oauth2-redirect"}

COMMON = [
    (b"x-content-type-options", b"nosniff"),      # no MIME sniffing of JSON into HTML
    (b"x-frame-options", b"DENY"),                # no clickjacking via iframes (older browsers)
    (b"referrer-policy", b"no-referrer"),         # never leak the checked URL in a Referer header
    (b"permissions-policy", b"camera=(), microphone=(), geolocation=(), payment=()"),
    (b"cross-origin-opener-policy", b"same-origin"),
    (b"cross-origin-resource-policy", b"same-site"),
    (b"cache-control", b"no-store"),              # verdicts on a user's URL are not cached by proxies
]


class SecurityHeadersMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        csp = (DOCS_CSP if scope["path"] in DOCS_PATHS else API_CSP).encode()
        https = scope.get("scheme") == "https"

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = [h for h in message.get("headers", []) if h[0].lower() != b"server"]
                present = {k.lower() for k, _ in headers}
                headers += [h for h in COMMON if h[0] not in present]
                headers.append((b"content-security-policy", csp))
                if https:
                    headers.append((b"strict-transport-security", b"max-age=31536000; includeSubDomains"))
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_with_headers)
