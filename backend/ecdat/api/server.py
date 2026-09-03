"""The socket adapter: real HTTP over `Api.handle`, and nothing else.

Everything of substance lives in `ecdat.api.service`. This file only translates between
`BaseHTTPRequestHandler` and the socket-free `(method, path, query, body) -> Response`
contract, so the transport can be replaced without touching a single handler. `serve()`
is a `ThreadingHTTPServer` for local, single-operator use; it is not hardened for
exposure to an untrusted network, and the module docstring of `service` says why the
data-protection guarantees (no snippets, no key bytes) hold regardless.
"""

from __future__ import annotations

import os
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .service import Api, MAX_BODY_BYTES

# The browser UI is served from its own port, so it is a cross-origin caller and needs
# CORS. It is an explicit allow-list rather than `*`: a wildcard cannot carry credentials
# at all under the CORS spec, so shipping one now would only have to be undone the moment
# any authentication is added, and in the meantime it lets any page in the browser read
# this estate's scan results. The two loopback origins are the ones `next dev` and
# `next start` actually serve on. Demonstrating over a LAN address means naming that
# origin explicitly:
#
#   ECDAT_API_ALLOWED_ORIGINS="http://192.168.1.10:3000" python -m ecdat.api
_DEFAULT_ALLOWED_ORIGINS = (
    "http://localhost:3000",
    "http://127.0.0.1:3000",
)


def allowed_origins() -> tuple[str, ...]:
    """Origins permitted to read the API from a browser, newest env value first."""
    configured = os.environ.get("ECDAT_API_ALLOWED_ORIGINS", "")
    extra = tuple(part.strip() for part in configured.split(",") if part.strip())
    return _DEFAULT_ALLOWED_ORIGINS + extra


class _Handler(BaseHTTPRequestHandler):
    server_version = "ECDAT/1.0"
    protocol_version = "HTTP/1.1"

    # The Api instance is attached to the server object by `serve()`.
    @property
    def api(self) -> Api:
        return self.server.api                          # type: ignore[attr-defined]

    def _send_cors_headers(self) -> None:
        """Echo the caller's origin only when it is allow-listed.

        A request with no `Origin` (curl, a server-side fetch, a same-origin XHR) gets no
        CORS header, because there is no cross-origin decision to communicate. `Vary`
        keeps a proxy from caching one origin's answer and serving it to another.
        """
        origin = self.headers.get("Origin")
        if origin and origin in allowed_origins():
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")

    def _dispatch(self, method: str) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        body = b""
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            if length > MAX_BODY_BYTES:
                self._write_raw(413, b'{"error":{"code":"body_too_large","status":413,'
                                     b'"message":"Request body exceeds 1 MiB."}}',
                                "application/json")
                # Drain so the connection can be reused/closed cleanly.
                self.rfile.read(length)
                return
            body = self.rfile.read(length)
        response = self.api.handle(method, parsed.path, query, body)
        self._write(response)

    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_POST(self) -> None:
        self._dispatch("POST")

    def do_PUT(self) -> None:
        self._dispatch("PUT")

    def do_DELETE(self) -> None:
        self._dispatch("DELETE")

    def do_HEAD(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        response = self.api.handle("GET", parsed.path, query, b"")
        self._write(response, head_only=True)

    # ----------------------------------------------------------------------------------
    def _write(self, response: Any, head_only: bool = False) -> None:
        self.send_response(response.status)
        self.send_header("Content-Type", response.content_type)
        self.send_header("Content-Length", str(len(response.body)))
        self._send_cors_headers()
        self.send_header("X-Content-Type-Options", "nosniff")
        for key, value in (response.headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if not head_only:
            self.wfile.write(response.body)

    def _write_raw(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self._send_cors_headers()
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, fmt: str, *args: Any) -> None:
        # Quiet by default; a scan log line per request would drown the console. The
        # `serve()` caller can pass a real logger if it wants request logs.
        logger = getattr(self.server, "request_logger", None)
        if logger is not None:
            logger("%s - %s" % (self.address_string(), fmt % args))


def make_server(host: str = "127.0.0.1", port: int = 8787,
                api: Api | None = None, request_logger=None) -> ThreadingHTTPServer:
    """Build (but do not start) a threading HTTP server bound to `host:port`.

    Defaults to loopback: the API is an operator tool, and binding all interfaces would
    expose an unauthenticated scan trigger. Pass `host="0.0.0.0"` deliberately, ideally
    with `Api(allowed_roots=[...])` so `POST /scan` cannot walk arbitrary paths.
    """
    httpd = ThreadingHTTPServer((host, port), _Handler)
    httpd.api = api or Api()                             # type: ignore[attr-defined]
    httpd.request_logger = request_logger               # type: ignore[attr-defined]
    return httpd


def serve(host: str = "127.0.0.1", port: int = 8787, api: Api | None = None,
          request_logger=print) -> None:
    """Start serving and block until interrupted. Convenience for `python -m`."""
    httpd = make_server(host, port, api, request_logger=request_logger)
    if request_logger:
        request_logger(f"ECDAT API on http://{host}:{port}  "
                       f"(GET /openapi.json for the contract)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
