"""The HTTP integration contract between the analytical backend and any future UI.

`ecdat.api.service` holds the routing and handler layer, which is socket-free: a request
is a `(method, path, query, body)` tuple and a response is a `Response` object, so the
whole API is testable without binding a port. `ecdat.api.server` is the thin
`http.server` adapter that turns real sockets into those calls, and `ecdat.api.openapi`
is the hand-authored OpenAPI 3.0 description.

The split is deliberate: the transport is replaceable (an ASGI/FastAPI adapter would be
a second file calling the same `Api.handle`) while the contract is not.
"""

from .service import Api, Response, ROUTES          # noqa: F401
from .openapi import document as openapi_document    # noqa: F401

__all__ = ["Api", "Response", "ROUTES", "openapi_document"]
