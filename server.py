#!/usr/bin/env python3
"""
session-ai-mcp — MCP Server entry point.

Transport : Streamable HTTP (compatible with claude.ai web and Claude Code CLI)
Auth      : OAuth 2.0 only — users must login via web portal before connecting CLI.

OAuth 2.0 Authorization Server (MCP spec):
  GET  /.well-known/oauth-authorization-server
  GET  /.well-known/oauth-protected-resource
  POST /oauth/register
  GET  /oauth/authorize
  POST /oauth/authorize
  POST /oauth/token
  POST /oauth/revoke
"""

import logging
import sys

import config

# Patch TransportSecurityMiddleware to validate Host/Origin against whitelist.
import mcp.server.transport_security as _ts
from urllib.parse import urlparse as _urlparse
from starlette.responses import Response as _Response


async def _validate_origin(self, request, is_post=False):
    allowed = config.MCP_ALLOWED_ORIGINS
    if not allowed:
        return None

    host = request.headers.get("host", "").split(":")[0].lower()
    if host in allowed:
        return None

    origin_header = request.headers.get("origin", "")
    if origin_header:
        hostname = _urlparse(origin_header).hostname or ""
        if hostname in allowed:
            return None

    _log = logging.getLogger("session-ai-mcp.transport")
    _log.warning("Blocked request: host=%r origin=%r allowed=%r", host, origin_header, allowed)
    return _Response(content="Forbidden: host not allowed", status_code=403)


_ts.TransportSecurityMiddleware.validate_request = _validate_origin

from mcp.server.fastmcp import FastMCP
from starlette.routing import Route, Mount
from starlette.staticfiles import StaticFiles

import db
from auth.middleware import UserAuthMiddleware
from auth.oauth import routes as oauth_routes
from tools import register_all
from web.routes import routes as web_routes

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
    stream=sys.stdout,
)

mcp = FastMCP(
    name=config.APP_NAME,
    lifespan=db.lifespan,
)

register_all(mcp)

# Build Starlette app and attach middleware + routes
app = mcp.streamable_http_app()

# Inject auth middleware
app.add_middleware(UserAuthMiddleware)

# Mount OAuth + Web routes
from starlette.routing import Router
from starlette.middleware import Middleware

# Attach extra routes by mounting them on the existing app
for route in oauth_routes + web_routes:
    app.routes.append(route)

# Health check
from starlette.requests import Request
from starlette.responses import JSONResponse


async def health(request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok", "app": config.APP_NAME})


app.routes.append(Route("/health", health))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "server:app",
        host=config.MCP_HOST,
        port=config.MCP_PORT,
        log_level="info",
    )
