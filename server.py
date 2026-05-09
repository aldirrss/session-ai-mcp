#!/usr/bin/env python3
"""
session-ai-mcp — MCP Server entry point.

Transport : Streamable HTTP (compatible with claude.ai web and Claude Code CLI)
Auth      : OAuth 2.0 only — users must login via web portal before connecting CLI.
"""

import logging
import sys
from contextlib import asynccontextmanager

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
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route

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

_logger = logging.getLogger("session-ai-mcp")


# ---------------------------------------------------------------------------
# MCP server
# ---------------------------------------------------------------------------

mcp = FastMCP(name=config.APP_NAME)
register_all(mcp)
_mcp_app = mcp.streamable_http_app()


# ---------------------------------------------------------------------------
# Lifespan — init DB then start MCP session manager (requires its own lifespan)
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app):
    # 1. Initialize database schema first
    await db.init_schema()
    _logger.info("Database schema ready")

    # 2. Run MCP app's own lifespan — this initializes StreamableHTTPSessionManager
    #    task group which is required before any /mcp request can be served.
    async with _mcp_app.router.lifespan_context(_mcp_app):
        try:
            yield
        finally:
            await db.close_pool()


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

async def health(request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok", "app": config.APP_NAME})


# ---------------------------------------------------------------------------
# App — specific routes first, MCP catch-all last
# ---------------------------------------------------------------------------

app = Starlette(
    routes=[
        Route("/health", health),
        *oauth_routes,
        *web_routes,
        Mount("/", app=_mcp_app),
    ],
    lifespan=lifespan,
)

app.add_middleware(UserAuthMiddleware)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "server:app",
        host=config.MCP_HOST,
        port=config.MCP_PORT,
        log_level="info",
    )
