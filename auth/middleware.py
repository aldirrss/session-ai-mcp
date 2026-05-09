"""
UserAuthMiddleware — validates Bearer tokens on /mcp paths.

Pure OAuth 2.0: only Bearer tokens accepted, no API key fallback.
Returns 401 with WWW-Authenticate pointing to OAuth resource metadata
so MCP clients (Claude Code CLI, VSCode) can auto-discover the OAuth server.
"""

import json
import logging

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

import config
from auth.context import set_current_user

_logger = logging.getLogger("session-ai-mcp.auth")


class UserAuthMiddleware(BaseHTTPMiddleware):

    _OPEN_PREFIXES = ("/.well-known/", "/oauth/", "/health", "/s/", "/web/")

    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path

        if any(path.startswith(p) for p in self._OPEN_PREFIXES):
            return await call_next(request)

        if not path.startswith("/mcp"):
            return await call_next(request)

        token = (
            self._bearer(request)
            or request.query_params.get("token")
        )

        if not token:
            return self._unauthorized()

        from auth.store import validate_token
        user = await validate_token(token)
        if not user:
            return self._unauthorized()

        set_current_user(user)
        try:
            return await call_next(request)
        finally:
            set_current_user(None)

    @staticmethod
    def _bearer(request: Request) -> str:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth[7:].strip()
        return ""

    @staticmethod
    def _unauthorized() -> Response:
        base = config.MCP_EXTERNAL_URL.rstrip("/")
        return Response(
            content=json.dumps({
                "error": "Unauthorized",
                "error_description": "Valid Bearer token required. Login at the web portal first.",
            }),
            status_code=401,
            media_type="application/json",
            headers={
                "WWW-Authenticate": (
                    f'Bearer realm="{config.APP_NAME}", '
                    f'resource_metadata="{base}/.well-known/oauth-protected-resource"'
                )
            },
        )
