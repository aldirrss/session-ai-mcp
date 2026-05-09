"""
Configuration loaded from environment variables.
All sensitive values must be set via .env or system env — never hardcoded.
"""

import os
from urllib.parse import urlparse


def _require(key: str) -> str:
    value = os.environ.get(key)
    if not value:
        raise RuntimeError(f"Required environment variable '{key}' is not set.")
    return value


MCP_HOST: str = os.environ.get("MCP_HOST", "0.0.0.0")
MCP_PORT: int = int(os.environ.get("MCP_PORT", "8765"))

DATABASE_URL: str = _require("DATABASE_URL")

MCP_EXTERNAL_URL: str = os.environ.get("MCP_EXTERNAL_URL", "http://localhost:8765")

_external_hostname: str = urlparse(MCP_EXTERNAL_URL).hostname or ""
_extra: list[str] = [
    h.strip()
    for h in os.environ.get("MCP_ALLOWED_ORIGINS", "").split(",")
    if h.strip()
]
MCP_ALLOWED_ORIGINS: list[str] = list(
    {_external_hostname, "localhost", "127.0.0.1", *_extra} - {""}
)

TOKEN_TTL_DAYS: int = int(os.environ.get("TOKEN_TTL_DAYS", "30"))
TOKEN_TTL_SECONDS: int = TOKEN_TTL_DAYS * 86400

APP_NAME: str = os.environ.get("APP_NAME", "session-ai-mcp")
