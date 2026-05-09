"""Auth DB queries — users, tokens, OAuth codes and sessions."""

import hashlib
import logging
import secrets
from datetime import datetime, timezone
from typing import Optional

import asyncpg
import bcrypt

import config
import db

_logger = logging.getLogger("session-ai-mcp.auth")


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


async def authenticate_user(identifier: str, password: str) -> Optional[dict]:
    """Authenticate by username or email + password. Returns user dict or None."""
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT id, username, email, password_hash, is_active
            FROM users
            WHERE (username = $1 OR email = $1) AND is_active = true
            """,
            identifier,
        )
    if row is None:
        return None
    if not bcrypt.checkpw(password.encode(), row["password_hash"].encode()):
        return None
    return {"id": str(row["id"]), "username": row["username"], "email": row["email"]}


async def create_user(username: str, email: str, password: str) -> dict:
    """Create a new user. Raises asyncpg.UniqueViolationError on duplicate."""
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO users (username, email, password_hash)
            VALUES ($1, $2, $3)
            RETURNING id, username, email
            """,
            username, email, password_hash,
        )
    return {"id": str(row["id"]), "username": row["username"], "email": row["email"]}


async def get_user_by_id(user_id: str) -> Optional[dict]:
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT id, username, email, is_active, created_at FROM users WHERE id = $1::uuid",
            user_id,
        )
    if row is None:
        return None
    return {
        "id": str(row["id"]),
        "username": row["username"],
        "email": row["email"],
        "is_active": row["is_active"],
        "created_at": row["created_at"].isoformat(),
    }


async def validate_token(raw_token: str) -> Optional[dict]:
    """Validate a raw Bearer token. Returns user dict or None."""
    token_hash = _hash_token(raw_token)
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT ut.user_id, u.username, u.email, u.is_active
            FROM user_tokens ut
            JOIN users u ON u.id = ut.user_id
            WHERE ut.token_hash = $1
              AND ut.revoked = false
              AND (ut.expires_at IS NULL OR ut.expires_at > NOW())
              AND u.is_active = true
            """,
            token_hash,
        )
        if row is None:
            return None
        await conn.execute(
            "UPDATE user_tokens SET last_used_at = NOW() WHERE token_hash = $1",
            token_hash,
        )
    return {
        "id": str(row["user_id"]),
        "username": row["username"],
        "email": row["email"],
    }


async def create_oauth_code(
    user_id: str, client_id: str, redirect_uri: str, code_challenge: str,
    client_name: str = "",
) -> str:
    code = secrets.token_urlsafe(32)
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO oauth_codes
                (code, user_id, client_id, redirect_uri, code_challenge, expires_at, client_name)
            VALUES ($1, $2::uuid, $3, $4, $5, NOW() + INTERVAL '10 minutes', $6)
            """,
            code, user_id, client_id, redirect_uri, code_challenge, client_name or None,
        )
    return code


async def exchange_oauth_code(
    code: str, code_verifier: str, redirect_uri: str
) -> Optional[dict]:
    """Exchange authorization code for user dict. Validates PKCE S256.
    Returns user dict with extra key 'oauth_redirect_uri' for client detection."""
    import base64
    import hashlib

    pool = await db.get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT oc.user_id, oc.code_challenge, oc.redirect_uri, oc.client_name
            FROM oauth_codes oc
            WHERE oc.code = $1
              AND oc.used = false
              AND oc.expires_at > NOW()
            """,
            code,
        )
        if row is None:
            return None

        # Validate PKCE S256
        digest = hashlib.sha256(code_verifier.encode()).digest()
        challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        if challenge != row["code_challenge"]:
            return None

        if row["redirect_uri"] != redirect_uri:
            return None

        stored_redirect_uri = row["redirect_uri"]
        stored_client_name = row["client_name"] or ""

        await conn.execute(
            "UPDATE oauth_codes SET used = true WHERE code = $1", code
        )
        user_id = str(row["user_id"])

    user = await get_user_by_id(user_id)
    if user:
        user["oauth_redirect_uri"] = stored_redirect_uri
        user["oauth_client_name"] = stored_client_name
    return user


def _is_random_token(s: str) -> bool:
    """Return True if string looks like a generated token/ID rather than a human-readable name."""
    import re
    return bool(s) and len(s) >= 12 and " " not in s and bool(re.match(r'^[A-Za-z0-9_\-]{12,}$', s))


def _detect_client(redirect_uri: str = "", client_name: str = "", user_agent: str = "") -> str:
    """Detect client type from redirect_uri (most reliable), then client_name/User-Agent."""
    uri = redirect_uri.lower()
    ua = user_agent.lower()
    cn = client_name.lower()

    # --- redirect_uri based (most reliable) ---
    if "claude.ai" in uri:
        return "claude.ai Web"
    if "aistudio.google.com" in uri or "generativelanguage.googleapis.com" in uri:
        return "Google AI Studio"
    if "gemini.google.com" in uri:
        return "Gemini Web"
    if "cursor://" in uri or "cursor.sh" in uri or "cursor.com" in uri:
        return "Cursor"
    if "windsurf://" in uri or "windsurf" in uri:
        return "Windsurf"
    if "zed.dev" in uri or "zed://" in uri:
        return "Zed"
    if "continue" in uri and ("localhost" in uri or "127.0.0.1" in uri):
        return "Continue.dev"
    if "cline" in uri:
        return "Cline"

    # --- localhost/127.0.0.1: use client_name or User-Agent to differentiate ---
    if "localhost" in uri or "127.0.0.1" in uri:
        if "cursor" in cn or "cursor" in ua:
            return "Cursor"
        if "windsurf" in cn or "windsurf" in ua:
            return "Windsurf"
        if "zed" in cn or "zed" in ua:
            return "Zed"
        if "vscode" in cn or "vscode" in ua or "visual studio code" in ua:
            return "VSCode Extension"
        if "continue" in cn or "continue" in ua:
            return "Continue.dev"
        if "cline" in cn or "cline" in ua:
            return "Cline"
        if "gemini" in cn or "gemini" in ua:
            return "Gemini CLI"
        if "claude" in cn or "claude" in ua:
            return "Claude Code CLI"
        # Show raw client_name if it's human-readable, else generic CLI label
        if client_name and not _is_random_token(client_name):
            return client_name[:64]
        return "Claude Code CLI"

    # --- Fallback: use client_name as-is, but skip random-looking tokens ---
    if client_name and not _is_random_token(client_name):
        return client_name[:64]
    return "Unknown Client"


async def create_token(
    user_id: str,
    name: str = "OAuth Token",
    client_name: str = "",
    created_ip: str = "",
) -> str:
    """Create a new personal access token and return the raw value."""
    raw = secrets.token_urlsafe(32)
    token_hash = _hash_token(raw)
    token_prefix = raw[:8]
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO user_tokens
                (user_id, token_hash, token_prefix, name, expires_at, client_name, created_ip)
            VALUES ($1::uuid, $2, $3, $4, NOW() + ($5 || ' seconds')::interval, $6, $7)
            """,
            user_id, token_hash, token_prefix, name,
            str(config.TOKEN_TTL_SECONDS), client_name or None, created_ip or None,
        )
    return raw


async def list_tokens(user_id: str) -> list[dict]:
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT id, name, token_prefix, client_name, created_ip,
                   last_used_at, expires_at, revoked, created_at
            FROM user_tokens
            WHERE user_id = $1::uuid
            ORDER BY created_at DESC
            """,
            user_id,
        )
    return [
        {
            "id": str(r["id"]),
            "name": r["name"],
            "prefix": r["token_prefix"],
            "client_name": r["client_name"] or "Unknown Client",
            "created_ip": r["created_ip"] or "—",
            "last_used_at": r["last_used_at"].isoformat() if r["last_used_at"] else None,
            "expires_at": r["expires_at"].isoformat() if r["expires_at"] else None,
            "revoked": r["revoked"],
            "created_at": r["created_at"].isoformat(),
        }
        for r in rows
    ]


async def delete_token(token_id: str, user_id: str) -> bool:
    """Permanently delete a revoked token."""
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        result = await conn.execute(
            """
            DELETE FROM user_tokens
            WHERE id = $1::uuid AND user_id = $2::uuid AND revoked = true
            """,
            token_id, user_id,
        )
    return result == "DELETE 1"


async def revoke_token(token_id: str, user_id: str) -> bool:
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        result = await conn.execute(
            "UPDATE user_tokens SET revoked = true WHERE id = $1::uuid AND user_id = $2::uuid",
            token_id, user_id,
        )
    return result == "UPDATE 1"


async def create_oauth_session(user_id: str) -> str:
    token = secrets.token_urlsafe(32)
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO oauth_sessions (token, user_id, expires_at)
            VALUES ($1, $2::uuid, NOW() + INTERVAL '7 days')
            """,
            token, user_id,
        )
    return token


async def validate_oauth_session(token: str) -> Optional[dict]:
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT u.id, u.username, u.email
            FROM oauth_sessions os
            JOIN users u ON u.id = os.user_id
            WHERE os.token = $1 AND os.expires_at > NOW() AND u.is_active = true
            """,
            token,
        )
    if row is None:
        return None
    return {"id": str(row["id"]), "username": row["username"], "email": row["email"]}
