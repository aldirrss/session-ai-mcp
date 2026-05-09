"""PostgreSQL queries for session management."""

import logging
from typing import Optional

import db
from auth.context import get_current_user

_logger = logging.getLogger("session-ai-mcp.sessions")


def _user_id() -> Optional[str]:
    user = get_current_user()
    return user.get("id") if user else None


def _session_row(row) -> dict:
    return {
        "id": str(row["id"]),
        "title": row["title"],
        "content": row["content"],
        "pinned": row["pinned"],
        "archived": row["archived"],
        "owner_id": str(row["owner_id"]),
        "created_at": row["created_at"].isoformat(),
        "updated_at": row["updated_at"].isoformat(),
    }


async def _can_access(conn, session_id: str, user_id: str) -> bool:
    """True if user owns the session or is an invited member."""
    result = await conn.fetchval(
        """
        SELECT 1 FROM sessions s
        WHERE s.id = $1::uuid
          AND (
            s.owner_id = $2::uuid
            OR EXISTS (
              SELECT 1 FROM session_members sm
              WHERE sm.session_id = s.id AND sm.user_id = $2::uuid
            )
          )
        """,
        session_id, user_id,
    )
    return result is not None


async def create_session(title: str, content: str = "") -> dict:
    user_id = _user_id()
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO sessions (owner_id, title, content)
            VALUES ($1::uuid, $2, $3)
            RETURNING *
            """,
            user_id, title, content,
        )
    return _session_row(row)


async def write_session(session_id: str, content: str) -> Optional[dict]:
    user_id = _user_id()
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        if not await _can_access(conn, session_id, user_id):
            return None
        row = await conn.fetchrow(
            """
            UPDATE sessions SET content = $1
            WHERE id = $2::uuid
            RETURNING *
            """,
            content, session_id,
        )
    if row is None:
        return None
    return _session_row(row)


async def read_session(session_id: str) -> Optional[dict]:
    user_id = _user_id()
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        if not await _can_access(conn, session_id, user_id):
            return None
        row = await conn.fetchrow(
            "SELECT * FROM sessions WHERE id = $1::uuid",
            session_id,
        )
    if row is None:
        return None
    return _session_row(row)


async def list_sessions(show_archived: bool = False) -> list[dict]:
    user_id = _user_id()
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT s.*, u.username AS owner_username,
                   (s.owner_id = $1::uuid) AS is_owner
            FROM sessions s
            JOIN users u ON u.id = s.owner_id
            WHERE (s.owner_id = $1::uuid OR EXISTS (
                    SELECT 1 FROM session_members sm
                    WHERE sm.session_id = s.id AND sm.user_id = $1::uuid
                  ))
              AND ($2 OR s.archived = false)
            ORDER BY s.pinned DESC, s.updated_at DESC
            """,
            user_id, show_archived,
        )
    result = []
    for row in rows:
        d = _session_row(row)
        d["owner_username"] = row["owner_username"]
        d["is_owner"] = row["is_owner"]
        result.append(d)
    return result


# ---------------------------------------------------------------------------
# Web-only operations (not exposed as MCP tools)
# ---------------------------------------------------------------------------

async def delete_session(session_id: str, user_id: str) -> bool:
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        result = await conn.execute(
            "DELETE FROM sessions WHERE id = $1::uuid AND owner_id = $2::uuid",
            session_id, user_id,
        )
    return result == "DELETE 1"


async def set_pinned(session_id: str, user_id: str, pinned: bool) -> bool:
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        result = await conn.execute(
            "UPDATE sessions SET pinned = $1 WHERE id = $2::uuid AND owner_id = $3::uuid",
            pinned, session_id, user_id,
        )
    return result == "UPDATE 1"


async def set_archived(session_id: str, user_id: str, archived: bool) -> bool:
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        result = await conn.execute(
            "UPDATE sessions SET archived = $1 WHERE id = $2::uuid AND owner_id = $3::uuid",
            archived, session_id, user_id,
        )
    return result == "UPDATE 1"


async def update_title(session_id: str, user_id: str, title: str) -> bool:
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        result = await conn.execute(
            "UPDATE sessions SET title = $1 WHERE id = $2::uuid AND owner_id = $3::uuid",
            title, session_id, user_id,
        )
    return result == "UPDATE 1"


async def get_members(session_id: str) -> list[dict]:
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT u.id, u.username, u.email, sm.joined_at
            FROM session_members sm
            JOIN users u ON u.id = sm.user_id
            WHERE sm.session_id = $1::uuid
            ORDER BY sm.joined_at
            """,
            session_id,
        )
    return [
        {
            "id": str(r["id"]),
            "username": r["username"],
            "email": r["email"],
            "joined_at": r["joined_at"].isoformat(),
        }
        for r in rows
    ]


async def add_member(session_id: str, owner_id: str, invitee_email: str) -> Optional[dict]:
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        # Only owner can invite
        owns = await conn.fetchval(
            "SELECT 1 FROM sessions WHERE id = $1::uuid AND owner_id = $2::uuid",
            session_id, owner_id,
        )
        if not owns:
            return None
        invitee = await conn.fetchrow(
            "SELECT id, username, email FROM users WHERE email = $1 AND is_active = true",
            invitee_email,
        )
        if not invitee:
            return None
        await conn.execute(
            """
            INSERT INTO session_members (session_id, user_id)
            VALUES ($1::uuid, $2::uuid)
            ON CONFLICT DO NOTHING
            """,
            session_id, invitee["id"],
        )
    return {"id": str(invitee["id"]), "username": invitee["username"], "email": invitee["email"]}


async def remove_member(session_id: str, owner_id: str, member_user_id: str) -> bool:
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        owns = await conn.fetchval(
            "SELECT 1 FROM sessions WHERE id = $1::uuid AND owner_id = $2::uuid",
            session_id, owner_id,
        )
        if not owns:
            return False
        result = await conn.execute(
            "DELETE FROM session_members WHERE session_id = $1::uuid AND user_id = $2::uuid",
            session_id, member_user_id,
        )
    return result == "DELETE 1"


async def create_share_token(session_id: str, owner_id: str) -> Optional[str]:
    import secrets
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        owns = await conn.fetchval(
            "SELECT 1 FROM sessions WHERE id = $1::uuid AND owner_id = $2::uuid",
            session_id, owner_id,
        )
        if not owns:
            return None
        # Return existing token if present
        existing = await conn.fetchval(
            "SELECT token FROM share_tokens WHERE session_id = $1::uuid",
            session_id,
        )
        if existing:
            return existing
        token = secrets.token_urlsafe(24)
        await conn.execute(
            "INSERT INTO share_tokens (token, session_id) VALUES ($1, $2::uuid)",
            token, session_id,
        )
    return token


async def revoke_share_token(session_id: str, owner_id: str) -> bool:
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        owns = await conn.fetchval(
            "SELECT 1 FROM sessions WHERE id = $1::uuid AND owner_id = $2::uuid",
            session_id, owner_id,
        )
        if not owns:
            return False
        result = await conn.execute(
            "DELETE FROM share_tokens WHERE session_id = $1::uuid",
            session_id,
        )
    return "DELETE 1" in result


async def get_session_by_share_token(token: str) -> Optional[dict]:
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT s.* FROM sessions s
            JOIN share_tokens st ON st.session_id = s.id
            WHERE st.token = $1
            """,
            token,
        )
    if row is None:
        return None
    return _session_row(row)


async def search_sessions_by_user(user_id: str, query: str) -> list[dict]:
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT s.id, s.title, s.updated_at,
                   ts_headline('english', s.content, plainto_tsquery('english', $2),
                               'MaxWords=20, MinWords=10') AS snippet
            FROM sessions s
            WHERE (s.owner_id = $1::uuid OR EXISTS (
                    SELECT 1 FROM session_members sm
                    WHERE sm.session_id = s.id AND sm.user_id = $1::uuid
                  ))
              AND s.archived = false
              AND s.search_vec @@ plainto_tsquery('english', $2)
            ORDER BY ts_rank(s.search_vec, plainto_tsquery('english', $2)) DESC
            LIMIT 20
            """,
            user_id, query,
        )
    return [
        {
            "id": str(r["id"]),
            "title": r["title"],
            "updated_at": r["updated_at"].isoformat(),
            "snippet": r["snippet"],
        }
        for r in rows
    ]
