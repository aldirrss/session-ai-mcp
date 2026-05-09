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


async def add_member(session_id: str, owner_id: str, invitee_email: str) -> "dict | str":
    """
    Returns dict on success, or error string:
    'not_owner' | 'email_not_found' | 'already_member' | 'already_invited'
    """
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        owns = await conn.fetchval(
            "SELECT 1 FROM sessions WHERE id = $1::uuid AND owner_id = $2::uuid",
            session_id, owner_id,
        )
        if not owns:
            return "not_owner"

        invitee = await conn.fetchrow(
            "SELECT id, username, email FROM users WHERE email = $1 AND is_active = true",
            invitee_email,
        )
        if not invitee:
            return "email_not_found"

        invitee_id = str(invitee["id"])

        is_member = await conn.fetchval(
            "SELECT 1 FROM session_members WHERE session_id = $1::uuid AND user_id = $2::uuid",
            session_id, invitee_id,
        )
        if is_member:
            return "already_member"

        already_invited = await conn.fetchval(
            """
            SELECT 1 FROM session_invitations
            WHERE session_id = $1::uuid AND invitee_id = $2::uuid AND status = 'pending'
            """,
            session_id, invitee_id,
        )
        if already_invited:
            return "already_invited"

        await conn.execute(
            """
            INSERT INTO session_invitations (session_id, inviter_id, invitee_id)
            VALUES ($1::uuid, $2::uuid, $3::uuid)
            ON CONFLICT (session_id, invitee_id)
            DO UPDATE SET status = 'pending', created_at = NOW()
            """,
            session_id, owner_id, invitee_id,
        )
    return {"id": invitee_id, "username": invitee["username"], "email": invitee["email"]}


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


async def get_pending_invitations_for_session(session_id: str, owner_id: str) -> list[dict]:
    """Pending invitations sent by owner for a specific session."""
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        owns = await conn.fetchval(
            "SELECT 1 FROM sessions WHERE id = $1::uuid AND owner_id = $2::uuid",
            session_id, owner_id,
        )
        if not owns:
            return []
        rows = await conn.fetch(
            """
            SELECT si.id, u.username, u.email, si.created_at
            FROM session_invitations si
            JOIN users u ON u.id = si.invitee_id
            WHERE si.session_id = $1::uuid AND si.status = 'pending'
            ORDER BY si.created_at
            """,
            session_id,
        )
    return [
        {
            "id": str(r["id"]),
            "username": r["username"],
            "email": r["email"],
            "created_at": r["created_at"].isoformat(),
        }
        for r in rows
    ]


async def cancel_invitation(invitation_id: str, owner_id: str) -> bool:
    """Owner cancels a pending invitation they sent."""
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        result = await conn.execute(
            """
            DELETE FROM session_invitations
            WHERE id = $1::uuid AND inviter_id = $2::uuid AND status = 'pending'
            """,
            invitation_id, owner_id,
        )
    return result == "DELETE 1"


async def list_invitations(user_id: str) -> list[dict]:
    """Pending invitations received by the user (for inbox)."""
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT si.id, si.session_id, si.created_at,
                   s.title AS session_title,
                   u.username AS inviter_username
            FROM session_invitations si
            JOIN sessions s ON s.id = si.session_id
            JOIN users u ON u.id = si.inviter_id
            WHERE si.invitee_id = $1::uuid AND si.status = 'pending'
            ORDER BY si.created_at DESC
            """,
            user_id,
        )
    return [
        {
            "id": str(r["id"]),
            "session_id": str(r["session_id"]),
            "session_title": r["session_title"],
            "inviter_username": r["inviter_username"],
            "created_at": r["created_at"].isoformat(),
        }
        for r in rows
    ]


async def get_pending_invitation_count(user_id: str) -> int:
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        count = await conn.fetchval(
            "SELECT COUNT(*) FROM session_invitations WHERE invitee_id = $1::uuid AND status = 'pending'",
            user_id,
        )
    return count or 0


async def respond_invitation(invitation_id: str, user_id: str, accept: bool) -> bool:
    """Accept or decline a pending invitation. Returns True if processed."""
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            row = await conn.fetchrow(
                """
                SELECT session_id FROM session_invitations
                WHERE id = $1::uuid AND invitee_id = $2::uuid AND status = 'pending'
                """,
                invitation_id, user_id,
            )
            if row is None:
                return False

            status = "accepted" if accept else "declined"
            await conn.execute(
                "UPDATE session_invitations SET status = $1 WHERE id = $2::uuid",
                status, invitation_id,
            )

            if accept:
                await conn.execute(
                    """
                    INSERT INTO session_members (session_id, user_id)
                    VALUES ($1::uuid, $2::uuid)
                    ON CONFLICT DO NOTHING
                    """,
                    str(row["session_id"]), user_id,
                )
    return True


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
