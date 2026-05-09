"""
Async PostgreSQL connection pool and schema management.
Schema is auto-initialized on first startup (idempotent DDL).
"""

import logging
from contextlib import asynccontextmanager
from typing import Optional

import asyncpg

import config

_logger = logging.getLogger("session-ai-mcp.db")
_pool: Optional[asyncpg.Pool] = None

_DDL_STEPS = [
    # Extensions
    "CREATE EXTENSION IF NOT EXISTS pg_trgm",

    # fn: auto-bump updated_at
    """
    CREATE OR REPLACE FUNCTION fn_touch_updated_at()
    RETURNS TRIGGER LANGUAGE plpgsql AS $$
    BEGIN
        NEW.updated_at = NOW();
        RETURN NEW;
    END;
    $$
    """,

    # Users
    """
    CREATE TABLE IF NOT EXISTS users (
        id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
        username      TEXT        UNIQUE NOT NULL,
        email         TEXT        UNIQUE NOT NULL,
        password_hash TEXT        NOT NULL,
        is_active     BOOLEAN     NOT NULL DEFAULT true,
        created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
    """,

    """
    DO $$ BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_users_updated_at') THEN
            CREATE TRIGGER trg_users_updated_at
                BEFORE UPDATE ON users FOR EACH ROW
                EXECUTE FUNCTION fn_touch_updated_at();
        END IF;
    END; $$
    """,

    # Personal Access Tokens (issued via OAuth)
    """
    CREATE TABLE IF NOT EXISTS user_tokens (
        id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id      UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token_hash   TEXT        UNIQUE NOT NULL,
        token_prefix TEXT,
        name         TEXT        NOT NULL DEFAULT 'Default',
        last_used_at TIMESTAMPTZ,
        expires_at   TIMESTAMPTZ,
        revoked      BOOLEAN     NOT NULL DEFAULT false,
        created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
    """,

    # OAuth authorization codes (PKCE S256, short-lived, single-use)
    """
    CREATE TABLE IF NOT EXISTS oauth_codes (
        code            TEXT        PRIMARY KEY,
        user_id         UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        client_id       TEXT        NOT NULL,
        redirect_uri    TEXT        NOT NULL,
        code_challenge  TEXT        NOT NULL,
        expires_at      TIMESTAMPTZ NOT NULL,
        used            BOOLEAN     NOT NULL DEFAULT false
    )
    """,

    # OAuth browser sessions (keeps user logged in on authorize page)
    """
    CREATE TABLE IF NOT EXISTS oauth_sessions (
        token       TEXT        PRIMARY KEY,
        user_id     UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        expires_at  TIMESTAMPTZ NOT NULL,
        created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
    """,

    # Sessions
    """
    CREATE TABLE IF NOT EXISTS sessions (
        id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
        owner_id    UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        title       TEXT        NOT NULL,
        content     TEXT        NOT NULL DEFAULT '',
        pinned      BOOLEAN     NOT NULL DEFAULT false,
        archived    BOOLEAN     NOT NULL DEFAULT false,
        search_vec  TSVECTOR,
        created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
    """,

    # fn: update search_vec from title + content
    """
    CREATE OR REPLACE FUNCTION fn_sessions_search_vec()
    RETURNS TRIGGER LANGUAGE plpgsql AS $$
    BEGIN
        NEW.search_vec := to_tsvector('english',
            coalesce(NEW.title,   '') || ' ' ||
            coalesce(NEW.content, '')
        );
        RETURN NEW;
    END;
    $$
    """,

    """
    DO $$ BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_sessions_search_vec') THEN
            CREATE TRIGGER trg_sessions_search_vec
                BEFORE INSERT OR UPDATE OF title, content ON sessions
                FOR EACH ROW EXECUTE FUNCTION fn_sessions_search_vec();
        END IF;
    END; $$
    """,

    """
    DO $$ BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_sessions_updated_at') THEN
            CREATE TRIGGER trg_sessions_updated_at
                BEFORE UPDATE ON sessions FOR EACH ROW
                EXECUTE FUNCTION fn_touch_updated_at();
        END IF;
    END; $$
    """,

    # Session members — shared read-write access between registered users
    """
    CREATE TABLE IF NOT EXISTS session_members (
        session_id  UUID        NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
        user_id     UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        joined_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        PRIMARY KEY (session_id, user_id)
    )
    """,

    # Share tokens — public read-only links (no login required)
    """
    CREATE TABLE IF NOT EXISTS share_tokens (
        token       TEXT        PRIMARY KEY,
        session_id  UUID        NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
        created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
    """,

    # Session invitations — inbox-based invite flow
    """
    CREATE TABLE IF NOT EXISTS session_invitations (
        id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
        session_id  UUID        NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
        inviter_id  UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        invitee_id  UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        status      TEXT        NOT NULL DEFAULT 'pending',
        created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE (session_id, invitee_id)
    )
    """,

    # Token metadata — client name and IP at token creation time
    "ALTER TABLE user_tokens ADD COLUMN IF NOT EXISTS client_name TEXT",
    "ALTER TABLE user_tokens ADD COLUMN IF NOT EXISTS created_ip  TEXT",

    # Store client_name from /oauth/authorize so it's available at token exchange
    "ALTER TABLE oauth_codes ADD COLUMN IF NOT EXISTS client_name TEXT",

    # Indexes
    "CREATE INDEX IF NOT EXISTS idx_users_email          ON users (email)",
    "CREATE INDEX IF NOT EXISTS idx_users_username       ON users (username)",
    "CREATE INDEX IF NOT EXISTS idx_user_tokens_user     ON user_tokens (user_id)",
    "CREATE INDEX IF NOT EXISTS idx_user_tokens_hash     ON user_tokens (token_hash)",
    "CREATE INDEX IF NOT EXISTS idx_oauth_codes_code     ON oauth_codes (code)",
    "CREATE INDEX IF NOT EXISTS idx_oauth_sessions_user  ON oauth_sessions (user_id)",
    "CREATE INDEX IF NOT EXISTS idx_sessions_owner       ON sessions (owner_id)",
    "CREATE INDEX IF NOT EXISTS idx_sessions_updated     ON sessions (updated_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_sessions_archived    ON sessions (archived, updated_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_sessions_search      ON sessions USING GIN (search_vec)",
    "CREATE INDEX IF NOT EXISTS idx_sessions_title_trgm  ON sessions USING GIN (title gin_trgm_ops)",
    "CREATE INDEX IF NOT EXISTS idx_session_members_sess ON session_members (session_id)",
    "CREATE INDEX IF NOT EXISTS idx_session_members_user ON session_members (user_id)",
    "CREATE INDEX IF NOT EXISTS idx_share_tokens_session ON share_tokens (session_id)",
    "CREATE INDEX IF NOT EXISTS idx_invitations_invitee  ON session_invitations (invitee_id, status)",
    "CREATE INDEX IF NOT EXISTS idx_invitations_session  ON session_invitations (session_id)",
]


async def get_pool() -> asyncpg.Pool:
    global _pool
    if _pool is None:
        _pool = await asyncpg.create_pool(
            dsn=config.DATABASE_URL,
            min_size=1,
            max_size=5,
            command_timeout=30,
        )
        _logger.info("PostgreSQL pool created")
    return _pool


async def close_pool() -> None:
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None
        _logger.info("PostgreSQL pool closed")


async def init_schema() -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            for sql in _DDL_STEPS:
                await conn.execute(sql)
    _logger.info("Database schema ready")


@asynccontextmanager
async def lifespan(_server):
    await init_schema()
    _logger.info("Session store ready")
    try:
        yield
    finally:
        await close_pool()
