import logging

from mcp.server.fastmcp import FastMCP

from .store import create_session, write_session, read_session, list_sessions
from .models import SessionCreateInput, SessionWriteInput, SessionReadInput, SessionListInput
from auth.context import get_current_user

_logger = logging.getLogger("session-ai-mcp.sessions")


def _error(msg: str) -> str:
    _logger.error(msg)
    return f"Error: {msg}"


def register(mcp: FastMCP) -> None:

    @mcp.tool(
        name="session_create",
        annotations={
            "title": "Create Session",
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": False,
            "openWorldHint": False,
        },
    )
    async def _session_create(params: SessionCreateInput) -> str:
        """
        Create a new session and return its ID.

        Call this at the start of a new project or topic to get a session ID.
        Save the returned ID — you will use it with session_write and session_read.

        Args:
            params.title: Short human-readable title (e.g. 'MCP Server Build').
            params.content: Optional initial context.
        """
        try:
            session = await create_session(params.title, params.content)
            return (
                f"Session created.\n"
                f"**ID:** `{session['id']}`\n"
                f"**Title:** {session['title']}\n"
                f"**Created:** {session['created_at']}\n\n"
                f"Use `session_write` with this ID to update context as work progresses."
            )
        except Exception as e:
            return _error(str(e))

    @mcp.tool(
        name="session_write",
        annotations={
            "title": "Update Session Content",
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    )
    async def _session_write(params: SessionWriteInput) -> str:
        """
        Overwrite the full content of a session.

        Use this whenever an important decision is made or the project state changes.
        Always include ALL previous context and decisions in the new content —
        this completely replaces the stored content.

        Recommended content structure:
        ## Project
        [brief description]

        ## Stack
        [technologies]

        ## Decisions
        - [decision 1]
        - [decision 2]

        ## Status & Next Steps
        - [ ] [next task]

        Args:
            params.session_id: UUID returned by session_create.
            params.content: Full updated content (markdown).
        """
        try:
            session = await write_session(params.session_id, params.content)
            if session is None:
                return _error(f"Session '{params.session_id}' not found or access denied.")
            return (
                f"Session `{params.session_id}` updated.\n"
                f"**Title:** {session['title']}\n"
                f"**Updated:** {session['updated_at']}"
            )
        except Exception as e:
            return _error(str(e))

    @mcp.tool(
        name="session_read",
        annotations={
            "title": "Read Session Content",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    )
    async def _session_read(params: SessionReadInput) -> str:
        """
        Read the full content of a session.

        Use this at the start of a conversation to restore context from a previous session.

        Args:
            params.session_id: UUID of the session to read.
        """
        try:
            session = await read_session(params.session_id)
            if session is None:
                return f"Session `{params.session_id}` not found or access denied."

            pin_marker = " [PINNED]" if session.get("pinned") else ""
            archived_marker = " [ARCHIVED]" if session.get("archived") else ""

            lines = [
                f"# Session: {session['title']}{pin_marker}{archived_marker}",
                f"**ID:** `{session['id']}`",
                f"**Created:** {session['created_at']} | **Updated:** {session['updated_at']}",
                "---",
                session["content"] or "*No content yet.*",
            ]
            return "\n".join(lines)
        except Exception as e:
            return _error(str(e))

    @mcp.tool(
        name="session_list",
        annotations={
            "title": "List Sessions",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    )
    async def _session_list(params: SessionListInput) -> str:
        """
        List all sessions you own or have been invited to.

        Pinned sessions appear first. Use the returned IDs with session_read.

        Args:
            params.show_archived: Include archived sessions (default false).
        """
        try:
            sessions = await list_sessions(show_archived=params.show_archived)
            if not sessions:
                return "No sessions found."

            lines = [
                f"## Your Sessions ({len(sessions)} total)",
                "",
                "| ID | Title | Owner | Flags | Updated |",
                "|----|-------|-------|-------|---------|",
            ]
            for s in sessions:
                flags = " ".join(filter(None, [
                    "PINNED" if s.get("pinned") else "",
                    "ARCHIVED" if s.get("archived") else "",
                    "" if s.get("is_owner") else "SHARED",
                ]))
                lines.append(
                    f"| `{s['id']}` | {s['title']} | {s.get('owner_username', '-')} "
                    f"| {flags or '-'} | {s['updated_at'][:10]} |"
                )
            return "\n".join(lines)
        except Exception as e:
            return _error(str(e))

    @mcp.tool(
        name="user_me",
        annotations={
            "title": "Get Current User",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    )
    async def _user_me() -> str:
        """Return info about the currently authenticated user."""
        user = get_current_user()
        if not user:
            return "Not authenticated."
        return (
            f"**Username:** {user['username']}\n"
            f"**Email:** {user['email']}\n"
            f"**ID:** `{user['id']}`"
        )
