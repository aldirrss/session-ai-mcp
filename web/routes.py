"""
Web UI routes — session management portal for registered users.

All routes are under /web/ prefix except /s/{token} (public share view).
Session auth uses a separate cookie (web_session) distinct from OAuth tokens.
"""

import logging
import os

from jinja2 import Environment, FileSystemLoader
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route

import config
from auth.store import (
    authenticate_user,
    create_user,
    create_oauth_session,
    validate_oauth_session,
    get_user_by_id,
    list_tokens,
    revoke_token,
    delete_token,
)
from tools.sessions.store import (
    list_sessions,
    read_session,
    delete_session,
    set_pinned,
    set_archived,
    update_title,
    get_members,
    add_member,
    remove_member,
    create_share_token,
    revoke_share_token,
    search_sessions_by_user,
    get_session_by_share_token,
    list_invitations,
    get_pending_invitation_count,
    get_pending_invitations_for_session,
    cancel_invitation,
    respond_invitation,
)

_logger = logging.getLogger("session-ai-mcp.web")

_tpl_dir = os.path.join(os.path.dirname(__file__), "templates")
_env = Environment(loader=FileSystemLoader(_tpl_dir), autoescape=True)


def _render(name: str, **ctx) -> HTMLResponse:
    tpl = _env.get_template(name)
    return HTMLResponse(tpl.render(app_name=config.APP_NAME, base_url=config.MCP_EXTERNAL_URL, **ctx))


async def _inbox_count(user: dict) -> int:
    return await get_pending_invitation_count(user["id"])


# ---------------------------------------------------------------------------
# Web session helpers (cookie-based, separate from MCP Bearer tokens)
# ---------------------------------------------------------------------------

_WEB_COOKIE = "ai_mcp_session"


async def _get_web_user(request: Request) -> dict | None:
    token = request.cookies.get(_WEB_COOKIE, "")
    if not token:
        return None
    return await validate_oauth_session(token)


def _redirect_login(next_url: str = "/panel/web/sessions") -> RedirectResponse:
    return RedirectResponse(f"/panel/web/login?next={next_url}", status_code=302)


def _set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        _WEB_COOKIE, token,
        max_age=7 * 24 * 3600,
        httponly=True,
        samesite="lax",
        secure=config.MCP_EXTERNAL_URL.startswith("https://"),
    )


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

async def web_login_get(request: Request) -> Response:
    user = await _get_web_user(request)
    if user:
        return RedirectResponse("/panel/web/sessions", status_code=302)
    error = request.query_params.get("error", "")
    return _render("login.html", error=error, next=request.query_params.get("next", "/panel/web/sessions"))


async def web_login_post(request: Request) -> Response:
    form = await request.form()
    email = str(form.get("email", "")).strip()
    password = str(form.get("password", ""))
    next_url = str(form.get("next", "/panel/web/sessions"))

    if not email or not password:
        return _render("login.html", error="Email and password are required.", next=next_url)

    user = await authenticate_user(email, password)
    if not user:
        return _render("login.html", error="Invalid credentials.", next=next_url)

    token = await create_oauth_session(user["id"])
    response = RedirectResponse(next_url, status_code=302)
    _set_session_cookie(response, token)
    return response


async def web_register_get(request: Request) -> Response:
    user = await _get_web_user(request)
    if user:
        return RedirectResponse("/panel/web/sessions", status_code=302)
    return _render("register.html", error="")


async def web_register_post(request: Request) -> Response:
    form = await request.form()
    username = str(form.get("username", "")).strip()
    email = str(form.get("email", "")).strip()
    password = str(form.get("password", ""))
    confirm = str(form.get("confirm_password", ""))

    if not username or not email or not password:
        return _render("register.html", error="All fields are required.")
    if password != confirm:
        return _render("register.html", error="Passwords do not match.")
    if len(password) < 8:
        return _render("register.html", error="Password must be at least 8 characters.")

    try:
        user = await create_user(username, email, password)
    except Exception:
        return _render("register.html", error="Username or email already taken.")

    token = await create_oauth_session(user["id"])
    response = RedirectResponse("/panel/web/sessions", status_code=302)
    _set_session_cookie(response, token)
    return response


async def web_logout(request: Request) -> Response:
    response = RedirectResponse("/panel/web/login", status_code=302)
    response.delete_cookie(_WEB_COOKIE)
    return response


# ---------------------------------------------------------------------------
# Sessions dashboard
# ---------------------------------------------------------------------------

async def web_sessions(request: Request) -> Response:
    user = await _get_web_user(request)
    if not user:
        return _redirect_login()

    show_archived = request.query_params.get("archived") == "1"
    query = request.query_params.get("q", "").strip()

    from auth.context import set_current_user
    set_current_user(user)
    try:
        if query:
            sessions = await search_sessions_by_user(user["id"], query)
        else:
            sessions = await list_sessions(show_archived=show_archived)
    finally:
        set_current_user(None)

    count = await _inbox_count(user)
    return _render("sessions.html", user=user, sessions=sessions,
                   show_archived=show_archived, query=query,
                   inbox_count=count, active_page="sessions")


async def web_session_detail(request: Request) -> Response:
    user = await _get_web_user(request)
    if not user:
        return _redirect_login(f"/panel/web/sessions/{request.path_params['session_id']}")

    session_id = request.path_params["session_id"]

    from auth.context import set_current_user
    set_current_user(user)
    try:
        session = await read_session(session_id)
    finally:
        set_current_user(None)

    if session is None:
        return _render("404.html", user=user), 404

    is_owner = session["owner_id"] == user["id"]
    members = await get_members(session_id) if is_owner else []
    pending_invites = await get_pending_invitations_for_session(session_id, user["id"]) if is_owner else []

    import db as _db
    pool = await _db.get_pool()
    async with pool.acquire() as conn:
        share_token = await conn.fetchval(
            "SELECT token FROM share_tokens WHERE session_id = $1::uuid", session_id
        )

    flash = request.query_params.get("msg", "")
    count = await _inbox_count(user)
    return _render("session_detail.html", user=user, session=session,
                   is_owner=is_owner, members=members,
                   pending_invites=pending_invites,
                   share_token=share_token,
                   public_url=f"{config.MCP_EXTERNAL_URL}/s/{share_token}" if share_token else None,
                   flash=flash, inbox_count=count, active_page="sessions")


async def web_session_action(request: Request) -> Response:
    """POST handler for session lifecycle actions from detail page."""
    user = await _get_web_user(request)
    if not user:
        return RedirectResponse("/panel/web/login", status_code=302)

    session_id = request.path_params["session_id"]
    form = await request.form()
    action = str(form.get("action", ""))

    if action == "delete":
        await delete_session(session_id, user["id"])
        return RedirectResponse("/panel/web/sessions?msg=deleted", status_code=302)
    elif action == "pin":
        await set_pinned(session_id, user["id"], True)
    elif action == "unpin":
        await set_pinned(session_id, user["id"], False)
    elif action == "archive":
        await set_archived(session_id, user["id"], True)
    elif action == "restore":
        await set_archived(session_id, user["id"], False)
    elif action == "rename":
        title = str(form.get("title", "")).strip()
        if title:
            await update_title(session_id, user["id"], title)
    elif action == "invite":
        email = str(form.get("email", "")).strip()
        if email:
            result = await add_member(session_id, user["id"], email)
            if isinstance(result, str):
                return RedirectResponse(f"/panel/web/sessions/{session_id}?msg={result}", status_code=302)
    elif action == "cancel_invite":
        invitation_id = str(form.get("invitation_id", ""))
        if invitation_id:
            await cancel_invitation(invitation_id, user["id"])
    elif action == "remove_member":
        member_id = str(form.get("member_id", ""))
        if member_id:
            await remove_member(session_id, user["id"], member_id)
    elif action == "share_create":
        await create_share_token(session_id, user["id"])
    elif action == "share_revoke":
        await revoke_share_token(session_id, user["id"])

    return RedirectResponse(f"/panel/web/sessions/{session_id}?msg={action}", status_code=302)


# ---------------------------------------------------------------------------
# Account page
# ---------------------------------------------------------------------------

async def web_account(request: Request) -> Response:
    user = await _get_web_user(request)
    if not user:
        return _redirect_login("/panel/web/account")

    tokens = await list_tokens(user["id"])
    flash = request.query_params.get("msg", "")
    count = await _inbox_count(user)
    return _render("account.html", user=user, tokens=tokens, flash=flash,
                   inbox_count=count, active_page="account")


async def web_account_action(request: Request) -> Response:
    user = await _get_web_user(request)
    if not user:
        return RedirectResponse("/panel/web/login", status_code=302)

    form = await request.form()
    action = str(form.get("action", ""))

    if action == "revoke_token":
        token_id = str(form.get("token_id", ""))
        if token_id:
            await revoke_token(token_id, user["id"])
    elif action == "delete_token":
        token_id = str(form.get("token_id", ""))
        if token_id:
            await delete_token(token_id, user["id"])

    return RedirectResponse("/panel/web/account?msg=done", status_code=302)


# ---------------------------------------------------------------------------
# Inbox
# ---------------------------------------------------------------------------

async def web_inbox(request: Request) -> Response:
    user = await _get_web_user(request)
    if not user:
        return _redirect_login("/panel/web/inbox")

    invitations = await list_invitations(user["id"])
    flash = request.query_params.get("msg", "")
    count = len(invitations)
    return _render("inbox.html", user=user, invitations=invitations, flash=flash,
                   inbox_count=count, active_page="inbox")


async def web_inbox_action(request: Request) -> Response:
    user = await _get_web_user(request)
    if not user:
        return RedirectResponse("/panel/web/login", status_code=302)

    form = await request.form()
    invitation_id = str(form.get("invitation_id", ""))
    action = str(form.get("action", ""))

    if invitation_id and action in ("accept", "decline"):
        await respond_invitation(invitation_id, user["id"], accept=(action == "accept"))

    return RedirectResponse("/panel/web/inbox?msg=done", status_code=302)


# ---------------------------------------------------------------------------
# Public share view (no login required)
# ---------------------------------------------------------------------------

async def web_public_share(request: Request) -> Response:
    token = request.path_params["token"]
    session = await get_session_by_share_token(token)
    if session is None:
        return _render("404.html", user=None)
    return _render("session_public.html", user=None, session=session)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

routes = [
    Route("/panel/web/login",    web_login_get,    methods=["GET"]),
    Route("/panel/web/login",    web_login_post,   methods=["POST"]),
    Route("/panel/web/register", web_register_get, methods=["GET"]),
    Route("/panel/web/register", web_register_post, methods=["POST"]),
    Route("/panel/web/logout",   web_logout,       methods=["GET", "POST"]),

    Route("/panel/web/sessions",                     web_sessions,       methods=["GET"]),
    Route("/panel/web/sessions/{session_id}",        web_session_detail, methods=["GET"]),
    Route("/panel/web/sessions/{session_id}/action", web_session_action, methods=["POST"]),

    Route("/panel/web/account",        web_account,        methods=["GET"]),
    Route("/panel/web/account/action", web_account_action, methods=["POST"]),

    Route("/panel/web/inbox",        web_inbox,        methods=["GET"]),
    Route("/panel/web/inbox/action", web_inbox_action, methods=["POST"]),

    Route("/s/{token}", web_public_share, methods=["GET"]),
]
