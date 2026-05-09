"""
OAuth 2.0 Authorization Server — MCP spec compliant.

Endpoints:
  GET  /.well-known/oauth-authorization-server
  GET  /.well-known/oauth-protected-resource
  POST /oauth/register   — dynamic client registration (RFC 7591)
  GET  /oauth/authorize  — show login form
  POST /oauth/authorize  — process login, issue code, redirect
  POST /oauth/token      — exchange code for Bearer token
  POST /oauth/revoke     — revoke token

PKCE S256 required for all authorization code flows.
"""

import logging
import secrets
import urllib.parse

from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response
from starlette.routing import Route

import config
from auth.store import (
    authenticate_user,
    create_oauth_code,
    exchange_oauth_code,
    create_token,
    create_oauth_session,
    validate_oauth_session,
    _detect_client,
)

_logger = logging.getLogger("session-ai-mcp.oauth")

BASE = config.MCP_EXTERNAL_URL.rstrip("/")


def _esc(s: str) -> str:
    return (s.replace("&", "&amp;").replace('"', "&quot;")
             .replace("<", "&lt;").replace(">", "&gt;"))


def _build_redirect(uri: str, params: dict) -> str:
    return uri + ("&" if "?" in uri else "?") + urllib.parse.urlencode(params)


# ---------------------------------------------------------------------------
# Discovery endpoints
# ---------------------------------------------------------------------------

async def well_known_server(request: Request) -> JSONResponse:
    return JSONResponse({
        "issuer": BASE,
        "authorization_endpoint": f"{BASE}/oauth/authorize",
        "token_endpoint": f"{BASE}/oauth/token",
        "registration_endpoint": f"{BASE}/oauth/register",
        "revocation_endpoint": f"{BASE}/oauth/revoke",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
    })


async def well_known_resource(request: Request) -> JSONResponse:
    return JSONResponse({
        "resource": BASE,
        "authorization_servers": [BASE],
        "bearer_methods_supported": ["header", "query"],
    })


# ---------------------------------------------------------------------------
# Dynamic client registration (RFC 7591) — stateless, public clients only
# ---------------------------------------------------------------------------

async def oauth_register(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid_request"}, status_code=400)

    client_id = secrets.token_urlsafe(16)
    redirect_uris = body.get("redirect_uris", [])
    client_name = body.get("client_name", "MCP Client")

    return JSONResponse({
        "client_id": client_id,
        "client_name": client_name,
        "redirect_uris": redirect_uris,
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    }, status_code=201)


# ---------------------------------------------------------------------------
# HTML templates
# ---------------------------------------------------------------------------

_STYLE = """
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
       background: #f8fafc; display: flex; min-height: 100vh;
       align-items: center; justify-content: center; }
.card { background: #fff; border: 1px solid #e2e8f0; border-radius: 16px;
        padding: 40px; width: 100%; max-width: 400px; box-shadow: 0 4px 24px rgba(0,0,0,.06); }
.logo { font-size: 13px; font-weight: 700; color: #64748b; letter-spacing: .08em;
        text-transform: uppercase; margin-bottom: 24px; }
h1 { font-size: 22px; font-weight: 700; color: #0f172a; margin-bottom: 6px; }
.sub { font-size: 14px; color: #64748b; margin-bottom: 28px; }
.sub strong { color: #0f172a; }
label { display: block; font-size: 13px; font-weight: 500; color: #374151; margin-bottom: 5px; }
input[type=text], input[type=email], input[type=password] {
  width: 100%; padding: 10px 12px; border: 1px solid #d1d5db; border-radius: 8px;
  font-size: 14px; outline: none; transition: border-color .15s; margin-bottom: 16px; }
input:focus { border-color: #3b82f6; box-shadow: 0 0 0 3px rgba(59,130,246,.15); }
.btn { width: 100%; padding: 11px; border: none; border-radius: 8px; font-size: 14px;
       font-weight: 600; cursor: pointer; transition: background .15s; }
.btn-primary { background: #2563eb; color: #fff; margin-bottom: 10px; }
.btn-primary:hover { background: #1d4ed8; }
.btn-secondary { background: #f1f5f9; color: #475569; }
.btn-secondary:hover { background: #e2e8f0; }
.error { background: #fef2f2; border: 1px solid #fecaca; color: #dc2626;
         border-radius: 8px; padding: 10px 14px; font-size: 13px; margin-bottom: 16px; }
.scope-box { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px;
             padding: 12px 14px; margin-bottom: 20px; font-size: 13px; color: #475569; }
.user-badge { display: flex; align-items: center; gap: 10px; background: #f0fdf4;
              border: 1px solid #bbf7d0; border-radius: 8px; padding: 10px 14px;
              margin-bottom: 20px; font-size: 13px; color: #166534; }
.avatar { width: 28px; height: 28px; border-radius: 50%; background: #16a34a;
          color: #fff; display: flex; align-items: center; justify-content: center;
          font-size: 12px; font-weight: 700; flex-shrink: 0; }
.divider { display: flex; align-items: center; gap: 10px; margin-bottom: 16px; }
.divider::before, .divider::after { content: ''; flex: 1; border-top: 1px solid #e2e8f0; }
.divider span { font-size: 12px; color: #94a3b8; }
"""

_PREAUTH_HTML = """<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Authorize — {app_name}</title><style>{style}</style></head>
<body><div class="card">
  <div class="logo">{app_name}</div>
  <h1>Authorize Access</h1>
  <p class="sub"><strong>{client_name}</strong> is requesting access to your account.</p>
  <div class="user-badge">
    <div class="avatar">{initial}</div>
    <div>Signed in as <strong>{username}</strong></div>
  </div>
  <div class="scope-box"><strong>Permissions:</strong><br/>Full MCP access (read + write sessions)</div>
  <form method="POST">
    <input type="hidden" name="client_id" value="{client_id}"/>
    <input type="hidden" name="redirect_uri" value="{redirect_uri}"/>
    <input type="hidden" name="code_challenge" value="{code_challenge}"/>
    <input type="hidden" name="state" value="{state}"/>
    <input type="hidden" name="action" value="preauth"/>
    <button class="btn btn-primary" type="submit">Authorize</button>
    <button class="btn btn-secondary" type="button" onclick="window.location='{cancel_url}'">Cancel</button>
  </form>
</div></body></html>"""

_LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Authorize — {app_name}</title><style>{style}</style></head>
<body><div class="card">
  <div class="logo">{app_name}</div>
  <h1>Authorize Access</h1>
  <p class="sub"><strong>{client_name}</strong> is requesting access to your account.</p>
  {error_html}
  <div class="scope-box"><strong>Permissions:</strong><br/>Full MCP access (read + write sessions)</div>
  <form method="POST" id="authForm">
    <input type="hidden" name="client_id" value="{client_id}"/>
    <input type="hidden" name="redirect_uri" value="{redirect_uri}"/>
    <input type="hidden" name="code_challenge" value="{code_challenge}"/>
    <input type="hidden" name="state" value="{state}"/>
    <input type="hidden" name="action" value="login"/>
    <label for="email">Email</label>
    <input id="email" name="email" type="email" autocomplete="email" placeholder="you@example.com"/>
    <label for="password">Password</label>
    <input id="password" name="password" type="password" autocomplete="current-password" placeholder="••••••••"/>
    <button class="btn btn-primary" type="submit">Authorize</button>
    <button class="btn btn-secondary" type="button" onclick="window.location='{cancel_url}'">Cancel</button>
  </form>
  <p style="text-align:center;font-size:12px;color:#94a3b8;margin-top:16px">
    No account? <a href="{register_url}" style="color:#3b82f6;text-decoration:none">Register</a>
  </p>
</div></body></html>"""


# ---------------------------------------------------------------------------
# Authorization endpoint
# ---------------------------------------------------------------------------

async def oauth_authorize_get(request: Request) -> Response:
    p = request.query_params
    client_id = p.get("client_id", "")
    redirect_uri = p.get("redirect_uri", "")
    code_challenge = p.get("code_challenge", "")
    code_challenge_method = p.get("code_challenge_method", "S256")
    state = p.get("state", "")
    client_name = p.get("client_name", "")

    if not redirect_uri or not code_challenge or code_challenge_method != "S256":
        return JSONResponse(
            {"error": "invalid_request", "error_description": "Missing required params or unsupported challenge method"},
            status_code=400,
        )

    cancel_url = _build_redirect(redirect_uri, {"error": "access_denied", "state": state})

    session_token = request.cookies.get("ai_mcp_session", "")
    if session_token:
        user = await validate_oauth_session(session_token)
        if user:
            return HTMLResponse(_PREAUTH_HTML.format(
                style=_STYLE, app_name=_esc(config.APP_NAME),
                client_id=_esc(client_id), redirect_uri=_esc(redirect_uri),
                code_challenge=_esc(code_challenge), state=_esc(state),
                client_name=_esc(client_name),
                username=_esc(user["username"]),
                initial=_esc(user["username"][0].upper()),
                cancel_url=_esc(cancel_url),
            ))

    return HTMLResponse(_LOGIN_HTML.format(
        style=_STYLE, app_name=_esc(config.APP_NAME),
        client_id=_esc(client_id), redirect_uri=_esc(redirect_uri),
        code_challenge=_esc(code_challenge), state=_esc(state),
        client_name=_esc(client_name), error_html="",
        cancel_url=_esc(cancel_url),
        register_url=_esc(f"{BASE}/panel/web/register"),
    ))


async def oauth_authorize_post(request: Request) -> Response:
    from starlette.responses import RedirectResponse

    form = await request.form()
    client_id = str(form.get("client_id", ""))
    redirect_uri = str(form.get("redirect_uri", ""))
    code_challenge = str(form.get("code_challenge", ""))
    state = str(form.get("state", ""))
    action = str(form.get("action", "login"))
    client_name = str(form.get("client_name", ""))

    cancel_url = _build_redirect(redirect_uri, {"error": "access_denied", "state": state})

    def _error(msg: str) -> HTMLResponse:
        return HTMLResponse(_LOGIN_HTML.format(
            style=_STYLE, app_name=_esc(config.APP_NAME),
            client_id=_esc(client_id), redirect_uri=_esc(redirect_uri),
            code_challenge=_esc(code_challenge), state=_esc(state),
            client_name=_esc(client_name),
            error_html=f'<div class="error">{_esc(msg)}</div>',
            cancel_url=_esc(cancel_url),
            register_url=_esc(f"{BASE}/panel/web/register"),
        ), status_code=400)

    if action == "preauth":
        session_token = request.cookies.get("ai_mcp_session", "")
        user = await validate_oauth_session(session_token) if session_token else None
        if not user:
            return _error("Session expired. Please log in again.")
        code = await create_oauth_code(user["id"], client_id, redirect_uri, code_challenge, client_name)
        return RedirectResponse(_build_redirect(redirect_uri, {"code": code, "state": state}), status_code=302)

    email = str(form.get("email", "")).strip()
    password = str(form.get("password", ""))

    if not email:
        return _error("Email is required.")
    if not password:
        return _error("Password is required.")

    user = await authenticate_user(email, password)
    if not user:
        return _error("Invalid credentials. Please try again.")

    code = await create_oauth_code(user["id"], client_id, redirect_uri, code_challenge, client_name)
    session_tok = await create_oauth_session(user["id"])

    response = RedirectResponse(_build_redirect(redirect_uri, {"code": code, "state": state}), status_code=302)
    response.set_cookie(
        "ai_mcp_session", session_tok,
        max_age=7 * 24 * 3600,
        httponly=True,
        samesite="lax",
        secure=BASE.startswith("https://"),
    )
    return response


# ---------------------------------------------------------------------------
# Token endpoint
# ---------------------------------------------------------------------------

async def oauth_token(request: Request) -> JSONResponse:
    try:
        form = await request.form()
    except Exception:
        return JSONResponse({"error": "invalid_request"}, status_code=400)

    grant_type = str(form.get("grant_type", ""))
    if grant_type != "authorization_code":
        return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)

    code = str(form.get("code", ""))
    redirect_uri = str(form.get("redirect_uri", ""))
    code_verifier = str(form.get("code_verifier", ""))

    if not code or not redirect_uri or not code_verifier:
        return JSONResponse({"error": "invalid_request", "error_description": "Missing required parameters"}, status_code=400)

    user = await exchange_oauth_code(code, code_verifier, redirect_uri)
    if not user:
        return JSONResponse({"error": "invalid_grant", "error_description": "Invalid or expired authorization code"}, status_code=400)

    # Capture client info for token metadata
    raw_client_name = str(form.get("client_name", ""))
    user_agent = request.headers.get("user-agent", "")
    client_ip = (
        request.headers.get("x-real-ip")
        or request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        or (request.client.host if request.client else "")
    )
    # Use redirect_uri + stored client_name from oauth_codes for accurate detection
    oauth_redirect_uri = user.get("oauth_redirect_uri", "")
    oauth_client_name = user.get("oauth_client_name", "") or raw_client_name
    detected_client = _detect_client(oauth_redirect_uri, oauth_client_name, user_agent)

    raw_token = await create_token(
        user["id"],
        name="OAuth Token",
        client_name=detected_client,
        created_ip=client_ip,
    )
    return JSONResponse({
        "access_token": raw_token,
        "token_type": "Bearer",
        "expires_in": config.TOKEN_TTL_SECONDS,
    })


# ---------------------------------------------------------------------------
# Revoke endpoint
# ---------------------------------------------------------------------------

async def oauth_revoke(request: Request) -> Response:
    return JSONResponse({}, status_code=200)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

routes = [
    Route("/.well-known/oauth-authorization-server", well_known_server),
    Route("/.well-known/oauth-protected-resource", well_known_resource),
    Route("/oauth/register", oauth_register, methods=["POST"]),
    Route("/oauth/authorize", oauth_authorize_get, methods=["GET"]),
    Route("/oauth/authorize", oauth_authorize_post, methods=["POST"]),
    Route("/oauth/token", oauth_token, methods=["POST"]),
    Route("/oauth/revoke", oauth_revoke, methods=["POST"]),
]
