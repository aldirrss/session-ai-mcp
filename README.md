# SESSION AI MCP

A lightweight MCP (Model Context Protocol) server for session continuity — persist and resume project context across Claude conversations.

Built as a focused simplification of [session-mcp-server](../session-mcp-server), with no skill library, no team management, no config management, and no GitHub integration. Just clean session storage with a user-facing web portal.

---

## Features

- **5 MCP tools** — `session_create`, `session_write`, `session_read`, `session_list`, `user_me`
- **Pure OAuth 2.0** — PKCE S256, no API key fallback; users must authenticate via browser
- **Session sharing** — invite registered users for read-write access, or generate a public read-only link
- **Web portal** — manage sessions, members, and tokens without touching the CLI
- **PostgreSQL-backed** — full-text search, pinning, archiving, auto-indexed
- **Works with** Claude Code CLI, Claude Web, and any MCP-compatible client

---

## How It Works

```
Claude CLI / Claude Web
        │
        │  MCP over HTTP (Bearer token)
        ▼
  session-ai-mcp server
  ├── OAuth 2.0 (authorize, token, revoke)
  ├── UserAuthMiddleware (validates token per request)
  ├── MCP Tools (5 tools)
  └── Web UI (Jinja2, session management)
        │
        ▼
    PostgreSQL
```

Users log in via the web portal, receive an OAuth token, and connect their CLI using that token. Sessions are stored in PostgreSQL and accessible across any client.

---

## Quick Start

### Prerequisites

- Docker + Docker Compose
- A domain with HTTPS (or localhost for development)

### 1. Clone and configure

```bash
git clone https://github.com/youruser/session-ai-mcp
cd session-ai-mcp
cp .env.example .env
```

Edit `.env`:

```env
DATABASE_URL=postgresql://mcp:changeme@db:5432/session_ai_mcp
MCP_EXTERNAL_URL=https://mcp.yourdomain.com
POSTGRES_PASSWORD=changeme
```

### 2. Start the server

```bash
docker-compose up -d
```

The server starts on port `8765`. Point your reverse proxy (Nginx, Caddy, Cloudflare Tunnel) to this port.

### 3. Register an account

Open `https://mcp.yourdomain.com/panel/web/register` and create your account.

### 4. Connect Claude Code CLI

```bash
claude mcp add --transport http session-ai https://mcp.yourdomain.com/mcp
```

Claude Code will open a browser window for OAuth authorization. After approving, a Bearer token is stored and the CLI is connected.

---

## MCP Tools

All tools require authentication. Connect your CLI via OAuth first.

### `session_create`

Create a new session. Returns a UUID to use in subsequent calls.

```
session_create(
  title: "My Project",
  content: "Optional initial context"
)
```

**Returns:** Session UUID, title, and creation timestamp.

---

### `session_write`

Overwrite the full content of a session. Always include all previous decisions — this replaces the entire content.

```
session_write(
  session_id: "uuid-here",
  content: """
## Project
Building a FastAPI service for order management.

## Stack
Python 3.12, FastAPI, PostgreSQL, deployed on Railway.

## Decisions
- Chose FastAPI over Django for lighter footprint
- PostgreSQL over SQLite for concurrent access under load

## Status & Next Steps
- [x] Database schema designed
- [ ] Implement order creation endpoint
- [ ] Add authentication middleware
"""
)
```

**Returns:** Confirmation with updated timestamp.

---

### `session_read`

Read the full content of a session. Use at the start of a conversation to restore context.

```
session_read(session_id: "uuid-here")
```

**Returns:** Session title, metadata, and full content.

---

### `session_list`

List all sessions you own plus sessions shared with you. Pinned sessions appear first.

```
session_list(show_archived: false)
```

**Returns:** Table of sessions with ID, title, owner, flags, and last updated date.

---

### `user_me`

Return info about the currently authenticated user.

```
user_me()
```

**Returns:** Username, email, and user ID.

---

## Web Portal

The web portal is available at `https://mcp.yourdomain.com/panel/web/`.

| Route | Description |
|---|---|
| `/panel/web/login` | Sign in to the portal |
| `/panel/web/register` | Create a new account |
| `/panel/web/sessions` | Dashboard — list and search sessions |
| `/panel/web/sessions/{id}` | Session detail — view, rename, manage sharing |
| `/panel/web/account` | View profile and manage active OAuth tokens |
| `/s/{token}` | Public read-only view (no login required) |

### Session Management

From the session detail page, the session owner can:

- **Rename** the session title
- **Pin** — keeps session at the top of the list and protects it
- **Archive** — soft-delete; hidden from list but recoverable
- **Delete** — permanently removes the session
- **Invite members** — share read-write access with other registered users (by email)
- **Remove members** — revoke a member's access
- **Generate public link** — creates a `/s/{token}` URL for read-only sharing with anyone
- **Revoke public link** — invalidates the public URL

---

## Session Content Convention

Since `session_write` fully overwrites content, Claude is responsible for carrying forward all previous context on each write. Use this structure:

```markdown
## Project
[Brief description — what are we building and why]

## Stack
[Technologies, frameworks, infrastructure]

## Decisions
- [Decision 1 — include the reasoning]
- [Decision 2 — include the reasoning]

## Key Code Snippets (if applicable)
[Only include code where the implementation choice is non-obvious]

## Status & Next Steps
- [x] Completed task
- [ ] Pending task
```

This ensures any future conversation can `session_read` and immediately understand the full project state.

---

## Authentication Flow

This server implements OAuth 2.0 with PKCE S256, compliant with the MCP specification.

```
1. Claude Code CLI → GET /oauth/authorize (opens browser)
2. User logs in at the web portal
3. Server issues authorization code
4. CLI exchanges code + PKCE verifier → POST /oauth/token
5. Server returns Bearer token (valid for TOKEN_TTL_DAYS, default 30 days)
6. CLI sends Bearer token in Authorization header on all MCP requests
```

**Discovery endpoints** (used automatically by MCP clients):
- `GET /.well-known/oauth-authorization-server`
- `GET /.well-known/oauth-protected-resource`

---

## Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `DATABASE_URL` | Yes | — | PostgreSQL connection string |
| `MCP_EXTERNAL_URL` | Yes | `http://localhost:8765` | Public URL of this server |
| `MCP_HOST` | No | `0.0.0.0` | Bind address |
| `MCP_PORT` | No | `8765` | Port to listen on |
| `TOKEN_TTL_DAYS` | No | `30` | OAuth token lifetime in days |
| `APP_NAME` | No | `session-ai-mcp` | Display name |
| `MCP_ALLOWED_ORIGINS` | No | _(derived from URL)_ | Extra allowed hostnames, comma-separated |
| `POSTGRES_PASSWORD` | No | `changeme` | PostgreSQL password (docker-compose only) |

---

## Database Schema

```
users           — registered user accounts
user_tokens     — OAuth Bearer tokens (hashed)
oauth_codes     — short-lived PKCE authorization codes
oauth_sessions  — browser login sessions (cookie-based)
sessions        — session records with full-text search index
session_members — read-write sharing between users
share_tokens    — public read-only links
```

Schema is initialized automatically on first startup via idempotent DDL — no migration tool required.

---

## Deployment

### Reverse Proxy (Nginx example)

```nginx
server {
    listen 443 ssl;
    server_name mcp.yourdomain.com;

    location / {
        proxy_pass http://127.0.0.1:8765;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 3600;
    }
}
```

### Cloudflare Tunnel

```bash
cloudflared tunnel --url http://localhost:8765
```

Set `MCP_EXTERNAL_URL` to the tunnel's public URL.

---

## Development

```bash
# Install dependencies
pip install -r requirements.txt

# Set environment variables
export DATABASE_URL=postgresql://user:pass@localhost:5432/session_ai_mcp
export MCP_EXTERNAL_URL=http://localhost:8765

# Run
python server.py
```

---

## Comparison with session-mcp-server

| Feature | session-mcp-server | session-ai-mcp |
|---|---|---|
| MCP tools | 21 | 5 |
| Skill library | Yes | No |
| Team sessions | Yes | No |
| Session append / notes | Yes | No |
| Config management | Yes | No |
| GitHub integration | Yes | No |
| API Key auth | Yes (fallback) | No |
| OAuth 2.0 | Yes | Yes |
| Session sharing | No | Yes |
| Web portal | Minimal | Full |

---

## License

MIT
