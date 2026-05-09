# session-ai-mcp — Claude Behavior Instructions

This MCP server provides session continuity — a way to persist and resume project context across conversations.

---

## Session Management

### At the start of every conversation:
1. Call `session_list` to see available sessions.
2. If the user mentions a project, topic, or task that matches a session title,
   call `session_read` with that session ID to restore full context before responding.

### During the conversation:
- Call `session_write` whenever an important decision is made or the project state changes significantly.
- Always include ALL previous context when calling `session_write` — it overwrites the entire content.

### Recommended content format for session_write:
```
## Project
[brief description of what this project is]

## Stack
[technologies, frameworks, services being used]

## Decisions
- [decision 1 — include the why]
- [decision 2 — include the why]

## Potongan Kode Penting (if any)
[only include code snippets where the decision is non-obvious]

## Status & Next Steps
- [ ] [next task]
- [ ] [following task]
```

### When to create a new session:
- Start of a new project or topic that will span multiple conversations
- Call `session_create` with a descriptive title

---

## Tools Reference

| Tool | When to use |
|------|-------------|
| `session_create` | Start of a new project — creates session, returns UUID |
| `session_write`  | After important decisions, before ending a session with unfinished work |
| `session_read`   | Start of conversation — restore context from previous session |
| `session_list`   | Start of conversation — discover available sessions |
| `user_me`        | When you need to know who is currently authenticated |

---

## Rules

- Never include sensitive data (passwords, API keys) in session content.
- Keep session content concise — focus on decisions and current state, not full logs.
- Code snippets in sessions should only be included when the implementation decision is non-obvious.
