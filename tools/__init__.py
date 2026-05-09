from mcp.server.fastmcp import FastMCP
from tools.sessions import register as register_sessions


def register_all(mcp: FastMCP) -> None:
    register_sessions(mcp)
