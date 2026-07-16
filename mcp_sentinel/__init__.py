"""mcp-sentinel: offline risk scanner for MCP (Model Context Protocol) client configs.

Zero network calls, zero third-party dependencies. Reads a local MCP config
file (Claude Desktop, Cursor, VS Code, or any client using the same
`mcpServers` shape) and flags supply-chain and secret-exposure risk patterns
in how each server entry is launched and configured.
"""

__version__ = "0.1.0"
