"""mcp-sentinel: offline risk scanner + lockfile for MCP (Model Context Protocol) client configs.

Zero network calls, zero third-party dependencies. Reads a local MCP config
file (Claude Desktop, Cursor, VS Code, or any client using the same
`mcpServers` shape), flags supply-chain and secret-exposure risk patterns,
and can pin every server (including captured tool schemas) to a lockfile so
silent changes -- the rug-pull attack shape -- fail CI instead of shipping.
"""

__version__ = "0.2.0"
