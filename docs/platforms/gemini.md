# Gemini and other MCP clients

Gemini does not have one universal consumer MCP connector. MCP support exists in **developer tools** (for example Gemini CLI and Gemini Code Assist agent mode), configured in their settings file.

Gemini CLI example (`~/.gemini/settings.json`):
```json
{ "mcpServers": { "universal-code-agent": { "httpUrl": "https://YOUR-HOST/mcp" } } }
```
Local stdio:
```json
{ "mcpServers": { "universal-code-agent": { "command": "node", "args": ["/path/to/dist/src/cli.js", "stdio"] } } }
```
**Limits:** the Gemini consumer chat app may not accept custom MCP servers. OAuth support depends on the client version. Verify with your client's docs. Any client that speaks MCP Streamable HTTP works the same way.
