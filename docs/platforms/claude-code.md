# Claude Code

Claude Code supports remote MCP servers over HTTP with OAuth.

```bash
claude mcp add --transport http universal-code-agent https://YOUR-HOST/mcp
```
Then inside Claude Code run `/mcp`, select the server and choose **Authenticate**. A browser opens your Universal-Code-Agent consent page; sign in with GitHub and approve the scopes.

Local (no OAuth, runs as your OS user inside an isolated workspace directory):
```bash
claude mcp add universal-code-agent -- node /path/to/dist/src/cli.js stdio
```
**Limits:** stdio mode has a single local user and no OAuth. Approvals for sensitive operations are shown in the dashboard (`/`), or set `UCA_REQUIRE_APPROVAL=false` only on a machine you fully trust.
