# ChatGPT

ChatGPT connects to **remote** MCP servers through Connectors / Developer mode, where your plan and workspace policy allow it. Availability and the exact menus change; check OpenAI's current docs.

1. Deploy this server on a public **HTTPS** URL (see `docs/deploy.md`). ChatGPT cannot reach `localhost`.
2. In ChatGPT enable Developer mode (if required for your plan) and add a custom connector with the URL `https://YOUR-HOST/mcp`.
3. Choose OAuth. ChatGPT discovers `/.well-known/oauth-protected-resource` and registers itself dynamically. You sign in with GitHub and approve.

**Limits (be aware):**
- Custom MCP connectors may be unavailable on some plans or regions, and may be restricted to certain modes.
- ChatGPT may require read-only `search`/`fetch` style tools in some modes; write/exec tools can need Developer mode.
- Each tool call may ask you to confirm in ChatGPT itself, separate from this server's approvals.
- Not tested against a live ChatGPT account in this repository's automated tests; the protocol layer is tested with a real MCP client.
