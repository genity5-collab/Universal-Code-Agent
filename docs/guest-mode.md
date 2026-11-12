# Guest mode (zero setup)

If you do not set `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET`, the server runs in **guest mode**. Nobody needs a GitHub OAuth app, an API key or an account.

## For you (the person using it)
1. Open `/setup`, copy the connector link.
2. Add it as a custom MCP connector in your AI app.
3. Tap **Allow** on the page that opens.

You get a private guest workspace (your own folder on the server). The dashboard works too: open the site and tap **Continue as guest**.

## What works in guest mode
- Files, search, edit, git on local folders, running commands and tests in your workspace.
- Cloud VM providers (Fly.io, DigitalOcean, Hetzner, Render, Freestyle, any): paste a key in the app, memory only. See [providers.md](providers.md).
- Approvals for risky actions, in the app.

## What is off
- GitHub repos, pull requests, Codespaces. They need GitHub sign-in. The AI is told this plainly instead of failing mysteriously.

## Limits and honest risks
- **A guest is identified by a browser cookie / the AI connection.** Clear your cookies or revoke the connector and you lose that workspace's link to you. There is no password and no recovery.
- **The server is shared.** Guest folders are separated and path traversal is blocked (tested), but guests run commands as the same OS user. Use a container, and do not put secrets in a guest workspace. Do not host guest mode for people you do not trust.
- **Anyone with the server link can create a guest**, up to `UCA_MAX_GUESTS` (default 5), with a login rate limit. If you do not want that, set `UCA_ALLOW_GUESTS=false`, or configure GitHub sign-in (which turns guest mode off by default).
- Risky commands (installs, deletes, pushes, network tools) wait for approval, and destructive ones are blocked. But **a guest approves their own requests**, so approval is a safety net against AI mistakes, not a barrier against a hostile guest. That is why the default cap is small (5) and why this is meant for you and people you trust.

## Settings
| Variable | Default | Meaning |
|---|---|---|
| `UCA_ALLOW_GUESTS` | on only if GitHub OAuth is not configured | `true` or `false` to force |
| `UCA_MAX_GUESTS` | 5 | cap on guest accounts |
