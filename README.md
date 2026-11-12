# Universal Code Agent

One MCP server that lets **Claude, ChatGPT, Gemini and any MCP client** work on your GitHub repositories: read and edit files, search code, run tests in a sandboxed terminal, use git, open PRs, read CI logs and manage Codespaces. No AI API keys are used or stored. You sign in with your own GitHub account.

Includes a **mobile-friendly dashboard** (repos, editor, tasks, terminal, approvals, settings).

## What you get
- **~70 MCP tools**: filesystem (chunked reads, exact edits, diff), code search and symbol index, repo map and dependency graph, sandboxed commands and background jobs, git, GitHub (repos, files, commits, issues, PRs, reviews, discussions, Actions logs, releases, security alerts), Codespaces.
- **OAuth 2.1 for MCP**: dynamic client registration, PKCE (S256 only), refresh rotation with reuse detection, token revocation, scopes `mcp:read`, `mcp:write`, `mcp:exec`.
- **Human approvals** for deletes, pushes, installs and risky commands. Approvals are single use and bound to the exact action.
- **Per-user isolation**: separate workspace directory, separate encrypted GitHub token, audit log.
- Also runs locally over **stdio** (no OAuth).

## Quick start
```bash
npm ci && npm run build
export GITHUB_CLIENT_ID=... GITHUB_CLIENT_SECRET=...   # GitHub OAuth App
export UCA_BASE_URL=https://your-host                   # public HTTPS URL
npm start                                               # MCP at /mcp, dashboard at /
```
GitHub OAuth App callback URL: `<UCA_BASE_URL>/auth/github/callback`.

Connect your AI: see [Claude Code](docs/platforms/claude-code.md), [ChatGPT](docs/platforms/chatgpt.md), [Gemini and others](docs/platforms/gemini.md). Deploy notes: [docs/deploy.md](docs/deploy.md). Agent instructions: [SKILL.md](SKILL.md) and [skills/](skills/).

Local stdio: `claude mcp add universal-code-agent -- node dist/src/cli.js stdio` (uses `GITHUB_TOKEN` from env).

## Honest limitations
- **Not a VM.** Commands run as the server's OS user in a per-user directory with an allowlist policy, no shell, and a scrubbed environment. For untrusted multi-user hosting, run it inside a container or VM, or use Codespaces.
- **Codespaces** uses your GitHub quota and billing. Running commands inside a Codespace is not exposed by GitHub's public REST API; the tool returns the `gh codespace ssh` command instead.
- **Platform support varies.** ChatGPT and Gemini MCP support depends on plan and client version, and was not verified against live accounts here. The protocol layer is tested with the official MCP SDK client.
- GitHub calls are tested against a mock GitHub API, not live GitHub.
- Security alert tools return `available:false` when the feature is disabled or not permitted.

## Tests
`npm test` runs fs, exec, github, auth and end-to-end integration suites.
