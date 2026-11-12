# Deploying

Requirements: Node 20+, a public HTTPS URL, a GitHub OAuth App.

1. Create a GitHub OAuth App. Callback URL: `https://YOUR-HOST/auth/github/callback`.
2. Set environment variables:
   - `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`
   - `UCA_BASE_URL=https://YOUR-HOST`
   - `UCA_SESSION_SECRET` (optional; auto-generated and stored 0600 in the data dir if empty)
   - `UCA_DATA_DIR` (persistent volume)
3. `npm ci && npm run build && npm start`.

Isolation note: commands run as the server's OS user inside a per-user directory with a scrubbed environment and an allowlist policy. This is **not** a container or VM boundary. For multi-tenant public hosting run each instance in a container/VM with no secrets mounted. Codespaces gives stronger isolation but uses your GitHub quota.
