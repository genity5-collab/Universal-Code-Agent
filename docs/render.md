# Deploy on Render (easiest)

You need: a free [Render](https://render.com) account and a GitHub account. About 5 minutes.

## 1. Deploy

Click **[Deploy to Render](https://render.com/deploy?repo=https://github.com/genity5-collab/Universal-Code-Agent)**.
Render reads `render.yaml`, builds the Docker image and creates the service with a persistent disk and a random session secret.
It asks for two values, `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET`. Leave them empty for now and continue.

When the deploy finishes you get a URL like `https://universal-code-agent-xxxx.onrender.com`. The server detects it by itself, so there is no `UCA_BASE_URL` to set.

## 2. Let the built-in wizard guide you

Open `https://YOUR-URL/setup`. It shows the exact **callback URL** to paste into GitHub, with a Copy button:

1. Open <https://github.com/settings/applications/new>.
2. Homepage URL = your Render URL. Authorization callback URL = the one the wizard shows.
3. Create the app, then **Generate a new client secret**.
4. In Render, open your service, then **Environment**, and set `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET`. Save. Render restarts the server.
5. Reload `/setup`. Every step turns green. Tap **Sign in with GitHub**.

## 3. Connect your AI

Add `https://YOUR-URL/mcp` as a custom MCP connector in Claude, ChatGPT or Gemini (see `docs/platforms/`). You sign in with GitHub and approve.

## 4. Put it on your phone

Open your URL on your phone:
- **Android / Chrome**: tap **Install** in the banner (or menu, **Install app**).
- **iPhone / Safari**: tap **Share**, then **Add to Home Screen**.

Approvals for risky actions then appear in the app, and you can approve with one tap.

## Plans and limits (read this)

- **The persistent disk needs a paid Render plan** (the blueprint uses `starter`). Without a disk, a restart wipes sign-ins, connected AIs and workspaces, and you must reconnect each time.
- **Free web services sleep after about 15 minutes idle** and take about a minute to wake. An AI client may time out on the first call after a sleep. To try it for free anyway, change `plan: starter` to `plan: free` and delete the `disk:` block in `render.yaml`, and expect the resets above.
- Prices and plan rules change, so check Render's pricing page.
- Commands the AI runs on the server share the server's OS user and are not a VM boundary. For stronger isolation use Codespace mode (`docs/codespaces.md`): the AI's commands then run inside your GitHub Codespace.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `/setup` says "not HTTPS" | You are on a local or `http://` address. Use your `onrender.com` URL. |
| GitHub says "redirect_uri mismatch" | The callback URL in your GitHub OAuth App must be exactly `https://YOUR-URL/auth/github/callback`. |
| Sign-in works but the AI can't connect | Open `https://YOUR-URL/healthz`. If it is slow, the service was asleep, so retry. |
| Everything resets after a deploy | No persistent disk. Use the blueprint on a paid plan. |
| Codespaces list is empty or errors | Sign out and in again so GitHub grants the `codespace` permission. |
