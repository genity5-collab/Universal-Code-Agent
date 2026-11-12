#!/usr/bin/env node
import { loadConfig } from "./util/config.js";
import { createApp } from "./http/app.js";
import { runStdio } from "./mcp/stdio.js";
import { installShutdownHandlers, onGracefulShutdown } from "./exec/runner.js";
import { mirrorFromEnv } from "./auth/mirror.js";
import path from "node:path";

const cmd = process.argv[2] ?? "http";
if (cmd === "stdio") {
  runStdio().catch((e) => { console.error(e); process.exit(1); });
} else if (cmd === "http") {
  const config = loadConfig();
  if (!config.githubClientId || !config.githubClientSecret) console.error("WARNING: GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET not set; GitHub login will not work.");
  installShutdownHandlers();
  (async () => {
    // No persistent disk? Restore the encrypted auth state from the private mirror repo BEFORE the store opens,
    // so ChatGPT's connection and your sign-in survive restarts and redeploys.
    let mirror = null;
    try { mirror = mirrorFromEnv(); } catch (e) { console.error("[mirror] disabled: " + (e as Error).message); }
    if (mirror) await mirror.restoreTo(path.join(config.dataDir, "auth-store.json"));
    const app = createApp(config, { mirror });
    app.server.listen(config.port, () => console.error(`universal-code-agent listening on ${config.baseUrl} (MCP at ${config.baseUrl}/mcp)${mirror ? " [state mirror on]" : ""}`));
    if (mirror) onGracefulShutdown(() => mirror!.flush());
  })().catch((e) => { console.error(e); process.exit(1); });
} else {
  console.error("Usage: universal-code-agent [http|stdio]"); process.exit(2);
}
