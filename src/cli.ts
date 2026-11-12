#!/usr/bin/env node
import { loadConfig } from "./util/config.js";
import { createApp } from "./http/app.js";
import { runStdio } from "./mcp/stdio.js";
import { installShutdownHandlers } from "./exec/runner.js";

const cmd = process.argv[2] ?? "http";
if (cmd === "stdio") {
  runStdio().catch((e) => { console.error(e); process.exit(1); });
} else if (cmd === "http") {
  const config = loadConfig();
  if (!config.githubClientId || !config.githubClientSecret) console.error("WARNING: GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET not set; GitHub login will not work.");
  installShutdownHandlers();
  const app = createApp(config);
  app.server.listen(config.port, () => console.error(`universal-code-agent listening on ${config.baseUrl} (MCP at ${config.baseUrl}/mcp)`));
} else {
  console.error("Usage: universal-code-agent [http|stdio]"); process.exit(2);
}
