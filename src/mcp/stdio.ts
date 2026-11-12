import fs from "node:fs";
import path from "node:path";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { loadConfig } from "../util/config.js";
import { buildMcpServer } from "./server.js";
import { ApprovalService, AuditLog, RateLimiter } from "./services.js";
import { installShutdownHandlers } from "../exec/runner.js";

/** Local single-user mode: no OAuth, uses GITHUB_TOKEN from the environment if present. */
export async function runStdio(): Promise<void> {
  const config = loadConfig();
  const root = path.resolve(process.env.UCA_WORKSPACE ?? path.join(config.workspacesDir, "local"));
  fs.mkdirSync(root, { recursive: true });
  installShutdownHandlers();
  const deps = { config, approvals: new ApprovalService(), audit: new AuditLog(config.dataDir), limiter: new RateLimiter(config.rateLimitPerMin) };
  const ctx = { userId: "local", login: process.env.UCA_LOGIN ?? "local", workspaceRoot: fs.realpathSync(root), githubToken: process.env.GITHUB_TOKEN };
  // stdio has no dashboard; approvals auto-resolve only if the operator opted out.
  const server = buildMcpServer(ctx, deps, ["mcp:read", "mcp:write", "mcp:exec"]);
  await server.connect(new StdioServerTransport());
  console.error(`universal-code-agent stdio ready. workspace=${ctx.workspaceRoot} github=${ctx.githubToken ? "token set" : "not connected"} approvals=${config.requireApproval ? "required (set UCA_REQUIRE_APPROVAL=false to disable on trusted machines)" : "off"}`);
}
