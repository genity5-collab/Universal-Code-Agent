import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { UserContext } from "../types.js";
import { TOOLS, runTool, type ToolDeps, type ToolScope } from "./tools.js";
import { CS_TOOLS } from "../codespace/tools.js";
import { PROVIDER_TOOLS } from "../providers/tools.js";

/** All tools: core + Codespace tools (the latter only when the server has a broker). */
export function allTools(deps: ToolDeps) { return [...TOOLS, ...(deps.broker ? CS_TOOLS : []), ...((deps as any).vault ? PROVIDER_TOOLS : [])]; }

/** Build an MCP server exposing only the tools the caller's granted scopes allow. */
export function buildMcpServer(ctx: UserContext, deps: ToolDeps, scopes: string[]): McpServer {
  const server = new McpServer({ name: "universal-code-agent", version: "0.1.0" }, {
    instructions: "Coding-agent tools for the user's own GitHub repositories and isolated workspace. Inspect before editing, use edit_file for changes, run tests, and report results honestly. Sensitive actions need human approval in the dashboard." + (deps.broker ? " For a real Linux VM, attach a GitHub Codespace (codespaces_attach) and use the cs_* tools: cs_exec, cs_read_file, cs_write_file, cs_git, etc." : ""),
  });
  const allowed = new Set(scopes);
  const has = (s: ToolScope) => allowed.has(s) || allowed.has("mcp:admin");
  for (const t of allTools(deps)) {
    if (!has(t.scope)) continue;
    server.registerTool(t.name, {
      title: t.title,
      description: t.description,
      inputSchema: t.shape,
      annotations: { readOnlyHint: t.readOnly, destructiveHint: !!t.destructive, openWorldHint: t.name.startsWith("github_") || t.name.startsWith("codespaces_") },
    }, async (args: unknown) => runTool(t, args, ctx, deps) as any);
  }
  return server;
}
