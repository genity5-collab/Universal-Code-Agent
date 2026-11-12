import { z } from "zod";
import type { ToolDef, ToolDeps } from "../mcp/tools.js";
import { ApprovalNeeded } from "../mcp/tools.js";
import type { UserContext } from "../types.js";
import { evaluateCommand } from "../exec/policy.js";
import type { CodespaceBroker, AgentOp } from "./broker.js";

/**
 * Tools that run INSIDE the user's GitHub Codespace (a real Linux VM) through the paired agent.
 * They only exist when the server has a broker. Every tool is scoped to the calling user.
 */

export interface CsDeps extends ToolDeps { broker?: CodespaceBroker; publicBaseUrl?: string }

function needApprovalCs(ctx: UserContext, deps: ToolDeps, action: string, detail: string): void {
  if (!deps.config.requireApproval) return;
  const r = deps.approvals.check(ctx.userId, action, detail);
  if (r.state === "approved") return;
  if (r.state === "denied") throw new Error(`The user denied this action: ${action}`);
  throw new ApprovalNeeded(r.id, action);
}

function pick(ctx: UserContext, d: CsDeps, name?: string): string {
  const b = d.broker; if (!b) throw new Error("Codespace support is not enabled on this server");
  const mine = b.list(ctx.userId);
  if (name) {
    if (!mine.some((m) => m.codespace === name)) throw new Error(`Codespace "${name}" is not attached. Use codespaces_attach.`);
    return name;
  }
  const online = mine.filter((m) => m.online);
  if (online.length === 1) return online[0].codespace;
  if (online.length > 1) throw new Error(`Several codespaces are online (${online.map((o) => o.codespace).join(", ")}). Pass "codespace".`);
  if (mine.length === 1) return mine[0].codespace;
  throw new Error("No codespace is attached and online. Use codespaces_attach first.");
}

async function run(ctx: UserContext, d: CsDeps, name: string | undefined, op: AgentOp, args: Record<string, unknown>, timeoutMs?: number): Promise<unknown> {
  const cs = pick(ctx, d, name);
  const r = await d.broker!.submit(ctx.userId, cs, op, args, timeoutMs);
  if (!r.ok) throw new Error(r.error || "codespace job failed");
  return r.data;
}

const cn = z.string().min(1).optional().describe("Codespace name. Optional when you have exactly one online.");
const rel = z.string().min(1).describe("Path relative to the codespace workspace root");

export const CS_TOOLS: ToolDef[] = [
  { name: "cs_info", title: "Codespace VM info", description: "Hostname, OS, CPU, memory, user and workspace root of the Codespace VM.", scope: "mcp:read", readOnly: true, shape: { codespace: cn },
    handler: (a, c, d) => run(c, d as CsDeps, a.codespace, "info", {}, 30_000) },
  { name: "cs_exec", title: "Run command in Codespace", description: "Run a bash command on the Codespace's real Linux VM (cwd = workspace root). Full toolchain: apt/pip/npm/git/docker if the image has them. Dangerous commands need human approval; obviously destructive ones are blocked.", scope: "mcp:exec", readOnly: false,
    shape: { command: z.string().min(1).max(8000), cwd: z.string().optional(), timeoutMs: z.number().int().min(1000).max(600_000).optional(), input: z.string().optional(), codespace: cn },
    handler: async (a, c, d) => {
      const risk = classifyCsCommand(a.command);
      if (risk.level === "deny") throw new Error(`Blocked: ${risk.reason}`);
      if (risk.level === "approval") needApprovalCs(c, d, "cs_exec", `[${a.codespace ?? "codespace"}] ${a.command}`);
      return run(c, d as CsDeps, a.codespace, "exec", { command: a.command, cwd: a.cwd, timeoutMs: a.timeoutMs, input: a.input }, (a.timeoutMs ?? 120_000) + 15_000);
    } },
  { name: "cs_read_file", title: "Read file in Codespace", description: "Read a file (offset/size paging; follow nextOffset until eof).", scope: "mcp:read", readOnly: true,
    shape: { path: rel, offset: z.number().int().min(0).optional(), size: z.number().int().positive().optional(), encoding: z.enum(["utf8", "base64"]).optional(), codespace: cn },
    handler: (a, c, d) => run(c, d as CsDeps, a.codespace, "read_file", { path: a.path, offset: a.offset, size: a.size, encoding: a.encoding }) },
  { name: "cs_write_file", title: "Write file in Codespace", description: "Create or overwrite a file (atomic).", scope: "mcp:write", readOnly: false,
    shape: { path: rel, content: z.string(), encoding: z.enum(["utf8", "base64"]).optional(), overwrite: z.boolean().optional(), createDirs: z.boolean().optional(), mode: z.string().regex(/^[0-7]{3,4}$/).optional(), codespace: cn },
    handler: (a, c, d) => run(c, d as CsDeps, a.codespace, "write_file", { path: a.path, content: a.content, encoding: a.encoding, overwrite: a.overwrite, createDirs: a.createDirs, mode: a.mode }) },
  { name: "cs_list_dir", title: "List directory in Codespace", description: "List a directory.", scope: "mcp:read", readOnly: true,
    shape: { path: z.string().default("."), limit: z.number().int().min(1).max(2000).optional(), offset: z.number().int().min(0).optional(), codespace: cn },
    handler: (a, c, d) => run(c, d as CsDeps, a.codespace, "list_dir", { path: a.path ?? ".", limit: a.limit, offset: a.offset }) },
  { name: "cs_stat", title: "Stat path in Codespace", description: "Type, size, mtime and mode.", scope: "mcp:read", readOnly: true, shape: { path: rel, codespace: cn },
    handler: (a, c, d) => run(c, d as CsDeps, a.codespace, "stat", { path: a.path }) },
  { name: "cs_mkdir", title: "Make directory in Codespace", description: "mkdir -p.", scope: "mcp:write", readOnly: false, shape: { path: rel, codespace: cn },
    handler: (a, c, d) => run(c, d as CsDeps, a.codespace, "mkdir", { path: a.path }) },
  { name: "cs_delete", title: "Delete path in Codespace", description: "Delete a file or directory. Requires approval.", scope: "mcp:write", readOnly: false, destructive: true,
    shape: { path: rel, recursive: z.boolean().optional(), codespace: cn },
    handler: async (a, c, d) => { needApprovalCs(c, d, "cs_delete", `[${a.codespace ?? "codespace"}] delete ${a.path}${a.recursive ? " (recursive)" : ""}`); return run(c, d as CsDeps, a.codespace, "delete", { path: a.path, recursive: a.recursive }); } },
  { name: "cs_search", title: "Search contents in Codespace", description: "grep the workspace (literal by default, regex optional).", scope: "mcp:read", readOnly: true,
    shape: { query: z.string().min(1), regex: z.boolean().optional(), caseSensitive: z.boolean().optional(), path: z.string().optional(), limit: z.number().int().min(1).max(1000).optional(), codespace: cn },
    handler: (a, c, d) => run(c, d as CsDeps, a.codespace, "search", { query: a.query, regex: a.regex, caseSensitive: a.caseSensitive, path: a.path, limit: a.limit }) },
  { name: "cs_git", title: "Run git in Codespace", description: "Run `git <args>` in the Codespace. Read-only subcommands run directly; commit/push/reset/etc. need approval.", scope: "mcp:exec", readOnly: false,
    shape: { args: z.array(z.string().max(2000)).min(1).max(40), cwd: z.string().optional(), codespace: cn },
    handler: async (a, c, d) => {
      const sub = String(a.args[0]);
      if (!/^[a-z][a-z-]*$/.test(sub)) throw new Error("Invalid git subcommand");
      const safe = new Set(["status", "diff", "log", "show", "branch", "remote", "rev-parse", "ls-files", "blame", "describe", "config", "fetch", "stash", "add", "checkout", "switch", "restore", "init", "clone", "pull", "merge", "tag"]);
      const read = new Set(["status", "diff", "log", "show", "rev-parse", "ls-files", "blame", "describe"]);
      if (!safe.has(sub) && !["commit", "push", "reset", "rebase", "clean", "cherry-pick", "revert"].includes(sub)) throw new Error(`git ${sub} is not supported`);
      if (a.args.some((x: string) => /^--(exec|upload-pack|receive-pack|config)\b|^-c$|^--git-dir|^--work-tree/.test(x))) throw new Error("That git option is not allowed");
      if (!read.has(sub)) needApprovalCs(c, d, "cs_git", `[${a.codespace ?? "codespace"}] git ${a.args.join(" ")}`);
      const quoted = a.args.map((x: string) => `'${x.replace(/'/g, `'\\''`)}'`).join(" ");
      return run(c, d as CsDeps, a.codespace, "exec", { command: `git ${quoted}`, cwd: a.cwd, timeoutMs: 120_000 }, 135_000);
    } },
  { name: "codespaces_attach", title: "Attach a Codespace for AI use", description: "Prepare a Codespace to be driven by the AI: returns the one-line command to start the UCA agent inside it (valid 10 minutes), plus how to make it start automatically. Run the command once in the Codespace terminal (or add the devcontainer snippet).", scope: "mcp:write", readOnly: false,
    shape: { codespace: z.string().min(1).regex(/^[A-Za-z0-9._-]+$/) },
    handler: async (a, c, d) => {
      const dd = d as CsDeps; if (!dd.broker) throw new Error("Codespace support is not enabled on this server");
      const base = dd.publicBaseUrl ?? dd.config.baseUrl;
      const { claim, expiresAt } = dd.broker.createClaim(c.userId, a.codespace);
      return {
        codespace: a.codespace, expiresAt: new Date(expiresAt).toISOString(),
        runOnceInCodespaceTerminal: `curl -fsSL ${base}/agent/install.sh | UCA_SERVER=${base} UCA_CLAIM=${claim} bash`,
        note: "The claim code is single-use and expires in 10 minutes. It is exchanged for a private pairing token inside the Codespace; nothing secret is written to your repo.",
        autoStartTip: "The command also adds a hook to ~/.bashrc so the agent restarts whenever a terminal opens in this Codespace. To start it without a terminal, add \"postStartCommand\": \"$HOME/.uca-agent/start.sh || true\" to .devcontainer/devcontainer.json (it contains no secret).",
        thenCheck: "Call codespaces_agents to confirm it shows online.",
      };
    } },
  { name: "codespaces_agents", title: "List attached Codespace agents", description: "Which of your Codespaces have a UCA agent paired, and whether they are online.", scope: "mcp:read", readOnly: true, shape: {},
    handler: async (_a, c, d) => { const dd = d as CsDeps; if (!dd.broker) throw new Error("Codespace support is not enabled on this server"); return { agents: dd.broker.list(c.userId) }; } },
  { name: "codespaces_detach", title: "Detach a Codespace agent", description: "Revoke the pairing token for a Codespace. The agent stops working immediately.", scope: "mcp:write", readOnly: false, destructive: true, shape: { codespace: z.string().min(1) },
    handler: async (a, c, d) => { const dd = d as CsDeps; if (!dd.broker) throw new Error("Codespace support is not enabled on this server"); return { detached: dd.broker.unpair(c.userId, a.codespace) }; } },
];

/** Codespace commands run on a real VM, so the policy is lighter than the local sandbox but still blocks the obvious disasters. */
export function classifyCsCommand(cmd: string): { level: "allow" | "approval" | "deny"; reason: string } {
  const c = cmd.trim();
  const frag = (...p: string[]) => p.join("");
  const denyRes: [RegExp, string][] = [
    [new RegExp(frag(":\\(\\)\\s*\\{\\s*:\\s*\\|", "\\s*:\\s*&")), "fork bomb"],
    [/\brm\s+(-[a-zA-Z]*\s+)*(\/|~|\$HOME|\/\*|\.\.)(\s|$)/, "recursive delete of root/home/parent"],
    [/\bmkfs(\.\w+)?\b|\bdd\s+[^|;&]*\bof=\/dev\//, "disk-destroying command"],
    [/>\s*\/dev\/(sd|nvme|vd)/, "writing to a raw disk"],
    [/\b(UCA_TOKEN|UCA_SERVER)\b|\/uca-agent|\.uca-agent/, "touching the UCA agent's own credentials"],
    [/\b(shutdown|poweroff|halt|reboot)\b/, "powering off the VM"],
    [/\bgh\s+auth\s+(token|status\s+-t)|\becho\s+\$\{?GITHUB_TOKEN|\bprintenv\b.*TOKEN|\benv\b\s*\|\s*grep\s+-i\s+(token|secret)/i, "printing credentials"],
    [/curl[^|]*\|\s*(sudo\s+)?(ba)?sh\b.*(?!github\.com|githubusercontent)/, ""],
  ].filter(([, r]) => r !== "") as [RegExp, string][];
  for (const [re, why] of denyRes) if (re.test(c)) return { level: "deny", reason: why };
  const approvalRes: RegExp[] = [
    /\bsudo\b/, /\bapt(-get)?\s+(install|remove|purge|upgrade)/, /\bpip3?\s+install/, /\bnpm\s+(i|install|add)\b/, /\byarn\s+add\b/, /\bpnpm\s+(i|add|install)\b/,
    /\bgit\s+(push|reset\s+--hard|clean|rebase|checkout\s+--|branch\s+-D)/, /\brm\s+-[a-zA-Z]*r/, /\bchmod\s+-R|\bchown\b/, /\bcurl\b[^|]*\|\s*(sudo\s+)?(ba)?sh/, /\bwget\b[^|]*\|\s*(sudo\s+)?(ba)?sh/,
    /\bdocker\b/, /\bkill(all)?\b|\bpkill\b/, /\bgh\s+(repo\s+delete|release\s+delete|secret|auth)/, /\bssh\b|\bscp\b|\bnc\b|\bncat\b/,
    /\b(curl|wget)\b[^|;&]*\s(-X\s*(POST|PUT|DELETE|PATCH)|-d\b|--data|-F\b|--upload-file|-T\b)/,
  ];
  if (approvalRes.some((re) => re.test(c))) return { level: "approval", reason: "can change the VM, install software or contact the network" };
  return { level: "allow", reason: "ok" };
}
