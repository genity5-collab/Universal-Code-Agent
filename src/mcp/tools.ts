import fsp from "node:fs/promises";
import path from "node:path";
import { z } from "zod";
import { ok, fail, type ToolResult, type UserContext } from "../types.js";
import { redact, SecurityError, resolveInside } from "../util/paths.js";
import type { Config } from "../util/config.js";
import * as F from "../fs/files.js";
import { RepoIndex } from "../fs/index.js";
import * as R from "../exec/runner.js";
import * as G from "../exec/git.js";
import * as T from "../exec/tasks.js";
import { evaluateCommand } from "../exec/policy.js";
import { GitHubClient, GitHubError } from "../github/client.js";
import { CodespacesClient } from "../github/codespaces.js";
import type { ApprovalService, AuditLog, RateLimiter } from "./services.js";

export type ToolScope = "mcp:read" | "mcp:write" | "mcp:exec";
export interface ToolDeps {
  broker?: import("../codespace/broker.js").CodespaceBroker;
  publicBaseUrl?: string;
  config: Config;
  approvals: ApprovalService;
  audit: AuditLog;
  limiter: RateLimiter;
  githubBaseUrl?: string;
  fetchImpl?: typeof fetch;
}
export interface ToolDef {
  name: string;
  title: string;
  description: string;
  scope: ToolScope;
  shape: z.ZodRawShape;
  readOnly: boolean;
  destructive?: boolean;
  handler: (args: any, ctx: UserContext, deps: ToolDeps) => Promise<unknown>;
}

const indexes = new Map<string, RepoIndex>();
async function getIndex(root: string): Promise<RepoIndex> {
  let idx = indexes.get(root);
  if (!idx) { idx = new RepoIndex(root); await idx.load(); indexes.set(root, idx); }
  return idx;
}
function gh(ctx: UserContext, deps: ToolDeps): GitHubClient {
  if (!ctx.githubToken) throw new Error("GitHub is not connected for this user. Sign in at the dashboard.");
  return new GitHubClient(ctx.githubToken, { baseUrl: deps.githubBaseUrl, fetchImpl: deps.fetchImpl });
}
function cs(ctx: UserContext, deps: ToolDeps): CodespacesClient { return new CodespacesClient(gh(ctx, deps)); }

/** Raised when a human must approve before the action runs. */
export class ApprovalNeeded extends Error {
  constructor(public approvalId: string, public action: string) { super(`approval_required: ${action}`); }
}
function needApproval(ctx: UserContext, deps: ToolDeps, action: string, detail: string): void {
  if (!deps.config.requireApproval) return;
  const r = deps.approvals.check(ctx.userId, action, detail);
  if (r.state === "approved") return;
  if (r.state === "denied") throw new Error(`The user denied this action: ${action}`);
  throw new ApprovalNeeded(r.id, action);
}

const repoArgs = { owner: z.string().min(1), repo: z.string().min(1) };
const p = z.string().min(1).describe("Path relative to the workspace root");
const page = { page: z.number().int().min(1).optional(), perPage: z.number().int().min(1).max(100).optional() };

export const TOOLS: ToolDef[] = [
  // ---------------- filesystem ----------------
  { name: "read_file", title: "Read file", description: "Read a whole file. For large files returns requiresChunking instead of truncating; then use read_file_chunk or read_file_range.", scope: "mcp:read", readOnly: true,
    shape: { path: p, maxBytes: z.number().int().positive().optional() }, handler: (a, c) => F.read_file(c.workspaceRoot, a.path, { maxBytes: a.maxBytes }) },
  { name: "read_file_chunk", title: "Read file chunk", description: "Read a byte chunk. Follow nextOffset until eof=true.", scope: "mcp:read", readOnly: true,
    shape: { path: p, offset: z.number().int().min(0).optional(), size: z.number().int().positive().optional(), encoding: z.enum(["utf8", "base64"]).optional() },
    handler: (a, c) => F.read_file_chunk(c.workspaceRoot, a.path, { offset: a.offset, size: a.size, encoding: a.encoding }) },
  { name: "read_file_range", title: "Read line range", description: "Read lines startLine..endLine (1-based), paginated.", scope: "mcp:read", readOnly: true,
    shape: { path: p, startLine: z.number().int().min(1).optional(), endLine: z.number().int().min(1).optional(), maxLines: z.number().int().min(1).optional(), includeLineNumbers: z.boolean().optional() },
    handler: (a, c) => F.read_file_range(c.workspaceRoot, a.path, a) },
  { name: "write_file", title: "Write file", description: "Create or overwrite a file (atomic). Prefer edit_file for changes to existing files.", scope: "mcp:write", readOnly: false,
    shape: { path: p, content: z.string(), createDirs: z.boolean().optional(), overwrite: z.boolean().optional() },
    handler: (a, c) => F.write_file(c.workspaceRoot, a.path, a.content, { createDirs: a.createDirs, overwrite: a.overwrite }) },
  { name: "create_file", title: "Create file", description: "Create a new file; fails if it already exists.", scope: "mcp:write", readOnly: false,
    shape: { path: p, content: z.string().default("") }, handler: (a, c) => F.create_file(c.workspaceRoot, a.path, a.content ?? "") },
  { name: "edit_file", title: "Edit file", description: "Exact string replace (oldString must be unique unless replaceAll) or replace a line range.", scope: "mcp:write", readOnly: false,
    shape: { path: p, oldString: z.string().optional(), newString: z.string().optional(), replaceAll: z.boolean().optional(), startLine: z.number().int().min(1).optional(), endLine: z.number().int().min(1).optional() },
    handler: (a, c) => F.edit_file(c.workspaceRoot, a.path, a) },
  { name: "delete_file", title: "Delete file", description: "Delete a file or directory. Requires human approval.", scope: "mcp:write", readOnly: false, destructive: true,
    shape: { path: p, recursive: z.boolean().optional() },
    handler: async (a, c, d) => { needApproval(c, d, "delete_file", `Delete ${a.path}${a.recursive ? " (recursive)" : ""}`); return F.delete_file(c.workspaceRoot, a.path, { recursive: a.recursive }); } },
  { name: "list_directory", title: "List directory", description: "List a directory with pagination.", scope: "mcp:read", readOnly: true,
    shape: { path: z.string().default("."), limit: z.number().int().min(1).optional(), offset: z.number().int().min(0).optional(), recursive: z.boolean().optional(), maxDepth: z.number().int().min(1).optional(), includeIgnored: z.boolean().optional() },
    handler: (a, c) => F.list_directory(c.workspaceRoot, a.path ?? ".", a) },
  { name: "search_files", title: "Search file names", description: "Find files by name/glob.", scope: "mcp:read", readOnly: true,
    shape: { pattern: z.string().min(1), limit: z.number().int().min(1).optional(), offset: z.number().int().min(0).optional(), matchPath: z.boolean().optional(), regex: z.boolean().optional() },
    handler: (a, c) => F.search_files(c.workspaceRoot, a.pattern, a) },
  { name: "search_content", title: "Search file contents", description: "Literal or regex search with context lines and cursor pagination.", scope: "mcp:read", readOnly: true,
    shape: { query: z.string().min(1), regex: z.boolean().optional(), caseSensitive: z.boolean().optional(), contextLines: z.number().int().min(0).max(10).optional(), limit: z.number().int().min(1).optional(), cursor: z.string().optional(), glob: z.string().optional() },
    handler: (a, c) => F.search_content(c.workspaceRoot, a.query, a) },
  { name: "find_symbol", title: "Find symbol", description: "Find functions/classes/types by name using the incremental symbol index.", scope: "mcp:read", readOnly: true,
    shape: { name: z.string().min(1), kind: z.enum(["function", "class", "method", "interface", "type", "const"]).optional(), fuzzy: z.boolean().optional() },
    handler: async (a, c) => { const i = await getIndex(c.workspaceRoot); await i.update(); return i.findSymbol(a.name, a.kind, a.fuzzy ?? false); } },
  { name: "get_file_metadata", title: "File metadata", description: "Size, mtime, line count, language, binary flag, sha256.", scope: "mcp:read", readOnly: true,
    shape: { path: p }, handler: (a, c) => F.get_file_metadata(c.workspaceRoot, a.path) },
  { name: "compare_files", title: "Compare files", description: "Unified diff between two workspace files.", scope: "mcp:read", readOnly: true,
    shape: { pathA: p, pathB: p, context: z.number().int().min(0).optional(), ignoreWhitespace: z.boolean().optional() },
    handler: (a, c) => F.compare_files(c.workspaceRoot, a.pathA, a.pathB, { context: a.context, ignoreWhitespace: a.ignoreWhitespace }) },

  // ---------------- repository intelligence ----------------
  { name: "index_repo", title: "Index repository", description: "Incrementally (re)index the workspace; only changed files are re-parsed.", scope: "mcp:read", readOnly: true,
    shape: { force: z.boolean().optional() }, handler: async (a, c) => { const i = await getIndex(c.workspaceRoot); return i.update({ force: a.force }); } },
  { name: "repo_map", title: "Repository map", description: "Directory tree, language stats, important files and entrypoints.", scope: "mcp:read", readOnly: true,
    shape: { maxDepth: z.number().int().min(1).optional(), maxEntriesPerDir: z.number().int().min(1).optional() },
    handler: async (a, c) => { const i = await getIndex(c.workspaceRoot); await i.update(); return { map: i.repoMap(), tree: i.renderRepoMap({ maxDepth: a.maxDepth, maxEntriesPerDir: a.maxEntriesPerDir }) }; } },
  { name: "dependency_map", title: "Dependency map", description: "Package manifests plus the local import graph.", scope: "mcp:read", readOnly: true,
    shape: {}, handler: async (_a, c) => { const i = await getIndex(c.workspaceRoot); await i.update(); return i.dependencyMap(); } },
  { name: "change_tracking", title: "Change tracking", description: "Files added/modified/deleted since the last snapshot. Set commit=true to reset the baseline.", scope: "mcp:read", readOnly: true,
    shape: { commit: z.boolean().optional() }, handler: async (a, c) => { const i = await getIndex(c.workspaceRoot); await i.update(); const ch = i.changes(); if (a.commit) i.commitSnapshot(); return ch; } },

  // ---------------- terminal / tasks ----------------
  { name: "run_command", title: "Run command", description: "Run a command in the sandboxed workspace (no shell). Safe commands auto-run; risky ones need approval; dangerous ones are denied.", scope: "mcp:exec", readOnly: false,
    shape: { command: z.string().min(1), cwd: z.string().optional(), timeoutMs: z.number().int().positive().optional() },
    handler: async (a, c, d) => {
      const pol = evaluateCommand(a.command, { root: c.workspaceRoot });
      if (pol.decision === "deny") throw new SecurityError(`Command denied: ${pol.reason}`);
      if (pol.decision === "approval") needApproval(c, d, "run_command", a.command);
      return R.runCommand(c.workspaceRoot, a.command, { cwd: a.cwd, timeoutMs: Math.min(a.timeoutMs ?? d.config.commandTimeoutMs, d.config.commandTimeoutMs), maxOutputBytes: d.config.maxOutputBytes, approved: pol.decision === "approval" });
    } },
  { name: "start_job", title: "Start background job", description: "Start a long-running command such as a dev server. Poll with job_output.", scope: "mcp:exec", readOnly: false,
    shape: { command: z.string().min(1), cwd: z.string().optional() },
    handler: async (a, c, d) => {
      const pol = evaluateCommand(a.command, { root: c.workspaceRoot });
      if (pol.decision === "deny") throw new SecurityError(`Command denied: ${pol.reason}`);
      if (pol.decision === "approval") needApproval(c, d, "start_job", a.command);
      return R.startJob(c.workspaceRoot, a.command, { cwd: a.cwd, approved: pol.decision === "approval" });
    } },
  { name: "job_status", title: "Job status", description: "Status of a background job.", scope: "mcp:exec", readOnly: true,
    shape: { jobId: z.string() }, handler: async (a, c) => R.jobStatus(c.workspaceRoot, a.jobId) },
  { name: "job_output", title: "Job output", description: "Paginated job output by byte offset (also use for reading full command logs).", scope: "mcp:exec", readOnly: true,
    shape: { jobId: z.string(), offset: z.number().int().min(0).optional(), limit: z.number().int().positive().optional() }, handler: async (a, c) => R.jobOutput(a.jobId, a.offset ?? 0, a.limit ?? 16384, c.workspaceRoot) },
  { name: "stop_job", title: "Stop job", description: "Stop a background job.", scope: "mcp:exec", readOnly: false,
    shape: { jobId: z.string() }, handler: async (a, c) => R.stopJob(a.jobId, c.workspaceRoot) },
  { name: "list_jobs", title: "List jobs", description: "List background jobs in this workspace.", scope: "mcp:exec", readOnly: true,
    shape: {}, handler: async (_a, c) => R.listJobs(c.workspaceRoot) },
  { name: "read_command_log", title: "Read command log", description: "Read a saved command log file under .uca/logs by byte offset.", scope: "mcp:exec", readOnly: true,
    shape: { logPath: z.string(), offset: z.number().int().min(0).optional(), limit: z.number().int().positive().max(262144).optional() },
    handler: async (a, c) => {
      const abs = resolveInside(c.workspaceRoot, a.logPath);
      if (!abs.includes(`${path.sep}.uca${path.sep}logs${path.sep}`)) throw new SecurityError("Only .uca/logs files can be read here");
      const fh = await fsp.open(abs, "r"); const st = await fh.stat(); const off = a.offset ?? 0; const len = Math.min(a.limit ?? 16384, Math.max(0, st.size - off)); const buf = Buffer.alloc(len);
      await fh.read(buf, 0, len, off); await fh.close();
      return { content: redact(buf.toString("utf8")), offset: off, nextOffset: off + len, eof: off + len >= st.size, totalBytes: st.size };
    } },
  { name: "install_dependencies", title: "Install dependencies", description: "Auto-detect and install dependencies. Requires approval.", scope: "mcp:exec", readOnly: false,
    shape: { cwd: z.string().optional() }, handler: async (a, c, d) => { needApproval(c, d, "install_dependencies", `Install dependencies in ${a.cwd ?? "."}`); return T.installDependencies(c.workspaceRoot, { cwd: a.cwd, approved: true }); } },
  { name: "run_tests", title: "Run tests", description: "Auto-detect and run the project's tests.", scope: "mcp:exec", readOnly: false,
    shape: { cwd: z.string().optional(), extraArgs: z.array(z.string()).optional() }, handler: (a, c) => T.runTests(c.workspaceRoot, { cwd: a.cwd, extraArgs: a.extraArgs }) },
  { name: "format_code", title: "Format code", description: "Run the project's formatter (prettier/ruff/gofmt...) if present.", scope: "mcp:exec", readOnly: false,
    shape: { cwd: z.string().optional() }, handler: (a, c) => T.formatCode(c.workspaceRoot, { cwd: a.cwd }) },
  { name: "static_analysis", title: "Static analysis", description: "Run type-check/lint tools that exist (tsc, eslint, ruff, go vet...).", scope: "mcp:exec", readOnly: true,
    shape: { cwd: z.string().optional() }, handler: (a, c) => T.staticAnalysis(c.workspaceRoot, { cwd: a.cwd }) },
  { name: "build_verify", title: "Verify build", description: "Run the project's build.", scope: "mcp:exec", readOnly: false,
    shape: { cwd: z.string().optional() }, handler: (a, c) => T.buildVerify(c.workspaceRoot, { cwd: a.cwd }) },

  // ---------------- local git ----------------
  { name: "git_status", title: "Git status", description: "Working tree status.", scope: "mcp:read", readOnly: true, shape: { cwd: z.string().optional() }, handler: (a, c) => G.status(c.workspaceRoot, { cwd: a.cwd }) },
  { name: "git_diff", title: "Git diff", description: "Diff of working tree or staged changes.", scope: "mcp:read", readOnly: true,
    shape: { staged: z.boolean().optional(), paths: z.array(z.string()).optional(), cwd: z.string().optional() }, handler: (a, c) => G.diff(c.workspaceRoot, { staged: a.staged, paths: a.paths, cwd: a.cwd }) },
  { name: "git_log", title: "Git log", description: "Recent commits.", scope: "mcp:read", readOnly: true,
    shape: { maxCount: z.number().int().min(1).max(200).optional(), cwd: z.string().optional() }, handler: (a, c) => G.log(c.workspaceRoot, { maxCount: a.maxCount, cwd: a.cwd }) },
  { name: "git_branch_create", title: "Create local branch", description: "Create a local branch.", scope: "mcp:write", readOnly: false,
    shape: { name: z.string(), startPoint: z.string().optional(), cwd: z.string().optional() }, handler: (a, c) => G.branchCreate(c.workspaceRoot, a.name, { startPoint: a.startPoint, cwd: a.cwd }) },
  { name: "git_checkout", title: "Git checkout", description: "Switch or create (create=true) a branch.", scope: "mcp:write", readOnly: false,
    shape: { target: z.string(), create: z.boolean().optional(), cwd: z.string().optional() }, handler: (a, c) => G.checkout(c.workspaceRoot, a.target, { create: a.create, cwd: a.cwd }) },
  { name: "git_commit", title: "Git commit", description: "Stage (paths or all) and commit.", scope: "mcp:write", readOnly: false,
    shape: { message: z.string().min(1), paths: z.array(z.string()).optional(), cwd: z.string().optional() },
    handler: async (a, c) => { const ad = await G.add(c.workspaceRoot, a.paths ?? [], { cwd: a.cwd, approved: true }); if (!ad.ok) return ad; return G.commit(c.workspaceRoot, a.message, { name: c.login, email: `${c.login}@users.noreply.github.com` }, { cwd: a.cwd, approved: true }); } },
  { name: "git_clone", title: "Clone repository", description: "Clone a github.com HTTPS repository into the workspace using your GitHub token.", scope: "mcp:write", readOnly: false,
    shape: { url: z.string().url(), dir: z.string() }, handler: (a, c) => G.clone(c.workspaceRoot, a.url, a.dir, { token: c.githubToken, approved: true }) },
  { name: "git_push", title: "Git push", description: "Push to GitHub using your own token. Requires approval.", scope: "mcp:write", readOnly: false, destructive: true,
    shape: { remote: z.string().optional(), branch: z.string().optional(), setUpstream: z.boolean().optional(), cwd: z.string().optional() },
    handler: async (a, c, d) => { needApproval(c, d, "git_push", `Push ${a.branch ?? "current branch"} to ${a.remote ?? "origin"}`); return G.push(c.workspaceRoot, { remote: a.remote, branch: a.branch, setUpstream: a.setUpstream, cwd: a.cwd, token: c.githubToken, approved: true }); } },
  { name: "git_pull", title: "Git pull", description: "Pull from remote.", scope: "mcp:write", readOnly: false,
    shape: { remote: z.string().optional(), branch: z.string().optional(), cwd: z.string().optional() }, handler: (a, c) => G.pull(c.workspaceRoot, { remote: a.remote, branch: a.branch, cwd: a.cwd, token: c.githubToken, approved: true }) },

  // ---------------- GitHub API ----------------
  { name: "github_whoami", title: "GitHub identity", description: "The authenticated GitHub user.", scope: "mcp:read", readOnly: true, shape: {}, handler: (_a, c, d) => gh(c, d).getAuthenticatedUser() },
  { name: "github_list_repos", title: "List repositories", description: "Repositories the user can access.", scope: "mcp:read", readOnly: true,
    shape: { visibility: z.enum(["all", "public", "private"]).optional(), ...page }, handler: (a, c, d) => gh(c, d).listRepos(a.visibility, undefined, a.page, a.perPage) },
  { name: "github_get_repo", title: "Get repository", description: "Repository details.", scope: "mcp:read", readOnly: true, shape: repoArgs, handler: (a, c, d) => gh(c, d).getRepo(a.owner, a.repo) },
  { name: "github_list_branches", title: "List branches", description: "Branches of a repo.", scope: "mcp:read", readOnly: true, shape: { ...repoArgs, ...page }, handler: (a, c, d) => gh(c, d).listBranches(a.owner, a.repo, { page: a.page, perPage: a.perPage }) },
  { name: "github_browse", title: "Browse directory", description: "List a directory in a repo at a ref.", scope: "mcp:read", readOnly: true,
    shape: { ...repoArgs, ref: z.string().optional(), path: z.string().optional() }, handler: (a, c, d) => gh(c, d).getTree(a.owner, a.repo, a.ref, a.path ?? "") },
  { name: "github_read_file", title: "Read repo file", description: "Read a file from GitHub with offset/limit chunking (no silent truncation).", scope: "mcp:read", readOnly: true,
    shape: { ...repoArgs, path: z.string(), ref: z.string().optional(), offset: z.number().int().min(0).optional(), limit: z.number().int().positive().optional() }, handler: (a, c, d) => gh(c, d).getContent(a.owner, a.repo, a.path, a.ref, { offset: a.offset, limit: a.limit }) },
  { name: "github_download_file", title: "Download repo file", description: "Download a file as base64 (size-capped with explicit flag). Optionally save into the workspace.", scope: "mcp:read", readOnly: true,
    shape: { ...repoArgs, path: z.string(), ref: z.string().optional(), saveTo: z.string().optional(), maxBytes: z.number().int().positive().optional() },
    handler: async (a, c, d) => {
      const f: any = await gh(c, d).downloadFile(a.owner, a.repo, a.path, a.ref, { maxBytes: a.maxBytes });
      if (a.saveTo) {
        if (f.truncated) throw new Error("File exceeds maxBytes; refusing to save a partial file. Raise maxBytes.");
        const dest = resolveInside(c.workspaceRoot, a.saveTo); await fsp.mkdir(path.dirname(dest), { recursive: true });
        await fsp.writeFile(dest, Buffer.from(f.contentBase64 ?? f.content ?? "", "base64")); return { saved: a.saveTo, size: f.size };
      }
      return f;
    } },
  { name: "github_write_file", title: "Create/update repo file", description: "Create or update a file directly on a branch via the API (needs sha for updates).", scope: "mcp:write", readOnly: false,
    shape: { ...repoArgs, path: z.string(), content: z.string(), message: z.string(), sha: z.string().optional(), branch: z.string().optional() },
    handler: (a, c, d) => gh(c, d).createOrUpdateFile(a.owner, a.repo, a.path, { content: a.content, message: a.message, sha: a.sha, branch: a.branch }) },
  { name: "github_delete_file", title: "Delete repo file", description: "Delete a file on GitHub. Requires approval.", scope: "mcp:write", readOnly: false, destructive: true,
    shape: { ...repoArgs, path: z.string(), sha: z.string(), message: z.string(), branch: z.string().optional() },
    handler: async (a, c, d) => { needApproval(c, d, "github_delete_file", `Delete ${a.owner}/${a.repo}:${a.path} on ${a.branch ?? "default branch"}`); return gh(c, d).deleteFile(a.owner, a.repo, a.path, { sha: a.sha, message: a.message, branch: a.branch }); } },
  { name: "github_create_branch", title: "Create branch", description: "Create a branch from a ref.", scope: "mcp:write", readOnly: false,
    shape: { ...repoArgs, branch: z.string(), from: z.string() }, handler: (a, c, d) => gh(c, d).createBranch(a.owner, a.repo, a.branch, a.from) },
  { name: "github_commit_files", title: "Commit multiple files", description: "Atomically commit several files (and deletions) to a branch.", scope: "mcp:write", readOnly: false,
    shape: { ...repoArgs, branch: z.string(), message: z.string(), baseBranch: z.string().optional(), files: z.array(z.object({ path: z.string(), content: z.string(), encoding: z.enum(["utf8", "base64"]).optional() })).optional(), deletions: z.array(z.string()).optional() },
    handler: (a, c, d) => gh(c, d).createCommitMultiFile(a.owner, a.repo, { branch: a.branch, message: a.message, baseBranch: a.baseBranch, files: a.files, deletions: a.deletions }) },
  { name: "github_search_code", title: "Search code", description: "GitHub code search (use qualifiers like repo:owner/name).", scope: "mcp:read", readOnly: true, shape: { q: z.string().min(1), ...page }, handler: (a, c, d) => gh(c, d).searchCode(a.q, { page: a.page, perPage: a.perPage }) },
  { name: "github_list_commits", title: "List commits", description: "Commits of a repo.", scope: "mcp:read", readOnly: true, shape: { ...repoArgs, sha: z.string().optional(), path: z.string().optional(), ...page }, handler: (a, c, d) => gh(c, d).listCommits(a.owner, a.repo, { sha: a.sha, path: a.path, page: a.page, perPage: a.perPage }) },
  { name: "github_get_commit", title: "Inspect commit", description: "Commit details with trimmed patches (explicit truncated flags).", scope: "mcp:read", readOnly: true, shape: { ...repoArgs, ref: z.string() }, handler: (a, c, d) => gh(c, d).getCommit(a.owner, a.repo, a.ref) },
  { name: "github_compare", title: "Compare refs", description: "Compare two refs.", scope: "mcp:read", readOnly: true, shape: { ...repoArgs, base: z.string(), head: z.string() }, handler: (a, c, d) => gh(c, d).compare(a.owner, a.repo, a.base, a.head) },
  { name: "github_create_issue", title: "Create issue", description: "Open an issue.", scope: "mcp:write", readOnly: false, shape: { ...repoArgs, title: z.string(), body: z.string().optional(), labels: z.array(z.string()).optional() }, handler: (a, c, d) => gh(c, d).createIssue(a.owner, a.repo, { title: a.title, body: a.body, labels: a.labels }) },
  { name: "github_list_issues", title: "List issues", description: "Issues of a repo.", scope: "mcp:read", readOnly: true, shape: { ...repoArgs, state: z.enum(["open", "closed", "all"]).optional(), ...page }, handler: (a, c, d) => gh(c, d).listIssues(a.owner, a.repo, { state: a.state, page: a.page, perPage: a.perPage }) },
  { name: "github_get_issue", title: "Get issue", description: "One issue.", scope: "mcp:read", readOnly: true, shape: { ...repoArgs, number: z.number().int() }, handler: (a, c, d) => gh(c, d).getIssue(a.owner, a.repo, a.number) },
  { name: "github_comment_issue", title: "Comment on issue/PR", description: "Add a comment.", scope: "mcp:write", readOnly: false, shape: { ...repoArgs, number: z.number().int(), body: z.string().min(1) }, handler: (a, c, d) => gh(c, d).commentOnIssue(a.owner, a.repo, a.number, a.body) },
  { name: "github_create_pull_request", title: "Create pull request", description: "Open a PR.", scope: "mcp:write", readOnly: false, shape: { ...repoArgs, title: z.string(), head: z.string(), base: z.string(), body: z.string().optional(), draft: z.boolean().optional() }, handler: (a, c, d) => gh(c, d).createPullRequest(a.owner, a.repo, { title: a.title, head: a.head, base: a.base, body: a.body, draft: a.draft }) },
  { name: "github_list_pull_requests", title: "List pull requests", description: "PRs of a repo.", scope: "mcp:read", readOnly: true, shape: { ...repoArgs, state: z.enum(["open", "closed", "all"]).optional(), ...page }, handler: (a, c, d) => gh(c, d).listPullRequests(a.owner, a.repo, { state: a.state, page: a.page, perPage: a.perPage }) },
  { name: "github_get_pull_request", title: "Get pull request", description: "One PR.", scope: "mcp:read", readOnly: true, shape: { ...repoArgs, number: z.number().int() }, handler: (a, c, d) => gh(c, d).getPullRequest(a.owner, a.repo, a.number) },
  { name: "github_pull_request_files", title: "PR files", description: "Files changed in a PR.", scope: "mcp:read", readOnly: true, shape: { ...repoArgs, number: z.number().int(), ...page }, handler: (a, c, d) => gh(c, d).listPullRequestFiles(a.owner, a.repo, a.number, { page: a.page, perPage: a.perPage }) },
  { name: "github_pull_request_diff", title: "PR diff", description: "Unified diff of a PR (size-capped with flag).", scope: "mcp:read", readOnly: true, shape: { ...repoArgs, number: z.number().int(), maxBytes: z.number().int().positive().optional() }, handler: (a, c, d) => gh(c, d).getPullRequestDiff(a.owner, a.repo, a.number, { maxBytes: a.maxBytes }) },
  { name: "github_review_pull_request", title: "Review pull request", description: "Submit a PR review. Approving or requesting changes needs human approval.", scope: "mcp:write", readOnly: false,
    shape: { ...repoArgs, number: z.number().int(), event: z.enum(["APPROVE", "REQUEST_CHANGES", "COMMENT"]), body: z.string().optional(), comments: z.array(z.object({ path: z.string(), body: z.string(), line: z.number().int().optional(), side: z.enum(["LEFT", "RIGHT"]).optional() })).optional() },
    handler: async (a, c, d) => { if (a.event !== "COMMENT") needApproval(c, d, "github_review_pull_request", `${a.event} on ${a.owner}/${a.repo}#${a.number}: ${a.body ?? ""}`); return gh(c, d).createPullRequestReview(a.owner, a.repo, a.number, { event: a.event, body: a.body, comments: a.comments }); } },
  { name: "github_list_discussions", title: "List discussions", description: "Discussions (GraphQL).", scope: "mcp:read", readOnly: true, shape: { ...repoArgs, first: z.number().int().min(1).max(50).optional(), after: z.string().optional() }, handler: (a, c, d) => gh(c, d).listDiscussions(a.owner, a.repo, { first: a.first, after: a.after }) },
  { name: "github_get_discussion", title: "Get discussion", description: "One discussion with comments.", scope: "mcp:read", readOnly: true, shape: { ...repoArgs, number: z.number().int() }, handler: (a, c, d) => gh(c, d).getDiscussion(a.owner, a.repo, a.number) },
  { name: "github_list_workflows", title: "List workflows", description: "GitHub Actions workflows.", scope: "mcp:read", readOnly: true, shape: repoArgs, handler: (a, c, d) => gh(c, d).listWorkflows(a.owner, a.repo) },
  { name: "github_list_workflow_runs", title: "List workflow runs", description: "Recent Actions runs.", scope: "mcp:read", readOnly: true, shape: { ...repoArgs, branch: z.string().optional(), status: z.string().optional(), ...page }, handler: (a, c, d) => gh(c, d).listWorkflowRuns(a.owner, a.repo, { branch: a.branch, status: a.status, page: a.page, perPage: a.perPage }) },
  { name: "github_get_workflow_run", title: "Get workflow run", description: "One Actions run.", scope: "mcp:read", readOnly: true, shape: { ...repoArgs, runId: z.number().int() }, handler: (a, c, d) => gh(c, d).getWorkflowRun(a.owner, a.repo, a.runId) },
  { name: "github_list_run_jobs", title: "List run jobs", description: "Jobs of a run.", scope: "mcp:read", readOnly: true, shape: { ...repoArgs, runId: z.number().int() }, handler: (a, c, d) => gh(c, d).listRunJobs(a.owner, a.repo, a.runId) },
  { name: "github_job_logs", title: "Build logs", description: "Job logs with offset/limit paging and total length.", scope: "mcp:read", readOnly: true, shape: { ...repoArgs, jobId: z.number().int(), offset: z.number().int().min(0).optional(), limit: z.number().int().positive().optional() }, handler: async (a, c, d) => { const r: any = await gh(c, d).getJobLogs(a.owner, a.repo, a.jobId, { offset: a.offset, limit: a.limit }); if (typeof r?.content === "string") r.content = redact(r.content); return r; } },
  { name: "github_rerun_workflow", title: "Re-run workflow", description: "Re-run an Actions run.", scope: "mcp:write", readOnly: false, shape: { ...repoArgs, runId: z.number().int() }, handler: (a, c, d) => gh(c, d).rerunWorkflow(a.owner, a.repo, a.runId) },
  { name: "github_list_releases", title: "List releases", description: "Releases.", scope: "mcp:read", readOnly: true, shape: { ...repoArgs, ...page }, handler: (a, c, d) => gh(c, d).listReleases(a.owner, a.repo, { page: a.page, perPage: a.perPage }) },
  { name: "github_get_release", title: "Get release", description: "One release by id or tag.", scope: "mcp:read", readOnly: true, shape: { ...repoArgs, release: z.union([z.number().int(), z.string()]) }, handler: (a, c, d) => gh(c, d).getRelease(a.owner, a.repo, a.release) },
  { name: "github_security_alerts", title: "Security findings", description: "Code scanning, Dependabot and secret scanning alerts; returns available:false when not enabled or not permitted.", scope: "mcp:read", readOnly: true,
    shape: { ...repoArgs, kind: z.enum(["code_scanning", "dependabot", "secret_scanning"]), state: z.string().optional() },
    handler: (a, c, d) => { const g = gh(c, d); return a.kind === "code_scanning" ? g.listCodeScanningAlerts(a.owner, a.repo, { state: a.state }) : a.kind === "dependabot" ? g.listDependabotAlerts(a.owner, a.repo, { state: a.state }) : g.listSecretScanningAlerts(a.owner, a.repo, { state: a.state }); } },

  // ---------------- Codespaces ----------------
  { name: "codespaces_list", title: "List codespaces", description: "Your Codespaces.", scope: "mcp:read", readOnly: true, shape: {}, handler: (_a, c, d) => cs(c, d).listCodespaces() },
  { name: "codespaces_status", title: "Codespaces status & limits", description: "Honest status and quota limitations.", scope: "mcp:read", readOnly: true, shape: {}, handler: (_a, c, d) => cs(c, d).status() },
  { name: "codespaces_machines", title: "Codespace machine types", description: "Available machine types for a repo.", scope: "mcp:read", readOnly: true, shape: repoArgs, handler: (a, c, d) => cs(c, d).listMachines(a.owner, a.repo) },
  { name: "codespaces_create", title: "Create codespace", description: "Create a Codespace (uses your GitHub quota; billing may apply). Requires approval.", scope: "mcp:write", readOnly: false,
    shape: { ...repoArgs, branch: z.string().optional(), machine: z.string().optional(), idleTimeout: z.number().int().positive().optional() },
    handler: async (a, c, d) => { needApproval(c, d, "codespaces_create", `Create codespace for ${a.owner}/${a.repo} (uses your GitHub Codespaces quota)`); return cs(c, d).createCodespace({ owner: a.owner, repo: a.repo, branch: a.branch, machine: a.machine, idleTimeout: a.idleTimeout }); } },
  { name: "codespaces_get", title: "Get codespace", description: "Codespace state.", scope: "mcp:read", readOnly: true, shape: { name: z.string() }, handler: (a, c, d) => cs(c, d).getCodespace(a.name) },
  { name: "codespaces_start", title: "Start codespace", description: "Start a Codespace.", scope: "mcp:write", readOnly: false, shape: { name: z.string() }, handler: (a, c, d) => cs(c, d).startCodespace(a.name) },
  { name: "codespaces_stop", title: "Stop codespace", description: "Stop a Codespace.", scope: "mcp:write", readOnly: false, shape: { name: z.string() }, handler: (a, c, d) => cs(c, d).stopCodespace(a.name) },
  { name: "codespaces_delete", title: "Delete codespace", description: "Delete a Codespace. Requires approval.", scope: "mcp:write", readOnly: false, destructive: true, shape: { name: z.string() },
    handler: async (a, c, d) => { needApproval(c, d, "codespaces_delete", `Delete codespace ${a.name}`); return cs(c, d).deleteCodespace(a.name); } },
  { name: "codespaces_export", title: "Export codespace changes", description: "Export a Codespace to a branch.", scope: "mcp:write", readOnly: false, shape: { name: z.string() }, handler: (a, c, d) => cs(c, d).exportCodespace(a.name) },
  { name: "codespaces_run_command", title: "Run command in codespace", description: "Legacy: only returns how to run a command with `gh codespace ssh`. To actually run commands in a Codespace, attach it with codespaces_attach and use cs_exec.", scope: "mcp:exec", readOnly: true, shape: { name: z.string(), command: z.string() }, handler: (a, c, d) => cs(c, d).runCommandViaSsh(a.name, a.command) },
];

/** Execute a tool with rate limiting, audit and uniform error mapping. */
export async function runTool(def: ToolDef, args: unknown, ctx: UserContext, deps: ToolDeps): Promise<ToolResult> {
  if (!deps.limiter.allow(ctx.userId)) { deps.audit.write({ userId: ctx.userId, tool: def.name, ok: false, note: "rate_limited" }); return fail("Rate limit exceeded. Wait a moment and retry."); }
  try {
    const parsed = z.object(def.shape).safeParse(args ?? {});
    if (!parsed.success) return fail(`Invalid arguments: ${parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ")}`);
    const out = await def.handler(parsed.data, ctx, deps);
    deps.audit.write({ userId: ctx.userId, tool: def.name, ok: true });
    return ok(JSON.parse(redact(JSON.stringify(out ?? null))));
  } catch (e: any) {
    if (e instanceof ApprovalNeeded) {
      deps.audit.write({ userId: ctx.userId, tool: def.name, ok: false, note: "approval_required" });
      return { content: [{ type: "text", text: JSON.stringify({ status: "approval_required", approvalId: e.approvalId, action: e.action, message: "A human must approve this in the dashboard (Approvals tab). Ask the user to approve, then call this tool again with the same arguments. Do not try to work around it." }) }], isError: true };
    }
    if (e instanceof R.ApprovalRequiredError) return fail(`approval_required: ${e.message}`);
    deps.audit.write({ userId: ctx.userId, tool: def.name, ok: false, note: String(e?.message ?? e) });
    const msg = e instanceof GitHubError || e instanceof SecurityError || e instanceof Error ? e.message : String(e);
    return fail(redact(msg));
  }
}
