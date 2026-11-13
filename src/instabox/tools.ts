/**
 * VM-backed implementations of every tool that would otherwise touch the server's disk.
 * `VM_HANDLERS` replaces the local handler for these tool names; `runTool` refuses them if no VM is attached.
 */
import { z } from "zod";
import type { ToolDef, ToolDeps } from "../mcp/tools.js";
import type { UserContext } from "../types.js";
import { evaluateCommand } from "../exec/policy.js";
import { shq, type InstaBoxManager } from "./client.js";
import type { ActivityFeed, Activity } from "./activity.js";

export const WORKSPACE_DIR = "/data/home/workspace";
export const MAX_WORKSPACE_BYTES = 1024 * 1024 * 1024; // 1 GB per user, enforced inside the VM

/** Resolve a user path to an absolute path inside the VM workspace. Rejects traversal. */
export function vmPath(p: string): string {
  const raw = String(p ?? ".").replace(/\\/g, "/");
  if (raw.includes("\0")) throw new Error("Invalid path.");
  const parts: string[] = [];
  for (const seg of (raw.startsWith("/") ? raw : `${WORKSPACE_DIR}/${raw}`).split("/")) {
    if (!seg || seg === ".") continue; if (seg === "..") { if (!parts.length) throw new Error("Path escapes the workspace."); parts.pop(); } else parts.push(seg);
  }
  const abs = "/" + parts.join("/");
  if (abs !== WORKSPACE_DIR && !abs.startsWith(WORKSPACE_DIR + "/")) throw new Error(`Path must be inside ${WORKSPACE_DIR}.`);
  return abs;
}

/**
 * Inside the user's own VM the AI works freely: the policy's "approval" tier (installs, git writes, npm/python/make, unknown commands...)
 * runs automatically. Only DELETES (and actions that throw away work) still wait for a human. Hard "deny" is never relaxed.
 */
export const DELETE_REASON = /\b(delet|remov|discards? workspace changes|git clean)/i;
export function needsHumanInVm(pol: { decision: string; reason?: string; argv?: string[] }): boolean {
  if (pol.decision !== "approval") return false;
  const argv = pol.argv ?? []; const head = (argv[0] ?? "").split("/").pop();
  if (head === "rm" || head === "rmdir" || head === "unlink" || head === "shred") return true;
  if (head === "git" && argv.slice(1).includes("clean")) return true;
  return DELETE_REASON.test(pol.reason ?? "");
}

export const GATED_TOOLS = new Set(["upload_part","finish_upload","read_file_slice","read_file","read_file_chunk","read_file_range","write_file","create_file","edit_file","delete_file","list_directory","search_files","search_content","find_symbol","get_file_metadata","compare_files","index_repo","repo_map","dependency_map","change_tracking","run_command","start_job","job_status","job_output","stop_job","list_jobs","read_command_log","install_dependencies","run_tests","format_code","static_analysis","build_verify","git_status","git_diff","git_log","git_branch_create","git_checkout","git_commit","git_clone","git_push","git_pull"]);

type H = (a: any, ctx: UserContext, deps: ToolDeps, vm: VmEnv) => Promise<unknown>;
export interface VmEnv { mgr: InstaBoxManager; feed: ActivityFeed }

/** Run an internal (server-authored, already-quoted) command in the VM workspace. Never pass raw AI text here: use run_command, which applies the policy. */
export async function sh(env: VmEnv, ctx: UserContext, cmd: string, timeoutSec = 60) {
  return env.mgr.exec(ctx.userId, `mkdir -p ${WORKSPACE_DIR} && cd ${WORKSPACE_DIR} && ${cmd}`, { timeoutSec });
}
/** Bytes used in the VM workspace. FAILS CLOSED: if usage cannot be measured the caller must refuse, never assume zero. */
export async function usedBytes(env: VmEnv, ctx: UserContext): Promise<number> {
  const r = await env.mgr.exec(ctx.userId, `mkdir -p ${WORKSPACE_DIR}; du -sb ${WORKSPACE_DIR} | cut -f1`);
  const t = String(r.stdout).trim(); const n = /^\d+$/.test(t) ? Number(t) : NaN;
  if (!Number.isFinite(n)) throw new Error("Could not measure workspace size, so the write was refused to keep the 1 GB limit safe. Try again.");
  return n;
}
export async function ensureRoom(env: VmEnv, ctx: UserContext, adding: number) {
  const used = await usedBytes(env, ctx);
  if (used + adding > MAX_WORKSPACE_BYTES) throw new Error(`Workspace limit reached: ${(used / 1048576).toFixed(0)} MB used of 1024 MB. Delete files before adding more.`);
}

export const VM_HANDLERS: Record<string, H> = {
  read_file: async (a, c, _d, e) => { const buf = await e.mgr.readFile(c.userId, vmPath(a.path), a.maxBytes ?? 1_000_000); const text = buf.toString("utf8"); e.feed.add(c.userId, { tool: "read_file", kind: "read", summary: `Read ${a.path}`, ok: true, path: a.path, bytes: buf.length }); return { path: a.path, size: buf.length, content: text }; },
  read_file_chunk: async (a, c, _d, e) => { const off = a.offset ?? 0, size = Math.min(a.size ?? 65536, 1_000_000); const r = await sh(e, c, `tail -c +${off + 1} ${shq(vmPath(a.path))} | head -c ${size} | base64 -w0`); const buf = Buffer.from(r.stdout.trim(), "base64"); const total = Number((await sh(e, c, `wc -c < ${shq(vmPath(a.path))}`)).stdout.trim()); e.feed.add(c.userId, { tool: "read_file_chunk", kind: "read", summary: `Read chunk of ${a.path}`, ok: true, path: a.path }); return { path: a.path, offset: off, size: buf.length, content: a.encoding === "base64" ? buf.toString("base64") : buf.toString("utf8"), nextOffset: off + buf.length, eof: off + buf.length >= total }; },
  read_file_range: async (a, c, _d, e) => { const s = a.startLine ?? 1, en = Math.min(a.endLine ?? s + (a.maxLines ?? 200) - 1, s + (a.maxLines ?? 200) - 1); const r = await sh(e, c, `sed -n '${s},${en}p' ${shq(vmPath(a.path))}`); const lines = r.stdout.split("\n"); if (lines[lines.length - 1] === "") lines.pop(); e.feed.add(c.userId, { tool: "read_file_range", kind: "read", summary: `Read ${a.path}:${s}-${en}`, ok: true, path: a.path }); return { path: a.path, startLine: s, endLine: s + lines.length - 1, content: a.includeLineNumbers ? lines.map((l, i) => `${s + i}\t${l}`).join("\n") : lines.join("\n") }; },
  write_file: async (a, c, _d, e) => { const p = vmPath(a.path); const data = Buffer.from(a.content, "utf8"); await ensureRoom(e, c, data.length); if (a.overwrite === false) { const x = await sh(e, c, `test -e ${shq(p)} && echo yes`); if (x.stdout.includes("yes")) throw new Error("File exists and overwrite=false."); } await e.mgr.writeFile(c.userId, p, data); e.feed.add(c.userId, { tool: "write_file", kind: "file", summary: `Wrote ${a.path} (${data.length} bytes)`, ok: true, path: a.path, bytes: data.length }); return { path: a.path, bytes: data.length, written: true }; },
  create_file: async (a, c, _d, e) => { const p = vmPath(a.path); const x = await sh(e, c, `test -e ${shq(p)} && echo yes`); if (x.stdout.includes("yes")) throw new Error("File already exists."); const data = Buffer.from(a.content ?? "", "utf8"); await ensureRoom(e, c, data.length); await e.mgr.writeFile(c.userId, p, data); e.feed.add(c.userId, { tool: "create_file", kind: "file", summary: `Created ${a.path}`, ok: true, path: a.path, bytes: data.length }); return { path: a.path, created: true }; },
  edit_file: async (a, c, _d, e) => {
    const p = vmPath(a.path); const cur = (await e.mgr.readFile(c.userId, p)).toString("utf8"); let next: string;
    if (a.oldString !== undefined) { const n = cur.split(a.oldString).length - 1; if (n === 0) throw new Error("oldString not found."); if (n > 1 && !a.replaceAll) throw new Error(`oldString matches ${n} times; make it unique or set replaceAll.`); next = a.replaceAll ? cur.split(a.oldString).join(a.newString ?? "") : cur.replace(a.oldString, () => a.newString ?? ""); }
    else if (a.startLine) { const ls = cur.split("\n"); ls.splice(a.startLine - 1, (a.endLine ?? a.startLine) - a.startLine + 1, ...(a.newString ?? "").split("\n")); next = ls.join("\n"); } else throw new Error("Provide oldString or startLine.");
    await ensureRoom(e, c, Math.max(0, next.length - cur.length)); await e.mgr.writeFile(c.userId, p, Buffer.from(next, "utf8")); e.feed.add(c.userId, { tool: "edit_file", kind: "file", summary: `Edited ${a.path}`, ok: true, path: a.path, bytes: next.length }); return { path: a.path, edited: true };
  },
  delete_file: async (a, c, _d, e) => { const p = vmPath(a.path); if (p === WORKSPACE_DIR) throw new Error("Cannot delete the workspace root."); const r = await sh(e, c, a.recursive ? `rm -r -- ${shq(p)}` : `rm -- ${shq(p)}`); e.feed.add(c.userId, { tool: "delete_file", kind: "file", summary: `Deleted ${a.path}`, ok: !r.exitCode, path: a.path }); if (r.exitCode) throw new Error(r.stderr.slice(0, 200) || "delete failed"); return { path: a.path, deleted: true }; },
  list_directory: async (a, c, _d, e) => { const p = vmPath(a.path ?? "."); const depth = a.recursive ? (a.maxDepth ?? 3) : 1; const r = await sh(e, c, `find ${shq(p)} -mindepth 1 -maxdepth ${depth} -not -path '*/.git/*' -not -path '*/node_modules/*' -printf '%y\\t%s\\t%P\\n' | sort -k3 | head -${Math.min(a.limit ?? 200, 1000)}`); const entries = r.stdout.split("\n").filter(Boolean).map((l) => { const [t, s, ...n] = l.split("\t"); return { name: n.join("\t"), type: t === "d" ? "directory" : "file", size: Number(s) }; }); e.feed.add(c.userId, { tool: "list_directory", kind: "read", summary: `Listed ${a.path ?? "."}`, ok: true, path: a.path }); return { path: a.path ?? ".", entries }; },
  search_files: async (a, c, _d, e) => { const r = await sh(e, c, `find . -not -path '*/.git/*' -not -path '*/node_modules/*' -type f | ${a.regex ? "grep -E" : "grep -iF"} -- ${shq(a.pattern)} | head -${Math.min(a.limit ?? 100, 500)}`); e.feed.add(c.userId, { tool: "search_files", kind: "read", summary: `Searched files: ${a.pattern}`, ok: true }); return { matches: r.stdout.split("\n").filter(Boolean).map((x) => x.replace(/^\.\//, "")) }; },
  search_content: async (a, c, _d, e) => { const flags = `-rn ${a.caseSensitive ? "" : "-i"} ${a.regex ? "-E" : "-F"} ${a.contextLines ? `-C ${Math.min(a.contextLines, 10)}` : ""} --exclude-dir=.git --exclude-dir=node_modules`; const r = await sh(e, c, `grep ${flags} -- ${shq(a.query)} . | head -${Math.min(a.limit ?? 100, 500)}`); e.feed.add(c.userId, { tool: "search_content", kind: "read", summary: `Searched for "${a.query}"`, ok: true }); return { results: r.stdout.split("\n").filter(Boolean) }; },
  find_symbol: async (a, c, _d, e) => {
    // Same result shape as the original index: SymbolHit[] = { name, kind, line, path, language }. kind/fuzzy honoured.
    const word = String(a.name ?? "").replace(/[^A-Za-z0-9_$]/g, ""); if (!word) return [];
    const KW: Record<string, string> = { function: "function", class: "class", interface: "interface", type: "type", const: "const", def: "function", fn: "function" };
    const pat = a.fuzzy ? `(function|class|interface|type|const|def|fn)[[:space:]]+[A-Za-z0-9_$]*${word}[A-Za-z0-9_$]*` : `(function|class|interface|type|const|def|fn)[[:space:]]+${word}([^A-Za-z0-9_$]|$)`;
    const r = await sh(e, c, `grep -rnEi ${shq(pat)} --exclude-dir=.git --exclude-dir=node_modules . | head -200`);
    const LANG: Record<string, string> = { ts: "typescript", tsx: "typescript", js: "javascript", jsx: "javascript", mjs: "javascript", py: "python", rs: "rust", go: "go", java: "java", rb: "ruby", c: "c", cpp: "cpp", cs: "csharp" };
    const hits: any[] = [];
    for (const ln of r.stdout.split("\n").filter(Boolean)) {
      const m = /^\.\/(.+?):(\d+):(.*)$/.exec(ln); if (!m) continue;
      const d = /(function|class|interface|type|const|def|fn)[ \t]+([A-Za-z0-9_$]+)/i.exec(m[3]); if (!d) continue;
      const kind = KW[d[1].toLowerCase()] ?? "function"; const name = d[2];
      if (a.kind && a.kind !== kind) continue;
      const exact = name.toLowerCase() === word.toLowerCase(); if (!a.fuzzy && !exact) continue;
      hits.push({ name, kind, line: Number(m[2]), path: m[1], language: LANG[m[1].split(".").pop() ?? ""] ?? "text", _x: exact ? 0 : 1 });
    }
    hits.sort((x, y) => x._x - y._x || x.path.localeCompare(y.path) || x.line - y.line); const out = hits.slice(0, 100).map(({ _x, ...h }) => h);
    e.feed.add(c.userId, { tool: "find_symbol", kind: "read", summary: `Find symbol ${a.name} (${out.length} found)`, ok: true }); return out;
  },
  get_file_metadata: async (a, c, _d, e) => { const p = shq(vmPath(a.path)); const r = await sh(e, c, `stat -c '%s %Y' ${p} && (wc -l < ${p}; sha256sum ${p} | cut -d' ' -f1)`); const [first, lines, sha] = r.stdout.split("\n"); const [size, mtime] = (first ?? "").split(" "); if (!size) throw new Error("File not found."); return { path: a.path, size: Number(size), mtimeMs: Number(mtime) * 1000, lines: Number(lines), sha256: sha }; },
  compare_files: async (a, c, _d, e) => { const r = await sh(e, c, `diff -u ${a.ignoreWhitespace ? "-w" : ""} -U${a.context ?? 3} ${shq(vmPath(a.pathA))} ${shq(vmPath(a.pathB))}`); return { diff: r.stdout, identical: r.exitCode === 0 }; },
  index_repo: async (_a, c, _d, e) => { const r = await sh(e, c, `find . -type f -not -path '*/.git/*' -not -path '*/node_modules/*' | wc -l`); return { files: Number(r.stdout.trim()), indexedIn: "vm" }; },
  repo_map: async (a, c, _d, e) => { const r = await sh(e, c, `find . -maxdepth ${a.maxDepth ?? 3} -not -path '*/.git*' -not -path '*/node_modules*' | sort | head -400`); return { tree: r.stdout.split("\n").filter(Boolean) }; },
  dependency_map: async (_a, c, _d, e) => { const r = await sh(e, c, `ls package.json requirements.txt pyproject.toml go.mod Cargo.toml pom.xml 2>/dev/null; cat package.json 2>/dev/null | head -60`); return { manifests: r.stdout }; },
  change_tracking: async (_a, c, _d, e) => { const r = await sh(e, c, `git status --porcelain 2>/dev/null || echo "(not a git repository)"`); return { changes: r.stdout.split("\n").filter(Boolean) }; },

  run_command: async (a, c, d, e) => {
    const cmd = String(a.command ?? ""); const pol = evaluateCommand(cmd, { root: WORKSPACE_DIR });
    if (pol.decision === "deny") { e.feed.add(c.userId, { tool: "run_command", kind: "command", summary: `$ ${cmd}`, ok: false, output: `Blocked: ${pol.reason}` }); throw new Error(`Blocked: ${pol.reason}`); }
    if (needsHumanInVm(pol) && d.config.requireApproval) { const r = d.approvals.check(c.userId, "run_command", cmd); if (r.state === "denied") throw new Error("The user denied this command."); if (r.state !== "approved") { const { ApprovalNeeded } = await import("../mcp/tools.js"); throw new ApprovalNeeded(r.id, `run_command: ${cmd}`); } }
    const t0 = Date.now(); const dir = a.cwd ? vmPath(a.cwd) : WORKSPACE_DIR; const r = await e.mgr.exec(c.userId, `mkdir -p ${shq(dir)} && cd ${shq(dir)} && ${cmd}`, { timeoutSec: Math.min(Math.ceil((a.timeoutMs ?? 60000) / 1000), 600) });
    e.feed.add(c.userId, { tool: "run_command", kind: "command", summary: `$ ${cmd}`, ok: !r.exitCode, output: (r.stdout + (r.stderr ? "\n" + r.stderr : "")).slice(0, 4000), ms: Date.now() - t0 });
    return { exitCode: r.exitCode, stdout: r.stdout.slice(0, 100_000), stderr: r.stderr.slice(0, 20_000), ranIn: "vm" };
  },
};

/**
 * Built-in scripts (server-authored; every AI-supplied value is shq-quoted). They skip the AI-command policy because the AI
 * never supplies the script text. `approval` names scripts that change state beyond the workspace and need a human OK.
 */
async function runScript(tool: string, script: string, a: any, c: UserContext, d: ToolDeps, e: VmEnv, approval?: string) {
  if (approval && d.config.requireApproval) { const r = d.approvals.check(c.userId, tool, approval); if (r.state === "denied") throw new Error("The user denied this action."); if (r.state !== "approved") { const { ApprovalNeeded } = await import("../mcp/tools.js"); throw new ApprovalNeeded(r.id, `${tool}: ${approval}`); } }
  const dir = a.cwd ? vmPath(a.cwd) : WORKSPACE_DIR; const t0 = Date.now();
  const r = await e.mgr.exec(c.userId, `mkdir -p ${shq(dir)} && cd ${shq(dir)} && ${script}`, { timeoutSec: 300 });
  e.feed.add(c.userId, { tool, kind: tool.startsWith("git") ? "git" : "command", summary: `${tool}${approval ? ": " + approval : ""}`, ok: !r.exitCode, output: (r.stdout + (r.stderr ? "\n" + r.stderr : "")).slice(0, 4000), ms: Date.now() - t0 });
  return { exitCode: r.exitCode, stdout: r.stdout.slice(0, 100_000), stderr: r.stderr.slice(0, 20_000), ranIn: "vm" };
}
const script = (tool: string, build: (a: any) => string, approval?: (a: any) => string): H => (a, c, d, e) => runScript(tool, build(a), a, c, d, e, approval?.(a));
const q = (v: unknown) => shq(String(v));
const refOk = (v: unknown, what: string) => { if (!/^[A-Za-z0-9._\/-]{1,200}$/.test(String(v)) || String(v).startsWith("-")) throw new Error(`Invalid ${what}.`); return String(v); };
Object.assign(VM_HANDLERS, {
  install_dependencies: script("install_dependencies", () => "if [ -f package-lock.json ]; then npm ci; elif [ -f package.json ]; then npm install; elif [ -f requirements.txt ]; then pip install -r requirements.txt; else echo nothing to install; fi", ),
  run_tests: script("run_tests", (a) => `if [ -f package.json ]; then npm test --silent -- ${(a.extraArgs ?? []).map(q).join(" ")}; elif [ -f pytest.ini ] || [ -d tests ]; then python -m pytest -q ${(a.extraArgs ?? []).map(q).join(" ")}; else echo no tests found; fi`),
  format_code: script("format_code", () => "if [ -f package.json ]; then npx --no-install prettier --write . ; else echo no formatter configured; fi"),
  static_analysis: script("static_analysis", () => "if [ -f tsconfig.json ]; then npx --no-install tsc --noEmit; elif [ -f package.json ]; then npx --no-install eslint . ; else python -m pyflakes . 2>&1 | head -50; fi"),
  build_verify: script("build_verify", () => "if [ -f package.json ]; then npm run build; else echo no build step; fi"),
  git_status: script("git_status", () => "git status --short --branch"),
  git_diff: script("git_diff", (a) => `git diff ${a.staged ? "--cached" : ""} ${a.paths?.length ? "-- " + a.paths.map((x: string) => q(vmPath(x).slice(WORKSPACE_DIR.length + 1) || ".")).join(" ") : ""}`),
  git_log: script("git_log", (a) => `git log --oneline -n ${Math.min(Math.max(1, Number(a.maxCount ?? 20) | 0), 200)}`),
  git_branch_create: script("git_branch_create", (a) => `git switch -c ${q(refOk(a.name, "branch name"))} ${a.startPoint ? q(refOk(a.startPoint, "start point")) : ""}`),
  git_checkout: script("git_checkout", (a) => `git switch ${a.create ? "-c" : ""} ${q(refOk(a.target, "target"))}`),
  git_commit: script("git_commit", (a) => `${a.paths?.length ? "git add -- " + a.paths.map((x: string) => q(vmPath(x).slice(WORKSPACE_DIR.length + 1) || ".")).join(" ") : "git add -A"} && git -c user.name=AI -c user.email=ai@example.invalid commit -m ${q(a.message)}`),
  git_clone: script("git_clone", (a) => `git clone -- ${q(a.url)} ${a.dir ? q(vmPath(a.dir).slice(WORKSPACE_DIR.length + 1)) : ""}`),
  git_pull: script("git_pull", (a) => `git pull --ff-only ${a.remote ? q(refOk(a.remote, "remote")) : ""} ${a.branch ? q(refOk(a.branch, "branch")) : ""}`),
  git_push: script("git_push", (a) => `git push ${a.setUpstream ? "-u" : ""} ${a.remote ? q(refOk(a.remote, "remote")) : ""} ${a.branch ? q(refOk(a.branch, "branch")) : ""}`),
  start_job: async (a, c, d, e) => { const pol = evaluateCommand(String(a.command ?? ""), { root: WORKSPACE_DIR }); if (pol.decision === "deny") throw new Error(`Blocked: ${pol.reason}`); if (needsHumanInVm(pol) && d.config.requireApproval) { const r = d.approvals.check(c.userId, "start_job", String(a.command)); if (r.state === "denied") throw new Error("The user denied this command."); if (r.state !== "approved") { const { ApprovalNeeded } = await import("../mcp/tools.js"); throw new ApprovalNeeded(r.id, "start_job"); } } const id = "j" + Date.now().toString(36); await runScript("start_job", `mkdir -p /tmp/uca_jobs && (nohup sh -c ${q(a.command)} > /tmp/uca_jobs/${id}.log 2>&1 & echo $! > /tmp/uca_jobs/${id}.pid)`, a, c, d, e); return { jobId: id, started: true }; },
  job_status: async (a, c, _d, e) => { const id = jobId(a.jobId); const r = await e.mgr.exec(c.userId, `kill -0 $(cat /tmp/uca_jobs/${id}.pid 2>/dev/null) 2>/dev/null && echo running || echo finished`); return { jobId: id, status: r.stdout.trim() }; },
  job_output: async (a, c, _d, e) => { const id = jobId(a.jobId); const off = Math.max(0, Number(a.offset ?? 0) | 0), lim = Math.min(Math.max(1, Number(a.limit ?? 20000) | 0), 200000); const r = await e.mgr.exec(c.userId, `tail -c +${off + 1} /tmp/uca_jobs/${id}.log 2>/dev/null | head -c ${lim}`); return { jobId: id, offset: off, output: r.stdout, nextOffset: off + Buffer.byteLength(r.stdout) }; },
  stop_job: async (a, c, _d, e) => { const id = jobId(a.jobId); await e.mgr.exec(c.userId, `kill $(cat /tmp/uca_jobs/${id}.pid 2>/dev/null) 2>/dev/null; true`); return { jobId: id, stopped: true }; },
  list_jobs: async (_a: any, c: UserContext, _d: ToolDeps, e: VmEnv) => { const r = await e.mgr.exec(c.userId, `ls /tmp/uca_jobs/*.log 2>/dev/null | xargs -n1 basename 2>/dev/null | sed 's/.log$//'`); return { jobs: r.stdout.split("\n").filter(Boolean) }; },
  read_command_log: async (a: any, c: UserContext, _d: ToolDeps, e: VmEnv) => ({ note: "Commands run in the VM; this is the live activity log.", logPath: a.logPath, log: e.feed.list(c.userId, 0, 100).filter((x: Activity) => x.kind === "command" || x.kind === "git") }),
} as Record<string, H>);
function jobId(v: unknown): string { const s = String(v ?? ""); if (!/^j[a-z0-9]{4,20}$/.test(s)) throw new Error("Invalid job id."); return s; }

export function missingHandlers(): string[] { return [...GATED_TOOLS].filter((n) => !VM_HANDLERS[n]); }

import { BIG_HANDLERS } from "./bigfiles.js";
Object.assign(VM_HANDLERS, BIG_HANDLERS); // bigfiles reads tools.ts exports only inside functions, so this cycle is safe
