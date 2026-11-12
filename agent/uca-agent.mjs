#!/usr/bin/env node
// Universal Code Agent: Codespace agent.
// Runs INSIDE a GitHub Codespace (a real Linux VM). It connects OUT to your UCA server over HTTPS,
// long-polls for jobs, runs them here and posts results back. No inbound port, no dependencies.
//
//   UCA_SERVER=https://your-server UCA_TOKEN=uca_xxx node agent/uca-agent.mjs [--root /workspaces/repo]
//
// Jobs are a fixed set of ops (exec, read_file, write_file, list_dir, stat, delete, mkdir, search, info).
// File ops are confined to the root directory. `exec` runs a real bash command in the Codespace:
// that is the point of using a Codespace, and the Codespace itself is the sandbox.
import fs from "node:fs";
import fsp from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";

const args = process.argv.slice(2);
const argVal = (n) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : undefined; };
const SERVER = (process.env.UCA_SERVER || argVal("--server") || "").replace(/\/+$/, "");
const TOKEN = process.env.UCA_TOKEN || argVal("--token") || "";
const ROOT = path.resolve(argVal("--root") || process.env.UCA_ROOT || process.env.CODESPACE_VSCODE_FOLDER || process.cwd());
const MAX_READ = 2_000_000;
const MAX_OUT = 200_000;
const VERSION = "1.0.0";

if (!SERVER || !TOKEN) { console.error("UCA_SERVER and UCA_TOKEN are required"); process.exit(2); }
if (!/^https:\/\//.test(SERVER) && !/^http:\/\/(localhost|127\.0\.0\.1)/.test(SERVER)) { console.error("UCA_SERVER must be https (or localhost for tests)"); process.exit(2); }

const ROOT_REAL = fs.realpathSync(ROOT);

/** Resolve a user path inside ROOT, following symlinks, refusing escapes. */
function inside(rel) {
  const p = path.resolve(ROOT_REAL, String(rel ?? "."));
  let real;
  try { real = fs.realpathSync(p); }
  catch { // not existing yet: check the nearest existing parent
    let parent = path.dirname(p);
    while (!fs.existsSync(parent) && parent !== path.dirname(parent)) parent = path.dirname(parent);
    real = path.join(fs.realpathSync(parent), path.relative(parent, p));
  }
  if (real !== ROOT_REAL && !real.startsWith(ROOT_REAL + path.sep)) throw new Error("Path escapes the workspace root");
  return real;
}

function scrub(s) {
  let t = String(s ?? "");
  if (TOKEN) t = t.split(TOKEN).join("[redacted]");
  return t.replace(/\b(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9]{20,}|uca_[A-Za-z0-9_-]{20,})\b/g, "[redacted]");
}

function exec(a) {
  return new Promise((resolve) => {
    const cwd = a.cwd ? inside(a.cwd) : ROOT_REAL;
    const timeoutMs = Math.min(Math.max(Number(a.timeoutMs) || 120_000, 1000), 600_000);
    const env = { ...process.env, CI: "1", TERM: "dumb" };
    delete env.UCA_TOKEN; delete env.UCA_SERVER; // never leak the pairing token to commands
    const child = spawn("bash", ["-lc", String(a.command)], { cwd, env, detached: true, stdio: ["pipe", "pipe", "pipe"] });
    let out = "", err = "", truncated = false, timedOut = false;
    const cap = (cur, d) => { if (cur.length + d.length > MAX_OUT) { truncated = true; return (cur + d).slice(0, MAX_OUT); } return cur + d; };
    child.stdout.on("data", (d) => { out = cap(out, d.toString()); });
    child.stderr.on("data", (d) => { err = cap(err, d.toString()); });
    if (a.input) child.stdin.end(String(a.input)); else child.stdin.end();
    const kill = (sig) => { try { process.kill(-child.pid, sig); } catch {} };
    const timer = setTimeout(() => { timedOut = true; kill("SIGTERM"); setTimeout(() => kill("SIGKILL"), 3000).unref(); }, timeoutMs);
    const started = Date.now();
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      resolve({ exitCode: code, signal, stdout: scrub(out), stderr: scrub(err), timedOut, truncated, durationMs: Date.now() - started, cwd });
    });
    child.on("error", (e) => { clearTimeout(timer); resolve({ exitCode: null, stdout: "", stderr: scrub(e.message), timedOut: false, truncated: false, durationMs: 0, cwd }); });
  });
}

const ops = {
  async info() {
    return { version: VERSION, root: ROOT_REAL, hostname: os.hostname(), platform: os.platform(), release: os.release(), arch: os.arch(),
      cpus: os.cpus().length, memTotalMb: Math.round(os.totalmem() / 1048576), memFreeMb: Math.round(os.freemem() / 1048576),
      node: process.version, user: os.userInfo().username, codespace: process.env.CODESPACE_NAME || null };
  },
  exec,
  async read_file(a) {
    const p = inside(a.path); const st = await fsp.stat(p);
    if (!st.isFile()) throw new Error("Not a file");
    const offset = Math.max(0, Number(a.offset) || 0); const size = Math.min(Number(a.size) || MAX_READ, MAX_READ);
    const fh = await fsp.open(p, "r");
    try {
      const buf = Buffer.alloc(Math.min(size, Math.max(0, st.size - offset)));
      await fh.read(buf, 0, buf.length, offset);
      const enc = a.encoding === "base64" ? "base64" : "utf8";
      return { path: path.relative(ROOT_REAL, p), size: st.size, offset, bytes: buf.length, eof: offset + buf.length >= st.size, nextOffset: offset + buf.length, content: scrub(buf.toString(enc)) };
    } finally { await fh.close(); }
  },
  async write_file(a) {
    const p = inside(a.path);
    if (a.overwrite === false && fs.existsSync(p)) throw new Error("File already exists");
    if (a.createDirs !== false) await fsp.mkdir(path.dirname(p), { recursive: true });
    const data = a.encoding === "base64" ? Buffer.from(String(a.content ?? ""), "base64") : String(a.content ?? "");
    const tmp = p + ".uca-" + process.pid + ".tmp";
    await fsp.writeFile(tmp, data, { mode: a.mode ? parseInt(a.mode, 8) : 0o644 });
    await fsp.rename(tmp, p);
    return { path: path.relative(ROOT_REAL, p), bytes: Buffer.byteLength(data) };
  },
  async list_dir(a) {
    const p = inside(a.path ?? "."); const entries = await fsp.readdir(p, { withFileTypes: true });
    const limit = Math.min(Number(a.limit) || 500, 2000); const offset = Number(a.offset) || 0;
    const items = [];
    for (const e of entries.sort((x, y) => x.name.localeCompare(y.name)).slice(offset, offset + limit)) {
      if (e.name === ".git" && !a.includeGit) continue;
      let size = null; try { if (e.isFile()) size = (await fsp.stat(path.join(p, e.name))).size; } catch {}
      items.push({ name: e.name, type: e.isDirectory() ? "dir" : e.isSymbolicLink() ? "symlink" : "file", size });
    }
    return { path: path.relative(ROOT_REAL, p) || ".", total: entries.length, offset, items };
  },
  async stat(a) {
    const p = inside(a.path); const st = await fsp.stat(p);
    return { path: path.relative(ROOT_REAL, p), type: st.isDirectory() ? "dir" : "file", size: st.size, mtime: st.mtime.toISOString(), mode: (st.mode & 0o777).toString(8) };
  },
  async delete(a) {
    const p = inside(a.path); if (p === ROOT_REAL) throw new Error("Refusing to delete the workspace root");
    await fsp.rm(p, { recursive: !!a.recursive, force: false });
    return { deleted: path.relative(ROOT_REAL, p) };
  },
  async mkdir(a) { const p = inside(a.path); await fsp.mkdir(p, { recursive: true }); return { path: path.relative(ROOT_REAL, p) }; },
  async search(a) {
    // Content search via grep -rIn with fixed args (no shell interpolation).
    const cwd = ROOT_REAL; const limit = Math.min(Number(a.limit) || 200, 1000);
    const argv = ["-rIn", "--exclude-dir=.git", "--exclude-dir=node_modules", "--max-count=50", ...(a.caseSensitive ? [] : ["-i"]), ...(a.regex ? ["-E"] : ["-F"]), "-e", String(a.query), "--", a.path ? path.relative(cwd, inside(a.path)) || "." : "."];
    return await new Promise((resolve) => {
      const c = spawn("grep", argv, { cwd }); let out = ""; c.stdout.on("data", (d) => { if (out.length < 400_000) out += d; });
      c.on("close", () => { const lines = out.split("\n").filter(Boolean).slice(0, limit); resolve({ count: lines.length, matches: lines.map((l) => { const m = /^(.*?):(\d+):(.*)$/.exec(l); return m ? { path: m[1], line: Number(m[2]), text: scrub(m[3].slice(0, 300)) } : { text: scrub(l) }; }) }); });
      c.on("error", () => resolve({ count: 0, matches: [], error: "grep not available" }));
    });
  },
};

async function call(pathname, body, signal) {
  const res = await fetch(SERVER + pathname, { method: "POST", signal, headers: { "content-type": "application/json", authorization: "Bearer " + TOKEN }, body: JSON.stringify(body ?? {}) });
  if (res.status === 401) throw Object.assign(new Error("unauthorized: pairing token rejected or revoked"), { fatal: true });
  if (!res.ok && res.status !== 204) throw new Error("server " + res.status);
  return res.status === 204 ? null : res.json();
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let stopping = false;
process.on("SIGINT", () => { stopping = true; });
process.on("SIGTERM", () => { stopping = true; });

async function runJob(job) {
  let result;
  try {
    const fn = ops[job.op];
    if (!fn) throw new Error("Unknown op: " + job.op);
    result = { ok: true, data: await fn(job.args || {}) };
  } catch (e) { result = { ok: false, error: scrub(String(e?.message ?? e)) }; }
  for (let i = 0; i < 3; i++) { try { await call("/agent/result", { jobId: job.id, result }); return; } catch (e) { if (e.fatal) throw e; await sleep(500 * (i + 1)); } }
}

async function main() {
  console.log(`[uca-agent] v${VERSION} root=${ROOT_REAL} server=${SERVER}`);
  let backoff = 1000;
  while (!stopping) {
    try {
      await call("/agent/hello", { info: await ops.info() });
      backoff = 1000;
      while (!stopping) {
        const r = await call("/agent/next", {});
        if (r && r.job) void runJob(r.job).catch((e) => { if (e.fatal) { console.error("[uca-agent]", e.message); process.exit(3); } });
      }
    } catch (e) {
      if (e.fatal) { console.error("[uca-agent]", e.message); process.exit(3); }
      console.error("[uca-agent] connection problem, retrying:", scrub(e.message));
      await sleep(backoff); backoff = Math.min(backoff * 2, 30_000);
    }
  }
}
main();
