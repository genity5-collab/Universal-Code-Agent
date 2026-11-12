/**
 * VM handlers that return EXACTLY the same result shapes as the original local tools (src/fs/*), so moving the work into the VM
 * does not change what the AI receives. Only POSIX tools are used inside the VM (find, stat, grep, sed, wc, sha256sum, diff, head, tail).
 * test/contract.test.ts compares these shapes against the originals key by key, so they cannot drift apart again.
 */
import crypto from "node:crypto";
import { VM_HANDLERS, WORKSPACE_DIR, vmPath, ensureRoom, sh, type VmEnv } from "./tools.js";
import { shq } from "./client.js";
import type { ToolDeps } from "../mcp/tools.js";
import type { UserContext } from "../types.js";

const EXCL = `-not -path '*/.git/*' -not -path '*/node_modules/*' -not -path '*/.git' -not -path '*/node_modules'`;
const LANG: Record<string, string> = { ts: "typescript", tsx: "typescript", js: "javascript", jsx: "javascript", mjs: "javascript", cjs: "javascript", py: "python", rs: "rust", go: "go", java: "java", rb: "ruby", c: "c", h: "c", cpp: "cpp", cs: "csharp", md: "markdown", json: "json", html: "html", css: "css", sh: "shell", yml: "yaml", yaml: "yaml", txt: "text" };
const lang = (p: string) => LANG[p.split(".").pop()?.toLowerCase() ?? ""] ?? "text";
const rel = (p: string) => p.replace(/^\.\//, "");
type H = (a: any, c: UserContext, d: ToolDeps, e: VmEnv) => Promise<unknown>;
const feed = (e: VmEnv, c: UserContext, tool: string, kind: "read" | "file", summary: string, extra: object = {}) => e.feed.add(c.userId, { tool, kind, summary, ok: true, ...extra });

/** find -printf record: type, size, mtime(sec), relative path */
async function listFind(e: VmEnv, c: UserContext, base: string, args: string): Promise<{ type: "file" | "directory" | "symlink"; size: number; mtimeMs: number; path: string }[]> {
  const r = await sh(e, c, `find ${shq(base)} -mindepth 1 ${args} -printf '%y\\t%s\\t%T@\\t%P\\n' 2>/dev/null | sort -t$'\\t' -k4`);
  return r.stdout.split("\n").filter(Boolean).map((l) => { const [y, s, t, ...p] = l.split("\t"); return { type: y === "d" ? "directory" as const : y === "l" ? "symlink" as const : "file" as const, size: Number(s) || 0, mtimeMs: Math.round(Number(t) * 1000) || 0, path: p.join("\t") }; });
}
const relTo = (base: string, p: string) => { const b = base === WORKSPACE_DIR ? "" : base.slice(WORKSPACE_DIR.length + 1) + "/"; return b + p; };

export const CONTRACT: Record<string, H> = {
  read_file: async (a, c, _d, e) => {
    const p = vmPath(a.path); const max = a.maxBytes ?? 1_000_000;
    const meta = await sh(e, c, `stat -c '%s %Y' ${shq(p)} && wc -l < ${shq(p)} && sha256sum ${shq(p)} | cut -d' ' -f1 && (head -c 8192 ${shq(p)} | tr -d '\\000' | wc -c; head -c 8192 ${shq(p)} | wc -c) && (grep -c $'\\r' ${shq(p)} || true)`);
    const [first, nl, sha, nonNul, allB, crlf] = meta.stdout.split("\n"); const [size, mtime] = (first ?? "").split(" ");
    if (!size) throw new Error(`File not found: ${a.path}`);
    const buf = await e.mgr.readFile(c.userId, p, max); const total = Number(size); const binary = Number(nonNul) !== Number(allB);
    const text = binary ? "" : buf.subarray(0, max).toString("utf8"); const totalLines = Number(nl) + (total > 0 && !text.endsWith("\n") && buf.length >= total ? 1 : 0);
    feed(e, c, "read_file", "read", `Read ${a.path}`, { path: a.path, bytes: buf.length });
    return { path: a.path, content: text, encoding: "utf8", binary, truncated: total > max, size: total, totalBytes: total, totalLines: Number(nl) || (total ? 1 : 0), language: lang(a.path), lineEnding: Number(crlf) > 0 ? "crlf" : "lf", mtimeMs: Number(mtime) * 1000, sha256: (sha ?? "").trim() };
  },
  read_file_chunk: async (a, c, _d, e) => {
    const p = vmPath(a.path); const off = a.offset ?? 0; const size = Math.min(a.size ?? 65536, 1_000_000); const enc = a.encoding ?? "utf8";
    const tot = await sh(e, c, `wc -c < ${shq(p)}`); const total = Number(tot.stdout.trim()); if (!Number.isFinite(total)) throw new Error(`File not found: ${a.path}`);
    const r = await sh(e, c, `tail -c +${off + 1} ${shq(p)} | head -c ${size} | base64 -w0`); const buf = Buffer.from(r.stdout.trim(), "base64");
    feed(e, c, "read_file_chunk", "read", `Read ${a.path} bytes ${off}-${off + buf.length}`, { path: a.path, bytes: buf.length });
    return { path: a.path, content: enc === "base64" ? buf.toString("base64") : buf.toString("utf8"), encoding: enc, offset: off, requestedOffset: off, requestedSize: a.size ?? 65536, bytesRead: buf.length, nextOffset: off + buf.length, eof: off + buf.length >= total, totalBytes: total };
  },
  read_file_range: async (a, c, _d, e) => {
    const p = vmPath(a.path); const s = a.startLine ?? 1; const maxLines = a.maxLines ?? 200; const en = Math.min(a.endLine ?? s + maxLines - 1, s + maxLines - 1);
    const cnt = await sh(e, c, `wc -l < ${shq(p)}; wc -c < ${shq(p)}`); const [nl, nb] = cnt.stdout.split("\n"); const totalLines = Number(nl) || 0; if (!Number.isFinite(Number(nb))) throw new Error(`File not found: ${a.path}`);
    const r = await sh(e, c, `sed -n '${s},${en}p' ${shq(p)}`); const lines = r.stdout.split("\n"); if (lines[lines.length - 1] === "") lines.pop();
    const shown = a.includeLineNumbers ? lines.map((l, i) => `${s + i}: ${l}`) : lines; const last = s + lines.length - 1;
    feed(e, c, "read_file_range", "read", `Read ${a.path}:${s}-${last}`, { path: a.path });
    return { path: a.path, startLine: s, endLine: last, lines: shown, text: shown.join("\n"), totalLines, totalBytes: Number(nb), hasMore: last < totalLines, nextStartLine: last < totalLines ? last + 1 : null };
  },
  list_directory: async (a, c, _d, e) => {
    const p = vmPath(a.path ?? "."); const limit = a.limit ?? 200; const offset = a.offset ?? 0; const depth = a.recursive ? (a.maxDepth ?? 3) : 1;
    const all = await listFind(e, c, p, `-maxdepth ${depth} ${a.includeIgnored ? "" : EXCL}`);
    const page = all.slice(offset, offset + limit);
    feed(e, c, "list_directory", "read", `Listed ${a.path ?? "."} (${all.length})`, { path: a.path ?? "." });
    return { path: a.path ?? ".", entries: page.map((x) => ({ name: x.path.split("/").pop(), path: relTo(p, x.path), type: x.type, size: x.size, mtimeMs: x.mtimeMs })), total: all.length, offset, limit, hasMore: offset + limit < all.length, nextOffset: offset + limit < all.length ? offset + limit : null };
  },
  search_files: async (a, c, _d, e) => {
    const limit = a.limit ?? 100; const offset = a.offset ?? 0; const all = await listFind(e, c, WORKSPACE_DIR, `-type f ${EXCL}`);
    const globToRe = (g: string) => new RegExp("^" + g.replace(/[.+^${}()|\\]/g, "\\$&").replace(/\*\*/g, "\u0000").replace(/\*/g, "[^/]*").replace(/\u0000/g, ".*").replace(/\?/g, "[^/]") + "$", "i");
    let test: (s: string) => boolean;
    if (a.regex) { let re: RegExp; try { re = new RegExp(a.pattern, "i"); } catch { throw new Error("Invalid regular expression."); } test = (s) => re.test(s); }
    else if (/[*?]/.test(a.pattern)) { const re = globToRe(a.pattern); const reAny = a.matchPath || a.pattern.includes("/") ? re : globToRe(a.pattern); test = (s) => (a.matchPath || a.pattern.includes("/") ? reAny.test(s) : reAny.test(s.split("/").pop() ?? s)); }
    else { const n = String(a.pattern).toLowerCase(); test = (s) => (a.matchPath ? s : s.split("/").pop() ?? s).toLowerCase().includes(n); }
    const hits = all.filter((x) => test(x.path)); const page = hits.slice(offset, offset + limit);
    feed(e, c, "search_files", "read", `Searched files: ${a.pattern} (${hits.length})`);
    return { pattern: a.pattern, matches: page.map((x) => ({ path: x.path, type: "file", size: x.size, mtimeMs: x.mtimeMs })), total: hits.length, offset, limit, hasMore: offset + limit < hits.length, nextOffset: offset + limit < hits.length ? offset + limit : null };
  },
  search_content: async (a, c, _d, e) => {
    const limit = Math.min(a.limit ?? 100, 500); const ctxN = Math.min(a.contextLines ?? 0, 10);
    const inc = a.glob ? `--include=${shq(a.glob)}` : ""; const flags = `-rnI ${a.caseSensitive ? "" : "-i"} ${a.regex ? "-E" : "-F"} ${inc} --exclude-dir=.git --exclude-dir=node_modules`;
    const r = await sh(e, c, `grep ${flags} -- ${shq(a.query)} . | head -${limit + 1}`); const lines = r.stdout.split("\n").filter(Boolean);
    const hasMore = lines.length > limit; const matches: any[] = []; const files = new Set<string>();
    for (const ln of lines.slice(0, limit)) { const m = /^\.\/(.+?):(\d+):(.*)$/.exec(ln); if (!m) continue; files.add(m[1]); const col = a.caseSensitive ? m[3].indexOf(a.query) : m[3].toLowerCase().indexOf(String(a.query).toLowerCase()); matches.push({ path: m[1], line: Number(m[2]), column: col >= 0 ? col + 1 : 1, text: m[3], before: [] as string[], after: [] as string[] }); }
    if (ctxN > 0) for (const m of matches) { const cx = await sh(e, c, `sed -n '${Math.max(1, m.line - ctxN)},${m.line + ctxN}p' ${shq(vmPath(m.path))}`); const ls = cx.stdout.split("\n"); const idx = Math.min(ctxN, m.line - 1); m.before = ls.slice(0, idx); m.after = ls.slice(idx + 1, idx + 1 + ctxN).filter((x, i, arr) => !(i === arr.length - 1 && x === "")); }
    const scanned = Number((await sh(e, c, `find . -type f ${EXCL} | wc -l`)).stdout.trim()) || 0;
    feed(e, c, "search_content", "read", `Searched for "${a.query}" (${matches.length})`);
    return { pattern: a.query, matches, count: matches.length, filesWithMatches: files.size, filesScanned: scanned, hasMore, nextCursor: hasMore ? String(limit) : null, limit };
  },
  get_file_metadata: async (a, c, _d, e) => {
    const p = vmPath(a.path); const r = await sh(e, c, `stat -c '%F|%s|%Y|%W|%Z|%a' ${shq(p)} && (test -f ${shq(p)} && wc -l < ${shq(p)} || echo 0) && (test -f ${shq(p)} && sha256sum ${shq(p)} | cut -d' ' -f1 || echo '') && (test -f ${shq(p)} && head -c 8192 ${shq(p)} | tr -d '\\000' | wc -c || echo 0) && (test -f ${shq(p)} && head -c 8192 ${shq(p)} | wc -c || echo 0) && (test -f ${shq(p)} && grep -c $'\\r' ${shq(p)} || echo 0)`);
    const [head, nl, sha, nn, ab, crlf] = r.stdout.split("\n"); if (!head) throw new Error(`Not found: ${a.path}`);
    const [kind, size, mt, bt, ct, mode] = head.split("|"); const isDir = kind.startsWith("directory");
    feed(e, c, "get_file_metadata", "read", `Metadata ${a.path}`, { path: a.path });
    return { path: a.path, type: isDir ? "directory" : "file", size: Number(size), mtimeMs: Number(mt) * 1000, mtimeIso: new Date(Number(mt) * 1000).toISOString(), birthtimeMs: Number(bt) > 0 ? Number(bt) * 1000 : Number(mt) * 1000, ctimeMs: Number(ct) * 1000, mode: parseInt(mode, 8), lines: Number(nl) || 0, sha256: (sha ?? "").trim(), language: lang(a.path), binary: Number(nn) !== Number(ab), lineEnding: Number(crlf) > 0 ? "crlf" : "lf" };
  },
  write_file: async (a, c, d, e) => {
    const p = vmPath(a.path); const data = Buffer.from(a.content, "utf8"); await ensureRoom(e, c, data.length);
    const ex = await sh(e, c, `test -e ${shq(p)} && echo yes`); const existed = ex.stdout.includes("yes"); if (existed && a.overwrite === false) throw new Error("File exists and overwrite=false.");
    await e.mgr.writeFile(c.userId, p, data);
    e.feed.add(c.userId, { tool: "write_file", kind: "file", summary: `Wrote ${a.path}`, ok: true, path: a.path, bytes: data.length });
    return { path: a.path, created: !existed, bytesWritten: data.length, size: data.length, mtimeMs: Date.now() };
  },
  create_file: async (a, c, _d, e) => {
    const p = vmPath(a.path); const x = await sh(e, c, `test -e ${shq(p)} && echo yes`); if (x.stdout.includes("yes")) throw new Error("File already exists."); const data = Buffer.from(a.content ?? "", "utf8");
    await ensureRoom(e, c, data.length); await e.mgr.writeFile(c.userId, p, data);
    e.feed.add(c.userId, { tool: "create_file", kind: "file", summary: `Created ${a.path}`, ok: true, path: a.path, bytes: data.length });
    return { path: a.path, created: true, bytesWritten: data.length, size: data.length, mtimeMs: Date.now() };
  },
  edit_file: async (a, c, _d, e) => {
    const p = vmPath(a.path); const cur = (await e.mgr.readFile(c.userId, p)).toString("utf8"); let next: string; let replacements = 1; let firstLine = 1;
    if (a.oldString !== undefined) {
      const n = cur.split(a.oldString).length - 1; if (n === 0) throw new Error("oldString not found."); if (n > 1 && !a.replaceAll) throw new Error(`oldString matches ${n} times; make it unique or set replaceAll.`);
      firstLine = cur.slice(0, cur.indexOf(a.oldString)).split("\n").length; replacements = a.replaceAll ? n : 1;
      next = a.replaceAll ? cur.split(a.oldString).join(a.newString ?? "") : cur.replace(a.oldString, () => a.newString ?? "");
    } else if (a.startLine) { const ls = cur.split("\n"); ls.splice(a.startLine - 1, (a.endLine ?? a.startLine) - a.startLine + 1, ...(a.newString ?? "").split("\n")); next = ls.join("\n"); firstLine = a.startLine; } else throw new Error("Provide oldString or startLine.");
    await ensureRoom(e, c, Math.max(0, next.length - cur.length)); await e.mgr.writeFile(c.userId, p, Buffer.from(next, "utf8"));
    const before = cur.split("\n"), after = next.split("\n"); let i = 0; while (i < before.length && i < after.length && before[i] === after[i]) i++;
    let j = 0; while (j < before.length - i && j < after.length - i && before[before.length - 1 - j] === after[after.length - 1 - j]) j++;
    const diff = [`--- ${a.path}`, `+++ ${a.path}`, `@@ -${i + 1},${before.length - i - j} +${i + 1},${after.length - i - j} @@`, ...before.slice(i, before.length - j).map((l) => "-" + l), ...after.slice(i, after.length - j).map((l) => "+" + l)].join("\n");
    e.feed.add(c.userId, { tool: "edit_file", kind: "file", summary: `Edited ${a.path}`, ok: true, path: a.path, bytes: next.length });
    return { path: a.path, replacements, firstChangedLine: firstLine, bytesBefore: Buffer.byteLength(cur), bytesAfter: Buffer.byteLength(next), diff };
  },
  compare_files: async (a, c, _d, e) => {
    const r = await sh(e, c, `diff -u ${a.ignoreWhitespace ? "-w" : ""} -U${a.context ?? 3} ${shq(vmPath(a.pathA))} ${shq(vmPath(a.pathB))}`);
    if (r.exitCode === 2) throw new Error(r.stderr.slice(0, 200) || "compare failed");
    const lines = r.stdout.split("\n"); const added = lines.filter((l) => l.startsWith("+") && !l.startsWith("+++")).length, removed = lines.filter((l) => l.startsWith("-") && !l.startsWith("---")).length;
    feed(e, c, "compare_files", "read", `Compared ${a.pathA} and ${a.pathB}`);
    return { pathA: a.pathA, pathB: a.pathB, identical: r.exitCode === 0, diff: r.stdout, added, removed };
  },
};
// The raw handlers in tools.ts that are not rewritten here (index/map/dependency/changes) are rebuilt in contract2.ts.
Object.assign(VM_HANDLERS, CONTRACT);
