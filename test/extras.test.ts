import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createApp } from "../src/http/app.js";
import { fakeInstaBox, KEY } from "./helpers/fakebox.js";
import { runTool } from "../src/mcp/tools.js";
import { allTools } from "../src/mcp/server.js";
import { GITHUB_EXTRA_TOOLS } from "../src/github/extratools.js";

const text = (r: any) => (r.content ?? []).map((c: any) => c.text).join("");

async function boot() {
  const vmf = fakeInstaBox(); const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "uca-ex-"));
  const calls: { url: string; method: string; body: any }[] = [];
  const fetchImpl = (async (url: any, init: any = {}) => {
    const u = String(url);
    if (u.includes("api.github.com")) { calls.push({ url: u, method: init.method ?? "GET", body: init.body ? JSON.parse(init.body) : undefined }); return new Response(JSON.stringify(u.includes("/search/code") ? { total_count: 1, items: [{ repository: { full_name: "o/r" }, path: "a.ts", html_url: "h" }] } : { ok: true }), { status: 200, headers: { "content-type": "application/json" } }); }
    return vmf.fetchImpl(url, init);
  }) as typeof fetch;
  const port = 20000 + Math.floor(Math.random() * 20000);
  const config: any = { baseUrl: `http://127.0.0.1:${port}`, port, host: "127.0.0.1", dataDir: tmp, workspaceRoot: path.join(tmp, "ws"), requireApproval: true, allowGuests: true, sessionSecret: "x".repeat(40), githubClientId: "", githubClientSecret: "" };
  let app: any;
  try { app = createApp(config, { fetchImpl, instaboxPollMs: 5, githubApiBase: "https://api.github.com" } as any); } catch (e) { fs.rmSync(tmp, { recursive: true, force: true }); throw e; }
  await new Promise<void>((r) => app.server.listen(port, "127.0.0.1", () => r()));
  const deps: any = app.deps; const tools = allTools(deps);
  const mk = (userId: string, gh = true) => { const ctx: any = { userId, login: "t", workspaceRoot: path.join(tmp, "x"), githubToken: gh ? "ghp_testtoken" : undefined }; return { ctx, call: (name: string, args: any = {}) => runTool(tools.find((t: any) => t.name === name)!, args, ctx, deps) as Promise<any> }; };
  return { app, deps, vmf, calls, mk, tools, async stop() { await app.close(); vmf.stop(); fs.rmSync(tmp, { recursive: true, force: true }); } };
}
const key = (b: any, u: any) => b.deps.vault.put(u.ctx.userId, { id: "instabox", label: "I", hosts: ["api.instabox.sh"], auth: { type: "header", name: "X-API-Key" } }, KEY);

test("tool names are unique across the whole registry", async () => {
  const b = await boot(); try { const names = b.tools.map((t: any) => t.name); assert.equal(new Set(names).size, names.length, "duplicate tool names: " + names.filter((n: string, i: number) => names.indexOf(n) !== i)); assert.ok(GITHUB_EXTRA_TOOLS.length >= 25); } finally { await b.stop(); }
});

test("github extras: exact API calls; destructive ones wait for approval and make no request", async () => {
  const b = await boot(); try {
    const u = b.mk("user:1");
    let r = await u.call("gh_pages_enable", { owner: "o", repo: "r", branch: "main", path: "/docs" }); assert.ok(!r.isError, text(r));
    assert.deepEqual(b.calls.at(-1), { url: "https://api.github.com/repos/o/r/pages", method: "POST", body: { source: { branch: "main", path: "/docs" } } });
    r = await u.call("gh_search_code", { q: "foo repo:o/r" }); assert.match(text(r), /a\.ts/);
    // destructive: approval first, nothing sent
    const before = b.calls.length;
    for (const [n, a] of [["gh_repo_delete", { owner: "o", repo: "r" }], ["gh_pr_merge", { owner: "o", repo: "r", number: 3 }], ["gh_pages_disable", { owner: "o", repo: "r" }], ["gh_release_delete", { owner: "o", repo: "r", releaseId: 5 }], ["gh_repo_update", { owner: "o", repo: "r", private: false }]] as any) {
      const x = await u.call(n, a); assert.equal(x.isError, true, n); assert.match(text(x), /approval/i, n);
    }
    assert.equal(b.calls.length, before, "no GitHub request is made while approval is pending");
    // owner/repo are validated: no path injection
    const bad = await u.call("gh_tags", { owner: "o/../../x", repo: "r" }); assert.equal(bad.isError, true); assert.equal(b.calls.length, before);
    // no GitHub sign-in (guest): refused, no request
    const g = b.mk("guest:g", false); const gr = await g.call("gh_tags", { owner: "o", repo: "r" }); assert.equal(gr.isError, true); assert.equal(b.calls.length, before);
  } finally { await b.stop(); }
});

test("big files: out-of-order parts assemble; 20 MB round trip is byte-exact; sha mismatch keeps the old file", async () => {
  const b = await boot(); try {
    const u = b.mk("guest:big"); key(b, u); await u.call("vm_start", {});
    const data = crypto.randomBytes(20 * 1024 * 1024); const sha = crypto.createHash("sha256").update(data).digest("hex"); const PART = 6 * 1024 * 1024;
    const parts: Buffer[] = []; for (let o = 0; o < data.length; o += PART) parts.push(data.subarray(o, o + PART));
    for (const i of [2, 0, 3, 1]) { const r = await u.call("upload_part", { uploadId: "up-test-1", index: i, dataBase64: parts[i].toString("base64") }); assert.ok(!r.isError, text(r)); }
    const f = await u.call("finish_upload", { uploadId: "up-test-1", path: "big/data.bin", sha256: sha, parts: 4 }); assert.ok(!f.isError, text(f)); assert.equal(JSON.parse(text(f)).size, data.length);
    const sess = [...b.vmf.sessions.values()][0]; const onDisk = fs.readFileSync(path.join(sess, "home/workspace/big/data.bin")); assert.ok(onDisk.equals(data), "assembled file is byte-exact");
    assert.equal(fs.existsSync(path.join(sess, "home/workspace/.uca-parts/up-test-1")), false, "parts are cleaned up");
    // read it back in slices
    let off = 0; const got: Buffer[] = []; let eof = false;
    for (let i = 0; i < 20 && !eof; i++) { const r = await u.call("read_file_slice", { path: "big/data.bin", offset: off, size: 4 * 1048576 }); assert.ok(!r.isError, text(r)); const j = JSON.parse(text(r)); got.push(Buffer.from(j.dataBase64, "base64")); assert.equal(j.total, data.length); off = j.nextOffset; eof = j.eof; }
    assert.ok(eof, "reached the end");
    assert.ok(Buffer.concat(got).equals(data), "slices reassemble to the exact file");
    // wrong checksum: old file untouched
    await u.call("upload_part", { uploadId: "up-test-2", index: 0, dataBase64: Buffer.from("NEW").toString("base64") });
    const bad = await u.call("finish_upload", { uploadId: "up-test-2", path: "big/data.bin", sha256: "0".repeat(64) }); assert.equal(bad.isError, true); assert.match(text(bad), /Checksum mismatch/);
    assert.ok(fs.readFileSync(path.join(sess, "home/workspace/big/data.bin")).equals(data), "a bad upload never replaces the good file");
    // hostile ids / paths
    for (const id of ["../x", "a b", "short", "a;b;c;d;e;f"]) { const r = await u.call("upload_part", { uploadId: id, index: 0, dataBase64: "QQ==" }); assert.equal(r.isError, true, id); }
    const esc = await u.call("finish_upload", { uploadId: "up-test-2", path: "../../etc/passwd" }); assert.equal(esc.isError, true);
  } finally { await b.stop(); }
});

test("big files need a VM; without one they refuse", async () => {
  const b = await boot(); try { const u = b.mk("guest:novm"); const r = await u.call("upload_part", { uploadId: "up-test-3", index: 0, dataBase64: "QQ==" }); assert.equal(r.isError, true); assert.match(text(r), /VM|key/i); } finally { await b.stop(); }
});
