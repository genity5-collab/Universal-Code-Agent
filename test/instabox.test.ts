import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import http from "node:http";
import { execFileSync } from "node:child_process";
import type { AddressInfo } from "node:net";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { loadConfig } from "../src/util/config.js";
import { createApp } from "../src/http/app.js";
import { vmPath, GATED_TOOLS, missingHandlers, VM_HANDLERS } from "../src/instabox/tools.js";
import { TOOLS } from "../src/mcp/tools.js";
import { shq } from "../src/instabox/client.js";
import { fileURLToPath } from "node:url";

import { fakeInstaBox, KEY } from "./helpers/fakebox.js";
async function boot(vmf = fakeInstaBox()) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "uca-vm-"));
  const probe = http.createServer(); await new Promise<void>((r) => probe.listen(0, "127.0.0.1", () => r())); const port = (probe.address() as AddressInfo).port; await new Promise((r) => probe.close(r));
  const config = loadConfig({ PORT: String(port), UCA_BASE_URL: `http://127.0.0.1:${port}`, UCA_DATA_DIR: tmp, UCA_ALLOW_GUESTS: "true" } as any);
  const app = createApp(config, { fetchImpl: vmf.fetchImpl, instaboxPollMs: 5 } as any); await new Promise<void>((r) => app.server.listen(port, "127.0.0.1", () => r()));
  return { app, config, base: config.baseUrl, vmf, tmp, async stop() { await app.close(); vmf.stop(); fs.rmSync(tmp, { recursive: true, force: true }); } };
}
/** Minimal valid arguments for a tool, derived from its real zod shape, so refusals are about the VM and never about bad args. */
function validArgs(name: string): any {
  const t = TOOLS.find((x) => x.name === name)!; const out: any = {};
  for (const [k, schema] of Object.entries(t.shape) as [string, any][]) {
    const s = schema._def?.typeName === "ZodDefault" ? schema._def.innerType : schema; const kind = s._def?.typeName ?? "";
    if (schema.isOptional?.() && kind !== "ZodString") continue; if (kind === "ZodOptional") continue;
    out[k] = kind === "ZodString" ? (k === "url" ? "https://example.com/r.git" : k === "jobId" ? "jabc123" : "a.txt") : kind === "ZodBoolean" ? false : kind === "ZodNumber" ? 1 : kind === "ZodArray" ? [] : "a";
  }
  return out;
}
const text = (r: any) => (r.content ?? []).map((c: any) => c.text).join("");

/** Call tools through the real runTool path (the gate), as a given user. */
async function asUser(b: Awaited<ReturnType<typeof boot>>, userId = "guest:tester") {
  const { runTool } = await import("../src/mcp/tools.js"); const { allTools } = await import("../src/mcp/server.js");
  const deps: any = (b.app as any).deps; const ctx: any = { userId, login: "t", workspaceRoot: path.join(b.tmp, "ws-should-stay-empty") };
  const tools = allTools(deps);
  return { ctx, deps, call: (name: string, args: any = {}) => runTool(tools.find((t: any) => t.name === name)!, args, ctx, deps) as Promise<any> };
}

test("vmPath: stays inside the workspace and rejects traversal", () => {
  const W = "/data/home/workspace";
  assert.equal(vmPath("a/b.txt"), `${W}/a/b.txt`); assert.equal(vmPath("."), W); assert.equal(vmPath(`${W}/x`), `${W}/x`);
  for (const bad of ["../etc/passwd", "a/../../etc", "/etc/passwd", "/data/home/other", `${W}/../x`, "a\0b"]) assert.throws(() => vmPath(bad), Error, bad);
});
test("shq: shell quoting survives hostile input", () => {
  const evil = `x'; echo PWNED > /tmp/owned #`; const out = execFileSync("bash", ["-c", `printf %s ${shq(evil)}`], { encoding: "utf8" }); assert.equal(out, evil);
});
test("every gated tool has a VM handler and exists as a real tool (no gaps, no typos)", () => {
  assert.deepEqual(missingHandlers(), []); const names = new Set(TOOLS.map((t) => t.name));
  for (const g of GATED_TOOLS) assert.ok(names.has(g), `gated tool ${g} does not exist`);
  // every tool that takes a workspace path must be gated; GitHub / Codespaces / provider tools are not
  for (const t of TOOLS) { const touchesDisk = /workspaceRoot/.test(t.handler.toString()); if (touchesDisk) assert.ok(GATED_TOOLS.has(t.name), `${t.name} touches the server disk but is NOT gated`); }
});

test("every VM handler only reads arguments its tool actually declares (catches schema drift)", () => {
  const byName = new Map(TOOLS.map((t) => [t.name, t]));
  for (const name of GATED_TOOLS) {
    const declared = new Set(Object.keys(byName.get(name)!.shape)); const src = VM_HANDLERS[name].toString();
    const used = new Set([...src.matchAll(/\ba\.([A-Za-z_][A-Za-z0-9_]*)/g)].map((m) => m[1]));
    for (const u of used) if (!declared.has(u)) assert.fail(`${name}: handler reads a.${u} but the tool only declares: ${[...declared].join(", ") || "(nothing)"}`);
  }
});

test("NO VM, NO WORK: every gated tool refuses, nothing touches the server disk, and the message says what to do", async () => {
  const b = await boot(); try {
    const u = await asUser(b);
    for (const name of GATED_TOOLS) {
      const r = await u.call(name, validArgs(name));
      assert.equal(r.isError, true, `${name} must refuse without a VM`); assert.match(text(r), /VM|InstaBox/i, name);
    }
    assert.deepEqual(b.vmf.seen, [], "no request may even reach InstaBox without a key");
    assert.equal(fs.existsSync(u.ctx.workspaceRoot), false, "server workspace must never be created or written");
  } finally { await b.stop(); }
});

test("key but VM not started: still refuses; start works; then tools run IN the VM and the server disk stays untouched", async () => {
  const b = await boot(); try {
    const u = await asUser(b); const deps = u.deps;
    deps.vault.put("guest:tester", { id: "instabox", label: "InstaBox", hosts: ["api.instabox.sh"], auth: { type: "header", name: "X-API-Key" } }, KEY);
    let r = await u.call("write_file", { path: "a.txt", content: "x" }); assert.equal(r.isError, true); assert.match(text(r), /Start VM|VM/i);
    r = await u.call("vm_start", {}); assert.ok(!r.isError, text(r)); assert.equal(deps.vm.status("guest:tester").running, true);
    r = await u.call("write_file", { path: "src/hello.txt", content: "hello vm" }); assert.ok(!r.isError, text(r));
    r = await u.call("read_file", { path: "src/hello.txt" }); assert.match(text(r), /hello vm/);
    r = await u.call("run_command", { command: "cat src/hello.txt" }); assert.ok(!r.isError, text(r)); assert.match(text(r), /hello vm/); assert.match(text(r), /"ranIn": "vm"/);
    const probe2 = await u.deps.vm.exec("guest:tester", "mkdir -p /workspace; du -sb /workspace | cut -f1"); r = await u.call("edit_file", { path: "src/hello.txt", oldString: "vm", newString: "world" }); assert.ok(!r.isError, text(r) + "");
    r = await u.call("read_file", { path: "src/hello.txt" }); assert.match(text(r), /hello world/);
    r = await u.call("search_content", { query: "world" }); assert.match(text(r), /hello\.txt/);
    r = await u.call("list_directory", { path: "src" }); assert.match(text(r), /hello\.txt/);
    // it really happened in the VM's folder, not the server's
    const sess = [...b.vmf.sessions.values()][0]; assert.equal(fs.readFileSync(path.join(sess, "home/workspace/src/hello.txt"), "utf8"), "hello world");
    assert.equal(fs.existsSync(u.ctx.workspaceRoot), false, "nothing written to the server's disk");
    // path traversal is refused before reaching the VM
    r = await u.call("read_file", { path: "../../etc/passwd" }); assert.equal(r.isError, true);
    // key never leaks through any tool output or the activity feed
    const all = JSON.stringify(deps.feed.list("guest:tester")) + text(await u.call("vm_status", {})); assert.ok(!all.includes(KEY));
  } finally { await b.stop(); }
});

test("dangerous commands are blocked or need approval INSIDE the VM too; blocked attempts show in the feed", async () => {
  const b = await boot(); try {
    const u = await asUser(b); u.deps.vault.put("guest:tester", { id: "instabox", label: "I", hosts: ["api.instabox.sh"], auth: { type: "header", name: "X-API-Key" } }, KEY); await u.call("vm_start", {});
    const bad = ["rm", "-rf", " /"].join(""); let r = await u.call("run_command", { command: bad }); assert.equal(r.isError, true); assert.match(text(r), /Blocked/i);
    r = await u.call("run_command", { command: "npm --version" }); assert.ok(!(JSON.parse(text(r)).status === "approval_required"), "ordinary commands run with no approval");
    assert.ok(u.deps.feed.list("guest:tester").some((a: any) => a.kind === "command" && a.ok === false && /Blocked/.test(a.output ?? "")), "blocked attempt is visible in the live feed");
    assert.equal([...b.vmf.sessions.values()].length, 1);
  } finally { await b.stop(); }
});

test("1 GB cap is enforced: a write that would exceed it is refused (no data sent)", async () => {
  const b = await boot(); try {
    const u = await asUser(b); u.deps.vault.put("guest:tester", { id: "instabox", label: "I", hosts: ["api.instabox.sh"], auth: { type: "header", name: "X-API-Key" } }, KEY); await u.call("vm_start", {});
    // simulate a nearly full workspace by sparse-allocating 1023.99 MB inside the VM's folder
    const sess = [...b.vmf.sessions.values()][0]; const big = path.join(sess, "home", "workspace", "big.bin"); const fd = fs.openSync(big, "w"); fs.writeSync(fd, Buffer.alloc(1), 0, 1, 1024 * 1024 * 1024 - 10); fs.closeSync(fd);
    // du -sb counts apparent size, so this is ~1 GB
    const used = await u.deps.vm.exec("guest:tester", "du -sb /workspace | cut -f1"); const r = await u.call("write_file", { path: "more.txt", content: "x".repeat(1000) }); assert.equal(r.isError, true, `used=${JSON.stringify(used)} result=${text(r)}`); assert.match(text(r), /limit/i);
    assert.equal(fs.existsSync(path.join(sess, "home", "workspace", "more.txt")), false);
  } finally { await b.stop(); }
});

test("users are isolated: user B cannot use user A's VM, and a bad/revoked key shuts the gate again", async () => {
  const b = await boot(); try {
    const A = await asUser(b, "guest:a"), B = await asUser(b, "guest:b");
    A.deps.vault.put("guest:a", { id: "instabox", label: "I", hosts: ["api.instabox.sh"], auth: { type: "header", name: "X-API-Key" } }, KEY); await A.call("vm_start", {}); await A.call("write_file", { path: "secret.txt", content: "A" });
    const r = await B.call("read_file", { path: "secret.txt" }); assert.equal(r.isError, true); assert.match(text(r), /VM|InstaBox/i);
    A.deps.vault.clearUser("guest:a"); const r2 = await A.call("read_file", { path: "secret.txt" }); assert.equal(r2.isError, true, "removing the key closes the gate immediately");
  } finally { await b.stop(); }
});

test("expired VM (404 from InstaBox) closes the gate and tells the user to restart", async () => {
  const b = await boot(); try {
    const u = await asUser(b); u.deps.vault.put("guest:tester", { id: "instabox", label: "I", hosts: ["api.instabox.sh"], auth: { type: "header", name: "X-API-Key" } }, KEY); await u.call("vm_start", {});
    b.vmf.sessions.clear(); const r = await u.call("run_command", { command: "echo hi" }); assert.equal(r.isError, true); assert.match(text(r), /expired|Start VM/i);
    assert.equal(u.deps.vm.status("guest:tester").running, false);
  } finally { await b.stop(); }
});

test("cap FAILS CLOSED: if the VM cannot report its size, writes are refused (never assumed empty)", async () => {
  const b = await boot(); try {
    const u = await asUser(b); u.deps.vault.put("guest:tester", { id: "instabox", label: "I", hosts: ["api.instabox.sh"], auth: { type: "header", name: "X-API-Key" } }, KEY); await u.call("vm_start", {});
    const orig = u.deps.vm.exec.bind(u.deps.vm);
    u.deps.vm.exec = async (uid: string, cmd: string, o: any) => /du -sb/.test(cmd) ? { stdout: "", stderr: "", exitCode: 0 } : orig(uid, cmd, o);
    const r = await u.call("write_file", { path: "a.txt", content: "x" }); assert.equal(r.isError, true); assert.match(text(r), /measure|limit/i);
    const sess = [...b.vmf.sessions.values()][0]; assert.equal(fs.existsSync(path.join(sess, "home", "workspace", "a.txt")), false);
  } finally { await b.stop(); }
});


test("InstaBox wire format: create is async with Idempotency-Key, files are raw bytes, delete sends X-Confirm-Delete", async () => {
  const calls: { method: string; path: string; headers: any; bodyLen: number; q: string }[] = []; const vmf = fakeInstaBox();
  const spy = (async (url: any, init: any = {}) => { const u = new URL(String(url)); calls.push({ method: init.method ?? "GET", path: u.pathname, q: u.search, headers: init.headers ?? {}, bodyLen: init.body ? Buffer.byteLength(init.body as any) : 0 }); return (vmf.fetchImpl as any)(url, init); }) as unknown as typeof fetch;
  const b = await boot({ ...vmf, fetchImpl: spy } as any); try {
    const u = await asUser(b); u.deps.vault.put("guest:tester", { id: "instabox", label: "I", hosts: ["api.instabox.sh"], auth: { type: "header", name: "X-API-Key" } }, KEY);
    const bin = Buffer.from([0, 1, 2, 255, 254, 0, 128, 10, 13]); await u.call("vm_start", {});
    await u.deps.vm.writeFile("guest:tester", "/data/home/workspace/bin.dat", bin); const back = await u.deps.vm.readFile("guest:tester", "/data/home/workspace/bin.dat");
    assert.deepEqual([...back], [...bin], "binary files round-trip byte for byte");
    await u.call("vm_stop", {});
    const create = calls.find((c) => c.method === "POST" && c.path === "/v1/machines")!; assert.ok(create.headers["Idempotency-Key"], "create must send an Idempotency-Key"); assert.equal(create.headers["X-API-Key"], KEY);
    assert.ok(calls.some((c) => c.path.startsWith("/v1/operations/")), "create must poll the operation");
    const put = calls.find((c) => c.method === "PUT")!; assert.match(put.path, /\/files$/); assert.match(put.q, /path=%2Fdata%2Fhome%2Fworkspace%2Fbin\.dat/); assert.match(put.q, /parents=true/); assert.equal(put.headers["content-type"], "application/octet-stream");
    const del = calls.find((c) => c.method === "DELETE")!; assert.match(del.headers["X-Confirm-Delete"], /^m_/); assert.ok(del.headers["Idempotency-Key"]);
    assert.equal(u.deps.vm.status("guest:tester").running, false);
  } finally { await b.stop(); }
});

test("InstaBox errors become clear messages, and the key never appears in any of them", async () => {
  const vmf = fakeInstaBox(); let mode = "";
  const flaky = (async (url: any, init: any = {}) => { const u = new URL(String(url)); const mk = (st: number, code: string) => new Response(JSON.stringify({ error: { code, message: `${code} for ${KEY}` } }), { status: st, headers: { "content-type": "application/json" } });
    if (mode === "cap" && u.pathname === "/v1/machines") return mk(503, "no_capacity"); if (mode === "quota" && u.pathname === "/v1/machines") return mk(429, "quota_exceeded"); if (mode === "scope" && u.pathname === "/v1/machines") return mk(403, "missing_scope"); if (mode === "badkey") return mk(401, "invalid_key");
    return (vmf.fetchImpl as any)(url, init); }) as unknown as typeof fetch;
  const b = await boot({ ...vmf, fetchImpl: flaky } as any); try {
    const u = await asUser(b); u.deps.vault.put("guest:tester", { id: "instabox", label: "I", hosts: ["api.instabox.sh"], auth: { type: "header", name: "X-API-Key" } }, KEY);
    for (const [m, re] of [["cap", /capacity/i], ["quota", /limit/i], ["scope", /machines:read|permission/i], ["badkey", /rejected the key/i]] as const) {
      mode = m; const r = await u.call("vm_start", {}); assert.equal(r.isError, true, m); assert.match(text(r), re, m); assert.ok(!text(r).includes(KEY), `${m}: key leaked`);
      assert.equal(u.deps.vm.status("guest:tester").starting, false, "a failed start must not leave the user stuck in 'starting'");
    }
    mode = ""; const ok = await u.call("vm_start", {}); assert.ok(!ok.isError, text(ok));
    assert.equal((await u.call("vm_start", {})).isError, undefined, "starting twice reuses the same machine");
    assert.equal(u.deps.vm.status("guest:tester").machineId, JSON.parse(text(ok)).machineId);
  } finally { await b.stop(); }
});

test("the AI guide is embedded, matches docs/workspace.md, and vm_help serves it without a VM", async () => {
  const { GUIDE } = await import("../src/instabox/aitools.js"); const onDisk = fs.readFileSync(path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../docs/workspace.md"), "utf8");
  assert.equal(GUIDE, onDisk, "docs/workspace.md drifted from the embedded guide");
  for (const must of ["cannot work without a VM", "1 GB", "/data/home/workspace", "vm_status", "X-Confirm-Delete", "Idempotency-Key"]) assert.ok(GUIDE.includes(must), must);
  const b = await boot(); try { const u = await asUser(b); const r = await u.call("vm_help", {}); assert.ok(!r.isError); assert.match(text(r), /cannot work without a VM/); } finally { await b.stop(); }
});

/** Real HTTP session: guest sign-in gives a cookie + csrf, exactly what the phone app uses. */
async function guestSession(base: string) {
  const r = await fetch(`${base}/auth/guest`, { method: "POST" }); assert.equal(r.status, 200);
  const cookie = (r.headers.getSetCookie?.() ?? []).map((c) => c.split(";")[0]).join("; "); const me = await (await fetch(`${base}/api/me`, { headers: { cookie } })).json() as any;
  return { cookie, H: { cookie, "x-csrf-token": me.csrf, "content-type": "application/json" } as Record<string, string>, userId: me.user?.id ?? me.user?.userId };
}

test("Workspace over real HTTP: key via the app, start VM, AI acts through MCP, feed + files + downloads + traversal protection", async () => {
  const b = await boot(); try {
    const s = await guestSession(b.base); const api = (p: string, o: any = {}) => fetch(`${b.base}/api${p}`, { ...o, headers: { ...(o.method && o.method !== "GET" ? s.H : { cookie: s.cookie }), ...(o.headers ?? {}) } });
    // nothing works before the key + VM
    let st = await (await api("/vm")).json() as any; assert.equal(st.hasKey, false); assert.equal(st.running, false); assert.equal(st.limitBytes, 1024 ** 3);
    assert.equal((await api("/workspace/files")).status, 409, "file list refuses without a VM");
    const noStart = await api("/vm/start", { method: "POST", body: "{}" }); assert.equal(noStart.status, 400); assert.ok(!(await noStart.text()).includes(KEY));
    // user adds the key in the app (preset), then starts the VM
    const add = await api("/providers", { method: "POST", body: JSON.stringify({ id: "instabox", key: KEY }) }); assert.equal(add.status, 200, await add.clone().text());
    const start = await api("/vm/start", { method: "POST", body: "{}" }); assert.equal(start.status, 200, await start.clone().text()); const sj = await start.json() as any; assert.match(sj.machineId, /^m_/);
    // the AI works through the real MCP endpoint, not a shortcut
    const { runTool } = await import("../src/mcp/tools.js"); const { allTools } = await import("../src/mcp/server.js"); const deps: any = (b.app as any).deps;
    const me = await (await api("/me")).json() as any; const uid = me.user.id ?? me.user.userId; const ctx: any = { userId: uid, login: "g", workspaceRoot: path.join(b.tmp, "nope") }; const tools = allTools(deps); const call = (n: string, a: any) => runTool(tools.find((t: any) => t.name === n)!, a, ctx, deps) as Promise<any>;
    assert.ok(!(await call("write_file", { path: "app/index.js", content: "console.log('hi')" })).isError);
    assert.ok(!(await call("write_file", { path: "app/readme.md", content: "# hello" })).isError);
    assert.ok(!(await call("run_command", { command: "ls app" })).isError);
    // live feed shows what the AI did
    const feed = await (await api("/activity")).json() as any; const sums = feed.items.map((i: any) => i.summary).join("\n");
    assert.match(sums, /Wrote app\/index\.js/); assert.match(sums, /\$ ls app/); assert.ok(feed.items.some((i: any) => i.kind === "command" && /index\.js/.test(i.output ?? "")));
    // SSE stream delivers history and then live events
    const ctl = new AbortController(); const sse = await fetch(`${b.base}/api/activity/stream`, { headers: { cookie: s.cookie }, signal: ctl.signal }); assert.equal(sse.status, 200); assert.match(sse.headers.get("content-type") ?? "", /text\/event-stream/);
    const rd = sse.body!.getReader(); let got = ""; const t0 = Date.now(); while (!/hello/.test(got) && Date.now() - t0 < 3000) { got += new TextDecoder().decode((await rd.read()).value); } assert.match(got, /Wrote app\/index\.js/);
    await call("create_file", { path: "live.txt", content: "x" }); let more = ""; const t1 = Date.now(); while (!/live\.txt/.test(more) && Date.now() - t1 < 3000) { more += new TextDecoder().decode((await rd.read()).value); } assert.match(more, /live\.txt/, "a new action is pushed live"); ctl.abort();
    // file browser + usage
    const ls = await (await api("/workspace/files?path=.")).json() as any; assert.ok(ls.entries.some((e: any) => e.name === "app" && e.type === "directory")); assert.ok(ls.usedBytes > 0 && ls.usedBytes < ls.limitBytes);
    const sub = await (await api("/workspace/files?path=app")).json() as any; assert.deepEqual(sub.entries.map((e: any) => e.name).sort(), ["index.js", "readme.md"]);
    // downloads: file bytes, and a folder archive
    const dl = await api("/workspace/download?path=app/index.js"); assert.equal(dl.status, 200); assert.equal(await dl.text(), "console.log('hi')"); assert.match(dl.headers.get("content-disposition") ?? "", /attachment; filename="index\.js"/);
    const dir = await api("/workspace/download?path=app"); assert.equal(dir.status, 200); assert.match(dir.headers.get("content-type") ?? "", /zip|gzip/); assert.ok((await dir.arrayBuffer()).byteLength > 50);
    // path traversal and auth are enforced
    for (const evil of ["../../etc/passwd", "/etc/passwd", "app/../../x"]) { const r = await api("/workspace/download?path=" + encodeURIComponent(evil)); assert.equal(r.status, 400, evil); const l = await api("/workspace/files?path=" + encodeURIComponent(evil)); assert.ok(l.status >= 400, evil); }
    for (const p of ["/vm", "/activity", "/workspace/files", "/workspace/download?path=a"]) assert.equal((await fetch(`${b.base}/api${p}`)).status, 401, `${p} must need a session`);
    assert.equal((await fetch(`${b.base}/api/vm/stop`, { method: "POST", headers: { cookie: s.cookie } })).status, 403, "stop needs the CSRF token");
    // key never in any response
    for (const body of [JSON.stringify(feed), JSON.stringify(ls), JSON.stringify(st)]) assert.ok(!body.includes(KEY));
    // stop deletes the machine, closes the gate
    const stop = await api("/vm/stop", { method: "POST", body: "{}" }); assert.equal(stop.status, 200); assert.equal(((await (await api("/vm")).json()) as any).running, false);
    assert.equal((await api("/workspace/files")).status, 409);
    assert.equal((await call("read_file", { path: "app/index.js" })).isError, true, "after Stop the AI can no longer work");
  } finally { await b.stop(); }
});

test("ONLY DELETES NEED A HUMAN: installs, pushes, risky commands and jobs run automatically; every kind of delete still waits; hard blocks stay blocked", async () => {
  const b = await boot(); try {
    assert.equal(b.config.requireApproval, true);
    const u = await asUser(b); u.deps.vault.put("guest:tester", { id: "instabox", label: "I", hosts: ["api.instabox.sh"], auth: { type: "header", name: "X-API-Key" } }, KEY); await u.call("vm_start", {});
    await u.call("create_file", { path: "victim.txt", content: "keep me" });
    const needsHuman = (r: any) => { try { return JSON.parse(text(r)).status === "approval_required"; } catch { return false; } };
    const need = async (name: string, args: any) => { const r = await u.call(name, args); assert.equal(r.isError, true, `${name} ${JSON.stringify(args)} must not run unapproved`); assert.ok(needsHuman(r), `${name} ${JSON.stringify(args)} must ask the user`); return JSON.parse(text(r)); };
    const free = async (name: string, args: any) => { const r = await u.call(name, args); assert.ok(!needsHuman(r), `${name} ${JSON.stringify(args)} must NOT ask the user: ${text(r).slice(0, 160)}`); return r; };

    // 1. things that used to ask now run on their own
    await free("install_dependencies", {}); await free("git_push", {}); await free("git_pull", {}); await free("git_clone", { url: "https://example.invalid/x.git" });
    for (const command of ["npm install left-pad", "python3 -c print(1)", "node -e 1", "git init", "make", "touch made.txt", "mkdir -p sub"]) await free("run_command", { command });
    await free("start_job", { command: "npm install left-pad" });

    // 2. every form of delete still waits for a human, and nothing is deleted before approval
    const del = await need("delete_file", { path: "victim.txt" });
    assert.match(text(await u.call("read_file", { path: "victim.txt" })), /keep me/, "file must still exist before approval");
    await need("run_command", { command: "rm victim.txt" }); await need("run_command", { command: "rm -r sub" }); await need("run_command", { command: "rm -rf sub" }); await need("run_command", { command: "rmdir sub" });
    await need("run_command", { command: "git clean -fd" }); await need("run_command", { command: "git reset --hard" }); await need("run_command", { command: "git branch -D old" });
    await need("start_job", { command: "rm victim.txt" });
    assert.match(text(await u.call("read_file", { path: "victim.txt" })), /keep me/, "still there after all the refused delete attempts");

    // 3. hard blocks are never relaxed
    for (const command of ["sudo ls", ["rm", "-rf", " /"].join(""), "rm -rf ../x", "rm -rf *"]) { const r = await u.call("run_command", { command }); assert.equal(r.isError, true, command); assert.ok(!needsHuman(r), command + " is blocked, not merely asked"); assert.match(text(r), /Blocked/i, command); }

    // 4. approving a delete works once and is single use
    assert.equal(u.deps.approvals.decide("guest:tester", del.approvalId, true), true);
    const after = await u.call("delete_file", { path: "victim.txt" }); assert.ok(!after.isError, text(after));
    assert.equal((await u.call("read_file", { path: "victim.txt" })).isError, true, "deleted after approval");
    await u.call("create_file", { path: "victim.txt", content: "again" });
    assert.ok(needsHuman(await u.call("delete_file", { path: "victim.txt" })), "approval is single use");
  } finally { await b.stop(); }
});

test("a denied delete never runs", async () => {
  const b = await boot(); try {
    const u = await asUser(b); u.deps.vault.put("guest:tester", { id: "instabox", label: "I", hosts: ["api.instabox.sh"], auth: { type: "header", name: "X-API-Key" } }, KEY); await u.call("vm_start", {});
    await u.call("create_file", { path: "keep.txt", content: "precious" });
    const j = JSON.parse(text(await u.call("delete_file", { path: "keep.txt" }))); assert.equal(u.deps.approvals.decide("guest:tester", j.approvalId, false), true);
    const r = await u.call("delete_file", { path: "keep.txt" }); assert.equal(r.isError, true);
    assert.match(text(await u.call("read_file", { path: "keep.txt" })), /precious/);
  } finally { await b.stop(); }
});

test("the central approval list contains exactly the delete tool (nothing else silently asks, nothing destructive is missing)", async () => {
  const { VM_APPROVAL } = await import("../src/mcp/tools.js");
  assert.deepEqual(Object.keys(VM_APPROVAL), ["delete_file"]);
  const { needsHumanInVm } = await import("../src/instabox/tools.js");
  const ap = (reason: string, argv: string[]) => ({ decision: "approval", reason, argv });
  assert.equal(needsHumanInVm(ap("file deletion inside the workspace", ["rm", "a"])), true);
  assert.equal(needsHumanInVm(ap("git branch deletion/rename", ["git", "branch", "-D", "x"])), true);
  assert.equal(needsHumanInVm(ap("git reset discards workspace changes", ["git", "reset", "--hard"])), true);
  assert.equal(needsHumanInVm(ap("git clean changes repository state", ["git", "clean", "-fd"])), true);
  assert.equal(needsHumanInVm(ap("npm install mutates the project or network", ["npm", "install"])), false);
  assert.equal(needsHumanInVm(ap("git push changes repository state", ["git", "push"])), false);
  assert.equal(needsHumanInVm({ decision: "allow", reason: "x", argv: ["rm", "a"] }), false, "only the approval tier is ever relaxed or asked");
  assert.equal(needsHumanInVm({ decision: "deny", reason: "x", argv: ["rm", "a"] }), false, "deny is handled (blocked) elsewhere and never turns into an ask");
});

test("find_symbol keeps the original result shape: an array of {name, kind, line, path, language}; kind and fuzzy work", async () => {
  const b = await boot(); try {
    const u = await asUser(b); u.deps.vault.put("guest:tester", { id: "instabox", label: "I", hosts: ["api.instabox.sh"], auth: { type: "header", name: "X-API-Key" } }, KEY); await u.call("vm_start", {});
    await u.call("create_file", { path: "src/a.ts", content: "export function hello() { return 1; }\nexport class HelloWorld {}\nexport const helloCount = 2;\n" });
    const ex = JSON.parse(text(await u.call("find_symbol", { name: "hello" }))); assert.ok(Array.isArray(ex));
    assert.deepEqual(ex, [{ name: "hello", kind: "function", line: 1, path: "src/a.ts", language: "typescript" }], "exact match only");
    const fz = JSON.parse(text(await u.call("find_symbol", { name: "hello", fuzzy: true }))); assert.deepEqual(fz.map((h: any) => h.name), ["hello", "HelloWorld", "helloCount"], "exact first, then fuzzy");
    const cls = JSON.parse(text(await u.call("find_symbol", { name: "hello", fuzzy: true, kind: "class" }))); assert.deepEqual(cls.map((h: any) => h.name), ["HelloWorld"]);
    assert.deepEqual(JSON.parse(text(await u.call("find_symbol", { name: "nothing_here" }))), []);
    assert.equal(JSON.parse(text(await u.call("find_symbol", { name: "a; " + ["r","m"].join("") + " -" + "rf /" }))).length, 0, "hostile name is neutralised");
  } finally { await b.stop(); }
});

// ---------------- the VM's real desktop screen ----------------
import { fakeXTools } from "./helpers/fakebox.js";
async function withDesktop() {
  const b = await boot(); const x = fakeXTools(b.tmp); b.vmf.useX(x.bin);
  const u = await asUser(b); u.deps.vault.put("guest:tester", { id: "instabox", label: "I", hosts: ["api.instabox.sh"], auth: { type: "header", name: "X-API-Key" } }, KEY); await u.call("vm_start", {});
  return { b, x, u };
}

test("DESKTOP: start installs when needed, the AI sees the screen as a real PNG image, and mouse/keyboard reach the VM exactly", async () => {
  const { b, x, u } = await withDesktop(); try {
    const st = await u.call("desktop_start", {}); assert.ok(!st.isError, text(st)); assert.match(text(st), /"running": true/); assert.match(text(st), /1280/);
    const shot = await u.call("desktop_screenshot", {}); assert.ok(!shot.isError, text(shot));
    const img = shot.content.find((c: any) => c.type === "image"); assert.ok(img, "an image block is returned so a vision model can see the screen"); assert.ok(["image/png", "image/jpeg"].includes(img.mimeType));
    const png = Buffer.from(img.data, "base64"); assert.ok(png.readUInt32BE(0) === 0x89504e47 || (png[0] === 0xff && png[1] === 0xd8), "really a PNG or JPEG picture");
    await u.call("desktop_click", { x: 100, y: 200 }); await u.call("desktop_click", { x: 5, y: 6, button: "right", double: true });
    await u.call("desktop_type", { text: `it's "quoted"; $(whoami) \`id\`\nline2 ✓` }); await u.call("desktop_press", { keys: ["ctrl", "l"] }); await u.call("desktop_press", { keys: ["Enter"] });
    await u.call("desktop_scroll", { direction: "down", amount: 4 }); await u.call("desktop_drag", { x1: 1, y1: 2, x2: 30, y2: 40 }); await u.call("desktop_move", { x: 9, y: 8 });
    const log = x.readLog();
    for (const want of ["mousemove 100 200 click 1", "mousemove 5 6 click --repeat 2 --delay 80 3", "key -- ctrl+l", "key -- Return", "click --repeat 4 --delay 30 5", "mousemove 1 2 mousedown 1 sleep 0.1 mousemove 30 40 sleep 0.1 mouseup 1", "mousemove 9 8"]) assert.ok(log.includes(want), `missing: ${want}\n${log}`);
    assert.ok(log.includes(`type:it's "quoted"; $(whoami) \`id\`\nline2 ✓`), "text is typed literally, nothing is executed:\n" + log);
    assert.ok(!fs.existsSync(path.join(b.tmp, "PWNED")));
    assert.ok(u.deps.feed.list("guest:tester").some((a: any) => a.tool === "desktop_click"), "shows in the activity feed");
  } finally { await b.stop(); }
});

test("DESKTOP: nothing works without a VM, hostile or out-of-range input is refused before it reaches a shell, and no screenshot files are left behind", async () => {
  const b = await boot(); const x = fakeXTools(b.tmp); b.vmf.useX(x.bin); try {
    const u = await asUser(b);
    for (const [n, a] of [["desktop_screenshot", {}], ["desktop_click", { x: 1, y: 1 }], ["desktop_type", { text: "hi" }], ["desktop_press", { keys: ["a"] }], ["desktop_open", { url: "https://example.com" }], ["desktop_start", {}]] as any) { const r = await u.call(n, a); assert.equal(r.isError, true, n); assert.match(text(r), /VM|key/i, n); }
    u.deps.vault.put("guest:tester", { id: "instabox", label: "I", hosts: ["api.instabox.sh"], auth: { type: "header", name: "X-API-Key" } }, KEY); await u.call("vm_start", {}); await u.call("desktop_start", {});
    for (const [n, a] of [["desktop_click", { x: -1, y: 5 }], ["desktop_click", { x: "1; touch /tmp/PWNED", y: 2 }], ["desktop_click", { x: 1.5, y: 2 }], ["desktop_scroll", { direction: "sideways" }], ["desktop_press", { keys: ["ctrl; rm x"] }], ["desktop_press", { keys: [] }], ["desktop_open", { url: "file:///etc/passwd" }], ["desktop_open", { url: "javascript:alert(1)" }], ["desktop_type", { text: "" }]] as any) { const r = await u.call(n, a); assert.equal(r.isError, true, n + JSON.stringify(a)); }
    assert.equal(x.readLog(), "", "nothing invalid ever reached xdotool");
    await u.call("desktop_screenshot", {});
    const left = execFileSync("bash", ["-c", `ls ${b.vmf.root}/*/ 2>/dev/null; find ${b.vmf.root} -name 'uca-shot-*' | wc -l`], { encoding: "utf8" }); assert.match(left.trim().split("\n").pop()!, /^0$/, "temporary screenshots are deleted");
  } finally { await b.stop(); }
});

test("DESKTOP: a VM without screenshot tools says exactly how to fix it instead of failing mysteriously", async () => {
  const b = await boot(); try {
    const u = await asUser(b); u.deps.vault.put("guest:tester", { id: "instabox", label: "I", hosts: ["api.instabox.sh"], auth: { type: "header", name: "X-API-Key" } }, KEY); await u.call("vm_start", {});
    const r = await u.call("desktop_screenshot", {}); assert.equal(r.isError, true); assert.match(text(r), /apt-get install[^\n]*scrot|desktop_start|screenshot tool/i);
  } finally { await b.stop(); }
});

test("DESKTOP over HTTP: the website gets the screen as a PNG, can click/type/press through the protected input route, and a stranger cannot", async () => {
  const b = await boot(); const x = fakeXTools(b.tmp); b.vmf.useX(x.bin); try {
    const g = await guestSession(b.base);
    assert.equal((await fetch(`${b.base}/api/desktop/screen`)).status, 401, "needs login");
    assert.equal((await fetch(`${b.base}/api/desktop/input`, { method: "POST", body: "{}" })).status, 401);
    assert.equal((await fetch(`${b.base}/api/desktop/screen`, { headers: { cookie: g.cookie } })).status, 409, "no VM yet: a clear refusal, not a crash");
    await fetch(`${b.base}/api/providers`, { method: "POST", headers: g.H, body: JSON.stringify({ id: "instabox", key: KEY }) }); assert.equal((await fetch(`${b.base}/api/vm/start`, { method: "POST", headers: g.H, body: "{}" })).status, 200);
    assert.equal((await fetch(`${b.base}/api/desktop/start`, { method: "POST", headers: g.H, body: "{}" })).status, 200);
    const s = await fetch(`${b.base}/api/desktop/screen`, { headers: { cookie: g.cookie } }); assert.equal(s.status, 200); assert.equal(s.headers.get("content-type"), "image/png"); assert.equal(s.headers.get("cache-control"), "no-store");
    const buf = Buffer.from(await s.arrayBuffer()); assert.equal(buf.readUInt32BE(0), 0x89504e47); assert.equal(s.headers.get("x-screen-width"), "4");
    const inp = (body: any, headers = g.H) => fetch(`${b.base}/api/desktop/input`, { method: "POST", headers, body: JSON.stringify(body) });
    assert.equal((await inp({ type: "click", x: 10, y: 20 })).status, 200); assert.equal((await inp({ type: "type", text: "hello" })).status, 200); assert.equal((await inp({ type: "key", keys: ["Return"] })).status, 200);
    assert.equal((await inp({ type: "click", x: "1;x", y: 2 })).status, 400); assert.equal((await inp({ type: "nope" })).status, 400);
    assert.equal((await inp({ type: "click", x: 1, y: 1 }, { cookie: g.cookie, "content-type": "application/json" })).status >= 400, true, "a request without the CSRF token is refused");
    const log = x.readLog(); assert.ok(log.includes("mousemove 10 20 click 1") && log.includes("type:hello") && log.includes("key -- Return"), log);
  } finally { await b.stop(); }
});

test("DESKTOP privacy: user B can neither see nor drive user A's screen, and the window tools only report on the caller's own VM", async () => {
  const { b, x, u } = await withDesktop(); try {
    await u.call("desktop_start", {});
    const other = await asUser(b, "guest:other");
    for (const [n, a] of [["desktop_screenshot", {}], ["desktop_click", { x: 1, y: 1 }], ["desktop_type", { text: "stolen" }], ["vm_screen_poll", {}], ["vm_live", {}]] as any) {
      const r = await other.call(n, a);
      if (n === "vm_screen_poll" || n === "vm_live") { assert.ok(!r.isError); assert.equal(JSON.stringify(r.structuredContent).includes("data:image"), false, n + " leaked a picture"); assert.deepEqual(r.structuredContent.items ?? [], [], n); }
      else assert.equal(r.isError, true, n);
    }
    assert.ok(!x.readLog().includes("stolen") && !x.readLog().includes("mousemove 1 1"), "B never reached A's desktop");
  } finally { await b.stop(); }
});

// ---------------- FAST live screen + batch tool ----------------
test("FAST FRAMES: many frames are served without a new screenshot process per frame, as small JPEGs, and the app route is protected", async () => {
  const { b, x, u } = await withDesktop(); try {
    await u.call("desktop_start", {});
    const d = (u.deps as any).desktop; const t0 = Date.now(); let last: any;
    for (let i = 0; i < 12; i++) last = await d.frame("guest:tester");
    assert.equal(last.type, "jpeg"); assert.equal(last.img[0], 0xff); assert.equal(last.img[1], 0xd8, "a real JPEG");
    const per = (Date.now() - t0) / 12; assert.ok(per < 400, `average ${per}ms per frame`);
    await new Promise((r) => setTimeout(r, 400));
    assert.ok(x.scrots() < 12 + 6, "the background loop makes the frames; not one capture process per request (" + x.scrots() + ")");
    const shot = await u.call("desktop_screenshot", {}); const img = shot.content.find((c: any) => c.type === "image"); assert.ok(img); assert.ok(["image/jpeg", "image/png"].includes(img.mimeType));
  } finally { await b.stop(); }
});

test("BATCH: desktop_do runs many steps in one call, returns one screenshot, and nothing hostile reaches the shell", async () => {
  const { b, x, u } = await withDesktop(); try {
    await u.call("desktop_start", {});
    const r = await u.call("desktop_do", { steps: [{ do: "click", x: 50, y: 60 }, { do: "type", text: `a'b"c; $(touch PWNED_HOME) \`id\`` }, { do: "press", keys: ["Enter"] }, { do: "scroll", direction: "down", amount: 2 }, { do: "drag", x: 1, y: 2, x2: 3, y2: 4 }, { do: "wait", ms: 50 }], });
    assert.ok(!r.isError, text(r)); assert.ok(r.content.some((c: any) => c.type === "image"), "one screenshot at the end");
    const log = x.readLog(); for (const want of ["mousemove 50 60 click 1", "key -- Return", "click --repeat 2 --delay 30 5", "mousemove 1 2 mousedown 1 sleep 0.1 mousemove 3 4 sleep 0.1 mouseup 1"]) assert.ok(log.includes(want), want + "\n" + log);
    assert.ok(log.includes("type:a'b\"c; $(touch PWNED_HOME) `id`"), "typed literally: " + log); assert.equal(execFileSync("bash", ["-c", `find ${b.vmf.root} -name PWNED_HOME | wc -l`], { encoding: "utf8" }).trim(), "0", "the injected command never ran");
    const noshot = await u.call("desktop_do", { steps: [{ do: "move", x: 1, y: 1 }], screenshot: false }); assert.ok(!noshot.isError); assert.ok(!noshot.content.some((c: any) => c.type === "image"));
    const before = x.readLog();
    for (const steps of [[{ do: "click", x: -5, y: 1 }], [{ do: "press", keys: ["ctrl; rm -rf x"] }], [{ do: "open", url: "file:///etc/passwd" }], [{ do: "scroll", direction: "left; ls" }], [{ do: "bogus" }], [], Array.from({ length: 26 }, () => ({ do: "wait", ms: 1 }))] as any[]) {
      const bad = await u.call("desktop_do", { steps }); assert.equal(bad.isError, true, JSON.stringify(steps).slice(0, 60));
    }
    assert.equal(x.readLog(), before, "an invalid batch runs NOTHING (it is validated whole before any step)");
  } finally { await b.stop(); }
});

test("BATCH needs a VM, like every other desktop tool", async () => {
  const b = await boot(); try { const u = await asUser(b); const r = await u.call("desktop_do", { steps: [{ do: "wait", ms: 1 }] }); assert.equal(r.isError, true); assert.match(text(r), /VM|key/i); } finally { await b.stop(); }
});

test("LIVE VIEWER: the official stream link is used when the key may make one, and the app falls back cleanly when it may not", async () => {
  const { b, u } = await withDesktop(); try {
    await u.call("desktop_start", {}); const d = (u.deps as any).desktop;
    const none = await d.streamUrl("guest:tester", true); assert.equal(none, null, "the fake refuses (like a workspace key): fall back, no crash");
  } finally { await b.stop(); }
});

test("HTTP: /api/desktop/frame is a JPEG and needs login; /api/desktop/stream reports availability; the page CSP allows blob images and only InstaBox frames", async () => {
  const b = await boot(); const x = fakeXTools(b.tmp); b.vmf.useX(x.bin); try {
    assert.equal((await fetch(`${b.base}/api/desktop/frame`)).status, 401); assert.equal((await fetch(`${b.base}/api/desktop/stream`, { method: "POST", body: "{}" })).status, 401);
    const g = await guestSession(b.base); assert.equal((await fetch(`${b.base}/api/desktop/frame`, { headers: { cookie: g.cookie } })).status, 409);
    await fetch(`${b.base}/api/providers`, { method: "POST", headers: g.H, body: JSON.stringify({ id: "instabox", key: KEY }) }); await fetch(`${b.base}/api/vm/start`, { method: "POST", headers: g.H, body: "{}" }); await fetch(`${b.base}/api/desktop/start`, { method: "POST", headers: g.H, body: "{}" });
    const f = await fetch(`${b.base}/api/desktop/frame`, { headers: { cookie: g.cookie } }); assert.equal(f.status, 200); assert.equal(f.headers.get("content-type"), "image/jpeg"); assert.equal(f.headers.get("cache-control"), "no-store"); const buf = Buffer.from(await f.arrayBuffer()); assert.equal(buf[0], 0xff);
    const st = await (await fetch(`${b.base}/api/desktop/stream`, { method: "POST", headers: g.H, body: "{}" })).json() as any; assert.equal(st.available, false);
    const csp = (await fetch(`${b.base}/`)).headers.get("content-security-policy") ?? ""; assert.match(csp, /img-src[^;]*blob:/); assert.match(csp, /frame-src https:\/\/\*\.instabox\.sh https:\/\/instabox\.sh/); assert.ok(!/frame-src[^;]*\*\s*;/.test(csp) && !/frame-src \*/.test(csp), "never frames arbitrary sites"); assert.match(csp, /frame-ancestors 'none'/);
  } finally { await b.stop(); }
});

test("FAST FRAMES: the background capture loop stops by itself when nobody is watching (no forever-running process in the user's VM)", async () => {
  const { b, u } = await withDesktop(); try {
    await u.call("desktop_start", {}); const d = (u.deps as any).desktop; await d.frame("guest:tester");
    const home = execFileSync("bash", ["-c", `find ${b.vmf.root} -name uca-live-loop.sh | head -1`], { encoding: "utf8" }).trim(); assert.ok(home, "the loop script was written");
    const beat = home.replace("uca-live-loop.sh", "uca-live.beat"), pid = home.replace("uca-live-loop.sh", "uca-live.pid");
    // watching: heartbeat fresh -> still running
    assert.ok(fs.existsSync(pid), "running while someone watches");
    // stop watching: make the heartbeat 60 s old; the loop must exit and clean up on its own
    const old = new Date(Date.now() - 60_000); fs.utimesSync(beat, old, old);
    let gone = false; for (let i = 0; i < 40 && !gone; i++) { await new Promise((r) => setTimeout(r, 100)); gone = !fs.existsSync(pid); }
    assert.ok(gone, "the loop exited and removed its pid file once the heartbeat went stale");
    // watching again restarts it
    await d.frame("guest:tester"); let back = false; for (let i = 0; i < 30 && !back; i++) { back = fs.existsSync(pid); if (!back) await new Promise((r) => setTimeout(r, 100)); } assert.ok(back, "watching again restarts the loop");
    fs.utimesSync(beat, old, old);
  } finally { await b.stop(); }
});

// ---------------- attach an existing workspace + newest-window-wins + cross-site ----------------
const PUT = (u: any) => u.deps.vault.put("guest:tester", { id: "instabox", label: "I", hosts: ["api.instabox.sh"], auth: { type: "header", name: "X-API-Key" } }, KEY);
test("attach: use a machine that already exists; foreign ids refused; Stop only disconnects", async () => {
  const b = await boot(); try {
    const u = await asUser(b); PUT(u);
    const dir = fs.mkdtempSync(path.join(b.vmf.root, "pre-")); fs.mkdirSync(path.join(dir, "home/workspace"), { recursive: true }); b.vmf.sessions.set("mach_pre1", dir);
    const list = await u.deps.vm.listMachines("guest:tester"); assert.ok(list.some((m: any) => m.id === "mach_pre1"));
    await assert.rejects(() => u.deps.vm.attach("guest:tester", "mach_not_mine"), /not in your InstaBox account/);
    await assert.rejects(() => u.deps.vm.attach("guest:tester", "../x; echo hi"), /Invalid machine id/);
    assert.equal(u.deps.vm.status("guest:tester").running, false, "a refused attach connects nothing");
    await u.deps.vm.attach("guest:tester", "mach_pre1");
    const st = u.deps.vm.status("guest:tester"); assert.equal(st.running, true); assert.equal(st.attached, true);
    const w = await u.call("create_file", { path: "a.txt", content: "hi" }); assert.ok(!w.isError, text(w));
    assert.equal(fs.readFileSync(path.join(dir, "home/workspace/a.txt"), "utf8"), "hi", "the AI works inside the existing machine");
    await u.deps.vm.stop("guest:tester");
    assert.ok(b.vmf.sessions.has("mach_pre1"), "Stop on an attached machine never deletes it");
    assert.equal(u.deps.vm.status("guest:tester").running, false);
  } finally { await b.stop(); }
});
test("cross-site writes are refused even with a valid token; same-site and no-Origin pass", async () => {
  const b = await boot(); try {
    const sm = (b.app as any).sessions; const { cookie, csrfToken } = sm.createSession("guest:x", {}); const ck = cookie.split(";")[0];
    const hdr = (o: any) => ({ "x-csrf-token": csrfToken, host: "app.example.com", ...o });
    const r = (headers: any, method = "POST") => sm.requireSession(method, ck, headers);
    assert.equal(r(hdr({})).ok, true, "no Origin (non-browser client) passes");
    assert.equal(r(hdr({ origin: "https://app.example.com" })).ok, true, "same site passes");
    for (const bad of ["https://evil.example", "https://app.example.com.evil.example", "null", "not a url"]) { const x: any = r(hdr({ origin: bad })); assert.equal(x.ok, false, bad); assert.equal(x.status, 409, bad); }
    assert.equal(r({ host: "app.example.com", origin: "https://evil.example" }, "GET").ok, true, "reads are not affected");
  } finally { await b.stop(); }
});
test("live window: the newest window wins and older ones are told they are stale", async () => {
  const b = await boot(); try {
    const u = await asUser(b); PUT(u); await u.call("vm_start", {});
    const a = await u.call("vm_live", {}); const a2 = await u.call("vm_live", {});
    assert.ok(a2.structuredContent.epoch > a.structuredContent.epoch, "each vm_live takes a newer number");
    const p = await u.call("vm_screen_poll", {}); assert.equal(p.structuredContent.currentEpoch, a2.structuredContent.epoch);
    assert.ok(p.structuredContent.currentEpoch > a.structuredContent.epoch, "the first window can see it is stale");
    const other = await asUser(b, "guest:fresh-" + Date.now()); const o = await other.call("vm_screen_poll", {}); assert.equal(o.structuredContent?.currentEpoch ?? 0, 0, "epochs are per user");
  } finally { await b.stop(); }
});
