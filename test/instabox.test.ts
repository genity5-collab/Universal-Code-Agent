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
    const used = new Set([...src.matchAll(/\ba\.([A-Za-z_]+)/g)].map((m) => m[1]));
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
    r = await u.call("run_command", { command: "npm install left-pad" }); assert.match(text(r), /approval/i);
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

test("APPROVALS SURVIVE THE VM GATE: delete, install, push and risky jobs/commands still wait for a human, and the VM is untouched until approved", async () => {
  const b = await boot(); try {
    assert.equal(b.config.requireApproval, true);
    const u = await asUser(b); u.deps.vault.put("guest:tester", { id: "instabox", label: "I", hosts: ["api.instabox.sh"], auth: { type: "header", name: "X-API-Key" } }, KEY); await u.call("vm_start", {});
    await u.call("create_file", { path: "victim.txt", content: "keep me" });
    const need = async (name: string, args: any) => { const r = await u.call(name, args); assert.equal(r.isError, true, `${name} must not run unapproved`); const j = JSON.parse(text(r)); assert.equal(j.status, "approval_required", name); return j; };
    const del = await need("delete_file", { path: "victim.txt" });
    assert.match(text(await u.call("read_file", { path: "victim.txt" })), /keep me/, "file must still exist before approval");
    await need("install_dependencies", {}); await need("git_push", {}); await need("run_command", { command: "npm install left-pad" }); await need("start_job", { command: "npm install left-pad" });
    assert.equal(u.deps.approvals.decide("guest:tester", del.approvalId, true), true);
    const after = await u.call("delete_file", { path: "victim.txt" }); assert.ok(!after.isError, text(after));
    assert.equal((await u.call("read_file", { path: "victim.txt" })).isError, true, "deleted after approval");
    assert.equal((await u.call("delete_file", { path: "victim.txt" })).isError, true, "approval is single use");
  } finally { await b.stop(); }
});

test("every tool that needed approval before the VM change still does (no silent regression)", async () => {
  const src = fs.readFileSync(path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../src/mcp/tools.ts"), "utf8");
  const original = [...src.matchAll(/needApproval\(c, d, "([a-z_]+)"/g)].map((m) => m[1]);
  const { VM_APPROVAL } = await import("../src/mcp/tools.js"); const { GATED_TOOLS } = await import("../src/instabox/tools.js");
  for (const name of original) { if (!GATED_TOOLS.has(name)) continue; if (name === "run_command" || name === "start_job") continue; assert.ok(VM_APPROVAL[name], `${name} needs approval in its original handler but nothing asks for it in the VM path`); }
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
