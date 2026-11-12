import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import type { AddressInfo } from "node:net";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { loadConfig } from "../src/util/config.js";
import { createApp, type App } from "../src/http/app.js";

// ---- mock GitHub (web + api) on one ephemeral port ----
function mockGithub(): Promise<{ url: string; server: http.Server; seen: string[] }> {
  const seen: string[] = [];
  const server = http.createServer((req, res) => {
    const u = new URL(req.url!, "http://x"); seen.push(`${req.method} ${u.pathname}`);
    const json = (o: unknown, s = 200) => { res.writeHead(s, { "content-type": "application/json" }); res.end(JSON.stringify(o)); };
    if (u.pathname === "/login/oauth/access_token") {
      let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => {
        const p = new URLSearchParams(b); const j = (() => { try { return JSON.parse(b); } catch { return {}; } })();
        const code = p.get("code") ?? j.code;
        return code === "good-code" ? json({ access_token: "gho_" + "a".repeat(36), token_type: "bearer", scope: "repo,read:user" }) : json({ error: "bad_verification_code" });
      }); return;
    }
    const auth = req.headers.authorization ?? "";
    if (!auth.includes("gho_")) return json({ message: "Bad credentials" }, 401);
    if (u.pathname === "/user") return json({ login: "alice", id: 4242, name: "Alice", avatar_url: "x", html_url: "x", type: "User" });
    if (u.pathname === "/user/repos") return json([{ id: 1, name: "demo", full_name: "alice/demo", private: false, owner: { login: "alice" }, default_branch: "main", html_url: "x" }]);
    if (u.pathname === "/repos/alice/demo") return json({ id: 1, name: "demo", full_name: "alice/demo", private: false, owner: { login: "alice" }, default_branch: "main", html_url: "x" });
    json({ message: "Not Found" }, 404);
  });
  return new Promise((r) => server.listen(0, "127.0.0.1", () => r({ url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, server, seen })));
}

const b64u = (b: Buffer) => b.toString("base64url");
function cookieJar() {
  const jar = new Map<string, string>();
  return {
    absorb(res: Response) { for (const c of res.headers.getSetCookie?.() ?? []) { const [kv] = c.split(";"); const i = kv.indexOf("="); const k = kv.slice(0, i); const v = kv.slice(i + 1); if (c.toLowerCase().includes("max-age=0")) jar.delete(k); else jar.set(k, v); } },
    header() { return [...jar].map(([k, v]) => `${k}=${v}`).join("; "); },
  };
}
async function follow(url: string, jar: ReturnType<typeof cookieJar>, stopAt: (u: string) => boolean, max = 10): Promise<Response> {
  let cur = url;
  for (let i = 0; i < max; i++) {
    const r = await fetch(cur, { redirect: "manual", headers: { cookie: jar.header() } }); jar.absorb(r);
    const loc = r.headers.get("location"); if (!loc || r.status < 300 || r.status >= 400) return r;
    const next = new URL(loc, cur).toString(); if (stopAt(next)) { (r as any).finalLocation = next; return r; } cur = next;
  }
  throw new Error("too many redirects");
}

interface Ctx { app: App; base: string; gh: Awaited<ReturnType<typeof mockGithub>>; tmp: string; stop(): Promise<void> }
async function boot(overrides: Record<string, string> = {}): Promise<Ctx> {
  const gh = await mockGithub();
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "uca-int-"));
  // choose port first so baseUrl is known
  const probe = http.createServer(); await new Promise<void>((r) => probe.listen(0, "127.0.0.1", () => r())); const port = (probe.address() as AddressInfo).port; await new Promise((r) => probe.close(r));
  const config = loadConfig({ PORT: String(port), UCA_BASE_URL: `http://127.0.0.1:${port}`, UCA_DATA_DIR: tmp, GITHUB_CLIENT_ID: "cid", GITHUB_CLIENT_SECRET: "csecret", UCA_REQUIRE_APPROVAL: "true", ...overrides } as any);
  const app = createApp(config, { githubApiBase: gh.url, githubWebBase: gh.url });
  await new Promise<void>((r) => app.server.listen(port, "127.0.0.1", () => r()));
  return { app, base: config.baseUrl, gh, tmp, async stop() { await app.close(); gh.server.close(); fs.rmSync(tmp, { recursive: true, force: true }); } };
}

/** Run the entire browser-like flow: dynamic registration -> authorize -> GitHub login -> consent -> code -> token. */
async function oauthFlow(c: Ctx, scope = "mcp:read mcp:write mcp:exec", jar = cookieJar()) {
  const reg = await (await fetch(`${c.base}/register`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_name: "Test Client", redirect_uris: ["http://127.0.0.1:9/cb"], token_endpoint_auth_method: "none", grant_types: ["authorization_code", "refresh_token"], response_types: ["code"] }) })).json() as any;
  assert.ok(reg.client_id, JSON.stringify(reg));
  const verifier = b64u(crypto.randomBytes(48)); const challenge = b64u(crypto.createHash("sha256").update(verifier).digest());
  const q = new URLSearchParams({ response_type: "code", client_id: reg.client_id, redirect_uri: "http://127.0.0.1:9/cb", code_challenge: challenge, code_challenge_method: "S256", scope, state: "st8", resource: `${c.base}/mcp` });
  // /authorize -> GitHub (mock) ; we emulate the browser hitting GitHub then coming back with code
  const r1 = await fetch(`${c.base}/authorize?${q}`, { redirect: "manual", headers: { cookie: jar.header() } }); jar.absorb(r1);
  assert.equal(r1.status, 302, "authorize should redirect to GitHub login");
  const ghUrl = new URL(r1.headers.get("location")!); assert.ok(ghUrl.toString().startsWith(c.gh.url), "redirect goes to GitHub: " + ghUrl);
  const state = ghUrl.searchParams.get("state")!; assert.ok(state);
  const r2 = await fetch(`${c.base}/auth/github/callback?code=good-code&state=${encodeURIComponent(state)}`, { redirect: "manual", headers: { cookie: jar.header() } }); jar.absorb(r2);
  assert.equal(r2.status, 302, "callback should redirect, got " + r2.status + " " + (r2.status >= 400 ? await r2.text() : ""));
  const consent = await fetch(new URL(r2.headers.get("location")!, c.base), { redirect: "manual", headers: { cookie: jar.header() } }); jar.absorb(consent);
  assert.equal(consent.status, 200, "consent page status");
  const html = await consent.text(); assert.match(html, /Authorize Test Client/);
  const pending = /name=pending value="([^"]+)"/.exec(html)![1]; const csrf = /name=csrf value="([^"]+)"/.exec(html)![1];
  return { reg, verifier, jar, pending, csrf, decide: async (decision: "approve" | "deny") => {
    const d = await fetch(`${c.base}/authorize/decision`, { method: "POST", redirect: "manual", headers: { "content-type": "application/x-www-form-urlencoded", cookie: jar.header() }, body: new URLSearchParams({ pending, csrf, decision }) });
    return d;
  } };
}
async function getToken(c: Ctx, f: Awaited<ReturnType<typeof oauthFlow>>) {
  const d = await f.decide("approve"); assert.equal(d.status, 302);
  const loc = new URL(d.headers.get("location")!); assert.equal(loc.searchParams.get("state"), "st8"); const code = loc.searchParams.get("code")!; assert.ok(code);
  const t = await fetch(`${c.base}/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: "http://127.0.0.1:9/cb", client_id: f.reg.client_id, code_verifier: f.verifier, resource: `${c.base}/mcp` }) });
  const tj = await t.json() as any; assert.equal(t.status, 200, JSON.stringify(tj)); return tj as { access_token: string; refresh_token: string; scope: string };
}
async function mcpClient(c: Ctx, token: string) {
  const client = new Client({ name: "it", version: "1" });
  await client.connect(new StreamableHTTPClientTransport(new URL(`${c.base}/mcp`), { requestInit: { headers: { authorization: `Bearer ${token}` } } }));
  return client;
}
const text = (r: any) => r.content.map((x: any) => x.text).join("");

test("discovery metadata and unauthenticated /mcp challenge", async () => {
  const c = await boot();
  try {
    const m = await (await fetch(`${c.base}/.well-known/oauth-authorization-server`)).json() as any;
    assert.deepEqual(m.code_challenge_methods_supported, ["S256"]); assert.ok(m.registration_endpoint);
    const pr = await (await fetch(`${c.base}/.well-known/oauth-protected-resource`)).json() as any;
    assert.equal(pr.resource, `${c.base}/mcp`);
    const r = await fetch(`${c.base}/mcp`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
    assert.equal(r.status, 401); assert.match(r.headers.get("www-authenticate") ?? "", /resource_metadata/);
  } finally { await c.stop(); }
});

test("full OAuth 2.1 + PKCE flow, then a real MCP client lists and calls tools", async () => {
  const c = await boot();
  try {
    const f = await oauthFlow(c); const tok = await getToken(c, f);
    assert.match(tok.scope, /mcp:read/);
    const client = await mcpClient(c, tok.access_token);
    const tools = await client.listTools(); const names = tools.tools.map((t) => t.name);
    for (const n of ["read_file", "read_file_chunk", "edit_file", "search_content", "find_symbol", "run_command", "github_list_repos", "github_review_pull_request", "codespaces_create"]) assert.ok(names.includes(n), "missing " + n);
    assert.ok(names.length >= 60, "tool count " + names.length);
    // filesystem round trip in the user's own workspace
    assert.ok(!(await client.callTool({ name: "create_file", arguments: { path: "src/hello.ts", content: "export function hello() { return 1; }\n" } }) as any).isError);
    const rd = JSON.parse(text(await client.callTool({ name: "read_file", arguments: { path: "src/hello.ts" } })));
    assert.match(rd.content, /hello/);
    const ed = await client.callTool({ name: "edit_file", arguments: { path: "src/hello.ts", oldString: "return 1", newString: "return 2" } }); assert.ok(!(ed as any).isError, text(ed));
    assert.match(JSON.parse(text(await client.callTool({ name: "read_file", arguments: { path: "src/hello.ts" } }))).content, /return 2/);
    const sym = JSON.parse(text(await client.callTool({ name: "find_symbol", arguments: { name: "hello" } }))); assert.ok(sym.length >= 1);
    // traversal blocked
    const bad = await client.callTool({ name: "read_file", arguments: { path: "../../etc/passwd" } }) as any; assert.equal(bad.isError, true);
    // real command execution (safe tier)
    const run = JSON.parse(text(await client.callTool({ name: "run_command", arguments: { command: "node --version" } }))); assert.equal(run.exitCode, 0); assert.match(run.stdout, /^v\d+/);
    // GitHub through the user's own token against the mock API
    const repos = JSON.parse(text(await client.callTool({ name: "github_list_repos", arguments: {} }))); assert.ok(JSON.stringify(repos).includes("alice/demo"));
    await client.close();
  } finally { await c.stop(); }
});

test("sensitive actions require human approval, and approval is single use", async () => {
  const c = await boot();
  try {
    const f = await oauthFlow(c); const tok = await getToken(c, f); const client = await mcpClient(c, tok.access_token);
    await client.callTool({ name: "create_file", arguments: { path: "victim.txt", content: "x" } });
    const r1 = await client.callTool({ name: "delete_file", arguments: { path: "victim.txt" } }) as any;
    assert.equal(r1.isError, true); const j = JSON.parse(text(r1)); assert.equal(j.status, "approval_required");
    assert.ok(fs.readdirSync(path.join(c.tmp, "workspaces")).length === 1);
    const ws = path.join(c.tmp, "workspaces", fs.readdirSync(path.join(c.tmp, "workspaces"))[0]); assert.ok(fs.existsSync(path.join(ws, "victim.txt")), "must not delete before approval");
    // approve through the dashboard API with session + CSRF
    const me = await (await fetch(`${c.base}/api/me`, { headers: { cookie: f.jar.header() } })).json() as any;
    const ap = await fetch(`${c.base}/api/approvals/${j.approvalId}/approve`, { method: "POST", headers: { cookie: f.jar.header(), "x-csrf-token": me.csrf, "content-type": "application/json" }, body: "{}" }); assert.equal(ap.status, 200);
    const r2 = await client.callTool({ name: "delete_file", arguments: { path: "victim.txt" } }) as any; assert.ok(!r2.isError, text(r2)); assert.ok(!fs.existsSync(path.join(ws, "victim.txt")));
    // single use: asking again needs a new approval
    await client.callTool({ name: "create_file", arguments: { path: "victim.txt", content: "x" } });
    const r3 = await client.callTool({ name: "delete_file", arguments: { path: "victim.txt" } }) as any; assert.equal(JSON.parse(text(r3)).status, "approval_required");
    // CSRF enforced on state-changing dashboard calls
    const noCsrf = await fetch(`${c.base}/api/approvals/${j.approvalId}/deny`, { method: "POST", headers: { cookie: f.jar.header(), "content-type": "application/json" }, body: "{}" }); assert.equal(noCsrf.status, 403);
    // denied commands never run even with approval flow
    const den = await client.callTool({ name: "run_command", arguments: { command: "sudo ls" } }) as any; assert.equal(den.isError, true); assert.match(text(den), /denied/i);
    await client.close();
  } finally { await c.stop(); }
});

test("scopes limit which tools are exposed; deny and revoke work", async () => {
  const c = await boot();
  try {
    const f = await oauthFlow(c, "mcp:read"); const tok = await getToken(c, f); const client = await mcpClient(c, tok.access_token);
    const names = (await client.listTools()).tools.map((t) => t.name);
    assert.ok(names.includes("read_file")); assert.ok(!names.includes("write_file")); assert.ok(!names.includes("run_command"));
    await client.close();
    // revoke token -> MCP rejects
    const rv = await fetch(`${c.base}/revoke`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ token: tok.access_token, client_id: f.reg.client_id }) }); assert.equal(rv.status, 200);
    const after = await fetch(`${c.base}/mcp`, { method: "POST", headers: { authorization: `Bearer ${tok.access_token}`, "content-type": "application/json", accept: "application/json, text/event-stream" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }) }); assert.equal(after.status, 401);
    // user denies consent -> access_denied, no code
    const f2 = await oauthFlow(c); const d = await f2.decide("deny"); const loc = new URL(d.headers.get("location")!); assert.equal(loc.searchParams.get("error"), "access_denied"); assert.equal(loc.searchParams.get("code"), null);
  } finally { await c.stop(); }
});

test("refresh token rotation works and old refresh token reuse is rejected", async () => {
  const c = await boot();
  try {
    const f = await oauthFlow(c); const tok = await getToken(c, f);
    const refresh = (rt: string) => fetch(`${c.base}/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: rt, client_id: f.reg.client_id }) });
    const r1 = await refresh(tok.refresh_token); const j1 = await r1.json() as any; assert.equal(r1.status, 200); assert.notEqual(j1.refresh_token, tok.refresh_token);
    const r2 = await refresh(tok.refresh_token); assert.equal(r2.status, 400);
    const r3 = await refresh(j1.refresh_token); assert.equal(r3.status, 400, "family revoked after reuse");
  } finally { await c.stop(); }
});

test("PKCE is enforced at the HTTP layer", async () => {
  const c = await boot();
  try {
    const reg = await (await fetch(`${c.base}/register`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ redirect_uris: ["http://127.0.0.1:9/cb"], token_endpoint_auth_method: "none" }) })).json() as any;
    const noPkce = await fetch(`${c.base}/authorize?${new URLSearchParams({ response_type: "code", client_id: reg.client_id, redirect_uri: "http://127.0.0.1:9/cb" })}`, { redirect: "manual" });
    assert.ok([302, 400].includes(noPkce.status)); if (noPkce.status === 302) assert.match(noPkce.headers.get("location")!, /error=/);
    const bad = await fetch(`${c.base}/register`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ redirect_uris: ["http://evil.example.com/cb"] }) }); assert.equal(bad.status, 400);
  } finally { await c.stop(); }
});

test("users are isolated: each gets a separate workspace and cannot read the other's files", async () => {
  const c = await boot();
  try {
    const f = await oauthFlow(c); const tok = await getToken(c, f); const client = await mcpClient(c, tok.access_token);
    await client.callTool({ name: "create_file", arguments: { path: "mine.txt", content: "secret-A" } });
    const dirs = fs.readdirSync(path.join(c.tmp, "workspaces")); assert.equal(dirs.length, 1); assert.match(dirs[0], /gh_4242/);
    // a second, different user directory cannot be reached by path tricks
    fs.mkdirSync(path.join(c.tmp, "workspaces", "gh_9999")); fs.writeFileSync(path.join(c.tmp, "workspaces", "gh_9999", "theirs.txt"), "secret-B");
    const r = await client.callTool({ name: "read_file", arguments: { path: "../gh_9999/theirs.txt" } }) as any; assert.equal(r.isError, true); assert.ok(!text(r).includes("secret-B"));
    await client.close();
  } finally { await c.stop(); }
});

test("dashboard API requires a session; tokens never appear in responses; static UI is served", async () => {
  const c = await boot();
  try {
    assert.equal((await fetch(`${c.base}/api/repos`)).status, 401);
    const idx = await fetch(`${c.base}/`); assert.equal(idx.status, 200); assert.match(await idx.text(), /Universal Code Agent/);
    assert.equal(idx.headers.get("x-frame-options"), "DENY");
    const f = await oauthFlow(c); await getToken(c, f);
    const repos = await (await fetch(`${c.base}/api/repos`, { headers: { cookie: f.jar.header() } })).json() as any; assert.equal(repos.repos[0].full_name, "alice/demo");
    const tok = await getToken(c, await oauthFlow(c)); const cl = await mcpClient(c, tok.access_token);
    await cl.callTool({ name: "github_whoami", arguments: {} }); await cl.close();
    const dump = fs.readFileSync(path.join(c.tmp, "audit.log"), "utf8");
    assert.ok(dump.includes("github_whoami") && !dump.includes("gho_"));
    // GitHub token is encrypted at rest
    for (const file of fs.readdirSync(c.tmp)) { const p = path.join(c.tmp, file); if (fs.statSync(p).isFile()) assert.ok(!fs.readFileSync(p, "utf8").includes("gho_" + "a".repeat(36)), "plaintext GitHub token in " + file); }
    // path traversal in static handler
    const trav = await fetch(`${c.base}/..%2f..%2fpackage.json`); assert.notEqual(trav.status, 200);
  } finally { await c.stop(); }
});

test("GitHub sign-in failure (e.g. wrong client secret) never strands ChatGPT: guest route still completes", async () => {
  const c = await boot({ UCA_ALLOW_GUESTS: "true" });
  try {
    const reg = await (await fetch(`${c.base}/oauth/register`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_name: "ChatGPT", redirect_uris: ["https://chatgpt.com/connector_platform_oauth_redirect"], token_endpoint_auth_method: "none", grant_types: ["authorization_code", "refresh_token"], response_types: ["code"] }) })).json() as any;
    const verifier = b64u(crypto.randomBytes(48)); const challenge = b64u(crypto.createHash("sha256").update(verifier).digest());
    const q = new URLSearchParams({ response_type: "code", client_id: reg.client_id, redirect_uri: "https://chatgpt.com/connector_platform_oauth_redirect", code_challenge: challenge, code_challenge_method: "S256", scope: "mcp:read mcp:write", state: "s", resource: `${c.base}/mcp` });
    const a = await fetch(`${c.base}/oauth/authorize?${q}`, { redirect: "manual" });
    const choose = await fetch(new URL(a.headers.get("location")!, c.base), { redirect: "manual" });
    const pid = /name=pending value="([^"]+)"/.exec(await choose.text())![1];
    // tap "Sign in with GitHub"
    const jar = cookieJar();
    const g = await fetch(`${c.base}/authorize/github?pending=${pid}`, { redirect: "manual" }); jar.absorb(g);
    const state = new URL(g.headers.get("location")!).searchParams.get("state")!;
    // GitHub returns a code its token endpoint rejects (what a mismatched secret looks like)
    const cb = await fetch(`${c.base}/auth/github/callback?code=rejected&state=${encodeURIComponent(state)}`, { redirect: "manual", headers: { cookie: jar.header() } });
    assert.equal(cb.status, 502); const html = await cb.text();
    assert.match(html, /GitHub sign-in failed/); assert.match(html, /Continue as guest instead/); assert.match(html, new RegExp(`value="${pid}"`)); assert.ok(!html.includes("gho_"));
    // the escape hatch works and finishes the connection
    const gu = await fetch(`${c.base}/authorize/guest`, { method: "POST", redirect: "manual", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ pending: pid }) });
    assert.equal(gu.status, 302); assert.match(gu.headers.get("location")!, /\/authorize\/consent/);
  } finally { await c.stop(); }
});
