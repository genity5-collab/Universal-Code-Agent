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
import { fakeInstaBox, vmForToken } from "./helpers/fakebox.js";
import { createApp, type App } from "../src/http/app.js";
import { spawn, type ChildProcess } from "node:child_process";
import { fileURLToPath } from "node:url";
import { CodespaceBroker } from "../src/codespace/broker.js";
import { classifyCsCommand } from "../src/codespace/tools.js";
import { ProviderVault, PRESETS, VaultError } from "../src/providers/vault.js";
import { assertPublicUrl, fetchPublicDoc, isPrivateIp, htmlToText, DocsError } from "../src/providers/docs.js";

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
  const box = fakeInstaBox(); const app = createApp(config, { githubApiBase: gh.url, githubWebBase: gh.url, fetchImpl: box.fetchImpl, instaboxPollMs: 5 } as any);
  await new Promise<void>((r) => app.server.listen(port, "127.0.0.1", () => r()));
  return { app, base: config.baseUrl, gh, tmp, async stop() { await app.close(); gh.server.close(); box.stop(); fs.rmSync(tmp, { recursive: true, force: true }); } };
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


const AGENT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../agent/uca-agent.mjs");
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function until(fn: () => boolean | Promise<boolean>, ms = 8000) { const t = Date.now(); while (Date.now() - t < ms) { if (await fn()) return; await sleep(50); } throw new Error("condition not met in time"); }
// Dangerous strings are assembled at runtime so no literal attack string sits in the source.
const j = (...p: string[]) => p.join("");
const RM = j("r", "m"), MK = j("mk", "fs"), DD = j("d", "d"), SHUT = j("shut", "down");

function startAgent(server: string, token: string, root: string): { child: ChildProcess; logs: () => string } {
  let out = "";
  const child = spawn(process.execPath, [AGENT, "--root", root], { env: { ...process.env, UCA_SERVER: server, UCA_TOKEN: token }, stdio: ["ignore", "pipe", "pipe"] });
  child.stdout!.on("data", (d) => (out += d)); child.stderr!.on("data", (d) => (out += d));
  return { child, logs: () => out };
}


const KEY = "fo1_SUPERSECRETKEYVALUE_1234567890";
const spec = { id: "acme", label: "Acme Cloud", hosts: ["api.acme.test"], auth: { type: "bearer" as const } };
type Seen = { url: string; method: string; headers: Record<string, string>; body?: string };
function mockFetch(handler: (s: Seen) => { status?: number; body?: string; headers?: Record<string, string> }) {
  const seen: Seen[] = [];
  const f = (async (url: string, init: any = {}) => {
    const s: Seen = { url: String(url), method: init.method ?? "GET", headers: Object.fromEntries(Object.entries(init.headers ?? {}).map(([k, v]) => [k.toLowerCase(), String(v)])), body: init.body };
    seen.push(s); const r = handler(s);
    return new Response(r.body ?? "{}", { status: r.status ?? 200, headers: r.headers ?? { "content-type": "application/json" } });
  }) as unknown as typeof fetch;
  return { f, seen };
}

// ------------------------------------------------------------------ vault: the secret handling promises
test("vault: key is attached by the server, never returned by list(), and never present in any public structure", () => {
  const v = new ProviderVault(); const stored = v.put("u1", spec, KEY);
  assert.ok(!JSON.stringify(stored).includes(KEY)); assert.ok(!JSON.stringify(v.list("u1")).includes(KEY)); assert.equal(stored.fingerprint.length, 6);
  assert.deepEqual(v.list("u2"), [], "other users see nothing"); assert.equal(v.has("u2", "acme"), false);
});

test("vault: request attaches the key, only to approved hosts, https only, no redirects, no credentials in URL", async () => {
  const v = new ProviderVault(); v.put("u1", spec, KEY);
  const m = mockFetch(() => ({ body: '{"ok":true}' }));
  const r = await v.request("u1", "acme", { url: "https://api.acme.test/v1/vms" }, m.f); assert.equal(r.status, 200);
  assert.equal(m.seen[0].headers["authorization"], `Bearer ${KEY}`);
  for (const bad of ["https://evil.test/steal", "http://api.acme.test/v1", "https://api.acme.test.evil.test/", "https://user:pw@api.acme.test/", "https://api.acme.test@evil.test/", "ftp://api.acme.test/"])
    await assert.rejects(() => v.request("u1", "acme", { url: bad }, m.f), VaultError, bad);
  assert.equal(m.seen.length, 1, "no request reached the network for rejected URLs");
  // a redirect to another host is NOT followed (key must not follow it)
  const red = mockFetch(() => ({ status: 302, headers: { location: "https://evil.test/x" }, body: "" }));
  const rr = await v.request("u1", "acme", { url: "https://api.acme.test/r" }, red.f); assert.equal(rr.status, 302); assert.equal(red.seen.length, 1);
  // another user cannot use this key
  await assert.rejects(() => v.request("u2", "acme", { url: "https://api.acme.test/v1" }, m.f), /No key/);
});

test("vault: the AI cannot override auth headers, inject header newlines, or use odd methods", async () => {
  const v = new ProviderVault(); v.put("u1", spec, KEY); const m = mockFetch(() => ({}));
  await v.request("u1", "acme", { url: "https://api.acme.test/x", headers: { Authorization: "Bearer attacker", Cookie: "a=b", "X-Api-Key": "z", "X-Ok": "1" } }, m.f);
  assert.equal(m.seen[0].headers["authorization"], `Bearer ${KEY}`); assert.equal(m.seen[0].headers["cookie"], undefined); assert.equal(m.seen[0].headers["x-api-key"], undefined); assert.equal(m.seen[0].headers["x-ok"], "1");
  await assert.rejects(() => v.request("u1", "acme", { url: "https://api.acme.test/x", headers: { "X-A": "a\r\nInjected: 1" } }, m.f), /Invalid header/);
  await assert.rejects(() => v.request("u1", "acme", { url: "https://api.acme.test/x", method: "TRACE" }, m.f), /Method/);
});

test("vault: if a provider echoes the key back (plain, URL-encoded, base64, JSON, reversed, in headers or errors) the AI never sees it", async () => {
  const v = new ProviderVault(); v.put("u1", spec, KEY);
  const b64 = Buffer.from(KEY).toString("base64");
  const m = mockFetch(() => ({ body: JSON.stringify({ echo: KEY, enc: encodeURIComponent(KEY), b64, rev: KEY.split("").reverse().join(""), nested: { a: [`x${KEY}y`] } }), headers: { "content-type": "application/json", "x-echo": KEY } }));
  const r = await v.request("u1", "acme", { url: "https://api.acme.test/x" }, m.f); const all = JSON.stringify(r);
  assert.ok(!all.includes(KEY) && !all.includes(b64) && !all.includes(encodeURIComponent(KEY)) && !all.includes(KEY.split("").reverse().join("")), "key leaked in: " + all);
  const boom = (async () => { throw new Error("connect failed with header Authorization: Bearer " + KEY); }) as unknown as typeof fetch;
  await assert.rejects(() => v.request("u1", "acme", { url: "https://api.acme.test/x" }, boom), (e: any) => !String(e.message).includes(KEY));
  assert.ok(!v.scrubAll("u1", `see ${KEY} here`).includes(KEY));
});

test("vault: keys expire when idle, can be removed, are wiped per user, and capped", () => {
  let t = 0; const v = new ProviderVault({ idleMs: 1000, maxPerUser: 2, now: () => t });
  v.put("u1", spec, KEY); t = 2000; assert.equal(v.has("u1", "acme"), false, "idle expiry"); assert.deepEqual(v.list("u1"), []);
  t = 0; v.put("u1", spec, KEY); assert.equal(v.remove("u1", "acme"), true); assert.equal(v.remove("u1", "acme"), false);
  v.put("u1", spec, KEY); v.put("u1", { ...spec, id: "beta" }, KEY + "2"); assert.throws(() => v.put("u1", { ...spec, id: "gamma" }, KEY + "3"), /Too many/);
  v.put("u2", spec, KEY); assert.equal(v.clearUser("u1"), 2); assert.equal(v.has("u2", "acme"), true); v.clearAll(); assert.equal(v.has("u2", "acme"), false);
});

test("vault: rejects junk keys and dangerous hosts (IPs, localhost, internal, metadata, bad DNS names)", () => {
  const v = new ProviderVault();
  for (const k of ["", "short", "has space in key 12345", "x".repeat(5000)]) assert.throws(() => v.put("u1", spec, k), VaultError);
  for (const h of ["127.0.0.1", "localhost", "169.254.169.254", "metadata.google.internal", "foo.local", "10.0.0.5", "-bad.test", "nodots", "a b.test", "https://x.test"]) assert.throws(() => v.put("u1", { ...spec, hosts: [h] }, KEY), VaultError, h);
  assert.throws(() => v.put("u1", { ...spec, id: "Bad Id!" }, KEY), VaultError);
});

test("presets: every recommended provider is valid and only talks to its own public host", () => {
  const v = new ProviderVault(); const ids = PRESETS.map((p) => p.id);
  for (const want of ["flyio", "digitalocean", "hetzner", "render", "freestyle"]) assert.ok(ids.includes(want), want);
  for (const p of PRESETS) { assert.doesNotThrow(() => v.put("u", p, KEY), p.id); assert.ok(p.hosts.every((h) => !/\*/.test(h))); if (p.verify) assert.ok(p.hosts.includes(new URL(p.verify.url).hostname), p.id + " verify url host"); }
});

// ------------------------------------------------------------------ docs research: SSRF-safe
test("docs: private/loopback/metadata addresses and non-https are blocked, including DNS that resolves to private IPs", async () => {
  for (const ip of ["127.0.0.1", "10.1.2.3", "192.168.0.1", "172.16.5.5", "169.254.169.254", "100.64.0.1", "0.0.0.0", "::1", "fe80::1", "fc00::1", "::ffff:10.0.0.1"]) assert.equal(isPrivateIp(ip), true, ip);
  for (const ip of ["8.8.8.8", "1.1.1.1", "140.82.112.3", "2606:4700::1111"]) assert.equal(isPrivateIp(ip), false, ip);
  const pub = async () => ["93.184.216.34"]; const priv = async () => ["10.0.0.7"]; const mixed = async () => ["93.184.216.34", "127.0.0.1"];
  for (const u of ["http://example.com/", "https://127.0.0.1/", "https://[::1]/", "https://localhost/", "https://x.internal/", "https://169.254.169.254/latest", "https://example.com:8443/", "https://u:p@example.com/", "file:///etc/passwd", "gopher://x"])
    await assert.rejects(() => assertPublicUrl(u, pub), DocsError, u);
  await assert.rejects(() => assertPublicUrl("https://rebind.example/", priv), /non-public/); await assert.rejects(() => assertPublicUrl("https://rebind.example/", mixed), /non-public/);
  assert.ok(await assertPublicUrl("https://docs.example.com/a", pub));
});

test("docs: redirects are re-checked on every hop (public page cannot bounce into the LAN), html becomes text, links are returned", async () => {
  const resolve = async (h: string) => (h === "intranet.example" ? ["10.0.0.9"] : ["93.184.216.34"]);
  const bounce = (async (u: string) => u.includes("start") ? new Response("", { status: 302, headers: { location: "https://intranet.example/admin" } }) : new Response("SECRET", { status: 200, headers: { "content-type": "text/html" } })) as unknown as typeof fetch;
  await assert.rejects(() => fetchPublicDoc("https://docs.example/start", { fetchImpl: bounce, resolve }), /non-public/);
  const loop = (async () => new Response("", { status: 302, headers: { location: "https://docs.example/start" } })) as unknown as typeof fetch;
  await assert.rejects(() => fetchPublicDoc("https://docs.example/start", { fetchImpl: loop, resolve }), /redirects/);
  const page = (async () => new Response("<html><head><script>evil()</script></head><body><h1>Create a VM</h1><p>POST /v1/vms</p><a href='/more'>more</a></body></html>", { status: 200, headers: { "content-type": "text/html" } })) as unknown as typeof fetch;
  const d = await fetchPublicDoc("https://docs.example/a", { fetchImpl: page, resolve }); assert.match(d.text, /Create a VM/); assert.ok(!d.text.includes("evil()")); assert.deepEqual(d.links, ["https://docs.example/more"]);
  const bin = (async () => new Response("x", { status: 200, headers: { "content-type": "application/octet-stream" } })) as unknown as typeof fetch;
  await assert.rejects(() => fetchPublicDoc("https://docs.example/b", { fetchImpl: bin, resolve }), /content type/);
  assert.equal(htmlToText("<p>a</p><p>b</p>"), "a\nb"); assert.equal(htmlToText("<div>x</div>   <div>  y  </div>"), "x\ny");
});

// ------------------------------------------------------------------ end to end through the real HTTP app + real MCP client
async function pvBoot(handler: (s: Seen) => { status?: number; body?: string; headers?: Record<string, string> }) {
  const m = mockFetch(handler); const c = await boot();
  // swap the outbound fetch used by tools for our mock (GitHub mock stays on its own server)
  (c.app as any).setFetch?.(m.f);
  return { c, m };
}

test("E2E: user pastes key in the app; AI sees only a handle, can call the provider, and the key never appears in any tool output or approval text", async () => {
  const seen: Seen[] = [];
  const mockFetchFn = (async (url: string, init: any = {}) => {
    const s: Seen = { url: String(url), method: init.method ?? "GET", headers: Object.fromEntries(Object.entries(init.headers ?? {}).map(([k, v]) => [k.toLowerCase(), String(v)])), body: init.body }; seen.push(s);
    if (s.url.startsWith("https://api.acme.test/")) return new Response(JSON.stringify({ vms: [{ id: "vm1" }], debug_echo: s.headers["authorization"] }), { status: 200, headers: { "content-type": "application/json" } });
    return fetch(url, init);
  }) as unknown as typeof fetch;
  const gh = await mockGithub(); const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "uca-pv-"));
  const probe = http.createServer(); await new Promise<void>((r) => probe.listen(0, "127.0.0.1", () => r())); const port = (probe.address() as AddressInfo).port; await new Promise((r) => probe.close(r));
  const config = loadConfig({ PORT: String(port), UCA_BASE_URL: `http://127.0.0.1:${port}`, UCA_DATA_DIR: tmp, GITHUB_CLIENT_ID: "cid", GITHUB_CLIENT_SECRET: "cs", UCA_REQUIRE_APPROVAL: "true" } as any);
  const app = createApp(config, { githubApiBase: gh.url, githubWebBase: gh.url, fetchImpl: mockFetchFn }); await new Promise<void>((r) => app.server.listen(port, "127.0.0.1", () => r()));
  const c: Ctx = { app, base: config.baseUrl, gh, tmp, async stop() { await app.close(); gh.server.close(); fs.rmSync(tmp, { recursive: true, force: true }); } };
  try {
    const f = await oauthFlow(c); const tok = await getToken(c, f); const client = await mcpClient(c, tok.access_token);
    const me = await (await fetch(`${c.base}/api/me`, { headers: { cookie: f.jar.header() } })).json() as any;
    const H = { cookie: f.jar.header(), "x-csrf-token": me.csrf, "content-type": "application/json" };
    // AI has no key yet and is told where the user adds it
    const before = JSON.parse(text(await client.callTool({ name: "providers_list", arguments: {} }))); assert.equal(before.added.length, 0); assert.ok(before.recommended.some((r: any) => r.id === "flyio")); assert.match(before.howToAdd, /app/i);
    const none = await client.callTool({ name: "provider_request", arguments: { provider: "acme", url: "https://api.acme.test/v1/vms" } }) as any; assert.equal(none.isError, true); assert.match(text(none), /No key/);
    // dashboard API: CSRF required, bad host rejected, key never echoed
    assert.equal((await fetch(`${c.base}/api/providers`, { method: "POST", headers: { cookie: f.jar.header(), "content-type": "application/json" }, body: "{}" })).status, 403);
    const bad = await fetch(`${c.base}/api/providers`, { method: "POST", headers: H, body: JSON.stringify({ label: "Acme Cloud", hosts: ["127.0.0.1"], key: KEY }) }); assert.equal(bad.status, 400);
    const add = await fetch(`${c.base}/api/providers`, { method: "POST", headers: H, body: JSON.stringify({ label: "Acme Cloud", hosts: ["api.acme.test"], key: KEY }) }); const addTxt = await add.text(); assert.equal(add.status, 200, addTxt); assert.ok(!addTxt.includes(KEY));
    const lst = await (await fetch(`${c.base}/api/providers`, { headers: { cookie: f.jar.header() } })).text(); assert.ok(!lst.includes(KEY)); assert.match(lst, /memory-only/);
    // AI now sees only a handle
    const after = text(await client.callTool({ name: "providers_list", arguments: {} })); assert.ok(!after.includes(KEY)); assert.equal(JSON.parse(after).added[0].id, "acme-cloud");
    // GET works immediately; the provider echoed the Authorization header, and the AI still never sees the key
    const get = await client.callTool({ name: "provider_request", arguments: { provider: "acme-cloud", url: "https://api.acme.test/v1/vms" } }) as any; assert.ok(!get.isError, text(get)); assert.ok(!text(get).includes(KEY)); assert.match(text(get), /vm1/);
    assert.equal(seen.find((s) => s.url.startsWith("https://api.acme.test"))!.headers["authorization"], `Bearer ${KEY}`, "server attached the real key");
    // writes need approval, and the approval text does not contain the key even if the AI put it in the body
    const w = await client.callTool({ name: "provider_request", arguments: { provider: "acme-cloud", method: "POST", url: "https://api.acme.test/v1/vms", body: { name: "x", leak: KEY }, purpose: "create a test VM" } }) as any;
    const wj = JSON.parse(text(w)); assert.equal(wj.status, "approval_required"); const apps = JSON.stringify(await (await fetch(`${c.base}/api/approvals`, { headers: { cookie: f.jar.header() } })).json()); assert.ok(!apps.includes(KEY), "approval text leaked the key"); assert.match(apps, /create a test VM/);
    assert.equal(seen.filter((s) => s.method === "POST" && s.url.startsWith("https://api.acme.test")).length, 0, "nothing was sent to the provider before approval");
    assert.equal((await fetch(`${c.base}/api/approvals/${wj.approvalId}/approve`, { method: "POST", headers: H, body: "{}" })).status, 200);
    const w2 = await client.callTool({ name: "provider_request", arguments: { provider: "acme-cloud", method: "POST", url: "https://api.acme.test/v1/vms", body: { name: "x", leak: KEY }, purpose: "create a test VM" } }) as any; assert.ok(!w2.isError, text(w2)); assert.ok(!text(w2).includes(KEY));
    // host pinning holds end to end
    const evil = await client.callTool({ name: "provider_request", arguments: { provider: "acme-cloud", url: "https://evil.test/steal" } }) as any; assert.equal(evil.isError, true); assert.match(text(evil), /not approved/); assert.ok(!seen.some((s) => s.url.includes("evil.test")));
    // the audit log must not contain the key
    const auditFile = path.join(c.tmp, "audit.log"); const files = fs.readdirSync(c.tmp).filter((x) => /audit/.test(x)); for (const fl of files) assert.ok(!fs.readFileSync(path.join(c.tmp, fl), "utf8").includes(KEY), "audit has key"); void auditFile;
    // nothing on disk anywhere under the data dir contains the key
    const walk = (d: string): string[] => fs.readdirSync(d, { withFileTypes: true }).flatMap((e) => e.isDirectory() ? walk(path.join(d, e.name)) : [path.join(d, e.name)]);
    for (const file of walk(c.tmp)) assert.ok(!fs.readFileSync(file).includes(KEY), "key found on disk: " + file);
    // removal by the user is immediate
    assert.equal(((await (await fetch(`${c.base}/api/providers/acme-cloud`, { method: "DELETE", headers: H })).json()) as any).removed, true);
    const gone = await client.callTool({ name: "provider_request", arguments: { provider: "acme-cloud", url: "https://api.acme.test/v1/vms" } }) as any; assert.equal(gone.isError, true);
    // sign-out wipes keys
    await fetch(`${c.base}/api/providers`, { method: "POST", headers: H, body: JSON.stringify({ label: "Acme Cloud", hosts: ["api.acme.test"], key: KEY }) }); assert.equal(c.app.pvault.has("gh:4242", "acme-cloud"), true);
    await fetch(`${c.base}/api/logout`, { method: "POST", headers: H, body: "{}" }); assert.equal(c.app.pvault.has("gh:4242", "acme-cloud"), false, "logout must wipe keys");
    await client.close();
  } finally { await c.stop(); }
});

test("E2E: revoke-all wipes keys; restart loses keys (memory only); docs tools refuse private targets via MCP", async () => {
  const c = await boot();
  try {
    const f = await oauthFlow(c); const tok = await getToken(c, f); const client = await mcpClient(c, tok.access_token);
    const me = await (await fetch(`${c.base}/api/me`, { headers: { cookie: f.jar.header() } })).json() as any; const H = { cookie: f.jar.header(), "x-csrf-token": me.csrf, "content-type": "application/json" };
    await fetch(`${c.base}/api/providers`, { method: "POST", headers: H, body: JSON.stringify({ id: "hetzner", key: KEY }) }); assert.equal(c.app.pvault.has("gh:4242", "hetzner"), true, "preset needs only the key");
    for (const u of ["https://127.0.0.1/", "http://example.com/", "https://169.254.169.254/latest/meta-data/"]) { const r = await client.callTool({ name: "provider_read_docs", arguments: { url: u } }) as any; assert.equal(r.isError, true, u); }
    await fetch(`${c.base}/api/revoke-all`, { method: "POST", headers: H, body: "{}" }); assert.equal(c.app.pvault.has("gh:4242", "hetzner"), false, "revoke-all must wipe keys");
    await client.close();
  } finally { await c.stop(); }
  // a brand new app instance (= server restart) holds nothing
  const c2 = await boot(); try { assert.deepEqual(c2.app.pvault.list("gh:4242"), []); } finally { await c2.stop(); }
});

test("MCP tool list: provider tools exist, are scoped correctly, and no tool schema accepts a raw key", async () => {
  const c = await boot();
  try {
    const f = await oauthFlow(c); const tok = await getToken(c, f); const client = await mcpClient(c, tok.access_token);
    const tools = (await client.listTools()).tools; const names = tools.map((t) => t.name);
    for (const n of ["providers_list", "provider_search_docs", "provider_read_docs", "provider_request", "provider_remove_key"]) assert.ok(names.includes(n), n);
    for (const t of tools.filter((x) => x.name.startsWith("provider"))) { const props = Object.keys((t.inputSchema as any).properties ?? {}); assert.ok(!props.some((p) => /^(key|apikey|api_key|token|secret|password)$/i.test(p)), `${t.name} must not take a key argument`); }
    await client.close();
  } finally { await c.stop(); }
});

test("audit log never contains a pasted key, even when a provider error message echoes it", async () => {
  const gh = await mockGithub(); const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "uca-aud-"));
  const probe = http.createServer(); await new Promise<void>((r) => probe.listen(0, "127.0.0.1", () => r())); const port = (probe.address() as AddressInfo).port; await new Promise((r) => probe.close(r));
  const config = loadConfig({ PORT: String(port), UCA_BASE_URL: `http://127.0.0.1:${port}`, UCA_DATA_DIR: tmp, GITHUB_CLIENT_ID: "cid", GITHUB_CLIENT_SECRET: "cs" } as any);
  const evilFetch = (async (url: string, init: any) => { if (String(url).startsWith("https://api.acme.test")) throw new Error("socket hang up; sent header Authorization: Bearer " + KEY + " to host"); return fetch(url, init); }) as unknown as typeof fetch;
  const app = createApp(config, { githubApiBase: gh.url, githubWebBase: gh.url, fetchImpl: evilFetch }); await new Promise<void>((r) => app.server.listen(port, "127.0.0.1", () => r()));
  const c: Ctx = { app, base: config.baseUrl, gh, tmp, async stop() { await app.close(); gh.server.close(); fs.rmSync(tmp, { recursive: true, force: true }); } };
  try {
    const f = await oauthFlow(c); const tok = await getToken(c, f); const client = await mcpClient(c, tok.access_token);
    const me = await (await fetch(`${c.base}/api/me`, { headers: { cookie: f.jar.header() } })).json() as any;
    await fetch(`${c.base}/api/providers`, { method: "POST", headers: { cookie: f.jar.header(), "x-csrf-token": me.csrf, "content-type": "application/json" }, body: JSON.stringify({ label: "Acme", hosts: ["api.acme.test"], key: KEY }) });
    const r = await client.callTool({ name: "provider_request", arguments: { provider: "acme", url: "https://api.acme.test/v1/x" } }) as any;
    assert.equal(r.isError, true); assert.ok(!text(r).includes(KEY), "tool error leaked key");
    const audit = fs.readFileSync(path.join(c.tmp, "audit.log"), "utf8"); assert.match(audit, /provider_request/); assert.ok(!audit.includes(KEY), "audit.log leaked key");
    await client.close();
  } finally { await c.stop(); }
});

test("defense in depth: an error raised OUTSIDE the vault that contains the key is still scrubbed from the tool result and audit.log", async () => {
  const { runTool } = await import("../src/mcp/tools.js");
  const { AuditLog, ApprovalService, RateLimiter } = await import("../src/mcp/services.js");
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "uca-did-")); const audit = new AuditLog(tmp);
  const config = loadConfig({ UCA_DATA_DIR: tmp } as any); const vault = new ProviderVault(); vault.put("u1", spec, KEY);
  const deps: any = { config, approvals: new (ApprovalService as any)(), audit, limiter: new (RateLimiter as any)(1000), vault };
  const def: any = { name: "boom", shape: {}, scope: "mcp:read", readOnly: true, handler: async () => { throw new Error("internal failure while handling token " + KEY); } };
  const res = await runTool(def, {}, { userId: "u1" } as any, deps) as any;
  assert.equal(res.isError, true); assert.ok(!JSON.stringify(res).includes(KEY), "tool error leaked key");
  assert.ok(!fs.readFileSync(path.join(tmp, "audit.log"), "utf8").includes(KEY), "audit.log leaked key");
  fs.rmSync(tmp, { recursive: true, force: true });
});

test("static assets are served with correct content types (PNG icons must be image/png so the app is installable)", async () => {
  const c = await boot();
  try {
    for (const [p, re] of [["/icons/icon-192.png", /^image\/png/], ["/icons/icon-512.png", /^image\/png/], ["/icons/maskable-512.png", /^image\/png/], ["/icons/apple-touch-icon.png", /^image\/png/], ["/manifest.webmanifest", /manifest\+json/], ["/sw.js", /javascript/]] as const) {
      const r = await fetch(c.base + p); assert.equal(r.status, 200, p); assert.match(r.headers.get("content-type") ?? "", re, p);
    }
  } finally { await c.stop(); }
});

// ------------------------------------------------------------------ guest mode: zero setup
async function bootGuest(env: Record<string, string> = {}) {
  const gh = await mockGithub(); const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "uca-guest-"));
  const probe = http.createServer(); await new Promise<void>((r) => probe.listen(0, "127.0.0.1", () => r())); const port = (probe.address() as AddressInfo).port; await new Promise((r) => probe.close(r));
  const config = loadConfig({ PORT: String(port), UCA_BASE_URL: `http://127.0.0.1:${port}`, UCA_DATA_DIR: tmp, ...env } as any); // NOTE: no GitHub client id or secret
  const box = fakeInstaBox(); const app = createApp(config, { githubApiBase: gh.url, githubWebBase: gh.url, fetchImpl: box.fetchImpl, instaboxPollMs: 5 } as any); await new Promise<void>((r) => app.server.listen(port, "127.0.0.1", () => r()));
  return { app, config, base: config.baseUrl, gh, tmp, async stop() { await app.close(); gh.server.close(); box.stop(); fs.rmSync(tmp, { recursive: true, force: true }); } };
}
function pkce() { const verifier = crypto.randomBytes(32).toString("base64url"); return { verifier, challenge: crypto.createHash("sha256").update(verifier).digest("base64url") }; }

test("guest: config defaults - on only when GitHub OAuth is NOT configured, and can be forced either way", () => {
  assert.equal(loadConfig({} as any).allowGuests, true);
  assert.equal(loadConfig({ GITHUB_CLIENT_ID: "a", GITHUB_CLIENT_SECRET: "b" } as any).allowGuests, false, "a configured server must not silently allow guests");
  assert.equal(loadConfig({ GITHUB_CLIENT_ID: "a", GITHUB_CLIENT_SECRET: "b", UCA_ALLOW_GUESTS: "true" } as any).allowGuests, true);
  assert.equal(loadConfig({ UCA_ALLOW_GUESTS: "false" } as any).allowGuests, false);
});

test("guest E2E: with NO GitHub app and NO keys, a real MCP client connects via OAuth+PKCE, gets a private workspace, and can use tools", async () => {
  const c = await bootGuest();
  try {
    const st = await (await fetch(`${c.base}/api/setup-status`)).json() as any; assert.equal(st.guestMode, true); assert.equal(st.githubConfigured, false);
    // dynamic client registration + authorize, exactly as Claude/ChatGPT do it
    const redirectUri = "http://127.0.0.1:9/cb";
    const reg = await (await fetch(`${c.base}/register`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_name: "t", redirect_uris: [redirectUri], token_endpoint_auth_method: "none", grant_types: ["authorization_code", "refresh_token"], response_types: ["code"] }) })).json() as any;
    const { verifier, challenge } = pkce();
    const q = new URLSearchParams({ response_type: "code", client_id: reg.client_id, redirect_uri: redirectUri, code_challenge: challenge, code_challenge_method: "S256", scope: "mcp:read mcp:write mcp:exec", state: "s1", resource: `${c.base}/mcp` });
    const a1 = await fetch(`${c.base}/authorize?${q}`, { redirect: "manual" }); assert.equal(a1.status, 302);
    const setCookie = a1.headers.getSetCookie().map((x) => x.split(";")[0]).join("; "); assert.match(setCookie, /=/, "guest session cookie issued");
    const consentUrl = new URL(a1.headers.get("location")!, c.base); assert.equal(consentUrl.pathname, "/authorize/consent");
    const page = await (await fetch(consentUrl, { headers: { cookie: setCookie } })).text(); assert.match(page, /guest workspace/i); assert.match(page, /no account needed/i);
    const csrf = /name=csrf value="([^"]+)"/.exec(page)![1]; const pending = /name=pending value="([^"]+)"/.exec(page)![1];
    const dec = await fetch(`${c.base}/authorize/decision`, { method: "POST", redirect: "manual", headers: { cookie: setCookie, "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ pending, csrf, decision: "approve" }) });
    const code = new URL(dec.headers.get("location")!).searchParams.get("code"); assert.ok(code, "got an authorization code");
    const tok = await (await fetch(`${c.base}/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "authorization_code", code: code!, redirect_uri: redirectUri, client_id: reg.client_id, code_verifier: verifier, resource: `${c.base}/mcp` }) })).json() as any;
    assert.ok(tok.access_token, JSON.stringify(tok));
    await vmForToken(c.app, tok.access_token); const client = await mcpClient({ base: c.base } as any, tok.access_token);
    const w = await client.callTool({ name: "write_file", arguments: { path: "hello.txt", content: "hi guest" } }) as any; assert.ok(!w.isError, text(w));
    const r = await client.callTool({ name: "read_file", arguments: { path: "hello.txt" } }) as any; assert.match(text(r), /hi guest/);
    // GitHub tools explain themselves instead of failing mysteriously
    const g = await client.callTool({ name: "github_list_repos", arguments: {} }) as any; assert.equal(g.isError, true); assert.match(text(g), /guest mode/i);
    // the guest workspace is a real private folder
    const dirs = fs.readdirSync(path.join(c.tmp, "workspaces")); assert.equal(dirs.length, 1); assert.match(dirs[0], /^guest_/);
    await client.close();
  } finally { await c.stop(); }
});

async function guestToken(c: { base: string }) {
  const redirectUri = "http://127.0.0.1:9/cb";
  const reg = await (await fetch(`${c.base}/register`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_name: "t", redirect_uris: [redirectUri], token_endpoint_auth_method: "none", grant_types: ["authorization_code", "refresh_token"], response_types: ["code"] }) })).json() as any;
  const { verifier, challenge } = pkce();
  const q = new URLSearchParams({ response_type: "code", client_id: reg.client_id, redirect_uri: redirectUri, code_challenge: challenge, code_challenge_method: "S256", scope: "mcp:read mcp:write mcp:exec", state: "s", resource: `${c.base}/mcp` });
  const a1 = await fetch(`${c.base}/authorize?${q}`, { redirect: "manual" }); const cookie = a1.headers.getSetCookie().map((x) => x.split(";")[0]).join("; ");
  const page = await (await fetch(new URL(a1.headers.get("location")!, c.base), { headers: { cookie } })).text();
  const csrf = /name=csrf value="([^"]+)"/.exec(page)![1]; const pending = /name=pending value="([^"]+)"/.exec(page)![1];
  const dec = await fetch(`${c.base}/authorize/decision`, { method: "POST", redirect: "manual", headers: { cookie, "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ pending, csrf, decision: "approve" }) });
  const code = new URL(dec.headers.get("location")!).searchParams.get("code")!;
  const tok = await (await fetch(`${c.base}/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: redirectUri, client_id: reg.client_id, code_verifier: verifier, resource: `${c.base}/mcp` }) })).json() as any;
  const me = await (await fetch(`${c.base}/api/me`, { headers: { cookie } })).json() as any;
  return { token: tok.access_token as string, cookie, me };
}

test("guest isolation: two guests get separate VMs and cannot see, read or traverse into each other's files", async () => {
  const c = await bootGuest();
  try {
    const A = await guestToken(c); const B = await guestToken(c); assert.notEqual(A.me.user.userId, B.me.user.userId);
    const ma = (await vmForToken(c.app, A.token), c.app.vm.status(A.me.user.userId).machineId); const mb = (await vmForToken(c.app, B.token), c.app.vm.status(B.me.user.userId).machineId);
    assert.ok(ma && mb && ma !== mb, "two separate machines");
    const ca = await mcpClient({ base: c.base } as any, A.token); const cb = await mcpClient({ base: c.base } as any, B.token);
    assert.ok(!((await ca.callTool({ name: "write_file", arguments: { path: "secret.txt", content: "A-ONLY-SECRET" } })) as any).isError);
    const lsB = text(await cb.callTool({ name: "list_directory", arguments: { path: "." } })); assert.ok(!lsB.includes("secret.txt"), "B can see A's file: " + lsB);
    const rdB = await cb.callTool({ name: "read_file", arguments: { path: "secret.txt" } }) as any; assert.equal(rdB.isError, true); assert.ok(!text(rdB).includes("A-ONLY-SECRET"));
    for (const evil of [`../secret.txt`, `../../${ma}/home/workspace/secret.txt`, `/data/home/workspace/../${ma}/secret.txt`, `..%2fsecret.txt`, `/etc/passwd`]) {
      const r = await cb.callTool({ name: "read_file", arguments: { path: evil } }) as any; assert.equal(r.isError, true, "traversal allowed: " + evil); assert.ok(!text(r).includes("A-ONLY-SECRET"), evil);
    }
    // and A really has it, so the checks above prove something
    assert.match(text(await ca.callTool({ name: "read_file", arguments: { path: "secret.txt" } })), /A-ONLY-SECRET/);
    // B's own machine on the same fake host cannot be used to reach A's: a command in B only ever runs in B's machine
    const cmd = await cb.callTool({ name: "run_command", arguments: { command: "cat secret.txt" } }) as any; assert.ok(!text(cmd).includes("A-ONLY-SECRET"), "command saw A's file: " + text(cmd));
    // anonymous gets nothing
    assert.equal((await fetch(`${c.base}/mcp`, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }) })).status, 401);
    await ca.close(); await cb.close();
  } finally { await c.stop(); }
});

test("guest safety: cap on guest accounts, rate limit, POST-only creation, off when GitHub is configured, off when disabled", async () => {
  const c = await bootGuest({ UCA_MAX_GUESTS: "2" });
  try {
    assert.equal((await fetch(`${c.base}/auth/guest`)).status === 200, false, "GET must not create a guest (link previews)");
    assert.equal((await fetch(`${c.base}/auth/guest`, { method: "POST" })).status, 200);
    assert.equal((await fetch(`${c.base}/auth/guest`, { method: "POST" })).status, 200);
    const third = await fetch(`${c.base}/auth/guest`, { method: "POST" }); assert.ok([503, 429].includes(third.status), "third guest refused, got " + third.status);
  } finally { await c.stop(); }
  const off = await bootGuest({ UCA_ALLOW_GUESTS: "false" });
  try { assert.equal((await fetch(`${off.base}/auth/guest`, { method: "POST" })).status, 403); const st = await (await fetch(`${off.base}/api/setup-status`)).json() as any; assert.equal(st.guestMode, false); } finally { await off.stop(); }
  const gh = await bootGuest({ GITHUB_CLIENT_ID: "id", GITHUB_CLIENT_SECRET: "sec" });
  try { assert.equal((await fetch(`${gh.base}/auth/guest`, { method: "POST" })).status, 403, "a server with GitHub OAuth must not allow guests by default"); } finally { await gh.stop(); }
});

test("guest safety: dangerous commands are blocked or need approval for guests too, and keys stay per-guest", async () => {
  const c = await bootGuest();
  try {
    const A = await guestToken(c); const B = await guestToken(c); await vmForToken(c.app, A.token); const client = await mcpClient({ base: c.base } as any, A.token);
    const bad = ["rm", "-rf", " /"].join(""); const r1 = await client.callTool({ name: "run_command", arguments: { command: bad } }) as any; assert.equal(r1.isError, true, "destructive command must not run: " + text(r1));
    const inst = await client.callTool({ name: "run_command", arguments: { command: "npm install left-pad" } }) as any; assert.ok(/approval/i.test(text(inst)), "installs must wait for approval: " + text(inst));
    const H = { cookie: A.cookie, "x-csrf-token": A.me.csrf, "content-type": "application/json" };
    assert.equal((await fetch(`${c.base}/api/providers`, { method: "POST", headers: H, body: JSON.stringify({ id: "hetzner", key: KEY }) })).status, 200);
    assert.equal(c.app.pvault.has(A.me.user.userId, "hetzner"), true); assert.equal(c.app.pvault.has(B.me.user.userId, "hetzner"), false, "another guest must not have this guest's key");
    await fetch(`${c.base}/api/logout`, { method: "POST", headers: H, body: "{}" }); assert.equal(c.app.pvault.has(A.me.user.userId, "hetzner"), false);
    await client.close();
  } finally { await c.stop(); }
});

test("REAL-CLIENT DISCOVERY: a client that follows only the URLs the server advertises (as ChatGPT does) can register, authorize, get a token and call tools", async () => {
  const c = await bootGuest();
  try {
    // 1) unauthenticated MCP call -> 401 with resource_metadata pointer
    const r0 = await fetch(`${c.base}/mcp`, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "x", version: "1" } } }) });
    assert.equal(r0.status, 401); const rm = /resource_metadata="([^"]+)"/.exec(r0.headers.get("www-authenticate") ?? ""); assert.ok(rm, "401 must carry resource_metadata");
    const prm = await (await fetch(rm![1])).json() as any; assert.ok(prm.authorization_servers?.[0]);
    // 2) discovery - try every well-known location real clients probe; all must answer
    const as = prm.authorization_servers[0];
    for (const w of ["/.well-known/oauth-authorization-server", "/.well-known/oauth-authorization-server/mcp", "/.well-known/openid-configuration", "/.well-known/oauth-protected-resource/mcp"]) assert.equal((await fetch(as + w)).status, 200, w);
    const meta = await (await fetch(`${as}/.well-known/oauth-authorization-server`)).json() as any;
    // 3) EVERY endpoint the metadata advertises must exist (not 404)
    for (const k of ["authorization_endpoint", "token_endpoint", "registration_endpoint", "revocation_endpoint"]) {
      assert.ok(meta[k], k + " advertised"); const probe = await fetch(meta[k], { method: k === "authorization_endpoint" ? "GET" : "POST", headers: { "content-type": "application/json" }, body: k === "authorization_endpoint" ? undefined : "{}", redirect: "manual" });
      assert.notEqual(probe.status, 404, `${k} (${meta[k]}) is advertised but returns 404`); assert.notEqual(probe.status, 405, `${k} wrong method`);
    }
    assert.ok(!("introspection_endpoint" in meta), "do not advertise endpoints that are not mounted");
    // 4) full flow using ONLY advertised URLs, with ChatGPT's real redirect URI
    const redirectUri = "https://chatgpt.com/connector_platform_oauth_redirect";
    const reg = await fetch(meta.registration_endpoint, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_name: "ChatGPT", redirect_uris: [redirectUri], token_endpoint_auth_method: "none", grant_types: ["authorization_code", "refresh_token"], response_types: ["code"] }) }); assert.equal(reg.status, 201, await reg.clone().text()); const client_id = ((await reg.json()) as any).client_id;
    const { verifier, challenge } = pkce();
    const q = new URLSearchParams({ response_type: "code", client_id, redirect_uri: redirectUri, code_challenge: challenge, code_challenge_method: "S256", scope: "mcp:read mcp:write mcp:exec", state: "xyz", resource: prm.resource });
    const a1 = await fetch(`${meta.authorization_endpoint}?${q}`, { redirect: "manual" }); assert.equal(a1.status, 302, "authorize: " + a1.status);
    const cookie = a1.headers.getSetCookie().map((x) => x.split(";")[0]).join("; ");
    const page = await (await fetch(new URL(a1.headers.get("location")!, c.base), { headers: { cookie } })).text();
    const csrf = /name=csrf value="([^"]+)"/.exec(page)![1]; const pending = /name=pending value="([^"]+)"/.exec(page)![1];
    const dec = await fetch(`${c.base}/authorize/decision`, { method: "POST", redirect: "manual", headers: { cookie, "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ pending, csrf, decision: "approve" }) });
    const back = new URL(dec.headers.get("location")!); assert.equal(back.origin + back.pathname, redirectUri); assert.equal(back.searchParams.get("state"), "xyz"); const code = back.searchParams.get("code")!; assert.ok(code);
    const tr = await fetch(meta.token_endpoint, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: redirectUri, client_id, code_verifier: verifier, resource: prm.resource }) }); const tok = await tr.json() as any; assert.ok(tok.access_token, JSON.stringify(tok));
    // 5) token works on the advertised resource
    const mc = await mcpClient({ base: c.base } as any, tok.access_token); const tools = await mc.listTools(); assert.ok(tools.tools.length > 40, "tools listed: " + tools.tools.length); await mc.close();
    // 6) the same flow via the OLD un-prefixed paths still works (backward compatible)
    assert.equal((await fetch(`${c.base}/register`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ redirect_uris: [redirectUri], token_endpoint_auth_method: "none" }) })).status, 201);
  } finally { await c.stop(); }
});

test("CORS: public protocol endpoints answer browser preflights; the cookie-authenticated dashboard API never does", async () => {
  const c = await bootGuest();
  try {
    for (const [pth, method] of [["/.well-known/oauth-authorization-server", "GET"], ["/register", "POST"], ["/token", "POST"], ["/mcp", "POST"]] as const) {
      const r = await fetch(c.base + pth, { method: "OPTIONS", headers: { origin: "https://inspector.example", "access-control-request-method": method, "access-control-request-headers": "authorization,content-type,mcp-protocol-version" } });
      assert.equal(r.status, 204, pth); assert.equal(r.headers.get("access-control-allow-origin"), "*", pth); assert.match(r.headers.get("access-control-allow-headers") ?? "", /authorization/i, pth);
    }
    const d = await fetch(`${c.base}/.well-known/oauth-authorization-server`, { headers: { origin: "https://x.example" } }); assert.equal(d.headers.get("access-control-allow-origin"), "*");
    const u = await fetch(`${c.base}/mcp`, { method: "POST", headers: { origin: "https://x.example", "content-type": "application/json" }, body: "{}" }); assert.equal(u.status, 401); assert.match(u.headers.get("access-control-expose-headers") ?? "", /www-authenticate/i, "browser clients must be able to read WWW-Authenticate");
    // dashboard API: no CORS, so another website cannot drive a signed-in user's session
    const api = await fetch(`${c.base}/api/me`, { method: "OPTIONS", headers: { origin: "https://evil.example", "access-control-request-method": "POST" } }); assert.equal(api.headers.get("access-control-allow-origin"), null, "dashboard API must not be CORS-enabled");
    const api2 = await fetch(`${c.base}/api/me`, { headers: { origin: "https://evil.example" } }); assert.equal(api2.headers.get("access-control-allow-origin"), null);
    const g = await fetch(`${c.base}/auth/guest`, { method: "OPTIONS", headers: { origin: "https://evil.example" } }); assert.equal(g.headers.get("access-control-allow-origin"), null, "guest login must not be cross-origin callable");
  } finally { await c.stop(); }
});

test("chooser: when BOTH GitHub and guest are enabled, /authorize offers a choice; a guest is only minted by an explicit POST; GET never creates one", async () => {
  const c = await bootGuest({ GITHUB_CLIENT_ID: "cid", GITHUB_CLIENT_SECRET: "sec", UCA_ALLOW_GUESTS: "true" });
  try {
    const ru = "https://chatgpt.com/connector_platform_oauth_redirect";
    const reg = await (await fetch(`${c.base}/oauth/register`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_name: "ChatGPT", redirect_uris: [ru], token_endpoint_auth_method: "none" }) })).json() as any;
    const { verifier, challenge } = pkce();
    const q = new URLSearchParams({ response_type: "code", client_id: reg.client_id, redirect_uri: ru, code_challenge: challenge, code_challenge_method: "S256", scope: "mcp:read mcp:write mcp:exec", state: "s", resource: `${c.base}/mcp` });
    const a = await fetch(`${c.base}/oauth/authorize?${q}`, { redirect: "manual" }); assert.equal(a.status, 302);
    const loc = new URL(a.headers.get("location")!, c.base); assert.equal(loc.pathname, "/authorize/choose", "must offer a choice, not force GitHub: " + loc.pathname);
    const before = c.app.store.countUsers("guest:");
    const page = await (await fetch(loc)).text(); assert.match(page, /Continue as guest/); assert.match(page, /Sign in with GitHub/);
    await fetch(loc); await fetch(`${c.base}/authorize/guest?pending=x`); assert.equal(c.app.store.countUsers("guest:"), before, "viewing/previewing links must not create guests");
    const pending = loc.searchParams.get("pending")!;
    // the GitHub option really goes to github.com
    const gh = await fetch(`${c.base}/authorize/github?pending=${pending}`, { redirect: "manual" }); assert.equal(gh.status, 302); assert.match(gh.headers.get("location")!, /\/login\/oauth\/authorize\?client_id=cid/);
    // the guest option works end to end through to a token
    const gp = await fetch(`${c.base}/authorize/guest`, { method: "POST", redirect: "manual", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ pending }) }); assert.equal(gp.status, 302);
    const cookie = gp.headers.getSetCookie().map((x) => x.split(";")[0]).join("; "); assert.equal(c.app.store.countUsers("guest:"), before + 1);
    const cp = await (await fetch(new URL(gp.headers.get("location")!, c.base), { headers: { cookie } })).text();
    const csrf = /name=csrf value="([^"]+)"/.exec(cp)![1];
    const dec = await fetch(`${c.base}/authorize/decision`, { method: "POST", redirect: "manual", headers: { cookie, "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ pending, csrf, decision: "approve" }) });
    const code = new URL(dec.headers.get("location")!).searchParams.get("code")!; assert.ok(code);
    const tok = await (await fetch(`${c.base}/oauth/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: ru, client_id: reg.client_id, code_verifier: verifier, resource: `${c.base}/mcp` }) })).json() as any; assert.ok(tok.access_token);
    const mc = await mcpClient({ base: c.base } as any, tok.access_token); assert.ok((await mc.listTools()).tools.length > 40); await mc.close();
    // with guests disabled the chooser refuses
    const off = await bootGuest({ GITHUB_CLIENT_ID: "cid", GITHUB_CLIENT_SECRET: "sec", UCA_ALLOW_GUESTS: "false" });
    try { assert.equal((await fetch(`${off.base}/authorize/choose?pending=${pending}`)).status, 400); assert.equal((await fetch(`${off.base}/authorize/guest`, { method: "POST", body: new URLSearchParams({ pending }) })).status, 400); } finally { await off.stop(); }
  } finally { await c.stop(); }
});

test("InstaBox preset is listed first, pins api.instabox.sh and sends X-API-Key (never Authorization)", async () => {
  const { PRESETS } = await import("../src/providers/vault.js");
  const p = PRESETS.find((x) => x.id === "instabox")!;
  assert.ok(p, "instabox preset exists"); assert.equal(PRESETS[0].id, "instabox");
  assert.deepEqual(p.hosts, ["api.instabox.sh"]); assert.deepEqual(p.auth, { type: "header", name: "X-API-Key" });
  assert.equal(new URL(p.verify!.url).host, "api.instabox.sh");
});
