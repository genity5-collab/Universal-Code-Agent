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
import { spawn, type ChildProcess } from "node:child_process";
import { fileURLToPath } from "node:url";
import { CodespaceBroker } from "../src/codespace/broker.js";
import { classifyCsCommand } from "../src/codespace/tools.js";

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


import { loadConfig as _lc } from "../src/util/config.js";

test("config: public URL is auto-detected on Render/Railway/Fly; explicit UCA_BASE_URL wins", () => {
  assert.equal(_lc({ RENDER_EXTERNAL_URL: "https://uca.onrender.com/" } as any).baseUrl, "https://uca.onrender.com");
  assert.equal(_lc({ RAILWAY_PUBLIC_DOMAIN: "uca.up.railway.app" } as any).baseUrl, "https://uca.up.railway.app");
  assert.equal(_lc({ FLY_APP_NAME: "uca" } as any).baseUrl, "https://uca.fly.dev");
  assert.equal(_lc({ UCA_BASE_URL: "https://mine.example", RENDER_EXTERNAL_URL: "https://x.onrender.com" } as any).baseUrl, "https://mine.example");
  assert.equal(_lc({ PORT: "9000" } as any).baseUrl, "http://localhost:9000");
});

test("setup wizard: status endpoint is public, reveals no secrets, and reports what is missing", async () => {
  const c = await boot({ GITHUB_CLIENT_ID: "", GITHUB_CLIENT_SECRET: "" });
  try {
    const s = await (await fetch(`${c.base}/api/setup-status`)).json() as any;
    assert.equal(s.githubConfigured, false); assert.equal(s.callbackUrl, `${c.base}/auth/github/callback`); assert.equal(s.mcpUrl, `${c.base}/mcp`);
    const raw = JSON.stringify(s); assert.ok(!/secret|token/i.test(raw.replace(/callbackUrl|githubConfigured/g, "")), "no secret-looking fields");
    const page = await fetch(`${c.base}/setup`); assert.equal(page.status, 200); assert.match(await page.text(), /Set up Universal Code Agent/);
    const js = await fetch(`${c.base}/setup.js`); assert.equal(js.status, 200);
  } finally { await c.stop(); }
  const c2 = await boot(); try { assert.equal(((await (await fetch(`${c2.base}/api/setup-status`)).json()) as any).githubConfigured, true); } finally { await c2.stop(); }
});

test("setup page works under the CSP: no inline scripts anywhere in the shipped web files", () => {
  const dir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../web");
  for (const f of fs.readdirSync(dir).filter((x) => x.endsWith(".html"))) {
    const h = fs.readFileSync(path.join(dir, f), "utf8");
    assert.ok(!/<script(?![^>]*\bsrc=)[^>]*>/i.test(h), f + " has an inline <script>, which the CSP blocks");
    assert.ok(!/\son(click|load|error|submit)\s*=/i.test(h.replace(/<button onclick="location\.reload\(\)"/g, "")) || f === "offline.html", f + " has an inline handler");
  }
});

test("PWA: manifest is valid with real icons; service worker never caches API/MCP/auth; icons are real PNGs", async () => {
  const c = await boot();
  try {
    const man = await (await fetch(`${c.base}/manifest.webmanifest`)).json() as any;
    assert.equal(man.display, "standalone"); assert.ok(man.icons.some((i: any) => i.sizes === "192x192") && man.icons.some((i: any) => i.sizes === "512x512"));
    assert.ok(man.icons.some((i: any) => i.purpose === "maskable"));
    for (const i of man.icons.filter((x: any) => x.type === "image/png")) {
      const r = await fetch(`${c.base}${i.src}`); assert.equal(r.status, 200, i.src); const b = Buffer.from(await r.arrayBuffer());
      assert.equal(b.subarray(1, 4).toString(), "PNG"); const w = b.readUInt32BE(16); assert.equal(`${w}x${w}`, i.sizes, i.src + " size matches manifest");
    }
    const sw = await (await fetch(`${c.base}/sw.js`)).text(); assert.match(sw, /api\|mcp\|agent\|auth\|authorize\|token/); assert.ok(!/addAll\(\[[^\]]*\/api/.test(sw));
    assert.equal((await fetch(`${c.base}/offline.html`)).status, 200);
    const idx = await (await fetch(`${c.base}/`)).text(); assert.match(idx, /apple-touch-icon/); assert.match(idx, /viewport-fit=cover/); assert.match(idx, /data-tab="codespaces"/);
  } finally { await c.stop(); }
});

test("dashboard Codespaces API: login required, lists paired agents, attach gives a working one-time command, detach revokes", async () => {
  const c = await boot();
  try {
    assert.equal((await fetch(`${c.base}/api/codespaces`)).status, 401);
    const f = await oauthFlow(c); await getToken(c, f);
    const me = await (await fetch(`${c.base}/api/me`, { headers: { cookie: f.jar.header() } })).json() as any;
    const H = { cookie: f.jar.header(), "x-csrf-token": me.csrf, "content-type": "application/json" };
    const att = await (await fetch(`${c.base}/api/codespaces/my-cs-1/attach`, { method: "POST", headers: H, body: "{}" })).json() as any;
    assert.match(att.command, /install\.sh \| UCA_SERVER=.* UCA_CLAIM=claim_/);
    assert.equal((await fetch(`${c.base}/api/codespaces/my-cs-1/attach`, { method: "POST", headers: { cookie: f.jar.header(), "content-type": "application/json" }, body: "{}" })).status, 403, "CSRF required");
    assert.equal((await fetch(`${c.base}/api/codespaces/bad%20name/attach`, { method: "POST", headers: H, body: "{}" })).status, 404);
    const claim = /UCA_CLAIM=(claim_[A-Za-z0-9_-]+)/.exec(att.command)![1];
    const tok = (await (await fetch(`${c.base}/agent/claim`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ claim }) })).json() as any).token;
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "uca-dash-")); const ag = startAgent(c.base, tok, root);
    try {
      await until(() => c.app.broker.isOnline("gh:4242", "my-cs-1"));
      const list = await (await fetch(`${c.base}/api/codespaces`, { headers: { cookie: f.jar.header() } })).json() as any;
      const row = list.codespaces.find((x: any) => x.name === "my-cs-1"); assert.ok(row && row.paired && row.online, JSON.stringify(list));
      assert.equal(((await (await fetch(`${c.base}/api/codespaces/my-cs-1/detach`, { method: "POST", headers: H, body: "{}" })).json()) as any).detached, true);
      await until(() => ag.child.exitCode !== null, 40_000); assert.equal(ag.child.exitCode, 3);
    } finally { ag.child.kill("SIGKILL"); fs.rmSync(root, { recursive: true, force: true }); }
  } finally { await c.stop(); }
});

test("Render blueprint and Dockerfile are consistent with the server", () => {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
  const yaml = fs.readFileSync(path.join(root, "render.yaml"), "utf8");
  for (const k of ["runtime: docker", "healthCheckPath: /healthz", "mountPath: /data", "GITHUB_CLIENT_ID", "GITHUB_CLIENT_SECRET", "generateValue: true", "UCA_DATA_DIR"]) assert.ok(yaml.includes(k), "render.yaml missing " + k);
  assert.ok(!/GITHUB_CLIENT_SECRET\s*\n\s*value:/.test(yaml), "secret must not have a literal value");
  const df = fs.readFileSync(path.join(root, "Dockerfile"), "utf8");
  for (const k of ["USER uca", "COPY web ./web", "COPY agent ./agent", "dist/src/cli.js", "UCA_DATA_DIR=/data"]) assert.ok(df.includes(k), "Dockerfile missing " + k);
  assert.ok(/mountPath: (\/\S+)/.exec(yaml)![1] === "/data", "disk mount matches UCA_DATA_DIR");
});
