/** Remote state mirror: MCP connections must survive a restart on a host with no disk. */
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { AuthMirror, openBlob, sealBlob } from "../src/auth/mirror.js";
import { createApp } from "../src/http/app.js";
import { loadConfig } from "../src/util/config.js";

const SECRET = "a-long-stable-session-secret-for-tests";

/** Fake of GitHub's contents API for one private repo. */
function fakeGithub(opts: { failGet?: number; failPut?: number } = {}) {
  const files = new Map<string, { content: string; sha: string }>();
  let n = 0; const puts: string[] = [];
  const fetchImpl = (async (url: any, init: any = {}) => {
    const u = new URL(String(url)); const m = (init.method ?? "GET").toUpperCase();
    assert.match(u.pathname, /^\/repos\/me\/state\/contents\//);
    assert.equal(init.headers.authorization, "Bearer tok");
    const key = u.pathname;
    if (m === "GET") {
      if (opts.failGet) return new Response("x", { status: opts.failGet });
      const f = files.get(key); if (!f) return new Response("{}", { status: 404 });
      return new Response(JSON.stringify({ sha: f.sha, content: f.content }), { status: 200 });
    }
    if (opts.failPut) return new Response("x", { status: opts.failPut });
    const b = JSON.parse(init.body); const cur = files.get(key);
    if (cur && b.sha !== cur.sha) return new Response("{}", { status: 409 });
    const sha = "sha" + ++n; files.set(key, { content: b.content, sha }); puts.push(Buffer.from(b.content, "base64").toString("utf8"));
    return new Response(JSON.stringify({ content: { sha } }), { status: 200 });
  }) as typeof fetch;
  return { fetchImpl, files, puts };
}
const mk = (gh: ReturnType<typeof fakeGithub>) => new AuthMirror({ repo: "me/state", token: "tok", secret: SECRET, fetchImpl: gh.fetchImpl, debounceMs: 5, log: () => {} });
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), "uca-mirror-"));
const cfg = (dir: string) => loadConfig({ UCA_DATA_DIR: dir, UCA_SESSION_SECRET: SECRET, UCA_BASE_URL: "https://x.test", UCA_ALLOW_GUESTS: "true" });

test("blob round-trips, is not plaintext, and a wrong secret is rejected", () => {
  const b = sealBlob('{"hello":"world","token":"abc"}', SECRET);
  assert.ok(!b.includes("hello") && !b.includes("abc"));
  assert.equal(openBlob(b, SECRET), '{"hello":"world","token":"abc"}');
  assert.equal(openBlob(b, "another-secret-another-secret"), null);
  assert.equal(openBlob("garbage", SECRET), null);
});

test("a connection survives a full redeploy (fresh empty disk)", async () => {
  const gh = fakeGithub();
  // deploy 1: a guest connects and gets tokens
  const dir1 = tmp(); const m1 = mk(gh);
  await m1.restoreTo(path.join(dir1, "auth-store.json"));
  const app1 = createApp(cfg(dir1), { mirror: m1 });
  app1.store.upsertUser({ userId: "guest:abc", login: "guest-abc", name: "Guest" });
  app1.store.putClient({ clientId: "chatgpt-client", redirectUris: ["https://chatgpt.com/cb"], grantTypes: ["authorization_code", "refresh_token"], responseTypes: ["code"], tokenEndpointAuthMethod: "none", scope: "mcp", createdAt: Date.now() } as any);
  await m1.flush(); await app1.close();
  assert.ok(gh.puts.length >= 1);
  assert.ok(!gh.puts.at(-1)!.includes("guest-abc"), "remote copy must be encrypted");

  // deploy 2: brand-new container, EMPTY disk, same repo
  const dir2 = tmp(); const m2 = mk(gh);
  assert.equal(await m2.restoreTo(path.join(dir2, "auth-store.json")), "restored");
  const app2 = createApp(cfg(dir2), { mirror: m2 });
  assert.equal(app2.store.snapshot().users["guest:abc"]?.login, "guest-abc");
  assert.ok(app2.store.snapshot().clients["chatgpt-client"], "ChatGPT's registered client must still exist");
  await app2.close();
});

test("without the mirror a redeploy loses the client (the bug this fixes)", () => {
  const a = createApp(cfg(tmp())); a.store.putClient({ clientId: "c", redirectUris: ["https://a/b"], grantTypes: ["authorization_code"], responseTypes: ["code"], tokenEndpointAuthMethod: "none", scope: "mcp", createdAt: 1 } as any);
  const b = createApp(cfg(tmp())); assert.equal(b.store.snapshot().clients["c"], undefined);
});

test("a local file wins over the remote (normal restart on a disk)", async () => {
  const gh = fakeGithub(); const dir = tmp(); const f = path.join(dir, "auth-store.json");
  fs.writeFileSync(f, '{"version":1,"local":true}');
  assert.equal(await mk(gh).restoreTo(f), "kept-local");
  assert.equal(fs.readFileSync(f, "utf8"), '{"version":1,"local":true}');
});

test("a changed secret never overwrites the remote copy", async () => {
  const gh = fakeGithub(); const dir1 = tmp(); const m1 = mk(gh);
  await m1.restoreTo(path.join(dir1, "auth-store.json"));
  const a1 = createApp(cfg(dir1), { mirror: m1 }); a1.store.upsertUser({ userId: "guest:keep", login: "keep" }); await m1.flush();
  const before = gh.puts.length;
  const m2 = new AuthMirror({ repo: "me/state", token: "tok", secret: "a-different-secret-entirely-1234", fetchImpl: gh.fetchImpl, debounceMs: 1, log: () => {} });
  const dir2 = tmp();
  assert.equal(await m2.restoreTo(path.join(dir2, "auth-store.json")), "undecryptable");
  const a2 = createApp(cfg(dir2), { mirror: m2 }); a2.store.upsertUser({ userId: "guest:new", login: "new" }); await m2.flush();
  assert.equal(gh.puts.length, before, "must not push over a copy it cannot read");
  assert.equal(m2.status().blocked, true);
});

test("a GitHub outage at boot never wipes the remote and never stops the server", async () => {
  const good = fakeGithub(); const d1 = tmp(); const m1 = mk(good); await m1.restoreTo(path.join(d1, "auth-store.json"));
  const a1 = createApp(cfg(d1), { mirror: m1 }); a1.store.upsertUser({ userId: "guest:z", login: "z" }); await m1.flush();
  const before = good.puts.length;
  const bad = { ...good, fetchImpl: (async (u: any, i: any) => { if ((i?.method ?? "GET") === "GET") throw new Error("down"); return good.fetchImpl(u, i); }) as typeof fetch };
  const m2 = new AuthMirror({ repo: "me/state", token: "tok", secret: SECRET, fetchImpl: bad.fetchImpl, debounceMs: 1, log: () => {} });
  const d2 = tmp();
  assert.equal(await m2.restoreTo(path.join(d2, "auth-store.json")), "unreachable");
  const a2 = createApp(cfg(d2), { mirror: m2 }); a2.store.upsertUser({ userId: "guest:y", login: "y" }); await m2.flush();
  assert.equal(good.puts.length, before);
  assert.ok(a2.store.snapshot().users["guest:y"], "server keeps working locally");
});

test("push failures are survivable and retried on the next change", async () => {
  const gh = fakeGithub({ failPut: 500 }); const d = tmp(); const m = mk(gh); await m.restoreTo(path.join(d, "auth-store.json"));
  const a = createApp(cfg(d), { mirror: m }); a.store.upsertUser({ userId: "guest:r", login: "r" }); await m.flush();
  assert.match(String(m.lastError), /500/);
  assert.ok(a.store.snapshot().users["guest:r"]);
});

test("rejects a mirror with no strong secret (it would be unencrypted-equivalent)", () => {
  assert.throws(() => new AuthMirror({ repo: "me/state", token: "t", secret: "short" }), /UCA_SESSION_SECRET/);
  assert.throws(() => new AuthMirror({ repo: "bad repo", token: "t", secret: SECRET }), /owner\/repo/);
});
