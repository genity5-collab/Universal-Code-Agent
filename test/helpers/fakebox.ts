import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
const realFetch = globalThis.fetch.bind(globalThis);
export const KEY = "ibk_" + "q".repeat(48);
/** A fake InstaBox that follows the REAL API (async create + operation polling, exec cmd/cwd, raw file PUT/GET, delete confirmation) and REALLY runs bash. The machine home is a per-machine temp dir mapped onto /data/home. */
export function fakeInstaBox() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "fakebox-")); const machines = new Map<string, string>(); const ops = new Map<string, { machineId: string; polls: number }>(); const seen: string[] = []; let n = 0; const idem = new Map<string, string>();
  const map = (dir: string, cmd: string) => cmd.replace(/\/data\/home(?=[\s'"\/;|&)]|$)/g, "\u0001H").replace(/\/tmp\//g, "\u0001T/").replace(/\u0001H/g, path.join(dir, "home")).replace(/\u0001T\//g, path.join(dir, "tmp") + "/");
  const fetchImpl = (async (url: any, init: any = {}) => {
    const u = new URL(String(url)); const method = init.method ?? "GET"; seen.push(`${method} ${u.pathname}`);
    const reply = (o: unknown, status = 200) => new Response(JSON.stringify(o), { status, headers: { "content-type": "application/json" } });
    const err = (status: number, code: string, message = code) => reply({ error: { code, message, retryable: false } }, status);
    if (u.hostname !== "api.instabox.sh") return realFetch(url, init); // other traffic (e.g. the local GitHub mock) is not ours to fake
    if (init.headers?.["X-API-Key"] !== KEY) return err(401, "invalid_key");
    if (u.pathname === "/v1/machines" && method === "POST") {
      const ik = init.headers?.["Idempotency-Key"]; if (!ik) return err(400, "bad_request", "Idempotency-Key required"); if (idem.has(ik)) return reply(JSON.parse(idem.get(ik)!), 202);
      const body = JSON.parse(init.body || "{}"); const id = "m_" + String(++n).padStart(26, "a"); const dir = path.join(root, id); fs.mkdirSync(path.join(dir, "home", "workspace"), { recursive: true }); fs.mkdirSync(path.join(dir, "tmp"), { recursive: true });
      machines.set(id, dir); ops.set("op_" + n, { machineId: id, polls: 0 }); const op = { id: "op_" + n, machineId: id, type: "create", state: "queued", error: null, name: body.name }; idem.set(ik, JSON.stringify(op)); return reply(op, 202);
    }
    let m: RegExpExecArray | null;
    if ((m = /^\/v1\/operations\/([^/]+)$/.exec(u.pathname))) { const o = ops.get(m[1]); if (!o) return err(404, "not_found"); o.polls++; return reply({ id: m[1], machineId: o.machineId, type: "create", state: o.polls >= 2 ? "succeeded" : "running", error: null }); }
    if ((m = /^\/v1\/machines\/([^/]+)(\/.*)?$/.exec(u.pathname))) {
      const dir = machines.get(m[1]); const sub = m[2] ?? "";
      if (!dir) return err(404, "not_found");
      if (!sub && method === "DELETE") { if (init.headers?.["X-Confirm-Delete"] !== m[1]) return err(409, "delete_confirmation_required"); machines.delete(m[1]); return new Response(null, { status: 202 }); }
      if (sub === "/exec" && method === "POST") {
        const b = JSON.parse(init.body || "{}"); if (typeof b.cmd !== "string") return err(400, "bad_request");
        const cwd = b.cwd ? map(dir, b.cwd) : path.join(dir, "home"); fs.mkdirSync(cwd, { recursive: true });
        try { const out = execFileSync("bash", ["-c", map(dir, b.cmd)], { cwd, encoding: "utf8", timeout: 20000, stdio: ["ignore", "pipe", "pipe"], maxBuffer: 30 * 1024 * 1024 }); return reply({ stdout: out, stderr: "", exitCode: 0, timedOut: false, truncated: false }); }
        catch (e: any) { return reply({ stdout: String(e.stdout ?? ""), stderr: String(e.stderr ?? ""), exitCode: e.status ?? 1, timedOut: false, truncated: false }); }
      }
      if (sub === "/files" && method === "PUT") { const p = map(dir, u.searchParams.get("path") ?? ""); if (u.searchParams.get("parents") === "true") fs.mkdirSync(path.dirname(p), { recursive: true }); const buf = Buffer.from(init.body as any); const existed = fs.existsSync(p); fs.writeFileSync(p, buf); return reply({ path: u.searchParams.get("path"), size: buf.length, sha256: "x", mode: "0644", created: !existed }, existed ? 200 : 201); }
      if (sub === "/files/content" && method === "GET") { const p = map(dir, u.searchParams.get("path") ?? ""); if (!fs.existsSync(p) || fs.statSync(p).isDirectory()) return err(404, "not_found"); return new Response(fs.readFileSync(p), { status: 200, headers: { "content-type": "application/octet-stream" } }); }
    }
    return err(404, "not_found", "unknown " + u.pathname);
  }) as unknown as typeof fetch;
  return { fetchImpl, root, sessions: machines, seen, stop() { fs.rmSync(root, { recursive: true, force: true }); } };
}


/** Do what a user does in the app: add the InstaBox key, press Start VM. Works with a cookie + csrf from any login flow. */
export async function provisionVm(base: string, cookie: string, csrf: string): Promise<string> {
  const H = { cookie, "x-csrf-token": csrf, "content-type": "application/json" };
  const add = await fetch(`${base}/api/providers`, { method: "POST", headers: H, body: JSON.stringify({ id: "instabox", key: KEY }) }); if (add.status !== 200) throw new Error("add key failed: " + (await add.text()));
  const st = await fetch(`${base}/api/vm/start`, { method: "POST", headers: H, body: "{}" }); if (st.status !== 200) throw new Error("start vm failed: " + (await st.text()));
  return ((await st.json()) as any).machineId;
}

/** For older end-to-end suites: give the user behind an access token a running VM, using the same vault + manager the routes use. */
export async function giveVm(app: any, userId: string): Promise<void> {
  app.deps.vault.put(userId, { id: "instabox", label: "InstaBox", hosts: ["api.instabox.sh"], auth: { type: "header", name: "X-API-Key" } }, KEY);
  await app.vm.start(userId);
}
/** Find the user id behind an MCP access token (the suites do not otherwise know it). */
export function userOfToken(app: any, accessToken: string): string {
  const rec = app.store.getAccessToken(app.store.hashToken(accessToken)); const id = rec?.userId; if (!id) throw new Error("cannot resolve user for token"); return id;
}
/** One call for a suite that just got an access token: the user behind it now has a running VM. */
export async function vmForToken(app: any, accessToken: string): Promise<string> { const id = userOfToken(app, accessToken); await giveVm(app, id); return id; }
