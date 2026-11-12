/**
 * InstaBox backend (https://instabox.sh). Contract read from the official OpenAPI (https://api.instabox.sh/v1/openapi.json):
 *   POST   /v1/machines                 (Idempotency-Key required) -> 202 Operation {id, machineId, state}
 *   GET    /v1/operations/{id}?wait=... -> Operation; terminal states: succeeded | failed
 *   POST   /v1/machines/{id}/exec       {cmd|argv, cwd, envs, stdin, timeoutSeconds<=600} -> {stdout, stderr, exitCode, timedOut, truncated}
 *   PUT    /v1/machines/{id}/files?path=&parents=true     raw bytes -> {path, size, sha256, created}
 *   GET    /v1/machines/{id}/files/content?path=          raw bytes
 *   DELETE /v1/machines/{id}            (Idempotency-Key + X-Confirm-Delete: <id or name>) -> 202
 * The API key (ibk_...) lives only in the ProviderVault (provider id "instabox"). Every request goes through vault.request, so the
 * key is never held here, never on disk and never returned to the AI. The vault pins the host and refuses redirects.
 */
import crypto from "node:crypto";
import type { ProviderVault } from "../providers/vault.js";

export const INSTABOX_ID = "instabox";
export const INSTABOX_HOST = "api.instabox.sh";
export const INSTABOX_SPEC = { id: INSTABOX_ID, label: "InstaBox", hosts: [INSTABOX_HOST], auth: { type: "header" as const, name: "X-API-Key" }, docs: ["https://instabox.sh/docs/api-reference/introduction.md"] };

export class NoVmError extends Error {
  constructor(msg = "No VM is attached. The AI cannot work without one. Ask the user to open the app, go to Workspace, add their InstaBox key and press Start VM, then retry.") { super(msg); }
}
export interface ExecResult { stdout: string; stderr: string; exitCode: number | null; timedOut?: boolean; truncated?: boolean }
interface Session { machineId: string; startedAt: number; attached?: boolean }

export class InstaBoxManager {
  private sessions = new Map<string, Session>();
  private starting = new Set<string>();
  constructor(private vault: ProviderVault, private fetchImpl: typeof fetch = fetch, private baseUrl = `https://${INSTABOX_HOST}`, private opts: { pollMs?: number; startTimeoutMs?: number } = {}) {}

  hasKey(userId: string): boolean { return this.vault.has(userId, INSTABOX_ID); }
  status(userId: string): { hasKey: boolean; running: boolean; starting: boolean; machineId?: string; attached?: boolean } {
    const hasKey = this.hasKey(userId); const s = this.sessions.get(userId);
    if (s && !hasKey) { this.sessions.delete(userId); return { hasKey, running: false, starting: false }; }
    return { hasKey, running: !!s, starting: this.starting.has(userId), machineId: s?.machineId, attached: s?.attached };
  }
  /** The single gate every local-disk tool passes through. Throws NoVmError unless this user has a live machine. */
  require(userId: string): string {
    const st = this.status(userId);
    if (!st.hasKey) throw new NoVmError("No InstaBox key. The AI cannot work without a VM. Ask the user to open the app's Workspace tab, add their InstaBox key and press Start VM.");
    if (!st.running || !st.machineId) throw new NoVmError(st.starting ? "The VM is still starting. Wait a few seconds and retry." : undefined);
    return st.machineId;
  }

  private async call(userId: string, method: string, path: string, o: { body?: unknown; headers?: Record<string, string>; timeoutMs?: number } = {}) {
    return this.vault.request(userId, INSTABOX_ID, { method, url: `${this.baseUrl}${path}`, body: o.body, headers: o.headers, timeoutMs: o.timeoutMs }, this.fetchImpl);
  }
  private fail(r: { status: number; body: string }, what: string): never {
    let code = "", msg = r.body.slice(0, 240);
    try { const j = JSON.parse(r.body); code = j?.error?.code ?? ""; msg = j?.error?.message ?? msg; } catch { /* keep raw */ }
    if (r.status === 401 || /_key$/.test(code)) throw new Error("InstaBox rejected the key. Ask the user to add it again (Workspace tab).");
    if (r.status === 403) throw new Error(`InstaBox: the key lacks a permission needed to ${what} (${code || "forbidden"}). Create a key with machines:read, machines:write and machines:delete.`);
    if (r.status === 402 || code === "quota_exceeded" || r.status === 429) throw new Error(`InstaBox limit reached while trying to ${what}: ${msg}`);
    if (r.status === 503 || code === "no_capacity") throw new Error(`InstaBox has no capacity right now (${what}). Try again in a minute.`);
    if (r.status === 404 || code === "not_found") throw new NoVmError("The VM no longer exists. Ask the user to press Start VM again.");
    if (code === "machine_not_running" || r.status === 409) throw new NoVmError(`The VM is not running (${code || "conflict"}). Ask the user to press Start VM.`);
    throw new Error(`InstaBox could not ${what} (HTTP ${r.status}${code ? " " + code : ""}): ${msg}`);
  }

  /** Create a machine and wait until it is running. One machine per user: an existing one is reused. */
  async start(userId: string): Promise<{ machineId: string }> {
    if (!this.hasKey(userId)) throw new NoVmError("Add your InstaBox key first.");
    const have = this.sessions.get(userId); if (have) return { machineId: have.machineId };
    if (this.starting.has(userId)) throw new Error("The VM is already starting.");
    this.starting.add(userId);
    try {
      const name = "uca-" + crypto.randomBytes(5).toString("hex");
      const r = await this.call(userId, "POST", "/v1/machines", { body: { name }, headers: { "Idempotency-Key": crypto.randomUUID() }, timeoutMs: 30_000 });
      if (r.status !== 202 && r.status !== 200 && r.status !== 201) this.fail(r, "create a VM");
      let op: any; try { op = JSON.parse(r.body); } catch { throw new Error("InstaBox returned an unreadable response."); }
      if (!op?.id || !op?.machineId) throw new Error("InstaBox did not return an operation.");
      const deadline = Date.now() + (this.opts.startTimeoutMs ?? 120_000);
      while (op.state !== "succeeded") {
        if (op.state === "failed") throw new Error(`InstaBox could not start the VM: ${op.error?.message ?? op.error?.code ?? "failed"}`);
        if (Date.now() > deadline) throw new Error("The VM took too long to start. Try again.");
        await new Promise((res) => setTimeout(res, this.opts.pollMs ?? 1500));
        const p = await this.call(userId, "GET", `/v1/operations/${encodeURIComponent(op.id)}`); if (p.status !== 200) this.fail(p, "check the VM");
        op = JSON.parse(p.body);
      }
      this.sessions.set(userId, { machineId: op.machineId, startedAt: Date.now() });
      return { machineId: op.machineId };
    } finally { this.starting.delete(userId); }
  }
  /** List the machines this key can see (read-only). */
  async listMachines(userId: string): Promise<{ id: string; name: string; state: string }[]> {
    if (!this.hasKey(userId)) throw new NoVmError("Add your InstaBox key first.");
    const r = await this.call(userId, "GET", "/v1/machines?limit=100"); if (r.status !== 200) this.fail(r, "list your machines");
    let j: any; try { j = JSON.parse(r.body); } catch { throw new Error("InstaBox returned an unreadable response."); }
    const arr: any[] = Array.isArray(j) ? j : Array.isArray(j?.machines) ? j.machines : Array.isArray(j?.items) ? j.items : Array.isArray(j?.data) ? j.data : [];
    return arr.filter((m) => m && typeof m.id === "string").map((m) => ({ id: String(m.id).slice(0, 80), name: String(m.name ?? m.id).slice(0, 80), state: String(m.state ?? m.status ?? "unknown").slice(0, 30) }));
  }
  /** Use a machine that already exists. Ownership is proven by the key itself: the id must be in the key's own list. Stop only disconnects it. */
  async attach(userId: string, machineId: string): Promise<{ machineId: string }> {
    const id = String(machineId ?? ""); if (!/^[A-Za-z0-9._-]{1,80}$/.test(id)) throw new Error("Invalid machine id.");
    const list = await this.listMachines(userId);
    if (!list.some((m) => m.id === id)) throw new Error("That machine is not in your InstaBox account.");
    this.sessions.set(userId, { machineId: id, startedAt: Date.now(), attached: true });
    return { machineId: id };
  }
  async stop(userId: string): Promise<boolean> {
    const s = this.sessions.get(userId); this.sessions.delete(userId); if (!s) return false;
    if (s.attached) return true; // a machine you brought is only disconnected, never deleted
    try { await this.call(userId, "DELETE", `/v1/machines/${encodeURIComponent(s.machineId)}`, { headers: { "Idempotency-Key": crypto.randomUUID(), "X-Confirm-Delete": s.machineId } }); } catch { /* it also auto-pauses/expires on InstaBox's side */ }
    return true;
  }
  forget(userId: string): void { this.sessions.delete(userId); }

  /** POST /v1/machines/{id}/<sub> with a JSON body; returns the response body text. */
  async rawCall(userId: string, method: string, sub: string, body: unknown, timeoutMs = 60_000): Promise<string> {
    const id = this.require(userId);
    const r = await this.call(userId, method, `/v1/machines/${encodeURIComponent(id)}/${sub}`, { body, timeoutMs });
    if (r.status < 200 || r.status >= 300) { try { this.fail(r, "use the desktop"); } catch (e) { if (e instanceof NoVmError) this.sessions.delete(userId); throw e; } }
    return r.body;
  }

  async exec(userId: string, command: string, opts: { timeoutSec?: number; cwd?: string } = {}): Promise<ExecResult> {
    const id = this.require(userId); const timeout = Math.min(Math.max(1, opts.timeoutSec ?? 60), 600);
    const r = await this.call(userId, "POST", `/v1/machines/${encodeURIComponent(id)}/exec`, { body: { cmd: command, cwd: opts.cwd, timeoutSeconds: timeout }, timeoutMs: Math.min(timeout * 1000 + 5000, 60_000) });
    if (r.status !== 200) { try { this.fail(r, "run the command"); } catch (e) { if (e instanceof NoVmError) this.sessions.delete(userId); throw e; } }
    let j: any; try { j = JSON.parse(r.body); } catch { throw new Error("InstaBox returned an unreadable response."); }
    return { stdout: String(j.stdout ?? ""), stderr: String(j.stderr ?? ""), exitCode: typeof j.exitCode === "number" ? j.exitCode : null, timedOut: !!j.timedOut, truncated: !!j.truncated };
  }

  /** Write bytes with a real binary upload (no base64 through the shell). Creates parent folders. */
  async writeFile(userId: string, remotePath: string, data: Buffer): Promise<void> {
    if (data.length > 25 * 1024 * 1024) throw new Error("File too large for a single write (max 25 MB).");
    const id = this.require(userId);
    const r = await this.vault.requestRaw(userId, INSTABOX_ID, { method: "PUT", url: `${this.baseUrl}/v1/machines/${encodeURIComponent(id)}/files?path=${encodeURIComponent(remotePath)}&parents=true`, rawBody: data, headers: { "content-type": "application/octet-stream" }, timeoutMs: 60_000 }, this.fetchImpl);
    if (r.status !== 200 && r.status !== 201) this.fail({ status: r.status, body: r.body.toString("utf8") }, "write the file");
  }
  async readFile(userId: string, remotePath: string, maxBytes = 25 * 1024 * 1024): Promise<Buffer> {
    const id = this.require(userId);
    const r = await this.vault.requestRaw(userId, INSTABOX_ID, { method: "GET", url: `${this.baseUrl}/v1/machines/${encodeURIComponent(id)}/files/content?path=${encodeURIComponent(remotePath)}`, timeoutMs: 60_000, maxBytes }, this.fetchImpl);
    if (r.status === 404) throw new Error(`File not found in the VM: ${remotePath}`);
    if (r.status !== 200 && r.status !== 206) this.fail({ status: r.status, body: r.body.toString("utf8") }, "read the file");
    if (r.truncated) throw new Error(`File is over the ${maxBytes} byte read limit.`);
    return r.body;
  }
}

/** POSIX single-quote escaping. Every value interpolated into a VM shell command goes through this. */
export function shq(s: string): string { return `'${String(s).replace(/'/g, `'\\''`)}'`; }
