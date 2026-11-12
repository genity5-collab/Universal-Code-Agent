/**
 * In-memory provider-key vault.
 *
 * Design goals (each is enforced by a test):
 *  - Keys exist ONLY in this process's memory. They are never written to disk, logged, audited or returned.
 *  - The AI never sees a key. It gets an opaque handle ("provider:flyio") and can only ask the server to make
 *    an HTTPS call; the server attaches the key itself.
 *  - A key is pinned to the hostnames the human approved when pasting it, so a prompt-injected AI cannot make
 *    the server send the key to an attacker's URL.
 *  - Responses are scrubbed of the exact key value (and common encodings of it) before the AI sees them.
 *  - Keys vanish on logout, "revoke all", per-provider removal, idle expiry, or a server restart.
 */
import crypto from "node:crypto";

export interface ProviderSpec {
  /** lowercase id, e.g. "flyio" */
  id: string;
  label: string;
  /** exact hostnames the key may be sent to (no wildcards by default) */
  hosts: string[];
  /** how the key is attached */
  auth: { type: "bearer" } | { type: "header"; name: string } | { type: "basic" };
  docsUrl?: string;
  /** a cheap authenticated GET used to verify the key right after pasting */
  verify?: { url: string };
  recommended?: boolean;
  note?: string;
}

/** Recommended presets. These are starting points; the user can still add any provider by hand. */
export const PRESETS: ProviderSpec[] = [
  { id: "flyio", label: "Fly.io Machines", hosts: ["api.machines.dev", "api.fly.io"], auth: { type: "bearer" }, docsUrl: "https://fly.io/docs/machines/api/", verify: { url: "https://api.machines.dev/v1/apps?org_slug=personal" }, recommended: true, note: "Real Linux microVMs." },
  { id: "digitalocean", label: "DigitalOcean Droplets", hosts: ["api.digitalocean.com"], auth: { type: "bearer" }, docsUrl: "https://docs.digitalocean.com/reference/api/", verify: { url: "https://api.digitalocean.com/v2/account" }, recommended: true, note: "Full Linux servers." },
  { id: "hetzner", label: "Hetzner Cloud", hosts: ["api.hetzner.cloud"], auth: { type: "bearer" }, docsUrl: "https://docs.hetzner.cloud/", verify: { url: "https://api.hetzner.cloud/v1/servers?per_page=1" }, recommended: true, note: "Cheap Linux servers." },
  { id: "render", label: "Render", hosts: ["api.render.com"], auth: { type: "bearer" }, docsUrl: "https://api-docs.render.com/", verify: { url: "https://api.render.com/v1/owners?limit=1" }, recommended: true, note: "Services and workers." },
  { id: "freestyle", label: "Freestyle VMs", hosts: ["api.freestyle.sh"], auth: { type: "bearer" }, docsUrl: "https://www.freestyle.sh/docs/llms.txt", recommended: true, note: "Agent-oriented VMs and snapshots." },
];

export interface StoredKey { spec: ProviderSpec; addedAt: number; lastUsed: number; fingerprint: string; }
interface Entry extends StoredKey { secret: string; }

const ID_RE = /^[a-z0-9][a-z0-9-]{1,31}$/;
const HOST_RE = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/;
const DENY_HOSTS = /^(localhost|.*\.local|.*\.internal|metadata\.google\.internal)$/;

export class VaultError extends Error {}

export function validateHost(h: string): string {
  const host = String(h).trim().toLowerCase();
  if (!HOST_RE.test(host) || DENY_HOSTS.test(host) || /^\d+\.\d+\.\d+\.\d+$/.test(host)) throw new VaultError(`Host not allowed: ${host.slice(0, 80)}. Use a public DNS hostname (no IPs, no localhost).`);
  return host;
}

export class ProviderVault {
  private readonly keys = new Map<string, Map<string, Entry>>();
  constructor(private readonly opts: { idleMs?: number; maxPerUser?: number; now?: () => number } = {}) {}
  private now(): number { return this.opts.now ? this.opts.now() : Date.now(); }

  /** Store a key. Replaces any previous key for the same provider. The secret is never returned. */
  put(userId: string, spec: ProviderSpec, secret: string): StoredKey {
    if (!ID_RE.test(spec.id)) throw new VaultError("Provider id must be 2-32 chars of a-z, 0-9 or '-'.");
    const key = String(secret ?? "").trim();
    if (key.length < 8 || key.length > 4096 || /\s/.test(key)) throw new VaultError("That does not look like an API key (8-4096 chars, no spaces).");
    const hosts = [...new Set(spec.hosts.map(validateHost))];
    if (!hosts.length || hosts.length > 8) throw new VaultError("Provide 1 to 8 hostnames the key may be sent to.");
    const m = this.keys.get(userId) ?? new Map<string, Entry>();
    if (!m.has(spec.id) && m.size >= (this.opts.maxPerUser ?? 10)) throw new VaultError("Too many provider keys. Remove one first.");
    const t = this.now();
    const e: Entry = { spec: { ...spec, hosts }, secret: key, addedAt: t, lastUsed: t, fingerprint: crypto.createHash("sha256").update(key).digest("hex").slice(0, 6) };
    m.set(spec.id, e); this.keys.set(userId, m);
    return this.pub(e);
  }

  private pub(e: Entry): StoredKey { return { spec: e.spec, addedAt: e.addedAt, lastUsed: e.lastUsed, fingerprint: e.fingerprint }; }
  private live(userId: string, id: string): Entry | undefined {
    const e = this.keys.get(userId)?.get(id); if (!e) return undefined;
    if (this.now() - e.lastUsed > (this.opts.idleMs ?? 2 * 3600_000)) { this.remove(userId, id); return undefined; }
    return e;
  }
  list(userId: string): StoredKey[] { return [...(this.keys.get(userId)?.keys() ?? [])].map((id) => this.live(userId, id)).filter((x): x is Entry => !!x).map((e) => this.pub(e)); }
  has(userId: string, id: string): boolean { return !!this.live(userId, id); }
  remove(userId: string, id: string): boolean { const m = this.keys.get(userId); const r = !!m?.delete(id); if (m && !m.size) this.keys.delete(userId); return r; }
  clearUser(userId: string): number { const n = this.keys.get(userId)?.size ?? 0; this.keys.delete(userId); return n; }
  clearAll(): void { this.keys.clear(); }

  /**
   * Perform an HTTPS request to an approved host with the stored key attached. The key never leaves this function
   * except in the Authorization header of the outgoing request, and the response is scrubbed before returning.
   */
  async request(userId: string, id: string, req: { method?: string; url: string; headers?: Record<string, string>; body?: unknown; timeoutMs?: number }, fetchImpl: typeof fetch = fetch): Promise<{ status: number; headers: Record<string, string>; body: string; truncated: boolean }> {
    const e = this.live(userId, id);
    if (!e) throw new VaultError(`No key for provider "${id}" in this session. Ask the user to add it in the app (Cloud tab, then Provider keys).`);
    let u: URL; try { u = new URL(req.url); } catch { throw new VaultError("Invalid URL."); }
    if (u.protocol !== "https:") throw new VaultError("Only https:// URLs are allowed.");
    if (u.username || u.password) throw new VaultError("Credentials in the URL are not allowed.");
    if (!e.spec.hosts.includes(u.hostname.toLowerCase())) throw new VaultError(`Host ${u.hostname} is not approved for ${id}. Approved: ${e.spec.hosts.join(", ")}.`);
    const method = (req.method ?? "GET").toUpperCase();
    if (!["GET", "POST", "PUT", "PATCH", "DELETE"].includes(method)) throw new VaultError("Method not allowed.");
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries(req.headers ?? {})) {
      const lk = k.toLowerCase();
      if (["authorization", "proxy-authorization", "cookie", "host", "x-api-key", "api-key"].includes(lk) || (e.spec.auth.type === "header" && lk === e.spec.auth.name.toLowerCase())) continue; // the AI cannot set auth itself
      if (/[\r\n]/.test(k + v)) throw new VaultError("Invalid header.");
      headers[k] = String(v).slice(0, 2000);
    }
    const a = e.spec.auth;
    if (a.type === "bearer") headers["Authorization"] = `Bearer ${e.secret}`;
    else if (a.type === "header") headers[a.name] = e.secret;
    else headers["Authorization"] = `Basic ${Buffer.from(e.secret.includes(":") ? e.secret : e.secret + ":").toString("base64")}`;
    let body: string | undefined;
    if (req.body !== undefined && method !== "GET") { body = typeof req.body === "string" ? req.body : JSON.stringify(req.body); if (body.length > 1_000_000) throw new VaultError("Request body too large."); if (typeof req.body !== "string" && !Object.keys(headers).some((h) => h.toLowerCase() === "content-type")) headers["Content-Type"] = "application/json"; }
    const ctl = new AbortController(); const t = setTimeout(() => ctl.abort(), Math.min(req.timeoutMs ?? 30_000, 60_000));
    e.lastUsed = this.now();
    try {
      // redirect:"manual" so a redirect can never carry the key to a different host
      const r = await fetchImpl(u.toString(), { method, headers, body, redirect: "manual", signal: ctl.signal });
      const raw = await r.text(); const cap = 200_000; const truncated = raw.length > cap;
      const outHeaders: Record<string, string> = {}; r.headers.forEach((v, k) => { if (!/^(set-cookie|authorization)$/i.test(k)) outHeaders[k] = this.scrub(e.secret, v); });
      return { status: r.status, headers: outHeaders, body: this.scrub(e.secret, truncated ? raw.slice(0, cap) : raw), truncated };
    } catch (err: any) {
      throw new VaultError(this.scrub(e.secret, err?.name === "AbortError" ? "Request timed out." : `Request failed: ${err?.message ?? err}`));
    } finally { clearTimeout(t); }
  }

  /** Remove the exact key value and its common encodings from any text. */
  scrub(secret: string, text: string): string {
    if (!secret) return text;
    const forms = new Set([secret, encodeURIComponent(secret), Buffer.from(secret).toString("base64"), Buffer.from(secret + ":").toString("base64"), JSON.stringify(secret).slice(1, -1), secret.split("").reverse().join("")]);
    let out = text; for (const f of forms) if (f.length >= 6) out = out.split(f).join("[REDACTED_KEY]");
    return out;
  }
  /** Scrub every key a user holds from arbitrary text (used on all tool output as a last line of defence). */
  scrubAll(userId: string, text: string): string {
    let out = text; for (const e of this.keys.get(userId)?.values() ?? []) out = this.scrub(e.secret, out); return out;
  }
}
