/**
 * Remote mirror for the auth database, so MCP connections survive restarts and
 * redeploys on hosts with no persistent disk (e.g. Render's free plan).
 *
 * Remote copy = auth-store.json wrapped in AES-256-GCM with a key derived from
 * UCA_SESSION_SECRET. The secret never leaves the host, so the copy is useless without it.
 *
 * Safety rules:
 *  - A remote copy that cannot be read (wrong secret, network error) is NEVER overwritten
 *    by a fresh empty database. We keep running locally and stop pushing.
 *  - A mirror failure never stops the server.
 *  - Pushes are debounced, serialised, and flushed on shutdown.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const MAGIC = "ucamirror1";
const SALT = "uca-mirror-v1";
const scrypt = (secret: string) => crypto.scryptSync(secret, SALT, 32, { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });

export interface MirrorOptions {
  /** `owner/repo` of a PRIVATE repo used only for state. */
  repo: string;
  token: string;
  secret: string;
  path?: string;
  branch?: string;
  apiBase?: string;
  fetchImpl?: typeof fetch;
  debounceMs?: number;
  log?: (msg: string) => void;
}

export function sealBlob(plain: string, secret: string): string {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", scrypt(secret), iv);
  const ct = Buffer.concat([c.update(plain, "utf8"), c.final()]);
  return [MAGIC, iv.toString("base64url"), c.getAuthTag().toString("base64url"), ct.toString("base64url")].join(".");
}

/** Returns the plaintext, or null if the blob is malformed or the secret is wrong. */
export function openBlob(blob: string, secret: string): string | null {
  try {
    const p = blob.trim().split(".");
    if (p.length !== 4 || p[0] !== MAGIC) return null;
    const d = crypto.createDecipheriv("aes-256-gcm", scrypt(secret), Buffer.from(p[1]!, "base64url"));
    d.setAuthTag(Buffer.from(p[2]!, "base64url"));
    return Buffer.concat([d.update(Buffer.from(p[3]!, "base64url")), d.final()]).toString("utf8");
  } catch {
    return null;
  }
}

export type RestoreResult = "restored" | "none" | "kept-local" | "undecryptable" | "unreachable";

export class AuthMirror {
  private readonly o: MirrorOptions;
  private sha: string | undefined;
  private timer: NodeJS.Timeout | null = null;
  private inflight: Promise<void> = Promise.resolve();
  private dirty = false;
  private blocked = false;
  private reader: (() => string | null) | null = null;
  lastError: string | null = null;
  lastPushAt = 0;

  constructor(o: MirrorOptions) {
    if (!/^[\w.-]+\/[\w.-]+$/.test(o.repo)) throw new Error("UCA_MIRROR_REPO must look like owner/repo");
    if (!o.secret || o.secret.length < 16) throw new Error("A mirror needs UCA_SESSION_SECRET (16+ chars) so the remote copy is encrypted");
    this.o = o;
  }

  private get f(): typeof fetch { return this.o.fetchImpl ?? fetch; }
  private get url(): string {
    const base = (this.o.apiBase ?? "https://api.github.com").replace(/\/$/, "");
    return `${base}/repos/${this.o.repo}/contents/${(this.o.path ?? "auth-store.enc").replace(/^\//, "")}`;
  }
  private get ref(): string { return this.o.branch ? `?ref=${encodeURIComponent(this.o.branch)}` : ""; }
  private headers(): Record<string, string> {
    return { authorization: `Bearer ${this.o.token}`, accept: "application/vnd.github+json", "x-github-api-version": "2022-11-28", "user-agent": "universal-code-agent-mirror", "content-type": "application/json" };
  }
  private log(m: string): void { (this.o.log ?? ((s: string) => console.error(s)))("[mirror] " + m); }

  /** Pull the remote copy into `localFile`. Only when no usable local file exists. */
  async restoreTo(localFile: string): Promise<RestoreResult> {
    if (fs.existsSync(localFile) && fs.statSync(localFile).size > 2) return "kept-local";
    let r: Response;
    try {
      r = await this.f(this.url + this.ref, { headers: this.headers() });
    } catch {
      this.blocked = true; this.lastError = "unreachable";
      this.log("restore failed (network). Starting empty and NOT overwriting the remote.");
      return "unreachable";
    }
    if (r.status === 404) return "none";
    if (!r.ok) {
      this.blocked = true; this.lastError = `restore http ${r.status}`;
      this.log(`restore failed (HTTP ${r.status}). Starting empty and NOT overwriting the remote.`);
      return "unreachable";
    }
    const j: any = await r.json();
    this.sha = j.sha;
    const plain = openBlob(Buffer.from(String(j.content ?? ""), "base64").toString("utf8"), this.o.secret);
    if (plain === null) {
      this.blocked = true; this.lastError = "undecryptable";
      this.log("remote copy cannot be decrypted (UCA_SESSION_SECRET changed?). Running without it and NOT overwriting it.");
      return "undecryptable";
    }
    fs.mkdirSync(path.dirname(localFile), { recursive: true, mode: 0o700 });
    fs.writeFileSync(localFile, plain, { mode: 0o600 });
    this.log("restored auth state from the remote mirror");
    return "restored";
  }

  /** How to read the current local file; called once after the store exists. */
  attach(read: () => string | null): void { this.reader = read; }

  /** Call after every store write. Cheap: schedules a debounced push. */
  markDirty(): void {
    this.dirty = true;
    if (this.timer || this.blocked) return;
    this.timer = setTimeout(() => { this.timer = null; void this.flush(); }, this.o.debounceMs ?? 2000);
    this.timer.unref?.();
  }

  /** Push now (also on shutdown). Never throws. */
  flush(): Promise<void> {
    if (this.timer) { clearTimeout(this.timer); this.timer = null; }
    this.inflight = this.inflight.then(() => this.pushOnce()).catch(() => undefined);
    return this.inflight;
  }

  private async pushOnce(): Promise<void> {
    if (!this.dirty || this.blocked || !this.reader) return;
    const plain = this.reader();
    if (plain === null) return;
    this.dirty = false;
    const blob = Buffer.from(sealBlob(plain, this.o.secret), "utf8").toString("base64");
    const body = () => JSON.stringify({ message: "state", content: blob, ...(this.sha ? { sha: this.sha } : {}), ...(this.o.branch ? { branch: this.o.branch } : {}) });
    try {
      for (let attempt = 0; attempt < 3; attempt++) {
        const r = await this.f(this.url, { method: "PUT", headers: this.headers(), body: body() });
        if (r.ok) { const j: any = await r.json(); this.sha = j?.content?.sha ?? this.sha; this.lastPushAt = Date.now(); this.lastError = null; return; }
        if (r.status === 409 || r.status === 422) {
          const g = await this.f(this.url + this.ref, { headers: this.headers() });
          if (g.ok) { this.sha = ((await g.json()) as any).sha; continue; }
          if (g.status === 404) { this.sha = undefined; continue; }
        }
        this.lastError = `push http ${r.status}`;
        this.log(`push failed (HTTP ${r.status}); will retry on the next change`);
        this.dirty = true;
        return;
      }
      this.dirty = true;
    } catch {
      this.lastError = "push network error";
      this.dirty = true;
      this.log("push failed (network); will retry on the next change");
    }
  }

  status(): { enabled: true; repo: string; lastPushAt: number; lastError: string | null; blocked: boolean } {
    return { enabled: true, repo: this.o.repo, lastPushAt: this.lastPushAt, lastError: this.lastError, blocked: this.blocked };
  }
}

/** Build a mirror from environment variables, or null when not configured. */
export function mirrorFromEnv(env: NodeJS.ProcessEnv = process.env, fetchImpl?: typeof fetch): AuthMirror | null {
  const repo = env.UCA_MIRROR_REPO, token = env.UCA_MIRROR_TOKEN;
  if (!repo || !token) return null;
  return new AuthMirror({ repo, token, secret: env.UCA_SESSION_SECRET ?? "", fetchImpl, branch: env.UCA_MIRROR_BRANCH || undefined });
}
