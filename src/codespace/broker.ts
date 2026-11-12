import crypto from "node:crypto";
import { redact } from "../util/paths.js";

/**
 * Codespace job broker.
 *
 * GitHub's public REST API cannot run commands inside a Codespace, and forwarded ports need
 * browser-style auth. So instead of connecting IN, a tiny agent running inside the Codespace
 * connects OUT to this server (long-poll over HTTPS), claims jobs, runs them on the Codespace's
 * real Linux VM and posts the result back.
 *
 * Security model:
 *  - A pairing token is minted per (user, codespace). Only its SHA-256 is kept.
 *  - A token only ever sees jobs for its own user.
 *  - Jobs are plain JSON ({op, args}); the agent implements a fixed set of ops, no eval.
 *  - Results are redacted before they leave the broker.
 */

export type AgentOp =
  | "exec" | "read_file" | "write_file" | "list_dir" | "stat" | "delete" | "mkdir" | "search" | "info";

export interface AgentJob { id: string; op: AgentOp; args: Record<string, unknown>; }
export interface AgentJobResult { ok: boolean; data?: unknown; error?: string; }

interface Pairing {
  userId: string; codespace: string; tokenHash: string;
  createdAt: number; expiresAt: number; lastSeen: number;
  agentInfo?: Record<string, unknown>;
}
interface PendingJob {
  job: AgentJob; pairingKey: string; claimed: boolean; createdAt: number;
  timeout: NodeJS.Timeout; resolve: (r: AgentJobResult) => void;
}
interface Waiter { resolve: (j: AgentJob | null) => void; timer: NodeJS.Timeout; }

const sha = (s: string) => crypto.createHash("sha256").update(s).digest("hex");
const keyOf = (userId: string, codespace: string) => `${userId}\0${codespace}`;

export interface BrokerOptions {
  now?: () => number;
  pairingTtlMs?: number;
  onlineWindowMs?: number;
  maxQueuePerAgent?: number;
}

export class CodespaceBroker {
  private pairings = new Map<string, Pairing>();
  private byToken = new Map<string, string>();
  private queues = new Map<string, PendingJob[]>();
  private inflight = new Map<string, PendingJob>();
  private waiters = new Map<string, Waiter[]>();
  private claims = new Map<string, { userId: string; codespace: string; expiresAt: number }>();
  private now: () => number;
  private ttl: number;
  private onlineWindow: number;
  private maxQueue: number;

  constructor(opts: BrokerOptions = {}) {
    this.now = opts.now ?? Date.now;
    this.ttl = opts.pairingTtlMs ?? 7 * 24 * 3600_000;
    this.onlineWindow = opts.onlineWindowMs ?? 45_000;
    this.maxQueue = opts.maxQueuePerAgent ?? 50;
  }

  /** Mint (or rotate) the pairing token for a user's codespace. The raw token is returned once. */
  pair(userId: string, codespace: string): { token: string; expiresAt: number } {
    if (!/^[A-Za-z0-9._-]{1,100}$/.test(codespace)) throw new Error("Invalid codespace name");
    const key = keyOf(userId, codespace);
    const old = this.pairings.get(key);
    if (old) this.byToken.delete(old.tokenHash);
    const token = "uca_" + crypto.randomBytes(32).toString("base64url");
    const t = this.now();
    const p: Pairing = { userId, codespace, tokenHash: sha(token), createdAt: t, expiresAt: t + this.ttl, lastSeen: 0 };
    this.pairings.set(key, p);
    this.byToken.set(p.tokenHash, key);
    return { token, expiresAt: p.expiresAt };
  }

  /**
   * One-time claim code (10 min). The Codespace bootstrap exchanges it for the real pairing token,
   * so nothing long-lived is ever written into a repo or a command line.
   */
  createClaim(userId: string, codespace: string): { claim: string; expiresAt: number } {
    if (!/^[A-Za-z0-9._-]{1,100}$/.test(codespace)) throw new Error("Invalid codespace name");
    const claim = "claim_" + crypto.randomBytes(18).toString("base64url");
    const expiresAt = this.now() + 10 * 60_000;
    this.claims.set(sha(claim), { userId, codespace, expiresAt });
    for (const [k, v] of this.claims) if (v.expiresAt < this.now()) this.claims.delete(k);
    return { claim, expiresAt };
  }

  /** Exchange a claim for a fresh pairing token. Single use. */
  redeemClaim(claim: string): { token: string; codespace: string; userId: string } | null {
    const h = sha(String(claim ?? ""));
    const c = this.claims.get(h);
    this.claims.delete(h);
    if (!c || c.expiresAt < this.now()) return null;
    const { token } = this.pair(c.userId, c.codespace);
    return { token, codespace: c.codespace, userId: c.userId };
  }

  unpair(userId: string, codespace: string): boolean {
    const key = keyOf(userId, codespace);
    const p = this.pairings.get(key);
    if (!p) return false;
    this.byToken.delete(p.tokenHash);
    this.pairings.delete(key);
    for (const j of this.queues.get(key) ?? []) { clearTimeout(j.timeout); this.inflight.delete(j.job.id); j.resolve({ ok: false, error: "Codespace agent was unpaired" }); }
    this.queues.delete(key);
    for (const w of this.waiters.get(key) ?? []) { clearTimeout(w.timer); w.resolve(null); }
    this.waiters.delete(key);
    for (const [id, j] of this.inflight) if (j.pairingKey === key) { clearTimeout(j.timeout); this.inflight.delete(id); j.resolve({ ok: false, error: "Codespace agent was unpaired" }); }
    return true;
  }

  authenticate(token: string | undefined): { userId: string; codespace: string; key: string } | null {
    if (!token) return null;
    const key = this.byToken.get(sha(token));
    if (!key) return null;
    const p = this.pairings.get(key);
    if (!p || p.expiresAt < this.now()) return null;
    return { userId: p.userId, codespace: p.codespace, key };
  }

  hello(key: string, info: Record<string, unknown>): void {
    const p = this.pairings.get(key);
    if (!p) return;
    p.lastSeen = this.now();
    p.agentInfo = info;
    p.expiresAt = this.now() + this.ttl;
  }

  list(userId: string): { codespace: string; online: boolean; lastSeen: number | null; info?: Record<string, unknown>; queued: number }[] {
    const out = [];
    for (const [key, p] of this.pairings) {
      if (p.userId !== userId) continue;
      out.push({
        codespace: p.codespace,
        online: p.lastSeen > 0 && this.now() - p.lastSeen < this.onlineWindow,
        lastSeen: p.lastSeen || null,
        info: p.agentInfo,
        queued: (this.queues.get(key) ?? []).length,
      });
    }
    return out;
  }

  isPaired(userId: string, codespace: string): boolean { return this.pairings.has(keyOf(userId, codespace)); }
  isOnline(userId: string, codespace: string): boolean {
    const p = this.pairings.get(keyOf(userId, codespace));
    return !!p && p.lastSeen > 0 && this.now() - p.lastSeen < this.onlineWindow;
  }

  /** Server-side: enqueue a job for the user's codespace and wait for its result. */
  submit(userId: string, codespace: string, op: AgentOp, args: Record<string, unknown>, timeoutMs = 120_000): Promise<AgentJobResult> {
    const key = keyOf(userId, codespace);
    if (!this.pairings.has(key)) return Promise.resolve({ ok: false, error: `Codespace "${codespace}" is not attached. Call codespaces_attach first.` });
    if (!this.isOnline(userId, codespace)) {
      return Promise.resolve({ ok: false, error: `The agent in codespace "${codespace}" is not online. Make sure the Codespace is running (codespaces_start) and the agent has started (see codespaces_attach for the setup).` });
    }
    const q = this.queues.get(key) ?? [];
    if (q.length >= this.maxQueue) return Promise.resolve({ ok: false, error: "Too many queued jobs for this codespace" });
    return new Promise<AgentJobResult>((resolve) => {
      const job: AgentJob = { id: crypto.randomBytes(12).toString("base64url"), op, args };
      const pj: PendingJob = {
        job, pairingKey: key, claimed: false, createdAt: this.now(),
        timeout: setTimeout(() => {
          this.inflight.delete(job.id);
          const arr = this.queues.get(key); if (arr) this.queues.set(key, arr.filter((x) => x !== pj));
          resolve({ ok: false, error: `Timed out after ${Math.round(timeoutMs / 1000)}s waiting for the codespace agent` });
        }, timeoutMs),
        resolve,
      };
      pj.timeout.unref?.();
      this.inflight.set(job.id, pj);
      const waiter = (this.waiters.get(key) ?? []).shift();
      if (waiter) { clearTimeout(waiter.timer); pj.claimed = true; waiter.resolve(job); }
      else { q.push(pj); this.queues.set(key, q); }
    });
  }

  /** Agent-side: long-poll for the next job. Resolves null on timeout (agent re-polls). */
  next(key: string, waitMs = 25_000): Promise<AgentJob | null> {
    const p = this.pairings.get(key); if (!p) return Promise.resolve(null);
    p.lastSeen = this.now();
    const q = this.queues.get(key) ?? [];
    const pj = q.shift();
    if (pj) { this.queues.set(key, q); pj.claimed = true; return Promise.resolve(pj.job); }
    return new Promise<AgentJob | null>((resolve) => {
      const w: Waiter = { resolve, timer: setTimeout(() => {
        const arr = this.waiters.get(key) ?? []; this.waiters.set(key, arr.filter((x) => x !== w));
        resolve(null);
      }, waitMs) };
      w.timer.unref?.();
      const arr = this.waiters.get(key) ?? []; arr.push(w); this.waiters.set(key, arr);
    });
  }

  /** Agent-side: deliver a result. Only the agent that owns the job may complete it. */
  complete(key: string, jobId: string, result: AgentJobResult): boolean {
    const pj = this.inflight.get(jobId);
    if (!pj || pj.pairingKey !== key || !pj.claimed) return false;
    this.inflight.delete(jobId);
    clearTimeout(pj.timeout);
    let data: unknown = undefined;
    if (result.data !== undefined) { try { data = JSON.parse(redact(JSON.stringify(result.data))); } catch { data = undefined; } }
    pj.resolve({ ok: !!result.ok, error: result.error ? redact(String(result.error)).slice(0, 8000) : undefined, data });
    return true;
  }
}
