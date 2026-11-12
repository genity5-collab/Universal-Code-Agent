import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { redact } from "../util/paths.js";
import type { ApprovalRequest } from "../types.js";

/** Human-in-the-loop approvals. In-memory with expiry; the dashboard approves or denies. */
export class ApprovalService {
  private items = new Map<string, ApprovalRequest & { expiresAt: number; fingerprint: string }>();
  constructor(private ttlMs = 15 * 60_000, private now: () => number = Date.now) {}

  private fp(userId: string, action: string, detail: string): string {
    return crypto.createHash("sha256").update(`${userId}\0${action}\0${detail}`).digest("hex");
  }
  private sweep(): void {
    const t = this.now();
    for (const [id, a] of this.items) {
      if (a.expiresAt < t) this.items.delete(id);
    }
  }
  /**
   * Returns "approved" (and consumes the approval) when the exact same action was approved,
   * otherwise records/returns a pending request. An approval is single-use and bound to the exact action.
   */
  check(userId: string, action: string, detail: string): { state: "approved" } | { state: "pending" | "denied"; id: string } {
    this.sweep();
    const fingerprint = this.fp(userId, action, detail);
    for (const [id, a] of this.items) {
      if (a.userId === userId && a.fingerprint === fingerprint) {
        if (a.status === "approved") { this.items.delete(id); return { state: "approved" }; }
        if (a.status === "denied") { this.items.delete(id); return { state: "denied", id }; }
        return { state: "pending", id };
      }
    }
    const id = crypto.randomBytes(9).toString("base64url");
    this.items.set(id, { id, userId, action, detail: redact(detail).slice(0, 4000), status: "pending", createdAt: this.now(), expiresAt: this.now() + this.ttlMs, fingerprint });
    return { state: "pending", id };
  }
  list(userId: string): ApprovalRequest[] {
    this.sweep();
    return [...this.items.values()].filter((a) => a.userId === userId).map(({ expiresAt: _e, fingerprint: _f, ...a }) => a).sort((a, b) => b.createdAt - a.createdAt);
  }
  decide(userId: string, id: string, approve: boolean): boolean {
    const a = this.items.get(id);
    if (!a || a.userId !== userId || a.status !== "pending" || a.expiresAt < this.now()) return false;
    a.status = approve ? "approved" : "denied";
    return true;
  }
}

/** Append-only JSONL audit log. Never records secrets (redacted) or file contents. */
export class AuditLog {
  private file: string;
  constructor(dataDir: string) {
    fs.mkdirSync(dataDir, { recursive: true });
    this.file = path.join(dataDir, "audit.log");
  }
  write(entry: { userId: string; tool: string; ok: boolean; note?: string }): void {
    const line = JSON.stringify({ t: new Date().toISOString(), ...entry, note: entry.note ? redact(entry.note).slice(0, 300) : undefined });
    try { fs.appendFileSync(this.file, line + "\n", { mode: 0o600 }); } catch { /* audit must never break a tool call */ }
  }
}

export class RateLimiter {
  private hits = new Map<string, number[]>();
  constructor(private limit: number, private windowMs = 60_000, private now: () => number = Date.now) {}
  allow(key: string): boolean {
    const t = this.now();
    const arr = (this.hits.get(key) ?? []).filter((x) => x > t - this.windowMs);
    if (arr.length >= this.limit) { this.hits.set(key, arr); return false; }
    arr.push(t); this.hits.set(key, arr); return true;
  }
}
