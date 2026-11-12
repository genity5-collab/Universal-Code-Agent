/** Per-user activity feed: everything the AI did in the VM. In memory (bounded) so secrets never reach disk; powers the live view and the Workspace log. */
import { redact } from "../util/paths.js";
export interface Activity { id: number; t: number; tool: string; kind: "command" | "file" | "read" | "git" | "vm" | "other"; summary: string; ok: boolean; output?: string; path?: string; bytes?: number; ms?: number }
type Listener = (a: Activity) => void;
export class ActivityFeed {
  private items = new Map<string, Activity[]>(); private seq = 0; private subs = new Map<string, Set<Listener>>();
  constructor(private max = 500) {}
  add(userId: string, a: Omit<Activity, "id" | "t">): Activity {
    const full: Activity = { ...a, id: ++this.seq, t: Date.now(), summary: redact(a.summary).slice(0, 300), output: a.output === undefined ? undefined : redact(a.output).slice(0, 4000) };
    const arr = this.items.get(userId) ?? []; arr.push(full); if (arr.length > this.max) arr.splice(0, arr.length - this.max); this.items.set(userId, arr);
    for (const l of this.subs.get(userId) ?? []) { try { l(full); } catch { /* ignore */ } }
    return full;
  }
  list(userId: string, sinceId = 0, limit = 200): Activity[] { return (this.items.get(userId) ?? []).filter((a) => a.id > sinceId).slice(-limit); }
  subscribe(userId: string, l: Listener): () => void { const s = this.subs.get(userId) ?? new Set(); s.add(l); this.subs.set(userId, s); return () => { s.delete(l); }; }
  clear(userId: string): void { this.items.delete(userId); }
}
