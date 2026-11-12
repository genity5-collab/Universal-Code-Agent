/**
 * The VM's real Linux desktop (InstaBox "agent-browser" etc. run X display :1).
 * Everything goes through the existing exec / file APIs, so it uses the same key handling, VM gate and activity feed as the other tools.
 * The AI sees the screen as a PNG image and drives it with mouse and keyboard, exactly like the official InstaBox SDK does (xdotool + scrot).
 * Every value that reaches a shell is either a validated integer or single-quoted.
 */
import { z } from "zod";
import type { ToolDef } from "../mcp/tools.js";
import type { ToolDeps } from "../mcp/tools.js";
import type { UserContext } from "../types.js";
import { shq, NoVmError, type InstaBoxManager } from "./client.js";
import type { ActivityFeed } from "./activity.js";

const ENV = "export DISPLAY=:1; ";
const KEYSYMS: Record<string, string> = { ctrl: "ctrl", control: "ctrl", alt: "alt", shift: "shift", super: "super", meta: "super", cmd: "super", enter: "Return", return: "Return", esc: "Escape", escape: "Escape", tab: "Tab", space: "space", backspace: "BackSpace", delete: "Delete", del: "Delete", up: "Up", down: "Down", left: "Left", right: "Right", home: "Home", end: "End", pageup: "Prior", pagedown: "Next" };
export const keysym = (k: string): string => { const s = String(k).trim(); const m = KEYSYMS[s.toLowerCase()]; if (m) return m; if (/^[A-Za-z0-9]$/.test(s) || /^F([1-9]|1[0-2])$/i.test(s)) return /^f\d/i.test(s) ? s.toUpperCase() : s; throw new Error(`Unknown key "${s.slice(0, 20)}". Use a letter, digit, F1-F12, Enter, Tab, Escape, Space, Backspace, Delete, arrows, Home, End, PageUp, PageDown, or ctrl/alt/shift/super.`); };
const int = (v: unknown, name: string, lo: number, hi: number): number => { const n = Number(v); if (!Number.isInteger(n) || n < lo || n > hi) throw new Error(`${name} must be a whole number from ${lo} to ${hi}.`); return n; };
const BUTTON: Record<string, number> = { left: 1, middle: 2, right: 3 }; const WHEEL: Record<string, number> = { up: 4, down: 5, left: 6, right: 7 };

/** Width and height from a JPEG's SOF marker, or undefined. */
export function jpegSize(b: Buffer): { width: number; height: number } | undefined {
  let i = 2; while (i + 9 < b.length) { if (b[i] !== 0xff) { i++; continue; } const m = b[i + 1]; if (m === 0xd8 || m === 0x01 || (m >= 0xd0 && m <= 0xd7)) { i += 2; continue; } const len = b.readUInt16BE(i + 2); if ((m >= 0xc0 && m <= 0xcf) && m !== 0xc4 && m !== 0xc8 && m !== 0xcc) return { height: b.readUInt16BE(i + 5), width: b.readUInt16BE(i + 7) }; i += 2 + len; }
  return undefined;
}
export interface DesktopStatus { running: boolean; width?: number; height?: number; installed: boolean }
export const MAX_SHOT_BYTES = 6 * 1024 * 1024;

export class Desktop {
  constructor(private mgr: InstaBoxManager, private feed: ActivityFeed) {}
  private async sh(userId: string, cmd: string, timeoutSec = 30) { return this.mgr.exec(userId, ENV + cmd, { timeoutSec }); }

  async status(userId: string): Promise<DesktopStatus> {
    const r = await this.sh(userId, `if command -v xdotool >/dev/null && xdotool getdisplaygeometry 2>/dev/null; then echo RUN; elif command -v xdotool >/dev/null || command -v Xvfb >/dev/null || command -v Xtigervnc >/dev/null; then echo INSTALLED; else echo NONE; fi`);
    const out = r.stdout; const g = /^(\d+)\s+(\d+)\s*$/m.exec(out);
    if (/RUN/.test(out) && g) return { running: true, installed: true, width: Number(g[1]), height: Number(g[2]) };
    return { running: false, installed: /INSTALLED|RUN/.test(out) };
  }

  /** Start the desktop through InstaBox's own action (it leaves a running one alone), installing it first on templates that lack it. */
  async start(userId: string, width = 1280, height = 800): Promise<DesktopStatus> {
    width = int(width, "width", 800, 2560); height = int(height, "height", 600, 1600);
    for (let i = 0; i < 2; i++) {
      const s = await this.action(userId, { action: "start", width, height });
      if (s.running) break;
      if (!s.installed) {
        if (!s.installing) await this.action(userId, { action: "install" });
        const t0 = Date.now(); let st = await this.action(userId, { action: "status" });
        while (!st.installed) { if (st.failed) throw new Error("The desktop could not be installed in this VM."); if (Date.now() - t0 > 240_000) throw new Error("Installing the desktop is taking too long. Try again in a minute."); await new Promise((r) => setTimeout(r, 4000)); st = await this.action(userId, { action: "status" }); }
      }
    }
    const st = await this.status(userId); this.feed.add(userId, { tool: "desktop_start", kind: "vm", summary: st.running ? `Desktop running ${st.width}x${st.height}` : "Desktop did not start", ok: st.running });
    if (!st.running) throw new Error("The desktop did not start.");
    return st;
  }
  private async action(userId: string, body: Record<string, unknown>): Promise<any> {
    const r = await this.mgr.rawCall(userId, "POST", "desktop", body, 90_000);
    try { return JSON.parse(r); } catch { return {}; }
  }

  /** One PNG of the whole screen. */
  async screenshot(userId: string): Promise<{ png: Buffer; width?: number; height?: number }> {
    const p = `/tmp/uca-shot-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}.png`;
    const r = await this.sh(userId, `if command -v scrot >/dev/null; then scrot -o ${shq(p)}; elif command -v import >/dev/null; then import -window root png:${shq(p)}; else echo 'no screenshot tool (scrot or ImageMagick) in the VM' >&2; exit 127; fi`);
    if (r.exitCode !== 0) throw new Error(/no screenshot tool/.test(r.stderr) ? "The VM has no screenshot tool. Run: sudo apt-get update && sudo apt-get install -y scrot xdotool" : `Screenshot failed. Is the desktop started? Call desktop_start. ${r.stderr.slice(0, 200)}`);
    try { const png = await this.mgr.readFile(userId, p, MAX_SHOT_BYTES); if (png.length < 8 || png.readUInt32BE(0) !== 0x89504e47) throw new Error("The screenshot was not a PNG."); return { png, width: png.readUInt32BE(16), height: png.readUInt32BE(20) }; }
    finally { await this.mgr.exec(userId, `rm -f ${shq(p)}`, { timeoutSec: 10 }).catch(() => undefined); }
  }

  /**
   * FAST FRAMES. One small background loop INSIDE the VM keeps overwriting a JPEG (about 6 per second); reading a frame is then one cheap
   * file download instead of: spawn shell, start scrot, encode PNG, download, delete. The loop stops itself when nobody asks for a frame for 20 s.
   */
  private static FRAME = "/tmp/uca-live.jpg"; private static BEAT = "/tmp/uca-live.beat";
  async frame(userId: string): Promise<{ img: Buffer; type: "jpeg" | "png"; width?: number; height?: number }> {
    const F = shq(Desktop.FRAME), B = shq(Desktop.BEAT), S = "/tmp/uca-live-loop.sh", PID = "/tmp/uca-live.pid";
    // The loop is a small script file (no quoting tricks). It runs while the heartbeat is fresh and removes its pid file when it stops.
    const script = `#!/bin/bash\nexport DISPLAY=:1\necho $$ > ${PID}\nwhile [ $(( $(date +%s) - $(stat -c %Y ${Desktop.BEAT} 2>/dev/null || echo 0) )) -lt 20 ]; do\n  if command -v scrot >/dev/null; then scrot -q 55 -o ${Desktop.FRAME}.tmp 2>/dev/null && mv -f ${Desktop.FRAME}.tmp ${Desktop.FRAME}; else import -window root -quality 55 jpg:${Desktop.FRAME}.tmp 2>/dev/null && mv -f ${Desktop.FRAME}.tmp ${Desktop.FRAME}; fi\n  sleep 0.12\ndone\nrm -f ${PID}\n`;
    const loop = `touch ${B}; if ! { [ -s ${PID} ] && kill -0 "$(cat ${PID})" 2>/dev/null; }; then printf %s ${shq(script)} > ${S} && chmod +x ${S} && (setsid nohup ${S} >/dev/null 2>&1 </dev/null &); fi; for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do [ -s ${F} ] && break; sleep 0.1; done; [ -s ${F} ]`;
    const r = await this.sh(userId, loop, 15);
    if (r.exitCode !== 0) { const s = await this.screenshot(userId); return { img: s.png, type: "png", width: s.width, height: s.height }; } // slow but always works
    const img = await this.mgr.readFile(userId, Desktop.FRAME, MAX_SHOT_BYTES);
    if (img.length > 3 && img[0] === 0xff && img[1] === 0xd8) return { img, type: "jpeg", ...jpegSize(img) };
    if (img.length > 8 && img.readUInt32BE(0) === 0x89504e47) return { img, type: "png", width: img.readUInt32BE(16), height: img.readUInt32BE(20) };
    throw new Error("The frame was not an image.");
  }

  /** InstaBox's own real-time viewer link (only the machine creator's personal key may make one). Returns null when the key is not allowed to. */
  async streamUrl(userId: string, viewOnly: boolean): Promise<{ url: string; expiresAt: string } | null> {
    try {
      const body = await this.mgr.rawCall(userId, "POST", "desktop/stream", { viewOnly, ttlSeconds: 1800 }, 20_000);
      const j = JSON.parse(body); if (typeof j.url !== "string" || !/^https:\/\//.test(j.url)) return null;
      return { url: j.url, expiresAt: String(j.expiresAt ?? "") };
    } catch (e: any) { if (/permission|forbidden|lacks a permission|404|not.*found|no longer exists|HTTP 4\d\d/i.test(String(e?.message))) return null; throw e; }
  }

  private async xdo(userId: string, args: string, stdin?: string) {
    const cmd = stdin === undefined ? `xdotool ${args}` : `printf %s ${shq(stdin)} | xdotool ${args}`;
    const r = await this.sh(userId, cmd); if (r.exitCode !== 0) throw new Error(/not found/.test(r.stderr) ? "xdotool is missing in the VM. Run: sudo apt-get update && sudo apt-get install -y xdotool" : `Input failed. Is the desktop started? Call desktop_start. ${r.stderr.slice(0, 200)}`); return r;
  }
  async click(u: string, x: number, y: number, button = "left", dbl = false) { const b = BUTTON[button]; if (!b) throw new Error("button must be left, right or middle."); await this.xdo(u, `mousemove ${int(x, "x", 0, 10000)} ${int(y, "y", 0, 10000)} click${dbl ? " --repeat 2 --delay 80" : ""} ${b}`); }
  async move(u: string, x: number, y: number) { await this.xdo(u, `mousemove ${int(x, "x", 0, 10000)} ${int(y, "y", 0, 10000)}`); }
  async drag(u: string, x1: number, y1: number, x2: number, y2: number) { await this.xdo(u, `mousemove ${int(x1, "x1", 0, 10000)} ${int(y1, "y1", 0, 10000)} mousedown 1 sleep 0.1 mousemove ${int(x2, "x2", 0, 10000)} ${int(y2, "y2", 0, 10000)} sleep 0.1 mouseup 1`); }
  async scroll(u: string, dir: string, amount = 3) { const w = WHEEL[dir]; if (!w) throw new Error("direction must be up, down, left or right."); await this.xdo(u, `click --repeat ${int(amount, "amount", 1, 100)} --delay 30 ${w}`); }
  async type(u: string, text: string) { if (typeof text !== "string" || !text) return; if (text.length > 5000) throw new Error("Type at most 5000 characters at a time."); await this.xdo(u, `type --delay 12 --file -`, text); }
  async press(u: string, keys: string[]) { if (!keys.length || keys.length > 6) throw new Error("Give 1 to 6 keys."); await this.xdo(u, `key -- ${shq(keys.map(keysym).join("+"))}`); }
  async runBatch(userId: string, script: string) { return this.sh(userId, script, 60); }
  async open(u: string, url: string) {
    let parsed: URL; try { parsed = new URL(url); } catch { throw new Error("Invalid URL."); } if (parsed.protocol !== "http:" && parsed.protocol !== "https:") throw new Error("Only http and https URLs can be opened.");
    const r = await this.sh(u, `b=$(command -v chromium || command -v chromium-browser || command -v google-chrome) || { echo 'no browser in the VM' >&2; exit 127; }; setsid nohup "$b" --no-first-run --no-default-browser-check --password-store=basic ${shq(parsed.href)} >/dev/null 2>&1 </dev/null &`); if (r.exitCode !== 0) throw new Error("No browser is installed in this VM.");
  }
}

/** Downscale for the chat so replies stay small: keeps the PNG as is (no image libs); the 6 MB cap bounds it. */
const SHOT_NOTE = "Coordinates are pixels from the top left of the screen in the image.";

type DeskDeps = ToolDeps & { vm: InstaBoxManager; feed: ActivityFeed; desktop: Desktop };
const D = (d: ToolDeps) => (d as DeskDeps).desktop;
const log = (d: ToolDeps, c: UserContext, tool: string, summary: string, ok = true) => (d as DeskDeps).feed.add(c.userId, { tool, kind: "other", summary, ok });
const need = (d: ToolDeps, c: UserContext) => { if (!d.vm || !(d as DeskDeps).desktop) throw new NoVmError("VM backend is not configured on this server, so the AI cannot work."); d.vm.require(c.userId); };

export interface Step { do: string; x?: number; y?: number; x2?: number; y2?: number; text?: string; keys?: string[]; direction?: string; amount?: number; button?: string; double?: boolean; ms?: number; url?: string }
/** Turn a list of steps into ONE xdotool shell script. Every number is validated; every string is quoted. */
export function buildBatch(steps: Step[]): string {
  if (!Array.isArray(steps) || !steps.length || steps.length > 25) throw new Error("Give 1 to 25 steps.");
  const out: string[] = [];
  for (const st of steps) {
    switch (st.do) {
      case "click": { const b = BUTTON[st.button ?? "left"]; if (!b) throw new Error("button must be left, right or middle."); out.push(`xdotool mousemove ${int(st.x, "x", 0, 10000)} ${int(st.y, "y", 0, 10000)} click${st.double ? " --repeat 2 --delay 80" : ""} ${b}`); break; }
      case "move": out.push(`xdotool mousemove ${int(st.x, "x", 0, 10000)} ${int(st.y, "y", 0, 10000)}`); break;
      case "drag": out.push(`xdotool mousemove ${int(st.x, "x", 0, 10000)} ${int(st.y, "y", 0, 10000)} mousedown 1 sleep 0.1 mousemove ${int(st.x2, "x2", 0, 10000)} ${int(st.y2, "y2", 0, 10000)} sleep 0.1 mouseup 1`); break;
      case "scroll": { const w = WHEEL[String(st.direction)]; if (!w) throw new Error("direction must be up, down, left or right."); out.push(`xdotool click --repeat ${int(st.amount ?? 3, "amount", 1, 100)} --delay 30 ${w}`); break; }
      case "type": { if (typeof st.text !== "string" || !st.text || st.text.length > 5000) throw new Error("type needs text of 1 to 5000 characters."); out.push(`printf %s ${shq(st.text)} | xdotool type --delay 8 --file -`); break; }
      case "press": { const k = st.keys ?? []; if (!k.length || k.length > 6) throw new Error("press needs 1 to 6 keys."); out.push(`xdotool key -- ${shq(k.map(keysym).join("+"))}`); break; }
      case "wait": out.push(`sleep ${(int(st.ms ?? 300, "ms", 0, 5000) / 1000).toFixed(3)}`); break;
      case "open": { let u: URL; try { u = new URL(String(st.url)); } catch { throw new Error("Invalid URL."); } if (u.protocol !== "http:" && u.protocol !== "https:") throw new Error("Only http and https URLs can be opened."); out.push(`b=$(command -v chromium || command -v chromium-browser || command -v google-chrome) || { echo 'no browser in the VM' >&2; exit 127; }; (setsid nohup "$b" --no-first-run --no-default-browser-check --password-store=basic ${shq(u.href)} >/dev/null 2>&1 </dev/null &)`); break; }
      default: throw new Error(`Unknown step "${String(st.do).slice(0, 20)}". Use click, move, drag, scroll, type, press, wait or open.`);
    }
  }
  return "set -e; " + out.join("; ");
}

export const DESKTOP_TOOLS: ToolDef[] = [
  { name: "desktop_do", title: "Do several things on the VM screen at once (fast)", description: "PREFERRED. Run up to 25 steps in ONE call and get ONE screenshot at the end. Much faster than separate calls. Steps: {do:\"click\",x,y,button?,double?}, {do:\"type\",text}, {do:\"press\",keys:[\"ctrl\",\"l\"]}, {do:\"scroll\",direction,amount?}, {do:\"drag\",x,y,x2,y2}, {do:\"move\",x,y}, {do:\"wait\",ms}, {do:\"open\",url}. Example: click the address bar, type a URL, press Enter, wait 1500, all in one call. " + SHOT_NOTE, scope: "mcp:exec", readOnly: false,
    shape: { steps: z.array(z.object({ do: z.enum(["click", "move", "drag", "scroll", "type", "press", "wait", "open"]), x: z.number().int().min(0).max(10000).optional(), y: z.number().int().min(0).max(10000).optional(), x2: z.number().int().min(0).max(10000).optional(), y2: z.number().int().min(0).max(10000).optional(), text: z.string().max(5000).optional(), keys: z.array(z.string().min(1).max(20)).max(6).optional(), direction: z.enum(["up", "down", "left", "right"]).optional(), amount: z.number().int().min(1).max(100).optional(), button: z.enum(["left", "right", "middle"]).optional(), double: z.boolean().optional(), ms: z.number().int().min(0).max(5000).optional(), url: z.string().max(2000).optional() })).min(1).max(25), screenshot: z.boolean().optional() },
    handler: async (a, c, d) => { need(d, c); const script = buildBatch(a.steps); const r = await D(d).runBatch(c.userId, script); if (r.exitCode !== 0) throw new Error(`A step failed: ${r.stderr.slice(0, 200) || "unknown"}. Is the desktop started? Call desktop_start.`); log(d, c, "desktop_do", `${a.steps.length} step(s): ${a.steps.map((s: Step) => s.do).join(", ").slice(0, 120)}`);
      if (a.screenshot === false) return { done: a.steps.length };
      const f = await D(d).frame(c.userId); return { __image: f.img.toString("base64"), __mime: f.type === "jpeg" ? "image/jpeg" : "image/png", __structured: { steps: a.steps.length, takenAt: Date.now() }, text: `Done ${a.steps.length} step(s). Screenshot attached. ${SHOT_NOTE}` }; } },
  { name: "desktop_start", title: "Start the VM desktop", description: "Start the VM's Linux desktop screen (installs it first if the VM template lacks it, about 30 s). Call once before using the screen. Then call desktop_screenshot to see it.", scope: "mcp:exec", readOnly: false, shape: { width: z.number().int().min(800).max(2560).optional(), height: z.number().int().min(600).max(1600).optional() },
    handler: async (a, c, d) => { need(d, c); const s = await D(d).start(c.userId, a.width, a.height); return { running: s.running, width: s.width, height: s.height, next: "Call desktop_screenshot to see the screen." }; } },
  { name: "desktop_screenshot", title: "See the VM screen", description: "Take a screenshot of the VM's desktop and return it as an image. " + SHOT_NOTE + " Prefer desktop_do for several actions, it returns a screenshot at the end.", scope: "mcp:read", readOnly: true, shape: {},
    handler: async (_a, c, d) => { need(d, c); const f = await D(d).frame(c.userId); log(d, c, "desktop_screenshot", "Screenshot"); return { __image: f.img.toString("base64"), __mime: f.type === "jpeg" ? "image/jpeg" : "image/png", __structured: { width: f.width, height: f.height, takenAt: Date.now() }, text: `Screenshot attached. ${SHOT_NOTE}` }; } },
  { name: "desktop_click", title: "Click on the VM screen", description: "Click at (x, y) on the VM screen. " + SHOT_NOTE + " Take a screenshot afterwards to check the result.", scope: "mcp:exec", readOnly: false, shape: { x: z.number().int().min(0).max(10000), y: z.number().int().min(0).max(10000), button: z.enum(["left", "right", "middle"]).optional(), double: z.boolean().optional() },
    handler: async (a, c, d) => { need(d, c); await D(d).click(c.userId, a.x, a.y, a.button ?? "left", !!a.double); log(d, c, "desktop_click", `${a.double ? "Double-click" : "Click"} ${a.button ?? "left"} at ${a.x},${a.y}`); return { clicked: true }; } },
  { name: "desktop_move", title: "Move the mouse on the VM screen", description: "Move the pointer to (x, y) without clicking.", scope: "mcp:exec", readOnly: false, shape: { x: z.number().int().min(0).max(10000), y: z.number().int().min(0).max(10000) },
    handler: async (a, c, d) => { need(d, c); await D(d).move(c.userId, a.x, a.y); log(d, c, "desktop_move", `Move to ${a.x},${a.y}`); return { moved: true }; } },
  { name: "desktop_drag", title: "Drag on the VM screen", description: "Drag with the left button from (x1, y1) to (x2, y2).", scope: "mcp:exec", readOnly: false, shape: { x1: z.number().int().min(0).max(10000), y1: z.number().int().min(0).max(10000), x2: z.number().int().min(0).max(10000), y2: z.number().int().min(0).max(10000) },
    handler: async (a, c, d) => { need(d, c); await D(d).drag(c.userId, a.x1, a.y1, a.x2, a.y2); log(d, c, "desktop_drag", `Drag ${a.x1},${a.y1} to ${a.x2},${a.y2}`); return { dragged: true }; } },
  { name: "desktop_scroll", title: "Scroll the VM screen", description: "Turn the mouse wheel at the pointer.", scope: "mcp:exec", readOnly: false, shape: { direction: z.enum(["up", "down", "left", "right"]), amount: z.number().int().min(1).max(100).optional() },
    handler: async (a, c, d) => { need(d, c); await D(d).scroll(c.userId, a.direction, a.amount ?? 3); log(d, c, "desktop_scroll", `Scroll ${a.direction} ${a.amount ?? 3}`); return { scrolled: true }; } },
  { name: "desktop_type", title: "Type on the VM screen", description: "Type text into the focused window on the VM screen (quotes, newlines and Unicode are fine). Click the field first.", scope: "mcp:exec", readOnly: false, shape: { text: z.string().min(1).max(5000) },
    handler: async (a, c, d) => { need(d, c); await D(d).type(c.userId, a.text); log(d, c, "desktop_type", `Typed ${a.text.length} character(s)`); return { typed: a.text.length }; } },
  { name: "desktop_press", title: "Press keys on the VM screen", description: "Press a key or a chord, e.g. keys [\"Enter\"] or [\"ctrl\",\"l\"]. Names: letters, digits, F1-F12, Enter, Tab, Escape, Space, Backspace, Delete, arrows, Home, End, PageUp, PageDown, ctrl, alt, shift, super.", scope: "mcp:exec", readOnly: false, shape: { keys: z.array(z.string().min(1).max(20)).min(1).max(6) },
    handler: async (a, c, d) => { need(d, c); await D(d).press(c.userId, a.keys); log(d, c, "desktop_press", `Press ${a.keys.join("+")}`); return { pressed: a.keys }; } },
  { name: "desktop_open", title: "Open a web page on the VM screen", description: "Open an http(s) URL in the desktop's browser.", scope: "mcp:exec", readOnly: false, shape: { url: z.string().url().max(2000) },
    handler: async (a, c, d) => { need(d, c); await D(d).open(c.userId, a.url); log(d, c, "desktop_open", `Open ${a.url}`); return { opened: a.url }; } },
];
