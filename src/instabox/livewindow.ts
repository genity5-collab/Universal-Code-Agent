/**
 * Live VM window inside ChatGPT (MCP Apps / Apps SDK widget).
 *
 *  - `vm_live`       (model-visible)  opens the window inline in the chat. Also returns a text snapshot, so it is useful even
 *                    when the host cannot render widgets.
 *  - `vm_live_poll`  (app-only)       the window calls it every ~1.5 s through the host bridge. It is hidden from the model.
 *
 * The widget needs NO network access and holds NO credentials: it only talks to the host with postMessage, and the host
 * forwards tools/call over the user's already-authorised MCP connection. Everything shown has passed through the activity
 * feed's redaction. Nothing here can change the VM: the poll is read-only.
 */
import { z } from "zod";
import type { ToolDef } from "../mcp/tools.js";
import { WORKSPACE_DIR } from "./tools.js";
import { shq } from "./client.js";
import type { Desktop } from "./desktop.js";

export const LIVE_URI = "ui://widget/vm-live-v2.html";
export const LIVE_MIME = "text/html;profile=mcp-app";

type Snap = { running: boolean; machineId?: string; items: unknown[]; lastId: number; files: { name: string; type: string; size: number }[]; usedBytes: number };

async function snapshot(c: { userId: string }, d: any, since: number, withFiles: boolean): Promise<Snap> {
  const st = d.vm.status(c.userId);
  const items = d.feed.list(c.userId, since, 60);
  const lastId = items.length ? items[items.length - 1].id : since;
  let files: Snap["files"] = []; let usedBytes = 0;
  if (withFiles && st.running) {
    try {
      const r = await d.vm.exec(c.userId, `cd ${shq(WORKSPACE_DIR)} 2>/dev/null && find . -mindepth 1 -maxdepth 2 -not -path '*/.git*' -not -path '*/node_modules*' -printf '%y\\t%s\\t%P\\n' 2>/dev/null | sort -t$'\\t' -k3 | head -40; echo ---; du -sb ${shq(WORKSPACE_DIR)} 2>/dev/null | cut -f1`, { timeoutSec: 15 });
      const [list, used] = r.stdout.split("\n---\n");
      files = list.split("\n").filter(Boolean).map((l: string) => { const [t, sz, ...nm] = l.split("\t"); return { name: nm.join("\t"), type: t === "d" ? "directory" : "file", size: Number(sz) || 0 }; });
      usedBytes = Number(String(used ?? "").trim()) || 0;
    } catch { /* the window just shows no file list this round */ }
  }
  return { running: !!st.running, machineId: st.machineId, items, lastId, files, usedBytes };
}

/** Latest picture of the VM desktop as a data URL, or a short reason it is not available. Never throws. */
async function screen(c: { userId: string }, d: any): Promise<{ image?: string; width?: number; height?: number; note?: string }> {
  if (!d.vm.status(c.userId).running) return { note: "The VM is not running." };
  try { const s = await (d.desktop as Desktop).screenshot(c.userId); return { image: "data:image/png;base64," + s.png.toString("base64"), width: s.width, height: s.height }; }
  catch (e: any) { return { note: /no screenshot tool|Is the desktop started|xdotool|scrot/i.test(String(e?.message)) ? "The desktop is not started yet. The AI can start it with desktop_start." : "Screen not available right now." }; }
}

export const LIVE_TOOLS: (ToolDef & { meta?: Record<string, unknown> })[] = [
  {
    name: "vm_live", title: "Open the live VM window",
    description: "Show the user a live window of the VM in this chat: every command, file change and git action as it happens, plus the file list. Call it once when you start working in the VM (after vm_status shows it is running). It does not change anything.",
    scope: "mcp:read", readOnly: true, shape: {},
    meta: { ui: { resourceUri: LIVE_URI }, "openai/outputTemplate": LIVE_URI, "openai/toolInvocation/invoking": "Opening the live VM window...", "openai/toolInvocation/invoked": "Live VM window open." },
    handler: async (_a, c, d) => {
      const s: any = await snapshot(c, d, 0, true); s.screen = await screen(c, d);
      return { __structured: s, text: s.running ? `Live VM window opened. ${s.items.length} recent action(s); ${s.files.length} file(s) shown.` : "The VM is not running, so there is nothing to show yet. Call vm_start first (the user must have added their InstaBox key)." };
    },
  },
  {
    name: "vm_live_poll", title: "Live VM window refresh (used by the window itself)",
    description: "Internal: returns the activity since a given id and the current file list. Called by the live window, not by the model.",
    scope: "mcp:read", readOnly: true, shape: { sinceId: z.number().int().min(0).max(1e9).optional(), files: z.boolean().optional() },
    meta: { ui: { visibility: ["app"] }, "openai/widgetAccessible": true },
    handler: async (a, c, d) => ({ __structured: await snapshot(c, d, Number(a.sinceId ?? 0), a.files !== false), text: "ok" }),
  },
  {
    name: "vm_screen_poll", title: "Live VM screen refresh (used by the window itself)",
    description: "Internal: returns the current picture of the VM desktop for the live window. Called by the window, not by the model.",
    scope: "mcp:read", readOnly: true, shape: {},
    meta: { ui: { visibility: ["app"] }, "openai/widgetAccessible": true },
    handler: async (_a, c, d) => ({ __structured: { screen: await screen(c, d) }, text: "ok" }),
  },
];

/** The window: the VM's real desktop picture on top, a small activity strip and file list underneath. One self-contained HTML file; no external requests; feed text is only ever inserted as text. */
export const LIVE_HTML = `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Live VM</title>
<style>
:root{color-scheme:light dark;--bg:#0b0f17;--fg:#e6edf6;--mut:#8a97ab;--card:#131a26;--line:#243047;--ok:#3ddc97;--bad:#ff6b6b;--acc:#4f8cff}
@media (prefers-color-scheme:light){:root{--bg:#fff;--fg:#14202e;--mut:#5b6b80;--card:#f3f6fa;--line:#d8e0ea}}
*{box-sizing:border-box}body{margin:0;font:13px/1.4 system-ui,sans-serif;background:var(--bg);color:var(--fg)}
header{display:flex;align-items:center;gap:8px;padding:8px 10px;border-bottom:1px solid var(--line)}
.dot{width:9px;height:9px;border-radius:50%;background:var(--mut)}.dot.on{background:var(--ok);box-shadow:0 0 6px var(--ok)}
header b{flex:1}button{font:inherit;color:var(--fg);background:var(--card);border:1px solid var(--line);border-radius:7px;padding:3px 8px;cursor:pointer}
#screenbox{position:relative;background:#000;display:flex;align-items:center;justify-content:center;min-height:180px}
#screen{display:block;width:100%;height:auto;max-height:70vh;object-fit:contain}
#msg{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;text-align:center;padding:16px;color:var(--mut)}
#msg[hidden]{display:none}
details{border-top:1px solid var(--line)}summary{cursor:pointer;padding:6px 10px;color:var(--mut)}
#feed{max-height:150px;overflow:auto;padding:4px 8px;font:12px ui-monospace,Menlo,monospace}
.a{margin:0 0 5px;padding:4px 6px;background:var(--card);border-left:3px solid var(--acc);border-radius:5px;word-break:break-word}.a.bad{border-color:var(--bad)}
.a .t{color:var(--mut);font-size:11px}.a pre{margin:3px 0 0;white-space:pre-wrap;max-height:60px;overflow:auto;color:var(--mut)}
.f{display:flex;justify-content:space-between;gap:6px;padding:2px 8px;border-bottom:1px dashed var(--line)}.f span:last-child{color:var(--mut)}
#files{max-height:110px;overflow:auto}.m{color:var(--mut)}footer{padding:5px 10px;border-top:1px solid var(--line);color:var(--mut);font-size:11px}
</style>
<header><span class="dot" id="dot"></span><b id="title">Live VM</b><button id="pause" type="button">Pause</button></header>
<div id="screenbox"><img id="screen" alt="Live screen of the VM desktop" hidden><div id="msg">Connecting to the VM screen...</div></div>
<details><summary>Activity and files</summary><div id="feed" role="log" aria-live="polite"><span class="m">Waiting for the AI to act...</span></div><div id="files" aria-label="Files in the VM"></div></details>
<footer id="foot">Read-only view of the AI's screen. Control it from the app.</footer>
<script>
(function(){
  var $=function(i){return document.getElementById(i)};
  var feed=$("feed"),files=$("files"),dot=$("dot"),title=$("title"),foot=$("foot"),pauseBtn=$("pause"),img=$("screen"),msg=$("msg");
  var nextId=1,pending={},last=0,paused=false,busy=false,empty=true,tick=0;
  function send(m){window.parent.postMessage(m,"*")}
  function request(method,params){return new Promise(function(res,rej){var id=nextId++;pending[id]={res:res,rej:rej};send({jsonrpc:"2.0",id:id,method:method,params:params});setTimeout(function(){if(pending[id]){delete pending[id];rej(new Error("timeout"))}},25000)})}
  function notify(method,params){send({jsonrpc:"2.0",method:method,params:params||{}})}
  function mb(n){return n>=1048576?(n/1048576).toFixed(1)+" MB":n>=1024?Math.round(n/1024)+" KB":n+" B"}
  function el(tag,cls,text){var e=document.createElement(tag);if(cls)e.className=cls;if(text!=null)e.textContent=text;return e}
  function addItem(a){
    if(empty){feed.textContent="";empty=false}
    var d=el("div","a"+(a.ok?"":" bad")),h=el("div",null,a.summary||a.tool);h.style.fontWeight="600";d.appendChild(h);
    d.appendChild(el("div","t",new Date(a.t).toLocaleTimeString()+(a.ms?" - "+a.ms+" ms":"")));
    if(a.output){d.appendChild(el("pre",null,a.output))}
    feed.appendChild(d);feed.scrollTop=feed.scrollHeight;
    while(feed.childNodes.length>80)feed.removeChild(feed.firstChild);
  }
  function showScreen(sc){
    if(!sc)return;
    if(sc.image&&typeof sc.image==="string"&&sc.image.indexOf("data:image/png;base64,")===0&&!/[^A-Za-z0-9+=]/.test(sc.image.slice(22).split("/").join(""))){img.src=sc.image;img.hidden=false;msg.hidden=true}
    else if(sc.note){if(img.hidden){msg.textContent=sc.note;msg.hidden=false}}
  }
  function render(s){
    if(!s||typeof s!=="object")return;
    if(typeof s.running==="boolean"){dot.className="dot"+(s.running?" on":"");title.textContent=s.running?"Live VM - running":"Live VM - not running"}
    if(s.screen)showScreen(s.screen);
    (s.items||[]).forEach(function(a){if(a.id>last){addItem(a);last=a.id}});
    if(typeof s.lastId==="number"&&s.lastId>last)last=s.lastId;
    if(Array.isArray(s.files)){files.textContent="";if(!s.files.length){files.appendChild(el("span","m","No files yet."))}
      s.files.forEach(function(f){var r=el("div","f");r.appendChild(el("span",null,(f.type==="directory"?"[dir] ":"")+f.name));r.appendChild(el("span",null,f.type==="file"?mb(f.size):""));files.appendChild(r)});
      if(typeof s.usedBytes==="number"&&s.usedBytes>0)foot.textContent="Read-only view of the AI's screen. "+mb(s.usedBytes)+" of 1 GB used."}
  }
  function fromResult(r){return r&&(r.structuredContent||null)}
  async function pollScreen(){try{var r=await request("tools/call",{name:"vm_screen_poll",arguments:{}});render(fromResult(r))}catch(e){}}
  async function pollFeed(){try{var r=await request("tools/call",{name:"vm_live_poll",arguments:{sinceId:last,files:tick%4===0}});render(fromResult(r))}catch(e){foot.textContent="Reconnecting..."}}
  async function loop(){
    if(busy||paused)return;busy=true;tick++;
    await pollScreen(); if(tick%2===0)await pollFeed();
    busy=false;
  }
  window.addEventListener("message",function(ev){
    var m=ev.data;if(!m||m.jsonrpc!=="2.0")return;
    if(m.id!=null&&pending[m.id]&&(m.result!==undefined||m.error)){var p=pending[m.id];delete pending[m.id];m.error?p.rej(new Error(m.error.message||"error")):p.res(m.result);return}
    if(m.method==="ui/notifications/tool-result"){render(fromResult(m.params))}
    if(m.method==="ui/resource-teardown"&&m.id!=null){send({jsonrpc:"2.0",id:m.id,result:{}})}
  });
  pauseBtn.onclick=function(){paused=!paused;pauseBtn.textContent=paused?"Resume":"Pause";if(!paused)loop()};
  function size(){notify("ui/notifications/size-changed",{width:document.documentElement.scrollWidth,height:document.documentElement.scrollHeight})}
  if(window.ResizeObserver)new ResizeObserver(size).observe(document.body);
  request("ui/initialize",{appInfo:{name:"Live VM",version:"2.0.0"},appCapabilities:{},protocolVersion:"2026-01-26"})
    .then(function(){notify("ui/notifications/initialized");size();setInterval(loop,1500);loop()})
    .catch(function(){msg.textContent="This chat app cannot show the live screen. Open the Workspace tab in the app instead.";msg.hidden=false});
})();
</script></html>`;
