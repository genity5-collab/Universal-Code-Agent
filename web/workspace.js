/* Workspace tab: VM control, live view of what the AI does in the VM, file browser, downloads, 1 GB usage. No inline script (CSP). */
(function () {
  const $ = (s, r = document) => r.querySelector(s);
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const mb = (n) => (n / 1048576 >= 100 ? (n / 1048576).toFixed(0) : (n / 1048576).toFixed(1)) + " MB";
  const ico = { command: "&#9000;", file: "&#9998;", read: "&#128065;", git: "&#9095;", vm: "&#9729;", other: "&#8226;" };
  let es = null, dir = ".";

  window.workspaceTab = async function workspaceTab() {
    const view = $("#view"); if (es) { es.close(); es = null; }
    view.innerHTML = `<div class="card"><h2>Workspace</h2><p class="muted">The AI works only inside your VM. Everything it does shows here live, and the files stay in the VM so you can download them.</p><div id="vmbox"></div></div>
      <div class="card"><h3 style="margin:0 0 8px">VM screen</h3><div id="screenbox"></div></div>
      <div class="card"><h3 style="margin:0 0 8px">Activity</h3><div id="live" class="live" role="log" aria-live="polite"><span class="muted">Waiting for the AI to act...</span></div></div>
      <div class="card"><h3 style="margin:0 0 8px">Files</h3><div id="use"></div><div id="crumb" class="muted" style="margin:6px 0"></div><div id="files"></div></div>`;
    if (stopScreen) { stopScreen(); stopScreen = null; }
    await drawVm(); stopScreen = mountScreen($("#screenbox"), { control: true }); startLive(); loadFiles(".");
  };


  /* The VM's real desktop: a live picture (refreshed about every 1.5 s), click on it to click in the VM, a box to type, quick keys. */
  function mountScreen(root, opts) {
    opts = opts || {}; let stop = false, w = 0, h = 0, url = null, mode = "frames", fails = 0;
    root.innerHTML = `<div class="scr"><img class="scr-img" alt="Live screen of your VM" hidden><iframe class="scr-live" title="Live VM desktop" hidden allow="clipboard-read; clipboard-write" referrerpolicy="no-referrer"></iframe><div class="scr-msg muted">Connecting to the VM screen...</div><span class="scr-badge" hidden></span><button type="button" class="scr-fs" aria-label="Fullscreen">&#x26F6;</button></div>` +
      (opts.control ? `<div class="scr-ctl"><input class="scr-type" placeholder="Type into the VM, then press Send" aria-label="Text to type"><button type="button" class="scr-send">Send</button><button type="button" data-k="Return">Enter</button><button type="button" data-k="Tab">Tab</button><button type="button" data-k="Escape">Esc</button><button type="button" class="scr-start secondary">Start desktop</button></div>` : "");
    const img = root.querySelector(".scr-img"), msg = root.querySelector(".scr-msg"), live = root.querySelector(".scr-live"), badge = root.querySelector(".scr-badge");
    const fsb = root.querySelector(".scr-fs"), box0 = root.querySelector(".scr");
    if (fsb) fsb.onclick = () => { const d = document; if (d.fullscreenElement) d.exitFullscreen(); else if (box0.requestFullscreen) box0.requestFullscreen().catch(() => box0.classList.toggle("scr-full")); else box0.classList.toggle("scr-full"); };
    const say = (t) => { msg.hidden = false; msg.textContent = t; };
    /* 1) InstaBox's own real-time viewer (true video + mouse + keyboard) when the key is allowed to make one. */
    async function tryLive() {
      try {
        const r = await api("/desktop/stream", { method: "POST", body: { control: !!opts.control } });
        if (r && r.available && /^https:\/\//.test(r.url)) { live.src = r.url; live.hidden = false; img.hidden = true; msg.hidden = true; mode = "live"; badge.hidden = false; badge.textContent = "LIVE"; return true; }
      } catch (e) { /* fall through to fast frames */ }
      return false;
    }
    /* 2) Fast frames: the next frame is requested the moment the last one has arrived, so speed is limited only by the network. */
    async function loop() {
      let shown = 0, t0 = Date.now();
      while (!stop && mode === "frames") {
        if (document.hidden) { await new Promise((r) => setTimeout(r, 500)); continue; }
        const t = Date.now();
        try {
          const r = await fetch("/api/desktop/frame", { credentials: "same-origin", cache: "no-store" });
          if (!r.ok) { let e = ""; try { e = (await r.json()).error || ""; } catch (x) {} throw new Error(e || "Screen not available"); }
          const blob = await r.blob(); const u = URL.createObjectURL(blob); const old = url; url = u;
          await new Promise((ok) => { img.onload = img.onerror = ok; img.src = u; }); if (old) URL.revokeObjectURL(old);
          img.hidden = false; msg.hidden = true; fails = 0; shown++;
          const nat = img.naturalWidth; if (nat) { w = nat; h = img.naturalHeight; }
          if (Date.now() - t0 > 2000) { badge.hidden = false; badge.textContent = (shown / ((Date.now() - t0) / 1000)).toFixed(1) + " fps"; shown = 0; t0 = Date.now(); }
          const spent = Date.now() - t; if (spent < 80) await new Promise((r2) => setTimeout(r2, 80 - spent));
        } catch (e) {
          fails++; if (img.hidden || fails > 3) say(/not started|desktop|screenshot|input/i.test(e.message) ? "The desktop is not started yet. Press Start desktop (or the AI will start it)." : e.message);
          await new Promise((r2) => setTimeout(r2, Math.min(4000, 700 * fails)));
        }
      }
    }
    (async () => { if (!(await tryLive())) loop(); })();
    if (opts.control) {
      const send = (body) => api("/desktop/input", { method: "POST", body }).catch((e) => say(e.message));
      img.onclick = (ev) => { if (!w || !h) return; const r = img.getBoundingClientRect(); send({ type: "click", x: Math.round(((ev.clientX - r.left) / r.width) * w), y: Math.round(((ev.clientY - r.top) / r.height) * h) }); };
      const ti = root.querySelector(".scr-type");
      root.querySelector(".scr-send").onclick = () => { if (ti.value) { send({ type: "type", text: ti.value }); ti.value = ""; } };
      ti.onkeydown = (ev) => { if (ev.key === "Enter") { ev.preventDefault(); root.querySelector(".scr-send").click(); } };
      root.querySelectorAll("button[data-k]").forEach((b) => (b.onclick = () => send({ type: "key", keys: [b.dataset.k] })));
      root.querySelector(".scr-start").onclick = async (ev) => { const b = ev.target; b.disabled = true; b.textContent = "Starting..."; try { await api("/desktop/start", { method: "POST", body: {} }); if (mode === "frames") { fails = 0; } else if (!(await tryLive())) { mode = "frames"; live.hidden = true; loop(); } } catch (e) { say(e.message); } b.disabled = false; b.textContent = "Start desktop"; };
    }
    return () => { stop = true; if (url) URL.revokeObjectURL(url); live.src = "about:blank"; };
  }
  let stopScreen = null;

  async function drawVm() {
    const box = $("#vmbox"); let s; try { s = await api("/vm"); } catch (e) { box.innerHTML = `<span class="err">${esc(e.message)}</span>`; return; }
    if (!s.hasKey) { box.innerHTML = `<p><b>No VM yet.</b> The AI cannot read, write or run anything until you add an InstaBox key.</p><ol class="muted"><li>Create an API key at <a href="https://dashboard.instabox.sh/dashboard/api-keys" target="_blank" rel="noopener">instabox.sh</a> with machines read, write and delete.</li><li>Open <b>Cloud</b>, then <b>Provider keys</b>, choose <b>InstaBox</b> and paste it.</li><li>Come back here and press Start VM.</li></ol><p class="muted">The key is kept in server memory only and your AI never sees it.</p>`; return; }
    if (!s.running) { box.innerHTML = `<p>Key added. <b>No VM is running.</b></p><button id="vmstart">Start new VM</button> <button id="vmwin" class="secondary" type="button">Live window</button> <span id="vmmsg" class="muted"></span><div style="margin-top:10px"><b>Or use a workspace you already have</b><div class="scr-ctl"><select id="vmpick" aria-label="Existing workspace"><option value="">Loading your machines...</option></select><button id="vmattach" type="button" class="secondary" disabled>Use this workspace</button></div><p class="muted">It is only connected, never deleted. Stop just disconnects it.</p></div>`;
      api("/vm/machines").then((r) => { const sel = $("#vmpick"); if (!sel) return; const ms = r.machines || []; sel.innerHTML = ms.length ? `<option value="">Choose a machine</option>` + ms.map((x) => `<option value="${esc(x.id)}">${esc(x.name)} (${esc(x.state)})</option>`).join("") : `<option value="">No machines found</option>`; sel.onchange = () => { $("#vmattach").disabled = !sel.value; }; }).catch((e) => { const sel = $("#vmpick"); if (sel) sel.innerHTML = `<option value="">${esc(e.message)}</option>`; });
      $("#vmattach").onclick = async () => { const id = $("#vmpick").value; if (!id) return; $("#vmattach").disabled = true; $("#vmmsg").textContent = "Connecting..."; try { await api("/vm/attach", { method: "POST", body: { machineId: id } }); workspaceTab(); } catch (e) { $("#vmattach").disabled = false; $("#vmmsg").innerHTML = `<span class="err">${esc(e.message)}</span>`; } };
      $("#vmwin").onclick = openWindow;
      $("#vmstart").onclick = async () => { $("#vmstart").disabled = true; $("#vmmsg").textContent = "Starting..."; try { await api("/vm/start", { method: "POST", body: {} }); workspaceTab(); } catch (e) { $("#vmstart").disabled = false; $("#vmmsg").innerHTML = `<span class="err">${esc(e.message)}</span>`; } }; return; }
    box.innerHTML = `<p><span class="dot on"></span> <b>VM running</b> <span class="muted">${esc(s.machineId || "")}</span></p><button id="vmwin" class="secondary" type="button">Live window</button> <button id="vmstop" class="danger">${s.attached ? "Disconnect" : "Stop VM"}</button><p class="muted">${s.attached ? "This is your existing workspace. Disconnecting never deletes it." : "Stopping deletes the files inside it. Download what you need first."}</p>`;
    $("#vmwin").onclick = openWindow;
    $("#vmstop").onclick = async () => { if (s.attached || confirm("Stop the VM? Files inside it will be lost.")) { await api("/vm/stop", { method: "POST", body: {} }); workspaceTab(); } };
  }

  function line(a) {
    const t = new Date(a.t).toLocaleTimeString();
    const out = a.output ? `<pre class="out">${esc(a.output)}</pre>` : "";
    return `<div class="act ${a.ok ? "" : "bad"}"><span class="ai">${ico[a.kind] || ico.other}</span><div><div><b>${esc(a.summary)}</b> <span class="muted">${t}${a.ms ? " · " + a.ms + " ms" : ""}${a.bytes != null ? " · " + a.bytes + " B" : ""}</span></div>${out}</div></div>`;
  }
  function startLive() {
    const live = $("#live"); let first = true;
    es = new EventSource("/api/activity/stream");
    es.onmessage = (ev) => {
      let d; try { d = JSON.parse(ev.data); } catch { return; }
      if (d.hello) { if (d.items.length) live.innerHTML = d.items.map(line).join(""); live.scrollTop = live.scrollHeight; return; }
      if (first) { if (live.querySelector(".muted") && !live.querySelector(".act")) live.innerHTML = ""; first = false; }
      live.insertAdjacentHTML("beforeend", line(d)); live.scrollTop = live.scrollHeight;
      if (d.kind === "file" || d.kind === "command" || d.kind === "git") loadFiles(dir);
      if (d.kind === "vm") drawVm();
    };
    es.onerror = () => { /* the browser reconnects by itself */ };
  }


  /* Floating "Live VM window": stays on top on every tab, shows the same stream, closes with the X. */
  let wes = null;
  let unmountWin = null;
  function closeWindow() { if (wes) { wes.close(); wes = null; } if (unmountWin) { unmountWin(); unmountWin = null; } const w = document.getElementById("vmlivewin"); if (w) w.remove(); }
  window.closeVmWindow = closeWindow;
  function openWindow() {
    if (document.getElementById("vmlivewin")) return;
    const w = document.createElement("div"); w.id = "vmlivewin"; w.className = "vmwin"; w.setAttribute("role", "dialog"); w.setAttribute("aria-label", "Live VM window");
    w.innerHTML = `<div class="vmwin-h"><span class="dot on"></span><b>Live VM</b><span class="grow"></span><button type="button" id="vmwin-min" aria-label="Minimise">_</button><button type="button" id="vmwin-x" aria-label="Close">&times;</button></div><div class="vmwin-b"><div id="vmwin-screen"></div><details class="vmwin-log"><summary class="muted">Activity</summary><div id="vmwin-live" class="live" role="log" aria-live="polite"><span class="muted">Waiting for the AI to act...</span></div></details></div>`;
    document.body.appendChild(w);
    const box = w.querySelector("#vmwin-live"); let empty = true; unmountWin = mountScreen(w.querySelector("#vmwin-screen"), { control: false });
    w.querySelector("#vmwin-x").onclick = closeWindow;
    w.querySelector("#vmwin-min").onclick = () => w.classList.toggle("min");
    wes = new EventSource("/api/activity/stream");
    wes.onmessage = (ev) => {
      let d; try { d = JSON.parse(ev.data); } catch { return; }
      if (d.hello) { if (d.items.length) { box.innerHTML = d.items.map(line).join(""); empty = false; } box.scrollTop = box.scrollHeight; return; }
      if (empty) { box.innerHTML = ""; empty = false; }
      box.insertAdjacentHTML("beforeend", line(d)); box.scrollTop = box.scrollHeight;
      while (box.children.length > 150) box.removeChild(box.firstChild);
    };
  }

  async function loadFiles(path) {
    dir = path; const box = $("#files"); if (!box) return; let d;
    try { d = await api("/workspace/files?path=" + encodeURIComponent(path)); } catch (e) { box.innerHTML = `<span class="muted">${esc(e.message)}</span>`; $("#use").innerHTML = ""; return; }
    const pct = Math.min(100, Math.round((d.usedBytes / d.limitBytes) * 100));
    $("#use").innerHTML = `<div class="bar" aria-label="Workspace usage"><div class="fill ${pct > 90 ? "hot" : ""}" style="width:${pct}%"></div></div><div class="muted">${mb(d.usedBytes)} of ${mb(d.limitBytes)} used (${pct}%)</div>`;
    const parts = d.path === "." ? [] : d.path.split("/");
    $("#crumb").innerHTML = `<a href="#" data-p=".">workspace</a>` + parts.map((p, i) => ` / <a href="#" data-p="${esc(parts.slice(0, i + 1).join("/"))}">${esc(p)}</a>`).join("");
    box.innerHTML = d.entries.length ? d.entries.map((e) => {
      const rel = d.path === "." ? e.name : d.path + "/" + e.name;
      return `<div class="row"><span>${e.type === "directory" ? `<a href="#" data-p="${esc(rel)}">&#128193; ${esc(e.name)}</a>` : `&#128196; ${esc(e.name)}`}</span><span class="muted">${e.type === "file" ? mb(e.size) : ""}</span><a class="dl" href="/api/workspace/download?path=${encodeURIComponent(rel)}" download>${e.type === "directory" ? "Zip" : "Download"}</a></div>`;
    }).join("") : `<span class="muted">Empty. Files the AI creates will appear here.</span>`;
    document.querySelectorAll("#crumb a[data-p], #files a[data-p]").forEach((a) => (a.onclick = (ev) => { ev.preventDefault(); loadFiles(a.dataset.p); }));
  }
})();
