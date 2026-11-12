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
      <div class="card"><h3 style="margin:0 0 8px">Live view</h3><div id="live" class="live" role="log" aria-live="polite"><span class="muted">Waiting for the AI to act...</span></div></div>
      <div class="card"><h3 style="margin:0 0 8px">Files</h3><div id="use"></div><div id="crumb" class="muted" style="margin:6px 0"></div><div id="files"></div></div>`;
    await drawVm(); startLive(); loadFiles(".");
  };

  async function drawVm() {
    const box = $("#vmbox"); let s; try { s = await api("/vm"); } catch (e) { box.innerHTML = `<span class="err">${esc(e.message)}</span>`; return; }
    if (!s.hasKey) { box.innerHTML = `<p><b>No VM yet.</b> The AI cannot read, write or run anything until you add an InstaBox key.</p><ol class="muted"><li>Create an API key at <a href="https://dashboard.instabox.sh/dashboard/api-keys" target="_blank" rel="noopener">instabox.sh</a> with machines read, write and delete.</li><li>Open <b>Cloud</b>, then <b>Provider keys</b>, choose <b>InstaBox</b> and paste it.</li><li>Come back here and press Start VM.</li></ol><p class="muted">The key is kept in server memory only and your AI never sees it.</p>`; return; }
    if (!s.running) { box.innerHTML = `<p>Key added. <b>No VM is running.</b></p><button id="vmstart">Start VM</button> <button id="vmwin" class="secondary" type="button">Live window</button> <span id="vmmsg" class="muted"></span>`;
      $("#vmwin").onclick = openWindow;
      $("#vmstart").onclick = async () => { $("#vmstart").disabled = true; $("#vmmsg").textContent = "Starting..."; try { await api("/vm/start", { method: "POST", body: {} }); workspaceTab(); } catch (e) { $("#vmstart").disabled = false; $("#vmmsg").innerHTML = `<span class="err">${esc(e.message)}</span>`; } }; return; }
    box.innerHTML = `<p><span class="dot on"></span> <b>VM running</b> <span class="muted">${esc(s.machineId || "")}</span></p><button id="vmwin" class="secondary" type="button">Live window</button> <button id="vmstop" class="danger">Stop VM</button><p class="muted">Stopping deletes the files inside it. Download what you need first.</p>`;
    $("#vmwin").onclick = openWindow;
    $("#vmstop").onclick = async () => { if (confirm("Stop the VM? Files inside it will be lost.")) { await api("/vm/stop", { method: "POST", body: {} }); workspaceTab(); } };
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
  function closeWindow() { if (wes) { wes.close(); wes = null; } const w = document.getElementById("vmlivewin"); if (w) w.remove(); }
  window.closeVmWindow = closeWindow;
  function openWindow() {
    if (document.getElementById("vmlivewin")) return;
    const w = document.createElement("div"); w.id = "vmlivewin"; w.className = "vmwin"; w.setAttribute("role", "dialog"); w.setAttribute("aria-label", "Live VM window");
    w.innerHTML = `<div class="vmwin-h"><span class="dot on"></span><b>Live VM</b><span class="grow"></span><button type="button" id="vmwin-min" aria-label="Minimise">_</button><button type="button" id="vmwin-x" aria-label="Close">&times;</button></div><div class="vmwin-b"><div id="vmwin-live" class="live" role="log" aria-live="polite"><span class="muted">Waiting for the AI to act...</span></div></div>`;
    document.body.appendChild(w);
    const box = w.querySelector("#vmwin-live"); let empty = true;
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
