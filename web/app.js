"use strict";
const $ = (s, r = document) => r.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const state = { tab: "repos", me: null, csrf: null, repo: null, path: "", file: null, jobs: [], activeJob: null };

async function api(path, opts = {}) {
  const o = { credentials: "same-origin", headers: {}, ...opts };
  if (o.body && typeof o.body !== "string") { o.body = JSON.stringify(o.body); o.headers["content-type"] = "application/json"; }
  if (state.csrf && o.method && o.method !== "GET") o.headers["x-csrf-token"] = state.csrf;
  const r = await fetch("/api" + path, o);
  const t = await r.text(); let j; try { j = t ? JSON.parse(t) : {}; } catch { j = { raw: t }; }
  if (!r.ok) { const e = new Error(j.error || r.statusText); e.status = r.status; throw e; }
  return j;
}
const view = $("#view");
const setConn = (on) => { const c = $("#conn"); c.textContent = on ? "connected" : "offline"; c.className = "pill " + (on ? "on" : "off"); };

async function boot() {
  try { const m = await api("/me"); state.me = m.user; state.csrf = m.csrf; setConn(true); }
  catch { state.me = null; setConn(false); }
  document.querySelectorAll("#tabs button").forEach((b) => b.addEventListener("click", () => go(b.dataset.tab)));
  if (!state.me) { try { const st = await (await fetch("/api/setup-status")).json(); if (!st.githubConfigured) { location.replace("/setup"); return; } } catch {} }
  const want = new URLSearchParams(location.search).get("tab");
  go(["repos", "editor", "tasks", "terminal", "codespaces", "approvals", "settings"].includes(want) ? want : "repos"); pollApprovals(); setInterval(pollApprovals, 8000);
  document.addEventListener("visibilitychange", () => { if (!document.hidden) pollApprovals(); });
  registerPwa();
}
function registerPwa() {
  if ("serviceWorker" in navigator && (location.protocol === "https:" || location.hostname === "localhost")) navigator.serviceWorker.register("/sw.js").catch(() => {});
  const standalone = matchMedia("(display-mode: standalone)").matches || navigator.standalone;
  if (standalone || localStorage.getItem("uca-install-dismissed")) return;
  const banner = $("#banner"); const ios = /iphone|ipad|ipod/i.test(navigator.userAgent);
  const show = (html, onAction) => { banner.hidden = false; banner.innerHTML = html + `<button class="btn sec" id="bx" aria-label="Dismiss">&times;</button>`; $("#bx").onclick = () => { banner.hidden = true; localStorage.setItem("uca-install-dismissed", "1"); }; if (onAction) onAction(); };
  window.addEventListener("beforeinstallprompt", (e) => { e.preventDefault(); show(`<span class="grow">Install this app on your phone</span><button class="btn" id="bi">Install</button>`, () => { $("#bi").onclick = async () => { e.prompt(); await e.userChoice.catch(() => {}); banner.hidden = true; }; }); });
  if (ios) show(`<span class="grow" style="font-size:14px">Install: tap <b>Share</b>, then <b>Add to Home Screen</b></span>`);
}
function go(tab) {
  state.tab = tab;
  document.querySelectorAll("#tabs button").forEach((b) => b.classList.toggle("active", b.dataset.tab === tab));
  ({ repos, editor, tasks, terminal, codespaces, approvals, settings }[tab])();
}
function needLogin() {
  view.innerHTML = `<div class="card"><h2>Connect GitHub</h2><p class="muted">Sign in with your own GitHub account. No AI API keys are needed or stored.</p><a class="btn" style="display:inline-block;text-decoration:none;padding:12px 16px;border-radius:10px;background:var(--accent);color:#fff" href="/auth/github/login">Sign in with GitHub</a></div>`;
}

async function repos() {
  if (!state.me) return needLogin();
  if (state.repo) return browse();
  view.innerHTML = `<h2>Repositories</h2><div class="card"><input id="q" placeholder="Filter repositories" autocomplete="off"></div><div id="list" class="card muted">Loading...</div>`;
  try {
    const d = await api("/repos"); const items = d.repos || [];
    const draw = (f) => { $("#list").innerHTML = items.filter((r) => r.full_name.toLowerCase().includes(f)).map((r) => `<div class="item" data-r="${esc(r.full_name)}"><div class="n">${esc(r.full_name)}<br><small>${esc(r.description || "")}</small></div><span class="tag">${r.private ? "private" : "public"}</span></div>`).join("") || "No repositories"; $("#list").classList.remove("muted"); };
    draw(""); $("#q").addEventListener("input", (e) => draw(e.target.value.toLowerCase()));
    $("#list").addEventListener("click", (e) => { const it = e.target.closest(".item"); if (it) { state.repo = it.dataset.r; state.path = ""; repos(); } });
  } catch (e) { $("#list").innerHTML = `<span class="err">${esc(e.message)}</span>`; }
}
async function browse() {
  const [o, n] = state.repo.split("/");
  view.innerHTML = `<div class="row"><button class="btn sec" id="back">Back</button><b class="grow" style="overflow:hidden;text-overflow:ellipsis">${esc(state.repo)}</b></div><div class="crumbs" id="cr"></div><div class="card" id="list">Loading...</div><div class="card"><div class="row wrap"><input class="grow" id="srch" placeholder="Search code in this repo"><button class="btn" id="go">Search</button></div><div id="res"></div></div>`;
  $("#back").onclick = () => { state.repo = null; repos(); };
  const parts = state.path ? state.path.split("/") : [];
  $("#cr").innerHTML = `<a href="#" data-p="">root</a>` + parts.map((p, i) => ` / <a href="#" data-p="${esc(parts.slice(0, i + 1).join("/"))}">${esc(p)}</a>`).join("");
  $("#cr").onclick = (e) => { const a = e.target.closest("a"); if (a) { e.preventDefault(); state.path = a.dataset.p; browse(); } };
  try {
    const d = await api(`/repos/${o}/${n}/contents?path=${encodeURIComponent(state.path)}`);
    const list = Array.isArray(d.entries) ? d.entries : [];
    list.sort((a, b) => (a.type === b.type ? a.name.localeCompare(b.name) : a.type === "dir" ? -1 : 1));
    $("#list").innerHTML = list.map((x) => `<div class="item" data-t="${x.type}" data-p="${esc(x.path)}"><span class="n">${x.type === "dir" ? "&#128193;" : "&#128196;"} ${esc(x.name)}</span><small>${x.type === "file" ? (x.size ?? "") : ""}</small></div>`).join("") || "Empty";
    $("#list").onclick = (e) => { const it = e.target.closest(".item"); if (!it) return; if (it.dataset.t === "dir") { state.path = it.dataset.p; browse(); } else openFile(it.dataset.p); };
  } catch (e) { $("#list").innerHTML = `<span class="err">${esc(e.message)}</span>`; }
  $("#go").onclick = async () => {
    $("#res").innerHTML = "Searching...";
    try { const d = await api(`/search?repo=${encodeURIComponent(state.repo)}&q=${encodeURIComponent($("#srch").value)}`);
      $("#res").innerHTML = (d.items || []).map((i) => `<div class="item" data-p="${esc(i.path)}"><span class="n">${esc(i.path)}</span></div>`).join("") || "<p class='muted'>No results</p>";
      $("#res").onclick = (e) => { const it = e.target.closest(".item"); if (it) openFile(it.dataset.p); };
    } catch (e) { $("#res").innerHTML = `<span class="err">${esc(e.message)}</span>`; }
  };
}
async function openFile(p) {
  const [o, n] = state.repo.split("/");
  try { const d = await api(`/repos/${o}/${n}/file?path=${encodeURIComponent(p)}`); state.file = { repo: state.repo, path: p, sha: d.sha, text: d.text, dirty: false, truncated: d.truncated }; go("editor"); }
  catch (e) { alert(e.message); }
}
function editor() {
  const f = state.file;
  if (!f) { view.innerHTML = `<div class="card muted">Open a file from Repos to edit it.</div>`; return; }
  view.innerHTML = `<div class="card"><b style="word-break:break-all">${esc(f.repo)}:${esc(f.path)}</b>${f.truncated ? `<p class="err">File is large; only part is loaded. Editing is disabled to avoid data loss.</p>` : ""}</div><textarea id="ed" spellcheck="false" ${f.truncated ? "readonly" : ""}>${esc(f.text)}</textarea><div class="card"><input id="msg" placeholder="Commit message" value="Update ${esc(f.path)}"><input id="br" placeholder="Branch (blank = default)" style="margin-top:8px"><div class="row" style="margin-top:8px"><button class="btn grow" id="save" ${f.truncated ? "disabled" : ""}>Commit and push</button></div><p id="st" class="muted"></p></div>`;
  $("#ed").addEventListener("input", (e) => { f.text = e.target.value; f.dirty = true; });
  $("#save").onclick = async () => {
    const [o, n] = f.repo.split("/"); $("#st").textContent = "Saving...";
    try { const d = await api(`/repos/${o}/${n}/file`, { method: "PUT", body: { path: f.path, text: f.text, sha: f.sha, message: $("#msg").value, branch: $("#br").value || undefined } }); f.sha = d.sha; f.dirty = false; $("#st").textContent = "Committed " + (d.commit || ""); }
    catch (e) { $("#st").innerHTML = `<span class="err">${esc(e.message)}</span>`; }
  };
}
async function tasks() {
  if (!state.me) return needLogin();
  view.innerHTML = `<h2>Tasks and builds</h2><div id="jobs" class="card muted">Loading...</div><div class="card"><div class="row"><input class="grow" id="rr" placeholder="owner/repo" value="${esc(state.repo || "")}"><button class="btn sec" id="runs">Workflow runs</button></div><div id="wr"></div></div>`;
  try { const d = await api("/jobs"); $("#jobs").classList.remove("muted"); $("#jobs").innerHTML = (d.jobs || []).map((j) => `<div class="item" data-id="${esc(j.id)}"><div class="n">${esc(j.command)}<br><small>${esc(j.status)}${j.exitCode != null ? " exit " + j.exitCode : ""}</small></div><span class="tag">${esc(j.status)}</span></div>`).join("") || "No running tasks"; $("#jobs").onclick = (e) => { const it = e.target.closest(".item"); if (it) { state.activeJob = it.dataset.id; go("terminal"); } }; }
  catch (e) { $("#jobs").innerHTML = `<span class="err">${esc(e.message)}</span>`; }
  $("#runs").onclick = async () => { const [o, n] = $("#rr").value.split("/"); try { const d = await api(`/repos/${o}/${n}/runs`); $("#wr").innerHTML = (d.runs || []).map((r) => `<div class="item"><div class="n">${esc(r.name)}<br><small>${esc(r.head_branch)} #${r.run_number}</small></div><span class="tag ${r.conclusion === "success" ? "approved" : r.conclusion ? "denied" : "pending"}">${esc(r.conclusion || r.status)}</span></div>`).join("") || "No runs"; } catch (e) { $("#wr").innerHTML = `<span class="err">${esc(e.message)}</span>`; } };
}
async function terminal() {
  if (!state.me) return needLogin();
  view.innerHTML = `<h2>Terminal</h2><div class="card"><div class="row"><input class="grow" id="cmd" placeholder="e.g. npm test" autocapitalize="off" autocorrect="off" spellcheck="false"><button class="btn" id="run">Run</button></div><p class="muted" style="font-size:13px">Commands run in your isolated workspace. Risky commands wait for your approval.</p></div><pre class="term" id="out">${state.activeJob ? "Loading job..." : "No output yet."}</pre>`;
  const out = $("#out");
  const show = (r) => { out.textContent = [r.stdout, r.stderr].filter(Boolean).join("\n") + (r.truncated ? "\n[output truncated; full log kept in workspace]" : "") + (r.decision === "approval" ? "\n[waiting for approval in the Approvals tab]" : ""); out.scrollTop = out.scrollHeight; };
  $("#run").onclick = async () => { out.textContent = "Running..."; try { show(await api("/exec", { method: "POST", body: { command: $("#cmd").value } })); } catch (e) { out.textContent = e.message; } };
  if (state.activeJob) { try { show(await api(`/jobs/${state.activeJob}/output`)); } catch (e) { out.textContent = e.message; } }
}
async function approvals() {
  if (!state.me) return needLogin();
  view.innerHTML = `<h2>Approvals</h2><div id="ap" class="card muted">Loading...</div>`;
  const draw = async () => { const d = await api("/approvals"); $("#ap").classList.remove("muted"); $("#ap").innerHTML = (d.approvals || []).map((a) => `<div class="card"><b>${esc(a.action)}</b><pre class="term" style="max-height:140px">${esc(a.detail)}</pre><div class="row"><span class="tag ${a.status}">${a.status}</span>${a.status === "pending" ? `<span class="grow"></span><button class="btn bad" data-d="${a.id}">Deny</button><button class="btn ok" data-a="${a.id}">Approve</button>` : ""}</div></div>`).join("") || "Nothing pending"; };
  try { await draw(); $("#ap").onclick = async (e) => { const id = e.target.dataset.a || e.target.dataset.d; if (!id) return; await api(`/approvals/${id}/${e.target.dataset.a ? "approve" : "deny"}`, { method: "POST", body: {} }); draw(); pollApprovals(); }; }
  catch (e) { $("#ap").innerHTML = `<span class="err">${esc(e.message)}</span>`; }
}
async function pollApprovals() {
  if (!state.me) return;
  try { const d = await api("/approvals"); const n = (d.approvals || []).filter((a) => a.status === "pending").length; const b = $("#badge"); b.hidden = n === 0; b.textContent = n; setConn(true); } catch { setConn(false); }
}


async function providerKeys(host) {
  host.innerHTML = `<div class="card"><b>Provider keys (other VMs)</b><p class="muted" style="font-size:13px;margin:4px 0 8px">Paste a key here, <b>not in the chat</b>. It is kept only in this server's memory. It is never saved to disk and your AI never sees it. It is wiped when you sign out, revoke access or the server restarts. Once added, your AI searches that provider's docs to learn how to use it.</p><div id="pk" class="muted"><span class="spin"></span></div></div>`;
  const draw = async () => {
    let d; try { d = await api("/providers"); } catch (e) { $("#pk").innerHTML = `<span class="err">${esc(e.message)}</span>`; return; }
    $("#pk").classList.remove("muted");
    const have = new Set((d.added || []).map((a) => a.id));
    $("#pk").innerHTML =
      ((d.added || []).map((a) => `<div class="item" style="cursor:default" data-id="${esc(a.id)}"><div class="n"><span class="dot on"></span>${esc(a.label)}<br><small>${esc(a.hosts.join(", "))} &middot; key #${esc(a.fingerprint)}</small></div><span class="row"><button class="btn sec" data-v="${esc(a.id)}">Test</button><button class="btn bad" data-r="${esc(a.id)}">Forget</button></span></div><div class="muted" data-m="${esc(a.id)}" style="font-size:13px;padding:0 4px"></div>`).join("") || `<p class="muted">No provider keys added.</p>`) +
      `<form id="pf" autocomplete="off" style="margin-top:10px"><label class="muted" style="font-size:13px">Provider</label>
        <select id="ps"><option value="">Choose a recommended provider...</option>${(d.presets || []).filter((p) => !have.has(p.id)).map((p) => `<option value="${esc(p.id)}">${esc(p.label)}${p.note ? " - " + esc(p.note) : ""}</option>`).join("")}<option value="__other">Other (type any provider)</option></select>
        <div id="oth" hidden><input id="pl" placeholder="Provider name, e.g. Vultr" maxlength="60" style="margin-top:8px"><input id="ph" placeholder="API hostname, e.g. api.vultr.com" style="margin-top:8px" autocapitalize="off" autocorrect="off" spellcheck="false"><p class="muted" style="font-size:12px;margin:4px 0">Your key will only ever be sent to this hostname.</p></div>
        <input id="pkey" type="password" placeholder="Paste API key" autocomplete="new-password" autocapitalize="off" autocorrect="off" spellcheck="false" style="margin-top:8px">
        <button class="btn" style="margin-top:8px;width:100%" type="submit">Add key (memory only)</button><div id="pmsg" style="margin-top:6px"></div></form>`;
    $("#ps").onchange = (e) => { $("#oth").hidden = e.target.value !== "__other"; };
    $("#pf").onsubmit = async (e) => {
      e.preventDefault(); const sel = $("#ps").value; const msg = $("#pmsg"); if (!sel) { msg.innerHTML = `<span class="err">Choose a provider.</span>`; return; }
      const body = { key: $("#pkey").value };
      if (sel === "__other") { body.label = $("#pl").value; body.hosts = [$("#ph").value]; } else body.id = sel;
      $("#pkey").value = ""; // clear the secret from the page immediately
      try { const r = await api("/providers", { method: "POST", body }); msg.innerHTML = `<span style="color:var(--ok)">Added ${esc(r.label)}. Tell your AI: "I added ${esc(r.label)}, learn how to use it."</span>`; setTimeout(draw, 900); }
      catch (err) { msg.innerHTML = `<span class="err">${esc(err.message)}</span>`; }
    };
  };
  await draw();
  $("#pk").onclick = async (e) => {
    const r = e.target.dataset.r, v = e.target.dataset.v;
    if (r && confirm("Forget this key now?")) { await api(`/providers/${encodeURIComponent(r)}`, { method: "DELETE" }); draw(); }
    if (v) { const m = $(`[data-m="${v}"]`); m.textContent = "Testing..."; try { const x = await api(`/providers/${encodeURIComponent(v)}/verify`, { method: "POST", body: {} }); m.innerHTML = x.ok === true ? `<span style="color:var(--ok)">Key works (HTTP ${x.status}).</span>` : x.ok === false ? `<span class="err">Rejected${x.status ? " (HTTP " + x.status + ")" : ""}${x.message ? ": " + esc(x.message) : ""}</span>` : esc(x.message); } catch (err) { m.innerHTML = `<span class="err">${esc(err.message)}</span>`; } }
  };
}
async function codespaces() {
  if (!state.me) return needLogin();
  view.innerHTML = `<h2>Cloud Linux VM (Codespaces)</h2><p class="muted" style="margin:0 4px 8px">Let the AI run commands, edit files and use git inside a real Linux Codespace.</p><div id="cs" class="muted"><span class="spin"></span> Loading...</div><div id="pkh"></div>`;
  providerKeys($("#pkh"));
  const draw = async () => {
    let d; try { d = await api("/codespaces"); } catch (e) { $("#cs").innerHTML = `<div class="card err">${esc(e.message)}</div>`; return; }
    const list = d.codespaces || [];
    $("#cs").classList.remove("muted");
    $("#cs").innerHTML = (d.ghError ? `<div class="card err">GitHub said: ${esc(d.ghError)}<br><span class="muted">Sign out and in again to grant the Codespaces permission.</span></div>` : "") +
      (list.map((c) => `<div class="card" data-n="${esc(c.name)}"><div class="row"><span class="dot ${c.online ? "on" : ""}"></span><b class="grow" style="overflow:hidden;text-overflow:ellipsis">${esc(c.name)}</b><span class="tag">${esc(c.state || (c.online ? "Available" : "unknown"))}</span></div>
        <div class="muted" style="font-size:13px;margin:4px 0 8px">${esc(c.repo || "")} ${c.paired ? (c.online ? "&middot; AI agent online" : "&middot; paired, agent offline") : "&middot; not connected to AI yet"}</div>
        <div class="row wrap">${c.paired ? `<button class="btn sec" data-a="detach">Disconnect</button>` : ""}<button class="btn" data-a="attach">${c.paired && !c.online ? "Reconnect" : c.paired ? "Re-pair" : "Connect to AI"}</button>
        ${c.state === "Shutdown" || c.state === "Stopped" ? `<button class="btn sec" data-a="start">Start</button>` : c.state === "Available" ? `<button class="btn sec" data-a="stop">Stop</button>` : ""}</div><div class="out"></div></div>`).join("") || `<div class="card muted">No Codespaces found. Create one on github.com/codespaces, or ask your AI to call <code>codespaces_create</code>.</div>`);
  };
  await draw();
  $("#cs").onclick = async (e) => {
    const a = e.target.dataset.a; const card = e.target.closest("[data-n]"); if (!a || !card) return; const n = card.dataset.n; const out = $(".out", card); e.target.disabled = true;
    try {
      if (a === "attach") {
        const r = await api(`/codespaces/${encodeURIComponent(n)}/attach`, { method: "POST", body: {} });
        out.innerHTML = `<p class="muted" style="font-size:13px">Open this Codespace's terminal, paste this once (valid 10 min, single use):</p><div class="copy"><code>${esc(r.command)}</code><button class="btn sec" data-copy>Copy</button></div>`;
        out.querySelector("[data-copy]").onclick = async (ev) => { try { await navigator.clipboard.writeText(r.command); ev.target.textContent = "Copied"; } catch { ev.target.textContent = "Press and hold the text to copy"; } };
        const t0 = Date.now(); const poll = setInterval(async () => { if (Date.now() - t0 > 600000 || !document.contains(out)) return clearInterval(poll); try { const d = await api("/codespaces"); if ((d.codespaces || []).find((c) => c.name === n && c.online)) { clearInterval(poll); draw(); } } catch {} }, 3000);
      } else { await api(`/codespaces/${encodeURIComponent(n)}/${a}`, { method: "POST", body: {} }); if (a === "start" || a === "stop") setTimeout(draw, 1500); else draw(); }
    } catch (err) { out.innerHTML = `<span class="err">${esc(err.message)}</span>`; }
    e.target.disabled = false;
  };
}
async function settings() {
  if (!state.me) return needLogin();
  view.innerHTML = `<h2>Settings</h2><div class="card"><b>${esc(state.me.login)}</b><p class="muted">Signed in with GitHub</p><button class="btn sec" id="out">Sign out</button></div><div class="card"><b>Connected AI clients</b><div id="gr" class="muted">Loading...</div></div><div class="card"><b>MCP endpoint</b><pre class="term" id="ep"></pre><p class="muted" style="font-size:13px">Add this URL as a custom MCP connector. You will be asked to approve access here.</p></div><div class="card"><button class="btn bad" id="all">Revoke all access</button></div>`;
  $("#ep").textContent = location.origin + "/mcp";
  $("#out").onclick = async () => { await api("/logout", { method: "POST", body: {} }); location.reload(); };
  const draw = async () => { const d = await api("/grants"); $("#gr").classList.remove("muted"); $("#gr").innerHTML = (d.grants || []).map((g) => `<div class="item"><div class="n">${esc(g.clientName || g.clientId)}<br><small>${esc((g.scopes || []).join(" "))}</small></div><button class="btn sec" data-c="${esc(g.clientId)}">Revoke</button></div>`).join("") || "None"; };
  try { await draw(); $("#gr").onclick = async (e) => { const c = e.target.dataset.c; if (c) { await api(`/grants/${encodeURIComponent(c)}/revoke`, { method: "POST", body: {} }); draw(); } }; } catch (e) { $("#gr").innerHTML = `<span class="err">${esc(e.message)}</span>`; }
  $("#all").onclick = async () => { if (confirm("Revoke every connected AI client and token?")) { await api("/revoke-all", { method: "POST", body: {} }); draw(); } };
}
boot();
