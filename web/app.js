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
  go("repos"); pollApprovals(); setInterval(pollApprovals, 8000);
}
function go(tab) {
  state.tab = tab;
  document.querySelectorAll("#tabs button").forEach((b) => b.classList.toggle("active", b.dataset.tab === tab));
  ({ repos, editor, tasks, terminal, approvals, settings }[tab])();
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
