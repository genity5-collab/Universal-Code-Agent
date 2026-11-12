"use strict";
const esc=(s)=>String(s).replace(/[&<>"']/g,(c)=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const copyRow=(v)=>`<div class="copy"><code>${esc(v)}</code><button class="btn sec" data-copy="${esc(v)}" style="min-width:76px">Copy</button></div>`;
async function draw(){
  let s; try{ s=await (await fetch("/api/setup-status")).json(); }catch{ document.getElementById("m").innerHTML='<div class="card err">Cannot reach the server.</div>'; return; }
  const ready=s.githubConfigured&&!s.needsHttps;
  const st=document.getElementById("st"); st.textContent=ready?"ready":"setup needed"; st.className="pill "+(ready?"on":"off");
  const step=(n,done,title,body)=>`<div class="card step ${done?"done":""}"><div class="num">${done?"&#10003;":n}</div><div class="grow"><b>${title}</b>${body}</div></div>`;
  document.getElementById("m").innerHTML=
   step(1,s.https,"Your server address",`<p class="muted">${s.https?"HTTPS is on, so AI apps can reach this server.":'<span class="warn">This address is not HTTPS.</span> ChatGPT and Claude need a public HTTPS URL. Deploy on Render (see the README) instead of running locally.'}</p>${copyRow(s.baseUrl)}`)+
   step(2,s.githubConfigured,"Create a GitHub OAuth App (2 minutes)",`<p class="muted">This lets you sign in with your own GitHub. No AI keys are needed.</p><ol class="muted" style="padding-left:18px;margin:6px 0"><li>Open the page below and fill the form.</li><li><b>Homepage URL</b>: your server address from step 1.</li><li><b>Authorization callback URL</b>: copy this exactly:</li></ol>${copyRow(s.callbackUrl)}<p><a class="btn" href="${esc(s.newOAuthAppUrl)}" target="_blank" rel="noopener">Open GitHub</a></p><p class="muted">Then click <b>Generate a new client secret</b>.</p>`)+
   step(3,s.githubConfigured,"Give the server the two values",s.githubConfigured?'<p class="muted">Client ID and secret are set.</p>':`<p class="muted">In your host (Render: <b>Environment</b>), set:</p><div class="copy"><code>GITHUB_CLIENT_ID</code></div><div class="copy"><code>GITHUB_CLIENT_SECRET</code></div><p class="muted">Save. The server restarts, then reload this page.</p>`)+
   step(4,false,"Sign in",`<p><a class="btn" href="/auth/github/login">Sign in with GitHub</a></p>`)+
   step(5,false,"Connect your AI",`<p class="muted">Add this URL as a custom MCP connector in Claude, ChatGPT or Gemini, then approve here when asked:</p>${copyRow(s.mcpUrl)}<p class="muted" style="font-size:13px">Claude Code: <code>claude mcp add --transport http universal-code-agent ${esc(s.mcpUrl)}</code></p>`)+
   (s.persistent?"":'<div class="card"><b class="warn">Heads up: no persistent disk detected</b><p class="muted">If your host wipes its disk on restart, you will have to sign in and reconnect your AI each time. On Render use the blueprint (it adds a disk).</p></div>');
}
document.addEventListener("click",async(e)=>{const b=e.target.closest("[data-copy]");if(!b)return;try{await navigator.clipboard.writeText(b.dataset.copy);b.textContent="Copied";}catch{const r=document.createRange();r.selectNodeContents(b.previousElementSibling);getSelection().removeAllRanges();getSelection().addRange(r);b.textContent="Select+copy";}setTimeout(()=>b.textContent="Copy",1500);});
draw();
