"use strict";
const esc=(s)=>String(s).replace(/[&<>"']/g,(c)=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const copyRow=(v)=>`<div class="copy"><code>${esc(v)}</code><button class="btn sec" data-copy="${esc(v)}" style="min-width:76px">Copy</button></div>`;
async function draw(){
  let s; try{ s=await (await fetch("/api/setup-status")).json(); }catch{ document.getElementById("m").innerHTML='<div class="card err">Cannot reach the server.</div>'; return; }
  if(s.guestMode&&!s.githubConfigured){
    const st0=document.getElementById("st"); st0.textContent="ready"; st0.className="pill on";
    document.getElementById("m").innerHTML=
      `<div class="card step done"><div class="num">1</div><div class="grow"><b>Copy this link</b><p class="muted">This is your connector link. No account, no API key, nothing to install.</p>${copyRow(s.mcpUrl)}</div></div>`+
      `<div class="card step"><div class="num">2</div><div class="grow"><b>Add it to your AI app</b><ul class="muted" style="padding-left:18px;margin:6px 0"><li><b>Claude</b> (app or claude.ai): Settings, Connectors, Add custom connector, paste the link.</li><li><b>ChatGPT</b>: Settings, Connectors, Advanced, Developer mode, then add the link.</li><li><b>Gemini</b> and others: add it as a remote MCP server with the link.</li></ul></div></div>`+
      `<div class="card step"><div class="num">3</div><div class="grow"><b>Tap Allow</b><p class="muted">Your AI app opens a page here. Tap <b>Allow</b>. That is all. You get a private guest workspace.</p></div></div>`+
      `<div class="card"><b>Good to know</b><p class="muted" style="font-size:13px">Guest workspaces are private to you but this server is shared, so do not put secrets in it. Risky actions (deleting, installing, pushing) still wait for your OK in the <a href="/">app</a>. GitHub features turn on if the owner connects a GitHub app.</p></div>`;
    return;
  }
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
