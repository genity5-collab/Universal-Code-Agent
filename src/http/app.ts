import http from "node:http";
import nodeCrypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type { Config } from "../util/config.js";
import type { AuthStore } from "../auth/store.js";
import { AuthorizationServer } from "../auth/oauth.js";
import { SessionManager, parseCookies } from "../auth/session.js";
import { GithubTokenVault } from "../auth/tokenvault.js";
import * as GHO from "../github/oauth.js";
import { GitHubClient } from "../github/client.js";
import { CodespacesClient } from "../github/codespaces.js";
import { buildMcpServer, allTools } from "../mcp/server.js";
import { CodespaceBroker } from "../codespace/broker.js";
import { ProviderVault, PRESETS, validateHost, VaultError, type ProviderSpec } from "../providers/vault.js";
import { fetchPublicDoc } from "../providers/docs.js";
import { ApprovalService, AuditLog, RateLimiter } from "../mcp/services.js";
import { type ToolDeps } from "../mcp/tools.js";
import * as R from "../exec/runner.js";
import { evaluateCommand } from "../exec/policy.js";
import { safeSegment, redact } from "../util/paths.js";
import type { UserContext } from "../types.js";

const WEB_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../web");
const MIME: Record<string, string> = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".webmanifest": "application/manifest+json", ".svg": "image/svg+xml", ".png": "image/png", ".ico": "image/x-icon", ".json": "application/json; charset=utf-8", ".txt": "text/plain; charset=utf-8", ".woff2": "font/woff2" };

export interface AppOptions { githubApiBase?: string; githubWebBase?: string; fetchImpl?: typeof fetch; webDir?: string }
export interface App { store: AuthStore; pvault: ProviderVault; broker: CodespaceBroker; server: http.Server; auth: AuthorizationServer; sessions: SessionManager; approvals: ApprovalService; deps: ToolDeps; close(): Promise<void> }

function readBody(req: http.IncomingMessage, limit = 2_000_000): Promise<string> {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => { size += c.length; if (size > limit) { reject(Object.assign(new Error("Body too large"), { status: 413 })); req.destroy(); } else chunks.push(c); });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}
function parseForm(body: string): Record<string, string> { return Object.fromEntries(new URLSearchParams(body)); }
function escHtml(s: string): string { return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c] as string)); }

export function createApp(config: Config, opts: AppOptions = {}): App {
  const auth = new AuthorizationServer(config);
  const store = auth.store;
  const sessions = new SessionManager(store);
  const vault = new GithubTokenVault(store);
  const approvals = new ApprovalService();
  const audit = new AuditLog(config.dataDir);
  const limiter = new RateLimiter(config.rateLimitPerMin);
  const broker = new CodespaceBroker();
  const pvault = new ProviderVault();
  const deps: ToolDeps = { vault: pvault, broker, publicBaseUrl: config.baseUrl, config, approvals, audit, limiter, githubBaseUrl: opts.githubApiBase, fetchImpl: opts.fetchImpl };
  const secure = config.baseUrl.startsWith("https://");
  const fetchImpl = opts.fetchImpl ?? fetch;
  const webDir = opts.webDir ?? WEB_DIR;
  const ghAuthorizeUrl = opts.githubWebBase ? `${opts.githubWebBase}/login/oauth/authorize` : undefined;
  const oauthEndpoints = { clientId: config.githubClientId, clientSecret: config.githubClientSecret, fetchImpl, ...(opts.githubWebBase ? { tokenUrl: `${opts.githubWebBase}/login/oauth/access_token` } : {}), ...(opts.githubApiBase ? { apiBaseUrl: opts.githubApiBase } : {}) };
  const guestCount = () => store.countUsers("guest:");
  const guestLogin = (req: http.IncomingMessage): { cookie: string } | { error: string; status: number } => {
    if (!config.allowGuests) return { error: "Guest mode is off.", status: 403 };
    if (!sessions.loginLimiter.hit(ip(req))) return { error: "Too many attempts. Try again in a minute.", status: 429 };
    if (guestCount() >= config.maxGuests) return { error: "This server has reached its guest limit.", status: 503 };
    const userId = "guest:" + nodeCrypto.randomBytes(9).toString("base64url");
    store.upsertUser({ userId, login: "guest-" + userId.slice(6, 12), name: "Guest" });
    const s2 = sessions.createSession(userId, { userAgent: String(req.headers["user-agent"] ?? ""), ip: ip(req) });
    return { cookie: s2.cookie };
  };
  const authUrl = (state: string) => GHO.buildAuthorizeUrl({ clientId: config.githubClientId, redirectUri: `${config.baseUrl}/auth/github/callback`, scope: config.githubScopes, state, authorizeUrl: ghAuthorizeUrl });
  vault.setRefreshCallback(async (cur) => {
    if (!cur.refreshToken) return null;
    try { const r = await GHO.refreshGithubToken({ ...oauthEndpoints, refreshToken: cur.refreshToken }); if (!r.accessToken) return null; return { accessToken: r.accessToken, scope: r.scope ?? cur.scope, refreshToken: r.refreshToken, expiresAt: r.expiresIn ? Date.now() + r.expiresIn * 1000 : undefined }; } catch { return null; }
  });

  const secHeaders: Record<string, string> = {
    "x-content-type-options": "nosniff", "referrer-policy": "no-referrer", "x-frame-options": "DENY",
    "content-security-policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; form-action 'self' https: http:",
    ...(secure ? { "strict-transport-security": "max-age=31536000; includeSubDomains" } : {}),
  };
  const send = (res: http.ServerResponse, status: number, body: unknown, headers: Record<string, string | string[]> = {}) => {
    const isStr = typeof body === "string";
    const buf = Buffer.from(isStr ? (body as string) : JSON.stringify(body));
    res.writeHead(status, { ...secHeaders, "content-type": isStr ? "text/html; charset=utf-8" : "application/json", "cache-control": "no-store", ...headers });
    res.end(buf);
  };
  const sendHandler = (res: http.ServerResponse, r: { status: number; headers: Record<string, string>; body: unknown }) => send(res, r.status, r.body ?? {}, r.headers);
  const redirect = (res: http.ServerResponse, to: string, extra: Record<string, string | string[]> = {}) => { res.writeHead(302, { ...secHeaders, location: to, "cache-control": "no-store", ...extra }); res.end(); };

  async function ctxForUser(userId: string): Promise<UserContext | null> {
    const user = store.getUser(userId); if (!user) return null;
    const root = path.join(config.workspacesDir, safeSegment(userId.replace(/[^A-Za-z0-9_.-]/g, "_")));
    fs.mkdirSync(root, { recursive: true, mode: 0o700 });
    const tok = await vault.getGithubToken(userId);
    return { userId, login: user.login, workspaceRoot: fs.realpathSync(root), githubToken: tok?.accessToken };
  }
  function ip(req: http.IncomingMessage): string { return req.socket.remoteAddress ?? "unknown"; }

  async function handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const url = new URL(req.url ?? "/", config.baseUrl);
    // Discovery advertises /oauth/<endpoint>; the handlers below are mounted at /<endpoint>. Serve both so no client gets a 404.
    const p = /^\/oauth\/(register|authorize|token|revoke)$/.test(url.pathname) ? url.pathname.slice(6) : url.pathname; const m = req.method ?? "GET";

    // ---- CORS for the PUBLIC protocol endpoints only (browser-based MCP clients). Never for the cookie-authenticated dashboard /api. ----
    const isProtocolPath = p.startsWith("/.well-known/") || p === "/register" || p === "/token" || p === "/revoke" || p === "/mcp";
    if (isProtocolPath) {
      res.setHeader("access-control-allow-origin", "*");
      res.setHeader("access-control-allow-methods", "GET, POST, DELETE, OPTIONS");
      res.setHeader("access-control-allow-headers", "authorization, content-type, mcp-protocol-version, mcp-session-id, accept, last-event-id");
      res.setHeader("access-control-expose-headers", "www-authenticate, mcp-session-id");
      res.setHeader("access-control-max-age", "600");
      if (m === "OPTIONS") { res.writeHead(204); return void res.end(); }
    }

    // ---- discovery ----
    if (p === "/.well-known/oauth-authorization-server" || p === "/.well-known/oauth-authorization-server/mcp" || p === "/.well-known/openid-configuration" || p === "/.well-known/openid-configuration/mcp" || p === "/mcp/.well-known/openid-configuration") return sendHandler(res, auth.metadata());
    if (p === "/.well-known/oauth-protected-resource" || p === "/.well-known/oauth-protected-resource/mcp") return sendHandler(res, auth.protectedResourceMetadata());
    if (p === "/healthz") return send(res, 200, { ok: true });


    // ---- first-run setup wizard (public; shows only booleans and the URLs you must paste into GitHub) ----
    if (p === "/api/setup-status" && m === "GET") {
      const needsHttps = !config.baseUrl.startsWith("https://") && !/^http:\/\/(localhost|127\.0\.0\.1)/.test(config.baseUrl);
      return send(res, 200, {
        baseUrl: config.baseUrl, mcpUrl: `${config.baseUrl}/mcp`, callbackUrl: `${config.baseUrl}/auth/github/callback`,
        githubConfigured: !!(config.githubClientId && config.githubClientSecret), guestMode: config.allowGuests, https: config.baseUrl.startsWith("https://"), needsHttps,
        persistent: process.env.UCA_PERSISTENT === "true",
        newOAuthAppUrl: "https://github.com/settings/applications/new",
      });
    }
    if (p === "/setup" && m === "GET") {
      const f = path.resolve(webDir, "setup.html");
      if (fs.existsSync(f)) { res.writeHead(200, { ...secHeaders, "content-type": MIME[".html"], "cache-control": "no-cache" }); return void res.end(fs.readFileSync(f)); }
    }

    // ---- OAuth 2.1 endpoints ----
    if (p === "/register" && m === "POST") {
      let body: any; try { body = JSON.parse((await readBody(req, 100_000)) || "{}"); } catch { return send(res, 400, { error: "invalid_client_metadata" }); }
      return sendHandler(res, auth.registerClient(body));
    }
    if (p === "/authorize" && m === "GET") {
      const r: any = auth.authorize(Object.fromEntries(url.searchParams));
      if (r.redirectTo) return redirect(res, r.redirectTo);
      if (!r.pending) return sendHandler(res, r);
      const sess = sessions.getSession(parseCookies(req.headers.cookie));
      if (!sess && config.allowGuests && !config.githubClientId) {
        const g = guestLogin(req); if ("error" in g) return send(res, g.status, `<h1>${escHtml(g.error)}</h1>`);
        return redirect(res, `/authorize/consent?pending=${encodeURIComponent(r.pending.id)}`, { "set-cookie": g.cookie });
      }
      if (!sess && config.allowGuests && config.githubClientId) {
        // Both are available: let the person choose. A guest is only created by an explicit POST (never by a link preview).
        return redirect(res, `/authorize/choose?pending=${encodeURIComponent(r.pending.id)}`);
      }
      if (!sess) {
        const tmp = sessions.createSession("anon:" + r.pending.id); // pre-login session binds the GitHub state
        const st = sessions.createOAuthState(tmp.session.id, { redirectTo: `/authorize/consent?pending=${encodeURIComponent(r.pending.id)}` });
        return redirect(res, authUrl(st.state), { "set-cookie": tmp.cookie });
      }
      return redirect(res, `/authorize/consent?pending=${encodeURIComponent(r.pending.id)}`);
    }
    if (p === "/authorize/choose" && m === "GET") {
      const pid = url.searchParams.get("pending") ?? ""; const pend = store.getPending(pid);
      if (!pend || pend.expiresAt < Date.now() || !config.allowGuests) return send(res, 400, "<h1>Authorization request expired. Start again from your AI client.</h1>");
      const html = `<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>Connect</title><style>body{font:16px system-ui;background:#0b0f17;color:#e6edf6;max-width:520px;margin:0 auto;padding:20px}.c{background:#131a26;border:1px solid #243047;border-radius:14px;padding:16px;margin-top:14px}button,a.b{display:block;width:100%;box-sizing:border-box;text-align:center;text-decoration:none;padding:14px;border-radius:10px;border:0;font-size:16px;margin-top:10px;background:#3b82f6;color:#fff}.s{background:#243047}p{color:#9fb0c8}</style><h2>Connect your AI</h2><div class=c><b>Continue as guest</b><p>Fastest. No account, no keys. You get a private workspace for files and commands. GitHub features stay off.</p><form method=post action="/authorize/guest"><input type=hidden name=pending value="${escHtml(pid)}"><button>Continue as guest</button></form></div><div class=c><b>Sign in with GitHub</b><p>Also lets your AI use your repos and Codespaces.</p><a class="b s" href="/authorize/github?pending=${encodeURIComponent(pid)}">Sign in with GitHub</a></div>`;
      return send(res, 200, html);
    }
    if (p === "/authorize/guest" && m === "POST") {
      const f = parseForm(await readBody(req, 5_000)); const pid = String(f.pending ?? ""); const pend = store.getPending(pid);
      if (!pend || pend.expiresAt < Date.now()) return send(res, 400, "<h1>Authorization request expired. Start again from your AI client.</h1>");
      const g = guestLogin(req); if ("error" in g) return send(res, g.status, `<h1>${escHtml(g.error)}</h1>`);
      return redirect(res, `/authorize/consent?pending=${encodeURIComponent(pid)}`, { "set-cookie": g.cookie });
    }
    if (p === "/authorize/github" && m === "GET") {
      const pid = url.searchParams.get("pending") ?? ""; const pend = store.getPending(pid);
      if (!pend || pend.expiresAt < Date.now()) return send(res, 400, "<h1>Authorization request expired. Start again from your AI client.</h1>");
      const tmp = sessions.createSession("anon:" + pid);
      const st = sessions.createOAuthState(tmp.session.id, { redirectTo: `/authorize/consent?pending=${encodeURIComponent(pid)}` });
      return redirect(res, authUrl(st.state), { "set-cookie": tmp.cookie });
    }
    if (p === "/authorize/consent" && m === "GET") {
      const sess = sessions.getSession(parseCookies(req.headers.cookie)); const pid = url.searchParams.get("pending") ?? "";
      const pend = store.getPending(pid);
      if (!sess || sess.userId.startsWith("anon:") || !pend || pend.expiresAt < Date.now()) return send(res, 400, "<h1>Authorization request expired. Start again from your AI client.</h1>");
      const client = store.getClient(pend.clientId);
      const html = `<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>Authorize</title><style>body{font:16px system-ui;background:#0b0f17;color:#e6edf6;max-width:520px;margin:0 auto;padding:20px}.c{background:#131a26;border:1px solid #243047;border-radius:14px;padding:16px}button{font:inherit;padding:14px 18px;border-radius:10px;border:0;margin:6px 6px 0 0;min-height:48px}.a{background:#4f8cff;color:#fff}.d{background:#1a2333;color:#e6edf6}code{background:#1a2333;padding:2px 6px;border-radius:6px}</style><div class=c><h2>Authorize ${escHtml(client?.clientName ?? pend.clientId)}</h2><p>${sess.userId.startsWith("guest:") ? "You are using a <b>guest workspace</b>: a private folder on this server, no account needed. GitHub features stay off until you sign in with GitHub. This AI client will be able to use it through these permissions:" : "Signed in as <b>" + escHtml(sess.login) + "</b>. This AI client will be able to use your GitHub account and workspace through these permissions:"}</p><ul>${pend.scopes.map((s) => `<li><code>${escHtml(s)}</code></li>`).join("")}</ul><p>Sensitive actions (delete, push, risky commands) still need your approval in the dashboard. You can revoke access any time.</p><form method=post action="/authorize/decision"><input type=hidden name=pending value="${escHtml(pid)}"><input type=hidden name=csrf value="${escHtml(sess.csrfToken)}"><button class=a name=decision value=approve>Allow</button><button class=d name=decision value=deny>Deny</button></form></div>`;
      return send(res, 200, html);
    }
    if (p === "/authorize/decision" && m === "POST") {
      const sess = sessions.getSession(parseCookies(req.headers.cookie)); const f = parseForm(await readBody(req, 20_000));
      if (!sess || sess.userId.startsWith("anon:") || !sessions.verifyCsrf(sess, f.csrf)) return send(res, 403, "<h1>Forbidden</h1>");
      const r: any = auth.completeAuthorization(f.pending ?? "", sess.userId, f.decision === "approve");
      return r.redirectTo ? redirect(res, r.redirectTo) : sendHandler(res, r);
    }
    if (p === "/token" && m === "POST") {
      const ct = String(req.headers["content-type"] ?? ""); const raw = await readBody(req, 100_000);
      const body: Record<string, unknown> = ct.includes("json") ? JSON.parse(raw || "{}") : parseForm(raw);
      const authz = req.headers.authorization; if (authz?.startsWith("Basic ")) { const [id, sec] = Buffer.from(authz.slice(6), "base64").toString().split(":"); body.client_id ??= decodeURIComponent(id ?? ""); body.client_secret ??= decodeURIComponent(sec ?? ""); }
      return sendHandler(res, auth.token(body));
    }
    if (p === "/revoke" && m === "POST") return sendHandler(res, auth.revoke(parseForm(await readBody(req, 20_000))));

    // ---- Guest login (no GitHub app, no keys) ----
    if (p === "/auth/guest" && m === "POST") {
      const g = guestLogin(req); if ("error" in g) return send(res, g.status, { error: g.error });
      return send(res, 200, { ok: true }, { "set-cookie": g.cookie });
    }
    // ---- GitHub login ----
    if (p === "/auth/github/login" && m === "GET") {
      if (!config.githubClientId) return send(res, 500, "<h1>GITHUB_CLIENT_ID is not configured</h1>");
      if (!sessions.loginLimiter.hit(ip(req))) return send(res, 429, "<h1>Too many attempts</h1>");
      const tmp = sessions.createSession("anon:login");
      const st = sessions.createOAuthState(tmp.session.id, { redirectTo: "/" });
      return redirect(res, authUrl(st.state), { "set-cookie": tmp.cookie });
    }
    if (p === "/auth/github/callback" && m === "GET") {
      const cookies = parseCookies(req.headers.cookie); const tmp = sessions.getSession(cookies);
      const chk = sessions.consumeOAuthState(url.searchParams.get("state"), tmp?.sessionId ?? null);
      if (!chk.ok || !tmp) return send(res, 400, "<h1>Login state invalid or expired. Please try again.</h1>");
      const code = url.searchParams.get("code"); if (!code) return send(res, 400, "<h1>GitHub denied the request.</h1>");
      try {
        const tok = await GHO.exchangeCode({ ...oauthEndpoints, code, redirectUri: `${config.baseUrl}/auth/github/callback` });
        if (!tok.accessToken) throw new Error(tok.errorDescription || tok.error || "GitHub did not return a token");
        const me = await new GitHubClient(tok.accessToken, { baseUrl: opts.githubApiBase, fetchImpl }).getAuthenticatedUser();
        const userId = `gh:${me.id}`;
        store.upsertUser({ userId, login: me.login, name: (me as any).name ?? undefined, avatarUrl: (me as any).avatarUrl ?? (me as any).avatar_url ?? undefined });
        vault.saveGithubToken(userId, tok.accessToken, tok.scope ?? "", tok.refreshToken, tok.expiresIn ? Date.now() + tok.expiresIn * 1000 : undefined);
        sessions.destroySession(cookies);
        const s = sessions.createSession(userId, { userAgent: String(req.headers["user-agent"] ?? ""), ip: ip(req) });
        return redirect(res, chk.redirectTo ?? "/", { "set-cookie": s.cookie });
      } catch (e: any) {
        // Never strand the user on a dead end: explain, and for an in-progress AI connection offer the guest route again.
        const m2 = /pending=([^&]+)/.exec(chk.redirectTo ?? ""); const pid = m2 ? decodeURIComponent(m2[1]) : "";
        const pend = pid ? store.getPending(pid) : null;
        const guestForm = pend && pend.expiresAt > Date.now() && config.allowGuests ? `<form method=post action="/authorize/guest"><input type=hidden name=pending value="${escHtml(pid)}"><button>Continue as guest instead</button></form>` : "";
        const retry = pend && pend.expiresAt > Date.now() ? `<p><a href="/authorize/choose?pending=${encodeURIComponent(pid)}">Back to the sign-in options</a></p>` : `<p><a href="/">Back to the app</a></p>`;
        return send(res, 502, `<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>GitHub sign-in failed</title><style>body{font:16px system-ui;background:#0b0f17;color:#e6edf6;max-width:520px;margin:0 auto;padding:20px}button{font:inherit;padding:14px 18px;border-radius:10px;border:0;background:#4f8cff;color:#fff;min-height:48px}a{color:#8db4ff}</style><h2>GitHub sign-in failed</h2><p>${escHtml(redact(String(e?.message ?? e)))}</p><p>This usually means the server's GitHub app settings (client ID and secret) do not match. The site owner needs to fix them.</p>${guestForm}${retry}`);
      }
    }


    // ---- Codespace agent endpoints (agent -> server; Bearer pairing token) ----
    if (p === "/agent/install.sh" && m === "GET") {
      const script = `#!/usr/bin/env bash
set -euo pipefail
# Universal Code Agent: installs the Codespace agent. Needs: node >= 18, curl.
: "\${UCA_SERVER:?UCA_SERVER missing}"; : "\${UCA_CLAIM:?UCA_CLAIM missing}"
command -v node >/dev/null || { echo "node is required in this Codespace" >&2; exit 1; }
DIR="\${UCA_HOME:-$HOME/.uca-agent}"; mkdir -p "$DIR"; chmod 700 "$DIR"
curl -fsSL "$UCA_SERVER/agent/uca-agent.mjs" -o "$DIR/uca-agent.mjs"
RESP="$(curl -fsS -X POST -H 'content-type: application/json' -d "{\\"claim\\":\\"$UCA_CLAIM\\"}" "$UCA_SERVER/agent/claim")"
TOKEN="$(printf '%s' "$RESP" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{process.stdout.write(JSON.parse(s).token||"")}catch{}})')"
[ -n "$TOKEN" ] || { echo "Claim rejected (expired or already used). Run codespaces_attach again." >&2; exit 1; }
umask 077
printf 'UCA_SERVER=%s\\nUCA_TOKEN=%s\\n' "$UCA_SERVER" "$TOKEN" > "$DIR/env"
cat > "$DIR/start.sh" <<'EOS'
#!/usr/bin/env bash
DIR="\${UCA_HOME:-$HOME/.uca-agent}"
pgrep -f "$DIR/uca-agent.mjs" >/dev/null && exit 0
set -a; . "$DIR/env"; set +a
nohup node "$DIR/uca-agent.mjs" --root "\${UCA_ROOT:-\${CODESPACE_VSCODE_FOLDER:-$PWD}}" >> "$DIR/agent.log" 2>&1 &
EOS
chmod 700 "$DIR/start.sh"
grep -q "uca-agent/start.sh" "$HOME/.bashrc" 2>/dev/null || echo '[ -x "$HOME/.uca-agent/start.sh" ] && "$HOME/.uca-agent/start.sh" >/dev/null 2>&1' >> "$HOME/.bashrc"
"$DIR/start.sh"
echo "UCA agent started. Log: $DIR/agent.log"
`;
      res.writeHead(200, { ...secHeaders, "content-type": "text/x-shellscript; charset=utf-8", "cache-control": "no-store" });
      return void res.end(script);
    }
    if (p === "/agent/uca-agent.mjs" && m === "GET") {
      const f = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../agent/uca-agent.mjs");
      if (!fs.existsSync(f)) return send(res, 404, { error: "agent_not_found" });
      res.writeHead(200, { ...secHeaders, "content-type": "text/javascript; charset=utf-8", "cache-control": "no-store" });
      return void res.end(fs.readFileSync(f));
    }
    if (p === "/agent/claim" && m === "POST") {
      if (!sessions.loginLimiter.hit("claim:" + ip(req))) return send(res, 429, { error: "too_many_attempts" });
      let b: any; try { b = JSON.parse((await readBody(req, 10_000)) || "{}"); } catch { return send(res, 400, { error: "bad_request" }); }
      const r = broker.redeemClaim(String(b.claim ?? ""));
      return r ? send(res, 200, { token: r.token, codespace: r.codespace }) : send(res, 403, { error: "claim_invalid_or_expired" });
    }
    if (p === "/agent/hello" || p === "/agent/next" || p === "/agent/result") {
      if (m !== "POST") return send(res, 405, { error: "method_not_allowed" });
      const bearer = /^Bearer\s+(.+)$/i.exec(String(req.headers.authorization ?? ""))?.[1];
      const ag = broker.authenticate(bearer);
      if (!ag) return send(res, 401, { error: "invalid_agent_token" });
      let b: any = {}; try { const raw = await readBody(req, 8_000_000); b = raw ? JSON.parse(raw) : {}; } catch { return send(res, 400, { error: "bad_request" }); }
      if (p === "/agent/hello") { broker.hello(ag.key, b.info && typeof b.info === "object" ? b.info : {}); return send(res, 200, { ok: true }); }
      if (p === "/agent/next") { const job = await broker.next(ag.key, 25_000); return job ? send(res, 200, { job }) : send(res, 200, { job: null }); }
      const okDone = broker.complete(ag.key, String(b.jobId ?? ""), b.result && typeof b.result === "object" ? b.result : { ok: false, error: "empty result" });
      return send(res, okDone ? 200 : 404, { ok: okDone });
    }

    // ---- MCP endpoint (Bearer token) ----
    if (p === "/mcp") {
      const a = auth.authorizeRequest({ headers: req.headers });
      if (!a.ok) return sendHandler(res, a.response);
      const ctx = await ctxForUser(a.principal.userId);
      if (!ctx) return send(res, 401, { error: "invalid_token" }, { "www-authenticate": auth.wwwAuthenticate("invalid_token") });
      const raw = m === "POST" ? await readBody(req) : ""; let parsed: unknown; if (raw) { try { parsed = JSON.parse(raw); } catch { return send(res, 400, { jsonrpc: "2.0", error: { code: -32700, message: "Parse error" }, id: null }); } }
      const server = buildMcpServer(ctx, deps, a.principal.scopes);
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
      res.on("close", () => { void transport.close(); void server.close(); });
      await server.connect(transport);
      return transport.handleRequest(req, res, parsed);
    }

    // ---- dashboard JSON API (cookie session + CSRF) ----
    if (p.startsWith("/api/")) return handleApi(req, res, url, p.slice(4), m);

    // ---- static dashboard ----
    if (m === "GET") {
      const rel = p === "/" ? "index.html" : p.replace(/^\/+/, "");
      const file = path.resolve(webDir, rel);
      if (file.startsWith(webDir + path.sep) && fs.existsSync(file) && fs.statSync(file).isFile()) {
        res.writeHead(200, { ...secHeaders, "content-type": MIME[path.extname(file)] ?? "application/octet-stream", "cache-control": "no-cache" });
        return void res.end(fs.readFileSync(file));
      }
    }
    return send(res, 404, { error: "not_found" });
  }

  async function handleApi(req: http.IncomingMessage, res: http.ServerResponse, url: URL, route: string, m: string): Promise<void> {
    const s = sessions.requireSession(m, parseCookies(req.headers.cookie), req.headers);
    if (!s.ok) return send(res, s.status, { error: s.error });
    const pr = s.principal; if (pr.userId.startsWith("anon:")) return send(res, 401, { error: "login_required" });
    const ctx = await ctxForUser(pr.userId); if (!ctx) return send(res, 401, { error: "login_required" });
    const body = async (): Promise<any> => { const r = await readBody(req, 5_000_000); return r ? JSON.parse(r) : {}; };
    const ghc = () => { if (!ctx.githubToken) throw Object.assign(new Error("GitHub not connected"), { status: 400 }); return new GitHubClient(ctx.githubToken, { baseUrl: opts.githubApiBase, fetchImpl }); };
    try {
      if (route === "/me") return send(res, 200, { user: { login: pr.login, userId: pr.userId }, csrf: pr.csrfToken });
      if (route === "/logout" && m === "POST") { pvault.clearUser(ctx.userId); const clear = sessions.destroySession(parseCookies(req.headers.cookie)); return send(res, 200, { ok: true }, { "set-cookie": clear }); }
      if (route === "/repos") { const r: any = await ghc().listRepos("all", undefined, 1, 100, 300); return send(res, 200, { repos: (r.items ?? r).map((x: any) => ({ full_name: x.fullName ?? x.full_name, description: x.description, private: x.private })) }); }
      let mm: RegExpExecArray | null;
      if ((mm = /^\/repos\/([^/]+)\/([^/]+)\/contents$/.exec(route))) {
        const t: any = await ghc().getTree(mm[1], mm[2], undefined, url.searchParams.get("path") ?? "");
        return send(res, 200, { entries: (t.entries ?? t.items ?? []).map((e: any) => ({ name: e.name, path: e.path, type: e.type === "tree" || e.type === "dir" ? "dir" : "file", size: e.size })) });
      }
      if ((mm = /^\/repos\/([^/]+)\/([^/]+)\/file$/.exec(route))) {
        if (m === "GET") { const f: any = await ghc().getContent(mm[1], mm[2], url.searchParams.get("path") ?? "", undefined, { limit: 400_000 }); return send(res, 200, { sha: f.sha, text: f.content ?? f.text ?? "", truncated: !!f.truncated || f.hasMore === true }); }
        if (m === "PUT") { const b = await body(); const r: any = await ghc().createOrUpdateFile(mm[1], mm[2], b.path, { content: b.text, message: b.message || `Update ${b.path}`, sha: b.sha, branch: b.branch }); return send(res, 200, { sha: r.contentSha ?? r.sha ?? r.content?.sha, commit: r.commitSha ?? r.commit?.sha }); }
      }
      if ((mm = /^\/repos\/([^/]+)\/([^/]+)\/runs$/.exec(route))) { const r: any = await ghc().listWorkflowRuns(mm[1], mm[2], { perPage: 20 }); return send(res, 200, { runs: (r.items ?? r).map((x: any) => ({ name: x.name, head_branch: x.headBranch ?? x.head_branch, run_number: x.runNumber ?? x.run_number, status: x.status, conclusion: x.conclusion })) }); }
      if (route === "/search") { const repo = url.searchParams.get("repo") ?? ""; const r: any = await ghc().searchCode(`${url.searchParams.get("q") ?? ""} repo:${repo}`, { perPage: 20 }); return send(res, 200, { items: (r.items ?? []).map((i: any) => ({ path: i.path })) }); }
      if (route === "/exec" && m === "POST") {
        const b = await body(); const pol = evaluateCommand(String(b.command ?? ""), { root: ctx.workspaceRoot });
        if (pol.decision === "deny") return send(res, 200, { stdout: "", stderr: `Denied: ${pol.reason}`, decision: "deny" });
        if (pol.decision === "approval") { const a = approvals.check(ctx.userId, "run_command", b.command); if (a.state !== "approved") return send(res, 200, { stdout: "", stderr: "", decision: "approval" }); }
        const r = await R.runCommand(ctx.workspaceRoot, b.command, { approved: pol.decision === "approval", timeoutMs: config.commandTimeoutMs, maxOutputBytes: config.maxOutputBytes });
        return send(res, 200, r);
      }
      if (route === "/jobs") return send(res, 200, { jobs: R.listJobs(ctx.workspaceRoot).map((j) => ({ id: j.jobId, command: j.command, status: j.status, exitCode: j.exitCode })) });
      if ((mm = /^\/jobs\/([^/]+)\/output$/.exec(route))) { const o: any = R.jobOutput(mm[1], 0, 65536, ctx.workspaceRoot); return send(res, 200, { stdout: redact(o.content ?? o.output ?? ""), stderr: "", truncated: !o.eof }); }
      if (route === "/codespaces" && m === "GET") {
        let list: any[] = []; let ghError: string | undefined;
        try { const r: any = await new CodespacesClient(ghc()).listCodespaces(); list = (r.items ?? r.codespaces ?? r) as any[]; } catch (e: any) { ghError = redact(String(e?.message ?? e)); }
        const agents = broker.list(ctx.userId);
        const names = new Set<string>([...list.map((c: any) => c.name), ...agents.map((a) => a.codespace)]);
        return send(res, 200, { ghError, codespaces: [...names].map((n) => { const c = list.find((x: any) => x.name === n); const a = agents.find((x) => x.codespace === n); return { name: n, repo: c?.repository?.fullName ?? c?.repository?.full_name ?? c?.repo ?? null, state: c?.state ?? null, machine: c?.machine?.displayName ?? c?.machine ?? null, paired: !!a, online: !!a?.online, lastSeen: a?.lastSeen ?? null }; }) });
      }
      if ((mm = /^\/codespaces\/([A-Za-z0-9._-]+)\/attach$/.exec(route)) && m === "POST") {
        const { claim, expiresAt } = broker.createClaim(ctx.userId, mm[1]);
        return send(res, 200, { command: `curl -fsSL ${config.baseUrl}/agent/install.sh | UCA_SERVER=${config.baseUrl} UCA_CLAIM=${claim} bash`, expiresAt });
      }
      if ((mm = /^\/codespaces\/([A-Za-z0-9._-]+)\/detach$/.exec(route)) && m === "POST") return send(res, 200, { detached: broker.unpair(ctx.userId, mm[1]) });
      if ((mm = /^\/codespaces\/([A-Za-z0-9._-]+)\/(start|stop)$/.exec(route)) && m === "POST") {
        const c = new CodespacesClient(ghc()); const r: any = mm[2] === "start" ? await c.startCodespace(mm[1]) : await c.stopCodespace(mm[1]); return send(res, 200, { ok: true, state: r?.state ?? null });
      }
      // ---- provider keys: the USER pastes a key here (never in chat). Memory only. The AI never sees it. ----
      if (route === "/providers" && m === "GET") {
        const mine = pvault.list(ctx.userId);
        return send(res, 200, { added: mine.map((k) => ({ id: k.spec.id, label: k.spec.label, hosts: k.spec.hosts, docsUrl: k.spec.docsUrl ?? null, fingerprint: k.fingerprint, addedAt: k.addedAt })), presets: PRESETS.map((p) => ({ id: p.id, label: p.label, hosts: p.hosts, docsUrl: p.docsUrl, note: p.note })), storage: "memory-only" });
      }
      if (route === "/providers" && m === "POST") {
        let b: any; try { b = JSON.parse((await readBody(req, 20_000)) || "{}"); } catch { return send(res, 400, { error: "Invalid JSON" }); } const preset = PRESETS.find((p) => p.id === String(b.id ?? "").toLowerCase());
        try {
          const hosts = Array.isArray(b.hosts) ? b.hosts.map(String) : preset?.hosts ?? [];
          const rawId = String(b.id ?? "").toLowerCase().trim() || String(b.label ?? "").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 32);
          const spec: ProviderSpec = { id: rawId, label: String(b.label || preset?.label || rawId).slice(0, 60), hosts: hosts.map((h: string) => validateHost(h)), auth: preset?.auth ?? (b.authHeader ? { type: "header", name: String(b.authHeader).replace(/[^A-Za-z0-9-]/g, "").slice(0, 40) } : { type: "bearer" }), docsUrl: preset?.docsUrl ?? (typeof b.docsUrl === "string" && b.docsUrl.startsWith("https://") ? b.docsUrl.slice(0, 500) : undefined) };
          const k = pvault.put(ctx.userId, spec, String(b.key ?? ""));
          return send(res, 200, { ok: true, id: k.spec.id, label: k.spec.label, hosts: k.spec.hosts, fingerprint: k.fingerprint, storage: "memory-only", next: "Tell your AI the provider is added. It will search the docs and learn how to use it." });
        } catch (e: any) { if (e instanceof VaultError) return send(res, 400, { error: e.message }); throw e; }
      }
      if ((mm = /^\/providers\/([a-z0-9-]{2,32})$/.exec(route)) && m === "DELETE") return send(res, 200, { removed: pvault.remove(ctx.userId, mm[1]) });
      if ((mm = /^\/providers\/([a-z0-9-]{2,32})\/verify$/.exec(route)) && m === "POST") {
        const spec = PRESETS.find((p) => p.id === mm![1]); if (!spec?.verify) return send(res, 200, { ok: null, message: "No automatic check for this provider. Your AI will test it when it first uses it." });
        try { const r = await pvault.request(ctx.userId, mm[1], { url: spec.verify.url }, fetchImpl); return send(res, 200, { ok: r.status >= 200 && r.status < 300, status: r.status }); }
        catch (e: any) { return send(res, 200, { ok: false, message: String(e?.message ?? e).slice(0, 200) }); }
      }
      if (route === "/approvals") return send(res, 200, { approvals: approvals.list(ctx.userId) });
      if ((mm = /^\/approvals\/([^/]+)\/(approve|deny)$/.exec(route)) && m === "POST") return send(res, approvals.decide(ctx.userId, mm[1], mm[2] === "approve") ? 200 : 404, { ok: true });
      if (route === "/grants") return send(res, 200, { grants: auth.listGrants(ctx.userId) });
      if ((mm = /^\/grants\/([^/]+)\/revoke$/.exec(route)) && m === "POST") return send(res, 200, { revoked: auth.revokeGrant(ctx.userId, decodeURIComponent(mm[1])) });
      if (route === "/revoke-all" && m === "POST") { pvault.clearUser(ctx.userId); return send(res, 200, { revoked: auth.revokeAllForUser(ctx.userId) }); }
      if (route === "/tools") return send(res, 200, { tools: allTools(deps).map((t) => ({ name: t.name, scope: t.scope, description: t.description })) });
      return send(res, 404, { error: "not_found" });
    } catch (e: any) { return send(res, e?.status && e.status < 600 ? e.status : 500, { error: redact(String(e?.message ?? e)) }); }
  }

  const server = http.createServer((req, res) => { handle(req, res).catch((e: any) => { if (!res.headersSent) send(res, e?.status ?? 500, { error: redact(String(e?.message ?? "internal_error")) }); else res.end(); }); });
  return { store, pvault, broker, server, auth, sessions, approvals, deps, close: () => new Promise<void>((r) => { const t = setTimeout(r, 3000); t.unref?.(); server.close(() => { clearTimeout(t); r(); }); (server as any).closeIdleConnections?.(); setTimeout(() => (server as any).closeAllConnections?.(), 1000).unref?.(); }) };
}
