/**
 * End-to-end tests for the OAuth 2.1 authorization server layer.
 * Run: npm run build && node --test dist/test/auth.test.js
 */
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { loadConfig, type Config } from "../src/util/config.js";
import { AuthStore } from "../src/auth/store.js";
import { AuthorizationServer, validateRedirectUri, verifyPkceS256 } from "../src/auth/oauth.js";
import {
  CSRF_HEADER,
  SESSION_COOKIE,
  SessionManager,
  parseCookies,
  serializeCookie,
} from "../src/auth/session.js";
import { GithubTokenVault } from "../src/auth/tokenvault.js";

// ------------------------------------------------------------------ helpers

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "uca-auth-test-"));
}

interface Env {
  dir: string;
  config: Config;
  server: AuthorizationServer;
  clock: { t: number };
}

function makeEnv(sessionSecret = "unit-test-session-secret"): Env {
  const dir = tmpDir();
  const config = loadConfig({
    UCA_DATA_DIR: dir,
    UCA_BASE_URL: "https://agent.example.test",
    UCA_SESSION_SECRET: sessionSecret,
    UCA_ACCESS_TTL: "3600",
    UCA_REFRESH_TTL: "2592000",
  } as NodeJS.ProcessEnv);
  const clock = { t: Date.now() };
  const server = new AuthorizationServer(config, { now: () => clock.t });
  return { dir, config, server, clock };
}

function pkcePair(): { verifier: string; challenge: string } {
  const verifier = crypto.randomBytes(48).toString("base64url");
  const challenge = crypto.createHash("sha256").update(verifier, "utf8").digest("base64url");
  return { verifier, challenge };
}

const USER = "gh:12345";

interface Registration {
  client_id: string;
  client_secret?: string;
  redirect_uris: string[];
}

function register(target: AuthorizationServer | Env, extra: Record<string, unknown> = {}): Registration {
  const server = target instanceof AuthorizationServer ? target : target.server;
  const res = server.registerClient({
    client_name: "Test MCP Client",
    redirect_uris: ["http://127.0.0.1:6277/callback"],
    ...extra,
  });
  assert.equal(res.status, 201, JSON.stringify(res.body));
  return res.body as Registration;
}

/**
 * Drive authorize -> completeAuthorization and return the auth code.
 * Pass `verifier` to reuse a known PKCE pair (its S256 challenge is derived).
 */
function startFlow(
  env: Env,
  client: Registration,
  opts: { scopes?: string; verifier?: string; redirectUri?: string; resource?: string } = {},
): { pendingId: string; code: string; verifier: string } {
  const verifier = opts.verifier ?? crypto.randomBytes(48).toString("base64url");
  const challenge = crypto.createHash("sha256").update(verifier, "utf8").digest("base64url");
  const redirectUri = opts.redirectUri ?? client.redirect_uris[0]!;
  const authRes = env.server.authorize({
    client_id: client.client_id,
    redirect_uri: redirectUri,
    response_type: "code",
    code_challenge: challenge,
    code_challenge_method: "S256",
    state: "state-abc",
    scope: opts.scopes ?? "mcp:read mcp:write",
    resource: opts.resource ?? `${env.config.baseUrl}/mcp`,
  });
  assert.equal(authRes.status, 200, JSON.stringify(authRes.body));
  const pendingId = (authRes.body as { pending_id: string }).pending_id;
  const done = env.server.completeAuthorization(pendingId, USER, true);
  assert.equal(done.status, 302);
  const loc = new URL((done as { redirectTo: string }).redirectTo);
  assert.equal(loc.searchParams.get("state"), "state-abc");
  const code = loc.searchParams.get("code");
  assert.ok(code, "code present in redirect");
  return { pendingId, code: code!, verifier };
}

function tokenReq(
  env: Env,
  client: Registration,
  params: Record<string, unknown>,
  useBasic = false,
): ReturnType<AuthorizationServer["token"]> {
  const body: Record<string, unknown> = { ...params };
  const headers: Record<string, string> = { "content-type": "application/x-www-form-urlencoded" };
  if (client.client_secret) {
    if (useBasic) {
      headers.authorization =
        "Basic " + Buffer.from(`${client.client_id}:${client.client_secret}`).toString("base64url");
    } else {
      body.client_id = client.client_id;
      body.client_secret = client.client_secret;
    }
  } else if (!useBasic) {
    body.client_id = client.client_id;
  } else {
    headers.authorization = "Basic " + Buffer.from(`${client.client_id}:`).toString("base64url");
  }
  return env.server.token({ ...body, headers });
}

// ------------------------------------------------------- 1. happy path + PKCE

test("full authorization code flow with S256 PKCE succeeds", () => {
  const env = makeEnv();
  const client = register(env);
  const { code, verifier } = startFlow(env, client);

  const res = tokenReq(env, client, {
    grant_type: "authorization_code",
    code,
    redirect_uri: client.redirect_uris[0],
    code_verifier: verifier,
  });
  assert.equal(res.status, 200, JSON.stringify(res.body));
  const body = res.body as {
    access_token: string;
    refresh_token: string;
    token_type: string;
    expires_in: number;
    scope: string;
  };
  assert.equal(body.token_type, "Bearer");
  assert.equal(body.expires_in, 3600);
  assert.equal(body.scope, "mcp:read mcp:write");
  // Opaque random 32-byte base64url tokens => 43 chars, no dots (not a JWT).
  assert.equal(Buffer.from(body.access_token, "base64url").length, 32);
  assert.equal(Buffer.from(body.refresh_token, "base64url").length, 32);
  assert.ok(!body.access_token.includes("."));

  const principal = env.server.verifyAccessToken(body.access_token);
  assert.ok(principal);
  assert.equal(principal!.userId, USER);
  assert.equal(principal!.clientId, client.client_id);
  assert.deepEqual(principal!.scopes, ["mcp:read", "mcp:write"]);
  assert.equal(principal!.resource, "https://agent.example.test/mcp");

  // requiredScope handling
  assert.ok(env.server.verifyAccessToken(body.access_token, "mcp:write"));
  assert.equal(env.server.verifyAccessToken(body.access_token, "mcp:admin"), null);
});

test("confidential client with client_secret_basic works and bad secret is rejected", () => {
  const env = makeEnv();
  const client = register(env, { token_endpoint_auth_method: "client_secret_basic" });
  assert.ok(client.client_secret);
  const { code, verifier } = startFlow(env, client);
  const okRes = tokenReq(
    env,
    client,
    { grant_type: "authorization_code", code, redirect_uri: client.redirect_uris[0], code_verifier: verifier },
    true,
  );
  assert.equal(okRes.status, 200, JSON.stringify(okRes.body));

  // Wrong secret
  const badRes = env.server.token({
    grant_type: "refresh_token",
    refresh_token: "whatever",
    client_id: client.client_id,
    client_secret: "not-the-secret",
  });
  assert.equal(badRes.status, 401);
  assert.equal((badRes.body as { error: string }).error, "invalid_client");
});

// --------------------------------------------------------- 2. PKCE failures

test("wrong code_verifier is rejected", () => {
  const env = makeEnv();
  const client = register(env);
  const { code, verifier } = startFlow(env, client);
  const res = tokenReq(env, client, {
    grant_type: "authorization_code",
    code,
    redirect_uri: client.redirect_uris[0],
    code_verifier: pkcePair().verifier,
  });
  assert.equal(res.status, 400);
  assert.equal((res.body as { error: string }).error, "invalid_grant");
});

test("missing PKCE (code_challenge) at authorize is rejected", () => {
  const env = makeEnv();
  const client = register(env);
  const res = env.server.authorize({
    client_id: client.client_id,
    redirect_uri: client.redirect_uris[0],
    response_type: "code",
    state: "s1",
    scope: "mcp:read",
  });
  assert.equal(res.status, 302);
  const loc = new URL((res as { redirectTo: string }).redirectTo);
  assert.equal(loc.searchParams.get("error"), "invalid_request");
  assert.equal(loc.searchParams.get("state"), "s1");
  assert.equal(loc.searchParams.get("code"), null);
});

test("missing code_verifier at the token endpoint is rejected", () => {
  const env = makeEnv();
  const client = register(env);
  const { code, verifier } = startFlow(env, client);
  const res = tokenReq(env, client, {
    grant_type: "authorization_code",
    code,
    redirect_uri: client.redirect_uris[0],
  });
  assert.equal(res.status, 400);
  assert.equal((res.body as { error: string }).error, "invalid_request");
});

test("plain code_challenge_method is rejected", () => {
  const env = makeEnv();
  const client = register(env);
  const res = env.server.authorize({
    client_id: client.client_id,
    redirect_uri: client.redirect_uris[0],
    response_type: "code",
    code_challenge: "a".repeat(43),
    code_challenge_method: "plain",
    scope: "mcp:read",
  });
  assert.equal(res.status, 302);
  const loc = new URL((res as { redirectTo: string }).redirectTo);
  assert.equal(loc.searchParams.get("error"), "invalid_request");
  assert.match(loc.searchParams.get("error_description") ?? "", /S256/);
});

test("verifyPkceS256 rejects verifiers outside RFC 7636 syntax", () => {
  const challenge = crypto.createHash("sha256").update("short", "utf8").digest("base64url");
  assert.equal(verifyPkceS256("short", challenge), false);
});

// ------------------------------------------------------ 3. redirect_uri rules

test("redirect_uri mismatch is rejected (authorize and token)", () => {
  const env = makeEnv();
  const client = register(env, { redirect_uris: ["http://127.0.0.1:6277/callback", "https://app.example/cb"] });
  // Unknown redirect at authorize time: no redirect, hard 400.
  const res = env.server.authorize({
    client_id: client.client_id,
    redirect_uri: "https://evil.example/cb",
    response_type: "code",
    code_challenge: "a".repeat(43),
    code_challenge_method: "S256",
    scope: "mcp:read",
  });
  assert.equal(res.status, 400);
  assert.equal((res.body as { error: string }).error, "invalid_request");
  assert.equal((res as { redirectTo?: string }).redirectTo, undefined);

  // Mismatch at token time.
  const { code, verifier } = startFlow(env, client, { redirectUri: "https://app.example/cb" });
  const tokenRes = tokenReq(env, client, {
    grant_type: "authorization_code",
    code,
    redirect_uri: "http://127.0.0.1:6277/callback",
    code_verifier: verifier,
  });
  assert.equal(tokenRes.status, 400);
  assert.equal((tokenRes.body as { error: string }).error, "invalid_grant");
});

test("unknown client_id at authorize does not redirect", () => {
  const env = makeEnv();
  const res = env.server.authorize({
    client_id: "nope",
    redirect_uri: "http://127.0.0.1:6277/callback",
    response_type: "code",
    code_challenge: "a".repeat(43),
    code_challenge_method: "S256",
  });
  assert.equal(res.status, 400);
  assert.equal((res.body as { error: string }).error, "invalid_client");
});

// ------------------------------------------------------------- 4. replay

test("code reuse is rejected and revokes tokens issued from it", () => {
  const env = makeEnv();
  const client = register(env);
  const { code, verifier } = startFlow(env, client);

  const first = tokenReq(env, client, {
    grant_type: "authorization_code",
    code,
    redirect_uri: client.redirect_uris[0],
    code_verifier: verifier,
  });
  assert.equal(first.status, 200);
  const tokens = first.body as { access_token: string; refresh_token: string };
  assert.ok(env.server.verifyAccessToken(tokens.access_token));

  const replay = tokenReq(env, client, {
    grant_type: "authorization_code",
    code,
    redirect_uri: client.redirect_uris[0],
    code_verifier: verifier,
  });
  assert.equal(replay.status, 400);
  assert.equal((replay.body as { error: string }).error, "invalid_grant");

  // Derived tokens are dead, including the refresh token.
  assert.equal(env.server.verifyAccessToken(tokens.access_token), null);
  const refresh = tokenReq(env, client, { grant_type: "refresh_token", refresh_token: tokens.refresh_token });
  assert.equal(refresh.status, 400);
});

// ------------------------------------------------------------- 5. expiry

test("authorization code expires after 10 minutes (injected clock)", () => {
  const env = makeEnv();
  const client = register(env);
  const { code, verifier } = startFlow(env, client);

  env.clock.t += 9 * 60 * 1000;
  const stillValid = tokenReq(env, client, {
    grant_type: "authorization_code",
    code,
    redirect_uri: client.redirect_uris[0],
    code_verifier: verifier,
  });
  assert.equal(stillValid.status, 200);

  const env2 = makeEnv();
  const client2 = register(env2);
  const { code: code2, verifier: verifier2 } = startFlow(env2, client2);
  env2.clock.t += 10 * 60 * 1000 + 1;
  const expired = tokenReq(env2, client2, {
    grant_type: "authorization_code",
    code: code2,
    redirect_uri: client2.redirect_uris[0],
    code_verifier: verifier2,
  });
  assert.equal(expired.status, 400);
  assert.equal((expired.body as { error: string }).error, "invalid_grant");
  assert.match((expired.body as { error_description: string }).error_description, /expired/i);
});

test("expired access token is rejected", () => {
  const env = makeEnv();
  const client = register(env);
  const { code, verifier } = startFlow(env, client);
  const res = tokenReq(env, client, {
    grant_type: "authorization_code",
    code,
    redirect_uri: client.redirect_uris[0],
    code_verifier: verifier,
  });
  const { access_token } = res.body as { access_token: string };
  assert.ok(env.server.verifyAccessToken(access_token));
  env.clock.t += 3600 * 1000 + 1;
  assert.equal(env.server.verifyAccessToken(access_token), null);
});

// ------------------------------------------------------ 6. refresh rotation

test("refresh rotation issues a new pair and invalidates the old refresh token", () => {
  const env = makeEnv();
  const client = register(env);
  const { code, verifier } = startFlow(env, client);
  const first = tokenReq(env, client, {
    grant_type: "authorization_code",
    code,
    redirect_uri: client.redirect_uris[0],
    code_verifier: verifier,
  }).body as { access_token: string; refresh_token: string };

  const rotated = tokenReq(env, client, { grant_type: "refresh_token", refresh_token: first.refresh_token });
  assert.equal(rotated.status, 200, JSON.stringify(rotated.body));
  const second = rotated.body as { access_token: string; refresh_token: string };
  assert.notEqual(second.refresh_token, first.refresh_token);
  assert.ok(env.server.verifyAccessToken(second.access_token));

  // New refresh token works...
  const third = tokenReq(env, client, { grant_type: "refresh_token", refresh_token: second.refresh_token });
  assert.equal(third.status, 200);

  // ...the superseded one does not (single use).
  const reuse = tokenReq(env, client, { grant_type: "refresh_token", refresh_token: first.refresh_token });
  assert.equal(reuse.status, 400);
  assert.equal((reuse.body as { error: string }).error, "invalid_grant");
});

test("old refresh token reuse revokes the whole token family", () => {
  const env = makeEnv();
  const client = register(env);
  const { code, verifier } = startFlow(env, client);
  const first = tokenReq(env, client, {
    grant_type: "authorization_code",
    code,
    redirect_uri: client.redirect_uris[0],
    code_verifier: verifier,
  }).body as { access_token: string; refresh_token: string };

  const second = tokenReq(env, client, { grant_type: "refresh_token", refresh_token: first.refresh_token })
    .body as { access_token: string; refresh_token: string };
  assert.ok(env.server.verifyAccessToken(second.access_token));

  // Attacker replays the superseded refresh token.
  const reuse = tokenReq(env, client, { grant_type: "refresh_token", refresh_token: first.refresh_token });
  assert.equal(reuse.status, 400);

  // The legitimate current refresh token and access tokens are now dead.
  assert.equal(env.server.verifyAccessToken(second.access_token), null);
  const afterRevoke = tokenReq(env, client, { grant_type: "refresh_token", refresh_token: second.refresh_token });
  assert.equal(afterRevoke.status, 400);
  assert.deepEqual(env.server.listGrants(USER), []);
});

test("refresh can only narrow scope, never widen it", () => {
  const env = makeEnv();
  const client = register(env);
  const { code, verifier } = startFlow(env, client, { scopes: "mcp:read mcp:write" });
  const first = tokenReq(env, client, {
    grant_type: "authorization_code",
    code,
    redirect_uri: client.redirect_uris[0],
    code_verifier: verifier,
  }).body as { access_token: string; refresh_token: string };

  // Widen -> rejected.
  const widen = tokenReq(env, client, {
    grant_type: "refresh_token",
    refresh_token: first.refresh_token,
    scope: "mcp:read mcp:write mcp:admin",
  });
  assert.equal(widen.status, 400);
  assert.equal((widen.body as { error: string }).error, "invalid_scope");

  // Narrow -> allowed.
  const narrow = tokenReq(env, client, {
    grant_type: "refresh_token",
    refresh_token: first.refresh_token,
    scope: "mcp:read",
  });
  assert.equal(narrow.status, 200, JSON.stringify(narrow.body));
  const narrowed = narrow.body as { access_token: string; refresh_token: string; scope: string };
  assert.equal(narrowed.scope, "mcp:read");
  const principal = env.server.verifyAccessToken(narrowed.access_token);
  assert.deepEqual(principal!.scopes, ["mcp:read"]);
  assert.equal(env.server.verifyAccessToken(narrowed.access_token, "mcp:write"), null);

  // Narrowed grant cannot be widened back on the next rotation.
  const back = tokenReq(env, client, {
    grant_type: "refresh_token",
    refresh_token: narrowed.refresh_token,
    scope: "mcp:read mcp:write",
  });
  assert.equal(back.status, 400);
});

// ------------------------------------------------------------- 7. resource

test("resource parameter must match the MCP resource (RFC 8707)", () => {
  const env = makeEnv();
  const client = register(env);
  const verifier = crypto.randomBytes(48).toString("base64url");
  const challenge = crypto.createHash("sha256").update(verifier, "utf8").digest("base64url");

  const bad = env.server.authorize({
    client_id: client.client_id,
    redirect_uri: client.redirect_uris[0],
    response_type: "code",
    code_challenge: challenge,
    code_challenge_method: "S256",
    scope: "mcp:read",
    resource: "https://evil.example/mcp",
  });
  assert.equal(bad.status, 302);
  const loc = new URL((bad as { redirectTo: string }).redirectTo);
  assert.equal(loc.searchParams.get("error"), "invalid_target");
  assert.equal(loc.searchParams.get("code"), null);

  // Matching resource is accepted and carried through the token response.
  const good = env.server.authorize({
    client_id: client.client_id,
    redirect_uri: client.redirect_uris[0],
    response_type: "code",
    code_challenge: challenge,
    code_challenge_method: "S256",
    scope: "mcp:read",
    resource: "https://agent.example.test/mcp",
  });
  assert.equal(good.status, 200);
  const done = env.server.completeAuthorization((good.body as { pending_id: string }).pending_id, USER, true);
  const code = new URL((done as { redirectTo: string }).redirectTo).searchParams.get("code")!;

  const wrongResource = tokenReq(env, client, {
    grant_type: "authorization_code",
    code,
    redirect_uri: client.redirect_uris[0],
    code_verifier: verifier,
    resource: "https://other.example/mcp",
  });
  assert.equal(wrongResource.status, 400);
  assert.equal((wrongResource.body as { error: string }).error, "invalid_target");

  const okRes = tokenReq(env, client, {
    grant_type: "authorization_code",
    code,
    redirect_uri: client.redirect_uris[0],
    code_verifier: verifier,
    resource: "https://agent.example.test/mcp",
  });
  assert.equal(okRes.status, 200);
  assert.equal((okRes.body as { resource: string }).resource, "https://agent.example.test/mcp");
});

// --------------------------------------------------------------- 8. revoke

test("revocation endpoint kills access and refresh tokens", () => {
  const env = makeEnv();
  const client = register(env);
  const { code, verifier } = startFlow(env, client);
  const tokens = tokenReq(env, client, {
    grant_type: "authorization_code",
    code,
    redirect_uri: client.redirect_uris[0],
    code_verifier: verifier,
  }).body as { access_token: string; refresh_token: string };

  const revokeAccess = env.server.revoke({ token: tokens.access_token, client_id: client.client_id });
  assert.equal(revokeAccess.status, 200);
  assert.equal(env.server.verifyAccessToken(tokens.access_token), null);

  const revokeRefresh = env.server.revoke({ token: tokens.refresh_token, client_id: client.client_id });
  assert.equal(revokeRefresh.status, 200);
  const afterRevoke = tokenReq(env, client, { grant_type: "refresh_token", refresh_token: tokens.refresh_token });
  assert.equal(afterRevoke.status, 400);

  // Unknown token is still 200 per RFC 7009.
  assert.equal(env.server.revoke({ token: "unknown-token", client_id: client.client_id }).status, 200);
});

test("revokeAllForUser and revokeGrant clear dashboard state", () => {
  const env = makeEnv();
  const clientA = register(env, { client_name: "A" });
  const clientB = register(env, { client_name: "B", redirect_uris: ["https://b.example/cb"] });

  const mint = (client: Registration): { access_token: string; refresh_token: string } => {
    const { code, verifier } = startFlow(env, client);
    return tokenReq(env, client, {
      grant_type: "authorization_code",
      code,
      redirect_uri: client.redirect_uris[0],
      code_verifier: verifier,
    }).body as { access_token: string; refresh_token: string };
  };
  const a = mint(clientA);
  const b = mint(clientB);

  const grants = env.server.listGrants(USER);
  assert.equal(grants.length, 2);
  assert.deepEqual(grants.map((g) => g.clientId).sort(), [clientA.client_id, clientB.client_id].sort());

  assert.equal(env.server.revokeGrant(USER, clientA.client_id), 2);
  assert.equal(env.server.verifyAccessToken(a.access_token), null);
  assert.ok(env.server.verifyAccessToken(b.access_token));
  assert.equal(env.server.listGrants(USER).length, 1);

  assert.equal(env.server.revokeAllForUser(USER), 2);
  assert.equal(env.server.verifyAccessToken(b.access_token), null);
  assert.deepEqual(env.server.listGrants(USER), []);
});

// ------------------------------------------------------------- 9. consent

test("denying consent redirects with error=access_denied and issues no code", () => {
  const env = makeEnv();
  const client = register(env);
  const pair = pkcePair();
  const auth = env.server.authorize({
    client_id: client.client_id,
    redirect_uri: client.redirect_uris[0],
    response_type: "code",
    code_challenge: pair.challenge,
    code_challenge_method: "S256",
    state: "st-9",
    scope: "mcp:read",
  });
  const pendingId = (auth.body as { pending_id: string }).pending_id;
  const denied = env.server.completeAuthorization(pendingId, USER, false);
  assert.equal(denied.status, 302);
  const loc = new URL((denied as { redirectTo: string }).redirectTo);
  assert.equal(loc.searchParams.get("error"), "access_denied");
  assert.equal(loc.searchParams.get("code"), null);
  assert.equal(loc.searchParams.get("state"), "st-9");

  // Pending record is gone; a second call cannot resurrect it as an approval.
  const again = env.server.completeAuthorization(pendingId, USER, true);
  assert.equal(again.status, 404);
});

test("unsupported scopes and response types are rejected", () => {
  const env = makeEnv();
  const client = register(env);
  const pair = pkcePair();
  const badScope = env.server.authorize({
    client_id: client.client_id,
    redirect_uri: client.redirect_uris[0],
    response_type: "code",
    code_challenge: pair.challenge,
    code_challenge_method: "S256",
    scope: "mcp:read mcp:root",
  });
  assert.equal(new URL((badScope as { redirectTo: string }).redirectTo).searchParams.get("error"), "invalid_scope");

  const badType = env.server.authorize({
    client_id: client.client_id,
    redirect_uri: client.redirect_uris[0],
    response_type: "token",
    code_challenge: pair.challenge,
    code_challenge_method: "S256",
    scope: "mcp:read",
  });
  assert.equal(
    new URL((badType as { redirectTo: string }).redirectTo).searchParams.get("error"),
    "unsupported_response_type",
  );
});

// ----------------------------------------------------------- 10. metadata

test("metadata documents the MCP endpoints and S256 only", () => {
  const env = makeEnv();
  const as = env.server.metadata();
  assert.equal(as.status, 200);
  const meta = as.body as Record<string, unknown>;
  assert.equal(meta.issuer, "https://agent.example.test");
  assert.equal(meta.authorization_endpoint, "https://agent.example.test/oauth/authorize");
  assert.equal(meta.token_endpoint, "https://agent.example.test/oauth/token");
  assert.deepEqual(meta.code_challenge_methods_supported, ["S256"]);
  assert.ok((meta.scopes_supported as string[]).includes("mcp:exec"));

  const prm = env.server.protectedResourceMetadata();
  assert.equal(prm.status, 200);
  const pr = prm.body as Record<string, unknown>;
  assert.equal(pr.resource, "https://agent.example.test/mcp");
  assert.deepEqual(pr.authorization_servers, ["https://agent.example.test"]);
  assert.match(env.server.wwwAuthenticate(), /resource_metadata="https:\/\/agent\.example\.test\/\.well-known\/oauth-protected-resource"/);
});

// ------------------------------------------- 11. dynamic registration rules

test("dynamic registration rejects bad redirect URIs", () => {
  const env = makeEnv();
  const bad = (uri: unknown) => {
    const res = env.server.registerClient({ client_name: "x", redirect_uris: [uri] });
    assert.equal(res.status, 400, `expected rejection for ${String(uri)}`);
    assert.equal((res.body as { error: string }).error, "invalid_redirect_uri");
  };
  bad("https://app.example/cb#fragment");
  bad("http://example.com/cb"); // plain http off loopback
  bad("https://*.example.com/cb");
  bad("https://app.example/*");
  bad("javascript:alert(1)");
  bad("file:///etc/passwd");
  bad("not a url");
  bad("");
  bad("https://user:pw@app.example/cb");

  assert.equal(env.server.registerClient({ redirect_uris: [] }).status, 400);
  assert.equal(env.server.registerClient({}).status, 400);
  assert.equal(
    env.server.registerClient({ redirect_uris: ["https://a.example/cb"], token_endpoint_auth_method: "private_key_jwt" }).status,
    400,
  );
  assert.equal(env.server.registerClient({ redirect_uris: ["https://a.example/cb"], scope: "mcp:root" }).status, 400);

  // Accepted forms.
  const okUris = [
    "https://app.example/cb",
    "http://localhost:3000/callback",
    "http://127.0.0.1:6277/callback",
    "vscode://vscode.github-authentication/did-authenticate",
    "com.example.mcp:/oauth/callback",
  ];
  for (const uri of okUris) {
    assert.equal(validateRedirectUri(uri).ok, true, `expected ${uri} to be accepted`);
    const res = env.server.registerClient({ client_name: "ok", redirect_uris: [uri] });
    assert.equal(res.status, 201, `expected ${uri} to register: ${JSON.stringify(res.body)}`);
  }

  // Public client: no secret. Confidential: secret returned.
  const pub = register(env);
  assert.equal(pub.client_secret, undefined);
  const conf = register(env, { token_endpoint_auth_method: "client_secret_post" });
  assert.ok(conf.client_secret);
});

// ------------------------------------------------------------- 12. at-rest

test("store file contains no plaintext tokens or GitHub token, and is mode 0600", () => {
  const env = makeEnv();
  const client = register(env);
  const { code, verifier } = startFlow(env, client);
  const tokens = tokenReq(env, client, {
    grant_type: "authorization_code",
    code,
    redirect_uri: client.redirect_uris[0],
    code_verifier: verifier,
  }).body as { access_token: string; refresh_token: string };

  const vault = new GithubTokenVault(env.server.store);
  const githubToken = "gho_" + crypto.randomBytes(18).toString("hex");
  const githubRefresh = "ghr_" + crypto.randomBytes(18).toString("hex");
  vault.saveGithubToken(USER, githubToken, "repo read:user", githubRefresh, env.clock.t + 8 * 3600 * 1000);

  const storePath = env.server.store.filePath;
  const raw = fs.readFileSync(storePath, "utf8");

  for (const secret of [tokens.access_token, tokens.refresh_token, code, verifier, githubToken, githubRefresh]) {
    assert.equal(raw.includes(secret), false, `store leaked plaintext: ${secret.slice(0, 12)}...`);
  }
  // Hashes and sealed blobs are present instead.
  assert.ok(raw.includes(env.server.store.hashToken(tokens.access_token)));
  assert.ok(raw.includes(env.server.store.hashToken(code)));
  assert.match(raw, /"v1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"/);

  const mode = fs.statSync(storePath).mode & 0o777;
  assert.equal(mode.toString(8), "600", `expected 0600, got ${mode.toString(8)}`);

  // Decryption round-trips, and expiry is honoured.
  assert.ok(raw.length > 0);
  const roundTripped = vault.getGithubTokenSync(USER);
  assert.equal(roundTripped?.accessToken, githubToken);
  assert.equal(roundTripped?.refreshToken, githubRefresh);
  env.clock.t += 9 * 3600 * 1000;
  assert.equal(vault.getGithubTokenSync(USER), null);
});

test("secret.key is generated with mode 0600 when sessionSecret is empty", async () => {
  const env = makeEnv("");
  const keyPath = path.join(env.dir, "secret.key");
  assert.ok(fs.existsSync(keyPath), "secret.key created");
  assert.equal(fs.statSync(keyPath).mode & 0o777, 0o600);
  assert.equal(fs.readFileSync(keyPath).length, 44); // 32 random bytes base64

  const vault = new GithubTokenVault(env.server.store);
  vault.saveGithubToken(USER, "gho_plaintext_value_here", "repo");
  const raw = fs.readFileSync(env.server.store.filePath, "utf8");
  assert.equal(raw.includes("gho_plaintext_value_here"), false);

  // A second store instance with the same dataDir decrypts it (key persisted).
  const store2 = new AuthStore(env.config);
  const vault2 = new GithubTokenVault(store2);
  assert.equal((await vault2.getGithubToken(USER))?.accessToken, "gho_plaintext_value_here");

  // github token vault: delete works.
  assert.equal(vault.deleteGithubToken(USER), true);
  assert.equal(await vault.getGithubToken(USER), null);
});

test("vault refreshes an expired GitHub token through the callback", async () => {
  const env = makeEnv();
  let calls = 0;
  const vault = new GithubTokenVault(env.server.store, async (current) => {
    calls += 1;
    assert.equal(current.refreshToken, "ghr_old");
    return { accessToken: "gho_new", scope: "repo", refreshToken: "ghr_new", expiresAt: env.clock.t + 8 * 3600 * 1000 };
  });
  vault.saveGithubToken(USER, "gho_old", "repo", "ghr_old", env.clock.t + 1000);
  const refreshed = await vault.getGithubToken(USER);
  assert.equal(refreshed?.accessToken, "gho_new");
  assert.equal(calls, 1);
  assert.equal((await vault.getGithubToken(USER))?.accessToken, "gho_new");
  assert.equal(calls, 1, "cached after refresh");

  const raw = fs.readFileSync(env.server.store.filePath, "utf8");
  assert.equal(raw.includes("gho_new"), false);
  assert.equal(raw.includes("ghr_new"), false);
});

// ------------------------------------------------------------- 13. session

test("session cookie signature tampering is rejected", () => {
  const env = makeEnv();
  const sessions = new SessionManager(env.server.store);
  env.server.store.upsertUser({ userId: USER, login: "octocat" });
  const { session, cookie } = sessions.createSession(USER, { ip: "1.2.3.4" });

  const jar = parseCookies(cookie.split(";")[0]);
  assert.equal(jar[SESSION_COOKIE] !== undefined, true);
  assert.match(cookie, /HttpOnly/);
  assert.match(cookie, /SameSite=Lax/);
  assert.match(cookie, /Secure/, "Secure flag set because baseUrl is https");

  const principal = sessions.getSession(jar);
  assert.equal(principal?.userId, USER);
  assert.equal(principal?.login, "octocat");

  // Flip a character in the signature.
  const parts = jar[SESSION_COOKIE]!.split(".");
  const tamperedSig = parts[2]!.slice(0, -1) + (parts[2]!.endsWith("A") ? "B" : "A");
  const tampered = { ...jar, [SESSION_COOKIE]: `${parts[0]}.${parts[1]}.${tamperedSig}` };
  assert.equal(sessions.getSession(tampered), null);

  // Swap in a different session id but keep the signature.
  const other = sessions.createSession(USER);
  const otherId = parseCookies(other.cookie.split(";")[0])[SESSION_COOKIE]!.split(".")[0]!;
  assert.equal(sessions.getSession({ [SESSION_COOKIE]: `${otherId}.${parts[1]}.${parts[2]}` }), null);

  // No signature at all.
  assert.equal(sessions.getSession({ [SESSION_COOKIE]: session.id }), null);
  // Random garbage.
  assert.equal(sessions.getSession({ [SESSION_COOKIE]: "a.b.c" }), null);

  // The Secure flag is dropped for an http baseUrl (localhost dev).
  const plain = loadConfig({ UCA_DATA_DIR: env.dir, UCA_BASE_URL: "http://localhost:8787", UCA_SESSION_SECRET: "s" } as NodeJS.ProcessEnv);
  const plainSessions = new SessionManager(new AuthorizationServer(plain).store);
  assert.doesNotMatch(plainSessions.createSession(USER).cookie, /Secure/);

  // Logout destroys the server-side record.
  sessions.destroySession(jar);
  assert.equal(sessions.getSession(jar), null);
});

test("session expiry and idle timeout are enforced", () => {
  const env = makeEnv();
  const sessions = new SessionManager(env.server.store, { ttlMs: 60_000, idleTimeoutMs: 10_000 });
  const { cookie } = sessions.createSession(USER);
  const jar = parseCookies(cookie.split(";")[0]);
  assert.ok(sessions.getSession(jar));
  env.clock.t += 10_001; // past idle timeout
  assert.equal(sessions.getSession(jar), null);
});

test("CSRF is enforced for state-changing requests", () => {
  const env = makeEnv();
  const sessions = new SessionManager(env.server.store);
  const { cookie, csrfToken } = sessions.createSession(USER);
  const jar = parseCookies(cookie.split(";")[0]);

  // GET needs no CSRF token.
  const get = sessions.requireSession("GET", jar, {});
  assert.equal(get.ok, true);

  // POST without a token is rejected.
  const noToken = sessions.requireSession("POST", jar, {});
  assert.equal(noToken.ok, false);
  assert.equal((noToken as { status: number }).status, 403);

  // Wrong token rejected.
  const wrong = sessions.requireSession("POST", jar, { [CSRF_HEADER]: "deadbeef" });
  assert.equal(wrong.ok, false);

  // Correct token accepted.
  const good = sessions.requireSession("POST", jar, { [CSRF_HEADER]: csrfToken });
  assert.equal(good.ok, true);

  // Unauthenticated request rejected before CSRF is even considered.
  const anon = sessions.requireSession("GET", {});
  assert.equal((anon as { status: number }).status, 401);

  const principal = sessions.getSession(jar)!;
  assert.equal(sessions.verifyCsrf(principal, csrfToken), true);
  assert.equal(sessions.verifyCsrf(principal, csrfToken + "x"), false);
  assert.equal(sessions.verifyCsrf(null, csrfToken), false);
});

test("oauth login state is single use and expires after 10 minutes", () => {
  const env = makeEnv();
  const sessions = new SessionManager(env.server.store);
  const { session } = sessions.createSession(USER);

  const { state } = sessions.createOAuthState(session.id, { nonce: "n-1", redirectTo: "/dashboard" });
  const first = sessions.consumeOAuthState(state, session.id, "n-1");
  assert.equal(first.ok, true);
  assert.equal((first as { redirectTo: string }).redirectTo, "/dashboard");

  const second = sessions.consumeOAuthState(state, session.id, "n-1");
  assert.equal(second.ok, false);
  assert.equal((second as { reason: string }).reason, "state_reused");

  // Unknown / missing state.
  assert.equal((sessions.consumeOAuthState("nope") as { reason: string }).reason, "unknown_state");
  assert.equal((sessions.consumeOAuthState(undefined) as { reason: string }).reason, "missing_state");

  // Bound to the session.
  const other = sessions.createSession(USER);
  const bound = sessions.createOAuthState(session.id);
  const mismatch = sessions.consumeOAuthState(bound.state, other.session.id);
  assert.equal(mismatch.ok, false);
  assert.equal((mismatch as { reason: string }).reason, "state_session_mismatch");

  // Nonce mismatch.
  const withNonce = sessions.createOAuthState(session.id, { nonce: "abc" });
  assert.equal(sessions.consumeOAuthState(withNonce.state, session.id, "zzz").ok, false);

  // Expiry.
  const expiring = sessions.createOAuthState(session.id);
  env.clock.t += 10 * 60 * 1000 + 1;
  const expired = sessions.consumeOAuthState(expiring.state, session.id);
  assert.equal(expired.ok, false);
  assert.equal((expired as { reason: string }).reason, "state_expired");
});

test("cookie helpers round-trip and login rate limiting slides", () => {
  const jar = parseCookies("a=1; b=%20x; malformed; c=");
  assert.deepEqual(jar, { a: "1", b: " x", c: "" });
  const cookie = serializeCookie("k", "v v", { maxAge: 10, secure: true, sameSite: "Strict" });
  assert.match(cookie, /^k=v%20v; Path=\/; Max-Age=10; HttpOnly; Secure; SameSite=Strict$/);

  const env = makeEnv();
  const sessions = new SessionManager(env.server.store);
  for (let i = 0; i < 10; i++) assert.equal(sessions.loginLimiter.hit("ip:1"), true);
  assert.equal(sessions.loginLimiter.hit("ip:1"), false);
  assert.equal(sessions.loginLimiter.hit("ip:2"), true, "independent key");
  assert.equal(sessions.loginLimiter.remaining("ip:1"), 0);
  assert.ok(sessions.loginLimiter.retryAfterMs("ip:1") > 0);
  env.clock.t += 15 * 60 * 1000 + 1;
  assert.equal(sessions.loginLimiter.hit("ip:1"), true, "window slid");
});

// --------------------------------------------------------- 14. persistence

test("store persists across instances and reloads from disk", () => {
  const env = makeEnv();
  const client = register(env);
  const { code, verifier } = startFlow(env, client);
  const tokens = tokenReq(env, client, {
    grant_type: "authorization_code",
    code,
    redirect_uri: client.redirect_uris[0],
    code_verifier: verifier,
  }).body as { access_token: string; refresh_token: string };

  const reopened = new AuthStore(env.config);
  assert.ok(reopened.getClient(client.client_id));
  assert.ok(reopened.getAccessToken(reopened.hashToken(tokens.access_token)));
  assert.ok(reopened.getRefreshToken(reopened.hashToken(tokens.refresh_token)));

  // A reload of a fresh instance still verifies tokens (cross-process safety).
  const server2 = new AuthorizationServer(env.config);
  assert.ok(server2.verifyAccessToken(tokens.access_token));
});
