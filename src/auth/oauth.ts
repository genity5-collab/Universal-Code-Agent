/**
 * MCP-compatible OAuth 2.1 authorization server (pure logic, no HTTP framework).
 *
 * Every public method is handler-shaped: it takes a plain object and returns a
 * plain `{ status, headers, body }` (plus optional extra fields such as the
 * pending consent record). The HTTP wiring lives elsewhere.
 *
 * Implements:
 *  - RFC 8414 authorization server metadata
 *  - RFC 9728 protected resource metadata
 *  - RFC 7591 dynamic client registration
 *  - RFC 7636 PKCE (S256 mandatory)
 *  - RFC 8707 resource indicators (bound to `<baseUrl>/mcp`)
 *  - RFC 7009 token revocation
 *  - Opaque access tokens, rotating refresh tokens with family-wide reuse
 *    detection, single-use authorization codes with replay revocation.
 */
import crypto from "node:crypto";
import type { Config } from "../util/config.js";
import {
  AuthStore,
  type AuthorizationCodeRecord,
  type ClientAuthMethod,
  type ClientRecord,
  type PendingAuthorizationRecord,
  randomToken,
  timingSafeEqualStr,
} from "./store.js";

/** Scopes the agent understands. */
export const SUPPORTED_SCOPES = ["mcp:read", "mcp:write", "mcp:exec", "mcp:admin"] as const;
export type Scope = (typeof SUPPORTED_SCOPES)[number];
const SCOPE_SET: ReadonlySet<string> = new Set(SUPPORTED_SCOPES);

export const AUTHORIZATION_CODE_TTL_MS = 10 * 60 * 1000;
export const PENDING_AUTHORIZATION_TTL_MS = 10 * 60 * 1000;
export const DEFAULT_SCOPE: Scope = "mcp:read";

/** Single-word custom schemes used by known desktop/mobile MCP clients. */
const KNOWN_APP_SCHEMES: ReadonlySet<string> = new Set([
  "vscode",
  "cursor",
  "claude",
  "codex",
  "zed",
  "windsurf",
  "jetbrains",
  "obsidian",
  "raycast",
]);

const FORBIDDEN_SCHEMES: ReadonlySet<string> = new Set([
  "javascript",
  "data",
  "file",
  "vbscript",
  "blob",
  "about",
  "chrome",
  "chrome-extension",
  "jar",
  "view-source",
]);

const AUTH_METHODS: ReadonlySet<string> = new Set(["none", "client_secret_post", "client_secret_basic"]);

export type Headers = Record<string, string>;

export interface HandlerResponse {
  status: number;
  headers: Headers;
  body: unknown;
}

export interface RedirectResponse extends HandlerResponse {
  redirectTo: string;
}

export interface VerifyResult {
  userId: string;
  clientId: string;
  scopes: string[];
  resource: string;
  familyId?: string;
  expiresAt: number;
}

export interface AuthorizationServerOptions {
  now?: () => number;
}

// ---------------------------------------------------------------- utilities

const JSON_HEADERS: Headers = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
  pragma: "no-cache",
};

function json(status: number, body: unknown, extra: Headers = {}): HandlerResponse {
  return { status, headers: { ...JSON_HEADERS, ...extra }, body };
}

function oauthError(
  status: number,
  error: string,
  description: string,
  extra: Headers = {},
): HandlerResponse {
  return json(status, { error, error_description: description }, extra);
}

function base64urlDecode(value: string): Buffer {
  return Buffer.from(value, "base64url");
}

function sha256Base64url(value: string): string {
  return crypto.createHash("sha256").update(value, "utf8").digest("base64url");
}

/** RFC 7636 §4.2 verifier syntax check. */
export function isValidCodeVerifier(verifier: string): boolean {
  return typeof verifier === "string" && verifier.length >= 43 && verifier.length <= 128 && /^[A-Za-z0-9\-._~]+$/.test(verifier);
}

/** RFC 7636 §4.1 challenge syntax (base64url, 43 chars for SHA-256). */
export function isValidCodeChallenge(challenge: string): boolean {
  return typeof challenge === "string" && /^[A-Za-z0-9\-_]{43,128}$/.test(challenge);
}

export function verifyPkceS256(verifier: string, challenge: string): boolean {
  if (!isValidCodeVerifier(verifier)) return false;
  if (!isValidCodeChallenge(challenge)) return false;
  return timingSafeEqualStr(sha256Base64url(verifier), challenge);
}

/** Parse a space-delimited scope string into a de-duplicated list. */
export function parseScopeString(scope: string | undefined | null): string[] {
  if (!scope) return [];
  return [...new Set(scope.split(/[\s]+/).filter(Boolean))];
}

export interface RedirectUriCheck {
  ok: boolean;
  reason?: string;
}

/**
 * Validate a redirect URI.
 *
 * Allowed:
 *  - `https://...` (any host, no fragment, no wildcard)
 *  - `http://localhost`, `http://127.0.0.1`, `http://[::1]` (any port/path)
 *  - custom app schemes for known desktop/mobile clients, either a single-word
 *    allowlisted scheme (`vscode://...`) or a reverse-DNS scheme containing a
 *    dot (`com.example.app:/callback`)
 *
 * Rejected: fragments, wildcards, whitespace, userinfo, dangerous schemes.
 */
export function validateRedirectUri(uri: unknown): RedirectUriCheck {
  if (typeof uri !== "string" || uri.length === 0) return { ok: false, reason: "empty" };
  if (uri.length > 2048) return { ok: false, reason: "too_long" };
  if (/\s/.test(uri)) return { ok: false, reason: "whitespace" };
  if (uri.includes("#")) return { ok: false, reason: "fragment" };
  if (uri.includes("*")) return { ok: false, reason: "wildcard" };
  let url: URL;
  try {
    url = new URL(uri);
  } catch {
    return { ok: false, reason: "unparsable" };
  }
  const scheme = url.protocol.replace(/:$/, "").toLowerCase();
  if (!scheme || FORBIDDEN_SCHEMES.has(scheme)) return { ok: false, reason: "scheme_not_allowed" };
  if (url.username || url.password) return { ok: false, reason: "userinfo_not_allowed" };

  if (scheme === "https") {
    if (!url.hostname) return { ok: false, reason: "missing_host" };
    return { ok: true };
  }
  if (scheme === "http") {
    const host = url.hostname.toLowerCase();
    const loopback = host === "localhost" || host === "127.0.0.1" || host === "::1" || host === "[::1]";
    if (!loopback) return { ok: false, reason: "insecure_http" };
    return { ok: true };
  }
  // Custom application scheme (native app / CLI loopback-out-of-band).
  if (KNOWN_APP_SCHEMES.has(scheme)) return { ok: true };
  if (scheme.includes(".")) return { ok: true }; // reverse-DNS app scheme
  return { ok: false, reason: "unknown_custom_scheme" };
}

// -------------------------------------------------------------------- server

export class AuthorizationServer {
  readonly store: AuthStore;
  readonly config: Config;

  constructor(config: Config, opts: AuthorizationServerOptions = {}) {
    this.config = config;
    this.store = new AuthStore(config, { now: opts.now });
  }

  // ------------------------------------------------------------- metadata

  /** The canonical MCP resource identifier this server protects. */
  get resource(): string {
    return `${this.config.baseUrl}/mcp`;
  }

  get issuer(): string {
    return this.config.baseUrl;
  }

  /** RFC 8414 `/.well-known/oauth-authorization-server`. */
  metadata(): HandlerResponse {
    const b = this.config.baseUrl;
    return json(200, {
      issuer: b,
      authorization_endpoint: `${b}/oauth/authorize`,
      token_endpoint: `${b}/oauth/token`,
      registration_endpoint: `${b}/oauth/register`,
      revocation_endpoint: `${b}/oauth/revoke`,
      introspection_endpoint: `${b}/oauth/introspect`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      token_endpoint_auth_methods_supported: ["none", "client_secret_post", "client_secret_basic"],
      code_challenge_methods_supported: ["S256"],
      scopes_supported: [...SUPPORTED_SCOPES],
      response_modes_supported: ["query"],
      service_documentation: `${b}/docs`,
      resource: this.resource,
    });
  }

  /** RFC 9728 `/.well-known/oauth-protected-resource`. */
  protectedResourceMetadata(): HandlerResponse {
    const b = this.config.baseUrl;
    return json(200, {
      resource: this.resource,
      authorization_servers: [b],
      scopes_supported: [...SUPPORTED_SCOPES],
      bearer_methods_supported: ["header"],
      resource_name: "Universal Code Agent MCP",
      resource_documentation: `${b}/docs`,
    });
  }

  /** `WWW-Authenticate` value for a 401 on the MCP endpoint (RFC 9728 §5). */
  wwwAuthenticate(error?: string): string {
    const parts = ["Bearer", `resource_metadata="${this.config.baseUrl}/.well-known/oauth-protected-resource"`];
    if (error) parts.push(`error="${error}"`);
    return parts.join(", ");
  }

  // ------------------------------------------------- dynamic registration

  /**
   * RFC 7591 dynamic client registration.
   * Body: { redirect_uris[], client_name?, token_endpoint_auth_method?, scope?,
   *         grant_types?, response_types?, client_uri?, software_id? }
   */
  registerClient(req: Record<string, unknown> = {}): HandlerResponse {
    const redirectUrisRaw = req.redirect_uris ?? req.redirectUris;
    if (!Array.isArray(redirectUrisRaw) || redirectUrisRaw.length === 0) {
      return json(400, { error: "invalid_redirect_uri", error_description: "redirect_uris must be a non-empty array" });
    }
    if (redirectUrisRaw.length > 10) {
      return json(400, { error: "invalid_redirect_uri", error_description: "at most 10 redirect_uris are allowed" });
    }
    const redirectUris: string[] = [];
    for (const candidate of redirectUrisRaw) {
      const check = validateRedirectUri(candidate);
      if (!check.ok) {
        return json(400, {
          error: "invalid_redirect_uri",
          error_description: `redirect_uri rejected (${check.reason}): ${String(candidate).slice(0, 120)}`,
        });
      }
      redirectUris.push(candidate as string);
    }
    if (new Set(redirectUris).size !== redirectUris.length) {
      return json(400, { error: "invalid_redirect_uri", error_description: "duplicate redirect_uris" });
    }

    const methodRaw = req.token_endpoint_auth_method ?? req.tokenEndpointAuthMethod ?? "none";
    if (typeof methodRaw !== "string" || !AUTH_METHODS.has(methodRaw)) {
      return json(400, {
        error: "invalid_client_metadata",
        error_description: "token_endpoint_auth_method must be none, client_secret_post or client_secret_basic",
      });
    }
    const tokenEndpointAuthMethod = methodRaw as ClientAuthMethod;

    const grantTypesRaw = req.grant_types ?? req.grantTypes;
    const grantTypes = Array.isArray(grantTypesRaw)
      ? grantTypesRaw.filter((g): g is string => typeof g === "string")
      : ["authorization_code", "refresh_token"];
    const allowedGrants = new Set(["authorization_code", "refresh_token"]);
    for (const g of grantTypes) {
      if (!allowedGrants.has(g)) {
        return json(400, { error: "invalid_client_metadata", error_description: `unsupported grant_type: ${g}` });
      }
    }
    if (!grantTypes.includes("authorization_code")) {
      return json(400, { error: "invalid_client_metadata", error_description: "authorization_code grant is required" });
    }

    const responseTypesRaw = req.response_types ?? req.responseTypes;
    const responseTypes = Array.isArray(responseTypesRaw)
      ? responseTypesRaw.filter((r): r is string => typeof r === "string")
      : ["code"];
    if (responseTypes.some((r) => r !== "code")) {
      return json(400, { error: "invalid_client_metadata", error_description: "only response_type=code is supported" });
    }

    // Scope: requested client scope must be a subset of our supported set.
    const requestedScopes = parseScopeString(typeof req.scope === "string" ? req.scope : undefined);
    const invalid = requestedScopes.filter((s) => !SCOPE_SET.has(s));
    if (invalid.length > 0) {
      return json(400, {
        error: "invalid_client_metadata",
        error_description: `unsupported scope(s): ${invalid.join(" ")}`,
      });
    }
    const scope = (requestedScopes.length > 0 ? requestedScopes : [...SUPPORTED_SCOPES]).join(" ");

    const clientId = `mcp_${randomToken(16)}`;
    const clientSecret = tokenEndpointAuthMethod === "none" ? undefined : randomToken(32);
    const at = this.store.now();
    const record: ClientRecord = {
      clientId,
      clientSecretHash: clientSecret ? this.store.hashToken(clientSecret) : undefined,
      clientName: typeof req.client_name === "string" ? req.client_name : (typeof req.clientName === "string" ? req.clientName : undefined),
      clientUri: typeof req.client_uri === "string" ? req.client_uri : undefined,
      softwareId: typeof req.software_id === "string" ? req.software_id : undefined,
      redirectUris,
      grantTypes,
      responseTypes: ["code"],
      tokenEndpointAuthMethod,
      scope,
      createdAt: at,
    };
    this.store.putClient(record);

    const body: Record<string, unknown> = {
      client_id: clientId,
      client_id_issued_at: Math.floor(at / 1000),
      redirect_uris: redirectUris,
      grant_types: grantTypes,
      response_types: ["code"],
      token_endpoint_auth_method: tokenEndpointAuthMethod,
      scope,
    };
    if (record.clientName) body.client_name = record.clientName;
    if (record.clientUri) body.client_uri = record.clientUri;
    if (clientSecret) {
      body.client_secret = clientSecret;
      body.client_secret_expires_at = 0;
    }
    return json(201, body);
  }

  // -------------------------------------------------------------- authorize

  /**
   * Validate an authorization request and create a pending-consent record.
   * Input is the parsed query object (`GET /oauth/authorize?...`).
   */
  authorize(
    params: Record<string, unknown>,
  ): (HandlerResponse & { pending?: PendingAuthorizationRecord }) | RedirectResponse {
    const get = (k: string): string | undefined => {
      const v = params[k];
      if (Array.isArray(v)) return typeof v[0] === "string" ? v[0] : undefined;
      return typeof v === "string" ? v : undefined;
    };

    const clientId = get("client_id");
    const redirectUri = get("redirect_uri");
    const responseType = get("response_type");
    const state = get("state");
    const codeChallenge = get("code_challenge");
    const challengeMethod = get("code_challenge_method");
    const scopeParam = get("scope");
    const resource = get("resource");

    // The client and its exact redirect_uri must be validated before ANY
    // redirect-based error can be returned (RFC 6749 §4.1.2.1).
    const client = clientId ? this.store.getClient(clientId) : null;
    if (!clientId || !client) {
      return oauthError(400, "invalid_client", "Unknown client_id");
    }
    if (!redirectUri || !client.redirectUris.includes(redirectUri)) {
      return oauthError(400, "invalid_request", "redirect_uri does not exactly match a registered redirect URI");
    }

    const redirectError = (error: string, description: string): RedirectResponse => {
      const url = new URL(redirectUri);
      url.searchParams.set("error", error);
      url.searchParams.set("error_description", description);
      if (state) url.searchParams.set("state", state);
      return {
        status: 302,
        headers: { location: url.toString(), "cache-control": "no-store" },
        body: null,
        redirectTo: url.toString(),
      };
    };

    if (responseType !== "code") {
      return redirectError("unsupported_response_type", "Only response_type=code is supported");
    }
    if (!codeChallenge) {
      return redirectError("invalid_request", "PKCE code_challenge is required");
    }
    if (challengeMethod !== "S256") {
      return redirectError("invalid_request", "code_challenge_method must be S256 (plain is not allowed)");
    }
    if (!isValidCodeChallenge(codeChallenge)) {
      return redirectError("invalid_request", "Malformed code_challenge");
    }
    if (resource !== undefined && resource !== this.resource) {
      return redirectError("invalid_target", `resource must be ${this.resource}`);
    }

    const requestedScopes = parseScopeString(scopeParam);
    if (requestedScopes.length === 0) requestedScopes.push(DEFAULT_SCOPE);
    const unsupported = requestedScopes.filter((s) => !SCOPE_SET.has(s));
    if (unsupported.length > 0) {
      return redirectError("invalid_scope", `Unsupported scope(s): ${unsupported.join(" ")}`);
    }
    const clientScopes = new Set(parseScopeString(client.scope));
    const notAllowed = requestedScopes.filter((s) => clientScopes.size > 0 && !clientScopes.has(s));
    if (notAllowed.length > 0) {
      return redirectError("invalid_scope", `Scope(s) not registered for this client: ${notAllowed.join(" ")}`);
    }

    const at = this.store.now();
    const pending: PendingAuthorizationRecord = {
      id: randomToken(24),
      clientId: client.clientId,
      redirectUri,
      codeChallenge,
      codeChallengeMethod: "S256",
      scopes: requestedScopes,
      resource: this.resource,
      state,
      createdAt: at,
      expiresAt: at + PENDING_AUTHORIZATION_TTL_MS,
      status: "pending",
    };
    this.store.putPending(pending);

    return {
      status: 200,
      headers: { ...JSON_HEADERS },
      body: {
        pending_id: pending.id,
        client_id: pending.clientId,
        client_name: client.clientName ?? null,
        redirect_uri: pending.redirectUri,
        scopes: pending.scopes,
        resource: pending.resource,
        state: pending.state ?? null,
        expires_at: pending.expiresAt,
        consent_required: true,
      },
      pending,
    };
  }

  /**
   * Finish a pending authorization after the GitHub-authenticated user decides.
   * Returns a redirect back to the client with a single-use code, or
   * `error=access_denied` when the user declines.
   */
  completeAuthorization(pendingId: string, userId: string, approve: boolean): RedirectResponse | HandlerResponse {
    const pending = this.store.getPending(pendingId);
    if (!pending) return oauthError(404, "invalid_request", "Unknown or expired authorization request");
    if (!userId) return oauthError(401, "access_denied", "No authenticated user");

    const at = this.store.now();
    if (pending.status !== "pending") {
      return oauthError(409, "invalid_request", "Authorization request already resolved");
    }
    if (pending.expiresAt <= at) {
      this.store.deletePending(pendingId);
      return oauthError(400, "expired_token", "Authorization request expired");
    }

    const url = new URL(pending.redirectUri);
    if (pending.state) url.searchParams.set("state", pending.state);

    if (!approve) {
      this.store.updatePending(pendingId, { status: "denied", userId });
      this.store.deletePending(pendingId);
      url.searchParams.set("error", "access_denied");
      url.searchParams.set("error_description", "The user denied the authorization request");
      return { status: 302, headers: { location: url.toString(), "cache-control": "no-store" }, body: null, redirectTo: url.toString() };
    }

    const code = randomToken(32);
    const codeHash = this.store.hashToken(code);
    const familyId = randomToken(16);
    const record: AuthorizationCodeRecord = {
      clientId: pending.clientId,
      userId,
      redirectUri: pending.redirectUri,
      codeChallenge: pending.codeChallenge,
      codeChallengeMethod: "S256",
      scopes: pending.scopes,
      resource: pending.resource,
      createdAt: at,
      expiresAt: at + AUTHORIZATION_CODE_TTL_MS,
      familyId,
    };
    this.store.putCode(codeHash, record);
    this.store.updatePending(pendingId, { status: "approved", userId });
    this.store.deletePending(pendingId);

    url.searchParams.set("code", code);
    return { status: 302, headers: { location: url.toString(), "cache-control": "no-store" }, body: null, redirectTo: url.toString() };
  }

  // ------------------------------------------------------- client authentication

  private authenticateClient(req: Record<string, unknown>): { ok: true; client: ClientRecord } | { ok: false; response: HandlerResponse } {
    const headers = (req.headers as Record<string, string | string[] | undefined> | undefined) ?? {};
    const headerValue = (name: string): string | undefined => {
      const raw = headers[name] ?? headers[name.toLowerCase()];
      return Array.isArray(raw) ? raw[0] : raw;
    };

    let clientId = typeof req.client_id === "string" ? req.client_id : undefined;
    let clientSecret = typeof req.client_secret === "string" ? req.client_secret : undefined;
    let usedBasic = false;

    const authz = headerValue("authorization");
    if (authz && /^basic\s+/i.test(authz)) {
      usedBasic = true;
      const decoded = base64urlDecode(authz.replace(/^basic\s+/i, "").trim()).toString("utf8");
      const idx = decoded.indexOf(":");
      if (idx < 0) return { ok: false, response: oauthError(401, "invalid_client", "Malformed Basic credentials") };
      const basicId = decodeURIComponent(decoded.slice(0, idx));
      const basicSecret = decodeURIComponent(decoded.slice(idx + 1));
      if (clientId && clientId !== basicId) {
        return { ok: false, response: oauthError(401, "invalid_client", "Conflicting client_id") };
      }
      clientId = basicId;
      clientSecret = basicSecret;
    }

    if (!clientId) return { ok: false, response: oauthError(401, "invalid_client", "client_id is required") };
    const client = this.store.getClient(clientId);
    if (!client) return { ok: false, response: oauthError(401, "invalid_client", "Unknown client") };

    if (!client.clientSecretHash) {
      // Public client: a secret must not be presented.
      if (clientSecret) return { ok: false, response: oauthError(401, "invalid_client", "Public client must not send a secret") };
      return { ok: true, client };
    }

    if (!clientSecret) return { ok: false, response: oauthError(401, "invalid_client", "client authentication required") };
    const presented = this.store.hashToken(clientSecret);
    if (!timingSafeEqualStr(presented, client.clientSecretHash)) {
      return { ok: false, response: oauthError(401, "invalid_client", "Invalid client credentials") };
    }
    if (client.tokenEndpointAuthMethod === "none" && usedBasic) {
      return { ok: false, response: oauthError(401, "invalid_client", "Client is registered for no authentication") };
    }
    return { ok: true, client };
  }

  // ------------------------------------------------------------ token issue

  private issueTokens(
    client: ClientRecord,
    userId: string,
    scopes: string[],
    resource: string,
    familyId: string,
    codeHash?: string,
  ): { body: Record<string, unknown>; accessToken: string; refreshToken: string } {
    const at = this.store.now();
    const accessToken = randomToken(32);
    const refreshToken = randomToken(32);
    const accessExpiresAt = at + this.config.accessTokenTtlSec * 1000;
    const refreshExpiresAt = at + this.config.refreshTokenTtlSec * 1000;

    this.store.putAccessToken(this.store.hashToken(accessToken), {
      userId,
      clientId: client.clientId,
      scopes,
      resource,
      createdAt: at,
      expiresAt: accessExpiresAt,
      familyId,
      codeHash,
    });
    this.store.putRefreshToken(this.store.hashToken(refreshToken), {
      userId,
      clientId: client.clientId,
      scopes,
      resource,
      createdAt: at,
      expiresAt: refreshExpiresAt,
      familyId,
    });

    return {
      accessToken,
      refreshToken,
      body: {
        access_token: accessToken,
        token_type: "Bearer",
        expires_in: this.config.accessTokenTtlSec,
        refresh_token: refreshToken,
        scope: scopes.join(" "),
        resource,
      },
    };
  }

  // -------------------------------------------------------------- token endpoint

  /**
   * `POST /oauth/token`. Supports `authorization_code` and `refresh_token`.
   */
  token(req: Record<string, unknown> = {}): HandlerResponse {
    const grantType = typeof req.grant_type === "string" ? req.grant_type : undefined;
    if (!grantType) return oauthError(400, "invalid_request", "grant_type is required");

    const auth = this.authenticateClient(req);
    if (!auth.ok) return auth.response;
    const client = auth.client;

    if (grantType === "authorization_code") return this.tokenAuthorizationCode(client, req);
    if (grantType === "refresh_token") return this.tokenRefresh(client, req);
    return oauthError(400, "unsupported_grant_type", `Unsupported grant_type: ${grantType}`);
  }

  private tokenAuthorizationCode(client: ClientRecord, req: Record<string, unknown>): HandlerResponse {
    const code = typeof req.code === "string" ? req.code : undefined;
    const redirectUri = typeof req.redirect_uri === "string" ? req.redirect_uri : undefined;
    const verifier = typeof req.code_verifier === "string" ? req.code_verifier : undefined;

    if (!code) return oauthError(400, "invalid_request", "code is required");
    if (!redirectUri) return oauthError(400, "invalid_request", "redirect_uri is required");
    if (!verifier) return oauthError(400, "invalid_request", "code_verifier is required (PKCE)");

    const codeHash = this.store.hashToken(code);
    const record = this.store.getCode(codeHash);
    if (!record) return oauthError(400, "invalid_grant", "Unknown authorization code");
    if (record.clientId !== client.clientId) {
      return oauthError(400, "invalid_grant", "Authorization code was issued to another client");
    }
    if (record.usedAt !== undefined) {
      // Replay: revoke everything derived from this code.
      this.store.revokeTokensFromCode(codeHash);
      if (record.familyId) this.store.revokeTokenFamily(record.familyId, "code_replay");
      return oauthError(400, "invalid_grant", "Authorization code already used");
    }
    const at = this.store.now();
    if (record.revokedAt !== undefined) return oauthError(400, "invalid_grant", "Authorization code revoked");
    if (record.expiresAt <= at) {
      this.store.updateCode(codeHash, { revokedAt: at });
      return oauthError(400, "invalid_grant", "Authorization code expired");
    }
    if (record.redirectUri !== redirectUri) {
      return oauthError(400, "invalid_grant", "redirect_uri does not match the authorization request");
    }
    if (record.codeChallengeMethod !== "S256") {
      return oauthError(400, "invalid_grant", "Unsupported code_challenge_method");
    }
    if (!verifyPkceS256(verifier, record.codeChallenge)) {
      return oauthError(400, "invalid_grant", "PKCE verification failed");
    }
    const requestedResource = typeof req.resource === "string" ? req.resource : undefined;
    if (requestedResource !== undefined && requestedResource !== record.resource) {
      return oauthError(400, "invalid_target", "resource does not match the authorization request");
    }

    // Consume the code before issuing, so a concurrent/replayed request fails.
    this.store.updateCode(codeHash, { usedAt: at });

    const familyId = record.familyId ?? randomToken(16);
    const issued = this.issueTokens(client, record.userId, record.scopes, record.resource, familyId, codeHash);
    return json(200, issued.body);
  }

  private tokenRefresh(client: ClientRecord, req: Record<string, unknown>): HandlerResponse {
    const refreshToken = typeof req.refresh_token === "string" ? req.refresh_token : undefined;
    if (!refreshToken) return oauthError(400, "invalid_request", "refresh_token is required");

    const tokenHash = this.store.hashToken(refreshToken);
    const record = this.store.getRefreshToken(tokenHash);
    if (!record) return oauthError(400, "invalid_grant", "Unknown refresh token");

    const at = this.store.now();
    if (record.clientId !== client.clientId) {
      this.store.revokeTokenFamily(record.familyId, "client_mismatch");
      return oauthError(400, "invalid_grant", "Refresh token was issued to another client");
    }

    // Reuse detection: a rotated (used) or revoked token means the whole family
    // is compromised.
    if (record.revokedAt !== undefined || record.usedAt !== undefined) {
      this.store.revokeTokenFamily(record.familyId, "refresh_reuse");
      return oauthError(400, "invalid_grant", "Refresh token reuse detected; token family revoked");
    }
    if (record.expiresAt <= at) {
      this.store.revokeTokenFamily(record.familyId, "expired");
      return oauthError(400, "invalid_grant", "Refresh token expired");
    }

    // Scope narrowing only.
    const requestedScopes = parseScopeString(typeof req.scope === "string" ? req.scope : undefined);
    let scopes = record.scopes;
    if (requestedScopes.length > 0) {
      const notOwned = requestedScopes.filter((s) => !record.scopes.includes(s));
      if (notOwned.length > 0) {
        return oauthError(400, "invalid_scope", `Refresh cannot widen scope: ${notOwned.join(" ")}`);
      }
      scopes = requestedScopes;
    }

    const requestedResource = typeof req.resource === "string" ? req.resource : undefined;
    if (requestedResource !== undefined && requestedResource !== record.resource) {
      return oauthError(400, "invalid_target", "resource does not match the original grant");
    }

    const issued = this.issueTokens(client, record.userId, scopes, record.resource, record.familyId);
    this.store.updateRefreshToken(tokenHash, {
      usedAt: at,
      replacedBy: this.store.hashToken(issued.refreshToken),
    });
    return json(200, issued.body);
  }

  // ---------------------------------------------------------------- revoke

  /** RFC 7009 `POST /oauth/revoke`. Always 200 for unknown tokens. */
  revoke(req: Record<string, unknown> = {}): HandlerResponse {
    const token = typeof req.token === "string" ? req.token : undefined;
    if (!token) return oauthError(400, "invalid_request", "token is required");

    const auth = this.authenticateClient(req);
    if (!auth.ok) return auth.response;

    const hash = this.store.hashToken(token);
    const at = this.store.now();
    const access = this.store.getAccessToken(hash);
    if (access) {
      if (access.clientId !== auth.client.clientId) {
        return oauthError(400, "unauthorized_client", "Token belongs to another client");
      }
      this.store.updateAccessToken(hash, { revokedAt: at });
      return json(200, {});
    }
    const refresh = this.store.getRefreshToken(hash);
    if (refresh) {
      if (refresh.clientId !== auth.client.clientId) {
        return oauthError(400, "unauthorized_client", "Token belongs to another client");
      }
      // Revoking a refresh token kills the whole family (the access tokens too).
      this.store.revokeTokenFamily(refresh.familyId, "revoked");
      return json(200, {});
    }
    // Unknown token: RFC 7009 requires a 200 response.
    return json(200, {});
  }

  // ------------------------------------------------------------ introspect

  /** RFC 7662 `POST /oauth/introspect`. */
  introspect(req: Record<string, unknown> = {}): HandlerResponse {
    const token = typeof req.token === "string" ? req.token : undefined;
    if (!token) return oauthError(400, "invalid_request", "token is required");
    const auth = this.authenticateClient(req);
    if (!auth.ok) return auth.response;

    const result = this.verifyAccessToken(token);
    if (!result) return json(200, { active: false });
    return json(200, {
      active: true,
      scope: result.scopes.join(" "),
      client_id: result.clientId,
      sub: result.userId,
      exp: Math.floor(result.expiresAt / 1000),
      token_type: "Bearer",
      aud: result.resource,
      resource: result.resource,
    });
  }

  // ------------------------------------------------------- verification

  /**
   * Validate an opaque access token. Returns the principal or null when the
   * token is unknown, revoked or expired (or lacks `requiredScope`).
   */
  verifyAccessToken(token: string | undefined | null, requiredScope?: string | string[]): VerifyResult | null {
    if (!token) return null;
    const hash = this.store.hashToken(token);
    const record = this.store.getAccessToken(hash);
    if (!record) return null;
    if (record.revokedAt !== undefined) return null;
    const at = this.store.now();
    if (record.expiresAt <= at) return null;

    const required = Array.isArray(requiredScope)
      ? requiredScope
      : requiredScope
        ? [requiredScope]
        : [];
    if (required.length > 0 && !required.every((s) => record.scopes.includes(s))) return null;

    // Track usage (best effort, throttled to avoid a disk write per request).
    if (record.lastUsedAt === undefined || at - record.lastUsedAt > 60_000) {
      this.store.updateAccessToken(hash, { lastUsedAt: at });
    }

    return {
      userId: record.userId,
      clientId: record.clientId,
      scopes: record.scopes,
      resource: record.resource,
      familyId: record.familyId,
      expiresAt: record.expiresAt,
    };
  }

  /** Extract a bearer token from an Authorization header value. */
  static bearerFromHeader(header: string | string[] | undefined | null): string | null {
    const raw = Array.isArray(header) ? header[0] : header;
    if (!raw) return null;
    const m = /^Bearer\s+(.+)$/i.exec(raw.trim());
    return m ? m[1]!.trim() : null;
  }

  /** Handler-shaped guard for the MCP endpoint. */
  authorizeRequest(
    req: { headers?: Record<string, string | string[] | undefined>; requiredScope?: string | string[] },
  ): { ok: true; principal: VerifyResult } | { ok: false; response: HandlerResponse } {
    const headers = req.headers ?? {};
    const bearer = AuthorizationServer.bearerFromHeader(headers.authorization ?? headers.Authorization);
    const principal = this.verifyAccessToken(bearer, req.requiredScope);
    if (!principal) {
      return {
        ok: false,
        response: json(
          401,
          {
            error: "invalid_token",
            error_description: bearer ? "The access token is invalid, revoked or expired" : "Missing bearer token",
          },
          { "www-authenticate": this.wwwAuthenticate(bearer ? "invalid_token" : undefined) },
        ),
      };
    }
    return { ok: true, principal };
  }

  // -------------------------------------------------------- dashboard APIs

  /** Revoke every access/refresh token a user holds. Returns count revoked. */
  revokeAllForUser(userId: string): number {
    return this.store.revokeAllForUser(userId);
  }

  /** Active grants (one entry per client/family) for the dashboard. */
  listGrants(userId: string): {
    clientId: string;
    clientName?: string;
    scopes: string[];
    resource: string;
    createdAt: number;
    lastUsedAt: number;
    familyId: string;
  }[] {
    return this.store.listActiveGrants(userId).sort((a, b) => b.lastUsedAt - a.lastUsedAt);
  }

  /** Revoke all tokens for a user+client pair. Returns count revoked. */
  revokeGrant(userId: string, clientId: string): number {
    // Revoke whole families so derived access tokens die with the grant too.
    const families = new Set<string>();
    for (const rec of Object.values(this.store.snapshot().refreshTokens)) {
      if (rec.userId === userId && rec.clientId === clientId) families.add(rec.familyId);
    }
    let count = this.store.revokeGrantsForUserClient(userId, clientId);
    for (const familyId of families) count += this.store.revokeTokenFamily(familyId, "grant_revoked");
    return count;
  }
}
