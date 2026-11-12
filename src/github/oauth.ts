/**
 * GitHub OAuth web-flow helpers.
 *
 * Only these four things need `client_secret`, and only on the server:
 *   - buildAuthorizeUrl  (no secret; browser redirect)
 *   - exchangeCode       (secret; code -> token)
 *   - refreshGithubToken (secret; needs expiring user tokens enabled on the app)
 *   - revokeGithubToken  (secret; DELETE /applications/{client_id}/token)
 *
 * The resulting `accessToken` is a per-user token: store it against that user
 * (see `UserContext.githubToken`) and build one `GitHubClient` per user.
 */

export interface AuthorizeUrlOptions {
  clientId: string;
  redirectUri: string;
  scope?: string | string[];
  state?: string;
  /** Defaults to https://github.com/login/oauth/authorize */
  authorizeUrl?: string;
  /** Skips the consent screen for apps the user already approved. */
  allowSignup?: boolean;
  login?: string;
}

export interface OAuthEndpoints {
  /** Defaults to https://github.com/login/oauth/access_token */
  tokenUrl?: string;
  /** Defaults to https://api.github.com */
  apiBaseUrl?: string;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
}

export interface OAuthTokenResult {
  /** Present on success; absent when GitHub returns an error payload. */
  accessToken: string | null;
  scope: string;
  tokenType: string;
  refreshToken?: string;
  /** Seconds. Only returned when expiring user tokens are enabled for the app. */
  expiresIn?: number;
  /** Convenience: absolute expiry time. */
  expiresAt?: string;
  refreshTokenExpiresIn?: number;
  error?: string;
  errorDescription?: string;
}

export interface ExchangeCodeParams extends OAuthEndpoints {
  clientId: string;
  clientSecret: string;
  code: string;
  redirectUri: string;
}

export interface RefreshParams extends OAuthEndpoints {
  clientId: string;
  clientSecret: string;
  refreshToken: string;
}

export interface RevokeParams extends OAuthEndpoints {
  clientId: string;
  clientSecret: string;
  token: string;
}

const DEFAULT_AUTHORIZE_URL = "https://github.com/login/oauth/authorize";
const DEFAULT_TOKEN_URL = "https://github.com/login/oauth/access_token";
const DEFAULT_API_BASE = "https://api.github.com";

function toScopeString(scope: string | string[] | undefined): string {
  if (!scope) return "";
  const list = Array.isArray(scope) ? scope : scope.split(/[\s,]+/);
  return list.map((s) => s.trim()).filter(Boolean).join(" ");
}

/** Redact every secret we know about, plus generic credential patterns. */
function scrub(text: string, secrets: (string | undefined)[]): string {
  let out = text;
  for (const secret of secrets) {
    if (secret && secret.length >= 4) out = out.split(secret).join("[REDACTED]");
  }
  return out
    .replace(/(gh[pousr]_)[A-Za-z0-9]{10,}/g, "$1[REDACTED]")
    .replace(/(github_pat_)[A-Za-z0-9_]{10,}/g, "$1[REDACTED]")
    .replace(/(access_token=)[^&\s]+/gi, "$1[REDACTED]")
    .replace(/("(?:access_token|refresh_token|client_secret)"\s*:\s*")[^"]*(")/gi, "$1[REDACTED]$2");
}

export class GitHubOAuthError extends Error {
  readonly status: number;
  readonly error: string | null;
  readonly errorDescription: string | null;

  constructor(message: string, opts: { status: number; error?: string | null; errorDescription?: string | null }) {
    super(message);
    this.name = "GitHubOAuthError";
    this.status = opts.status;
    this.error = opts.error ?? null;
    this.errorDescription = opts.errorDescription ?? null;
  }
}

/**
 * Build the browser URL for step 1 of the web flow. `state` should be a random
 * value the caller keeps in the session and verifies on the callback (CSRF).
 */
export function buildAuthorizeUrl(opts: AuthorizeUrlOptions): string {
  if (!opts.clientId) throw new GitHubOAuthError("buildAuthorizeUrl requires a clientId", { status: 0, error: "invalid_client" });
  if (!opts.redirectUri) {
    throw new GitHubOAuthError("buildAuthorizeUrl requires a redirectUri (it must match the app settings)", {
      status: 0,
      error: "invalid_request",
    });
  }
  const url = new URL(opts.authorizeUrl ?? DEFAULT_AUTHORIZE_URL);
  url.searchParams.set("client_id", opts.clientId);
  url.searchParams.set("redirect_uri", opts.redirectUri);
  const scope = toScopeString(opts.scope);
  if (scope) url.searchParams.set("scope", scope);
  if (opts.state) url.searchParams.set("state", opts.state);
  if (opts.allowSignup !== undefined) url.searchParams.set("allow_signup", String(opts.allowSignup));
  if (opts.login) url.searchParams.set("login", opts.login);
  return url.toString();
}

interface RawTokenPayload {
  access_token?: unknown;
  scope?: unknown;
  token_type?: unknown;
  refresh_token?: unknown;
  expires_in?: unknown;
  refresh_token_expires_in?: unknown;
  error?: unknown;
  error_description?: unknown;
}

async function postForm(
  url: string,
  form: Record<string, string>,
  opts: OAuthEndpoints,
  secrets: (string | undefined)[],
): Promise<{ status: number; body: RawTokenPayload & { raw?: string } }> {
  const doFetch = opts.fetchImpl ?? fetch;
  const timeoutMs = opts.timeoutMs ?? 20_000;
  let res: Response;
  try {
    res = await doFetch(url, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "universal-code-agent/0.1.0",
      },
      body: new URLSearchParams(form).toString(),
      ...(timeoutMs > 0 ? { signal: AbortSignal.timeout(timeoutMs) } : {}),
    });
  } catch (err) {
    const reason = err instanceof Error ? err.message : "network error";
    throw new GitHubOAuthError(scrub(`GitHub OAuth request failed before a response: ${reason}`, secrets), { status: 0 });
  }
  const text = await res.text();
  let parsed: RawTokenPayload = {};
  try {
    parsed = (JSON.parse(text) as RawTokenPayload) ?? {};
  } catch {
    // GitHub can answer form-encoded when Accept is ignored.
    const params = new URLSearchParams(text);
    parsed = {
      access_token: params.get("access_token") ?? undefined,
      scope: params.get("scope") ?? undefined,
      token_type: params.get("token_type") ?? undefined,
      refresh_token: params.get("refresh_token") ?? undefined,
      error: params.get("error") ?? undefined,
      error_description: params.get("error_description") ?? undefined,
    };
  }
  return { status: res.status, body: parsed };
}

function toResult(status: number, body: RawTokenPayload, secrets: (string | undefined)[]): OAuthTokenResult {
  const accessToken = typeof body.access_token === "string" && body.access_token ? body.access_token : null;
  const error = typeof body.error === "string" && body.error ? scrub(body.error, secrets) : undefined;
  const errorDescription =
    typeof body.error_description === "string" && body.error_description ? scrub(body.error_description, secrets) : undefined;

  if (!accessToken) {
    throw new GitHubOAuthError(
      scrub(
        `GitHub OAuth token request failed${status ? ` (HTTP ${status})` : ""}: ${error ?? "no access_token"}${errorDescription ? ` — ${errorDescription}` : ""}`,
        secrets,
      ),
      { status, error: error ?? null, errorDescription: errorDescription ?? null },
    );
  }

  const result: OAuthTokenResult = {
    accessToken,
    scope: typeof body.scope === "string" ? body.scope : "",
    tokenType: typeof body.token_type === "string" && body.token_type ? body.token_type : "bearer",
  };
  if (typeof body.refresh_token === "string" && body.refresh_token) result.refreshToken = body.refresh_token;
  if (typeof body.expires_in === "number" && Number.isFinite(body.expires_in)) {
    result.expiresIn = body.expires_in;
    result.expiresAt = new Date(Date.now() + body.expires_in * 1000).toISOString();
  }
  if (typeof body.refresh_token_expires_in === "number" && Number.isFinite(body.refresh_token_expires_in)) {
    result.refreshTokenExpiresIn = body.refresh_token_expires_in;
  }
  return result;
}

/** Step 2 of the web flow: swap the `code` from the callback for a user token. */
export async function exchangeCode(params: ExchangeCodeParams): Promise<OAuthTokenResult> {
  if (!params.code) throw new GitHubOAuthError("exchangeCode requires the ?code= value from the callback", { status: 0, error: "invalid_request" });
  if (!params.clientId || !params.clientSecret) {
    throw new GitHubOAuthError("exchangeCode requires clientId and clientSecret", { status: 0, error: "invalid_client" });
  }
  if (!params.redirectUri) {
    throw new GitHubOAuthError("exchangeCode requires the same redirectUri used in the authorize step", {
      status: 0,
      error: "invalid_request",
    });
  }
  const { status, body } = await postForm(
    params.tokenUrl ?? DEFAULT_TOKEN_URL,
    {
      client_id: params.clientId,
      client_secret: params.clientSecret,
      code: params.code,
      redirect_uri: params.redirectUri,
    },
    params,
    [params.clientSecret, params.code],
  );
  return toResult(status, body, [params.clientSecret]);
}

/**
 * Refresh an expiring user token (requires "Expire user authorization tokens"
 * on the OAuth app). Returns the new access token AND the new refresh token —
 * GitHub rotates it, so the old one must be discarded.
 */
export async function refreshGithubToken(params: RefreshParams): Promise<OAuthTokenResult> {
  if (!params.refreshToken) {
    throw new GitHubOAuthError("refreshGithubToken requires a refresh token", { status: 0, error: "invalid_request" });
  }
  if (!params.clientId || !params.clientSecret) {
    throw new GitHubOAuthError("refreshGithubToken requires clientId and clientSecret", { status: 0, error: "invalid_client" });
  }
  const { status, body } = await postForm(
    params.tokenUrl ?? DEFAULT_TOKEN_URL,
    {
      client_id: params.clientId,
      client_secret: params.clientSecret,
      grant_type: "refresh_token",
      refresh_token: params.refreshToken,
    },
    params,
    [params.clientSecret, params.refreshToken],
  );
  return toResult(status, body, [params.clientSecret, params.refreshToken]);
}

/**
 * Revoke a user token: `DELETE /applications/{client_id}/token` with HTTP Basic
 * auth (client_id:client_secret) and `{"access_token": token}`.
 * Succeeds (204) even when the token was already invalid.
 */
export async function revokeGithubToken(params: RevokeParams): Promise<{ revoked: true; status: number }> {
  if (!params.clientId || !params.clientSecret) {
    throw new GitHubOAuthError("revokeGithubToken requires clientId and clientSecret", { status: 0, error: "invalid_client" });
  }
  if (!params.token) throw new GitHubOAuthError("revokeGithubToken requires the token to revoke", { status: 0, error: "invalid_request" });

  const apiBase = (params.apiBaseUrl ?? DEFAULT_API_BASE).replace(/\/+$/, "");
  const url = `${apiBase}/applications/${encodeURIComponent(params.clientId)}/token`;
  const basic = Buffer.from(`${params.clientId}:${params.clientSecret}`, "utf8").toString("base64");
  const doFetch = params.fetchImpl ?? fetch;
  const timeoutMs = params.timeoutMs ?? 20_000;

  let res: Response;
  try {
    res = await doFetch(url, {
      method: "DELETE",
      headers: {
        Accept: "application/vnd.github+json",
        Authorization: `Basic ${basic}`,
        "X-GitHub-Api-Version": "2022-11-28",
        "Content-Type": "application/json",
        "User-Agent": "universal-code-agent/0.1.0",
      },
      body: JSON.stringify({ access_token: params.token }),
      ...(timeoutMs > 0 ? { signal: AbortSignal.timeout(timeoutMs) } : {}),
    });
  } catch (err) {
    const reason = err instanceof Error ? err.message : "network error";
    throw new GitHubOAuthError(scrub(`GitHub OAuth revoke failed before a response: ${reason}`, [params.clientSecret, params.token, basic]), {
      status: 0,
    });
  }

  if (res.status === 204 || res.status === 200) return { revoked: true, status: res.status };
  const text = await res.text().catch(() => "");
  throw new GitHubOAuthError(
    scrub(`GitHub OAuth revoke failed with ${res.status}${text ? `: ${text.slice(0, 300)}` : ""}`, [params.clientSecret, params.token, basic]),
    { status: res.status },
  );
}
