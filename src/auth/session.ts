/**
 * Browser session management for the web dashboard + GitHub login.
 *
 * Cookies carry `sessionId.hmac` where the HMAC-SHA256 (keyed from the store's
 * derived secret) covers the session id and issue timestamp. The session id is
 * never trusted without the signature.
 *
 * Security properties:
 *  - httpOnly, SameSite=Lax, Path=/ and Secure when `config.baseUrl` is https.
 *  - Server-side record with absolute expiry and an idle timeout (sliding).
 *  - Per-session CSRF token required on state-changing requests.
 *  - OAuth `state` values are random, single-use, 10 minute TTL, bound to the
 *    session and to the GitHub nonce (defence against login CSRF replay).
 *  - Sliding-window login rate limiter keyed by IP / login.
 */
import crypto from "node:crypto";
import type { AuthStore, SessionRecord } from "./store.js";
import { randomToken, timingSafeEqualStr } from "./store.js";

export const SESSION_COOKIE = "uca_session";
export const CSRF_HEADER = "x-csrf-token";
export const OAUTH_STATE_TTL_MS = 10 * 60 * 1000;
export const DEFAULT_SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
export const DEFAULT_IDLE_TIMEOUT_MS = 12 * 60 * 60 * 1000;

export interface CookieOptions {
  maxAge?: number;
  path?: string;
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: "Strict" | "Lax" | "None";
  expires?: Date;
  domain?: string;
}

/** Parse a `Cookie` header into a plain object (last value wins). */
export function parseCookies(header: string | string[] | undefined | null): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  const raw = Array.isArray(header) ? header.join("; ") : header;
  for (const part of raw.split(";")) {
    const idx = part.indexOf("=");
    if (idx < 1) continue;
    const name = part.slice(0, idx).trim();
    if (!name) continue;
    let value = part.slice(idx + 1).trim();
    if (value.startsWith('"') && value.endsWith('"') && value.length >= 2) value = value.slice(1, -1);
    try {
      out[name] = decodeURIComponent(value);
    } catch {
      out[name] = value;
    }
  }
  return out;
}

/** Serialize a Set-Cookie value. */
export function serializeCookie(name: string, value: string, opts: CookieOptions = {}): string {
  const parts: string[] = [`${name}=${encodeURIComponent(value)}`];
  parts.push(`Path=${opts.path ?? "/"}`);
  if (opts.maxAge !== undefined) parts.push(`Max-Age=${Math.floor(opts.maxAge)}`);
  if (opts.expires) parts.push(`Expires=${opts.expires.toUTCString()}`);
  if (opts.domain) parts.push(`Domain=${opts.domain}`);
  if (opts.httpOnly !== false) parts.push("HttpOnly");
  if (opts.secure) parts.push("Secure");
  parts.push(`SameSite=${opts.sameSite ?? "Lax"}`);
  return parts.join("; ");
}

export interface SessionPrincipal {
  sessionId: string;
  userId: string;
  csrfToken: string;
  expiresAt: number;
  login: string;
  isAdmin: boolean;
}

export interface SessionOptions {
  /** Absolute session lifetime (default 7 days). */
  ttlMs?: number;
  /** Idle timeout, refreshed on each authenticated request (default 12h). */
  idleTimeoutMs?: number;
}

/**
 * Sliding-window rate limiter (in-memory). Suitable for a single-process agent
 * server; `key` is typically an IP address or `ip:login`.
 */
export class SlidingWindowLimiter {
  private readonly hits = new Map<string, number[]>();
  constructor(
    private readonly limit: number,
    private readonly windowMs: number,
    private readonly clock: () => number = () => Date.now(),
  ) {}

  /** Record an attempt. Returns whether the attempt is allowed. */
  hit(key: string): boolean {
    const now = this.clock();
    const cutoff = now - this.windowMs;
    const arr = (this.hits.get(key) ?? []).filter((t) => t > cutoff);
    if (arr.length >= this.limit) {
      this.hits.set(key, arr);
      return false;
    }
    arr.push(now);
    this.hits.set(key, arr);
    return true;
  }

  /** Attempts remaining in the current window. */
  remaining(key: string): number {
    const cutoff = this.clock() - this.windowMs;
    const arr = (this.hits.get(key) ?? []).filter((t) => t > cutoff);
    return Math.max(0, this.limit - arr.length);
  }

  /** Milliseconds until the window frees a slot (0 when not limited). */
  retryAfterMs(key: string): number {
    const now = this.clock();
    const cutoff = now - this.windowMs;
    const arr = (this.hits.get(key) ?? []).filter((t) => t > cutoff);
    if (arr.length < this.limit) return 0;
    const oldest = arr[0]!;
    return Math.max(0, oldest + this.windowMs - now);
  }

  /** Clear one key, or the whole limiter when called without a key. */
  reset(key?: string): void {
    if (key === undefined) this.hits.clear();
    else this.hits.delete(key);
  }
}

export class SessionManager {
  private readonly store: AuthStore;
  private readonly ttlMs: number;
  private readonly idleTimeoutMs: number;
  readonly loginLimiter: SlidingWindowLimiter;

  constructor(store: AuthStore, opts: SessionOptions = {}) {
    this.store = store;
    this.ttlMs = opts.ttlMs ?? DEFAULT_SESSION_TTL_MS;
    this.idleTimeoutMs = opts.idleTimeoutMs ?? DEFAULT_IDLE_TIMEOUT_MS;
    // 10 login attempts per 15 minutes per key (IP, or IP:login).
    this.loginLimiter = new SlidingWindowLimiter(10, 15 * 60 * 1000, () => this.store.now());
  }

  private get secure(): boolean {
    return /^https:/i.test(this.config().baseUrl);
  }

  private config() {
    return this.store.config;
  }

  // ------------------------------------------------------------ cookie auth

  private sign(payload: string): string {
    return crypto.createHmac("sha256", this.store.getSecretKey()).update(payload, "utf8").digest("base64url");
  }

  /** `sessionId.timestamp.hmac` — the timestamp allows cheap rotation checks. */
  private signSessionCookie(sessionId: string, issuedAt: number): string {
    const payload = `${sessionId}.${issuedAt}`;
    return `${payload}.${this.sign(payload)}`;
  }

  /** Verify a raw cookie value; returns the session id or null. */
  verifySessionCookie(raw: string | undefined | null): string | null {
    if (!raw) return null;
    const parts = raw.split(".");
    if (parts.length !== 3) return null;
    const [sessionId, tsRaw, sig] = parts as [string, string, string];
    if (!/^[A-Za-z0-9_-]{16,}$/.test(sessionId)) return null;
    const issuedAt = Number(tsRaw);
    if (!Number.isFinite(issuedAt)) return null;
    const expected = this.sign(`${sessionId}.${issuedAt}`);
    if (!timingSafeEqualStr(sig, expected)) return null;
    return sessionId;
  }

  // --------------------------------------------------------------- sessions

  /** Create a server-side session and return the Set-Cookie header value. */
  createSession(
    userId: string,
    opts: { userAgent?: string; ip?: string; csrfToken?: string } = {},
  ): { session: SessionRecord; cookie: string; csrfToken: string } {
    const now = this.store.now();
    const id = randomToken(32);
    const csrfToken = opts.csrfToken ?? randomToken(32);
    const session: SessionRecord = {
      id,
      userId,
      csrfToken,
      createdAt: now,
      lastSeenAt: now,
      expiresAt: now + this.ttlMs,
      idleTimeoutMs: this.idleTimeoutMs,
      userAgent: opts.userAgent,
      ip: opts.ip,
    };
    this.store.putSession(session);
    const cookie = serializeCookie(SESSION_COOKIE, this.signSessionCookie(id, now), {
      httpOnly: true,
      secure: this.secure,
      sameSite: "Lax",
      path: "/",
      maxAge: Math.floor(this.ttlMs / 1000),
    });
    return { session, cookie, csrfToken };
  }

  /**
   * Resolve a request to a principal. Returns null when the cookie is missing,
   * forged, expired, idle-expired or its session record no longer exists.
   */
  getSession(cookies: Record<string, string> | string | undefined | null): SessionPrincipal | null {
    const jar = typeof cookies === "string" ? parseCookies(cookies) : cookies;
    const raw = jar?.[SESSION_COOKIE];
    const sessionId = this.verifySessionCookie(raw);
    if (!sessionId) return null;
    const session = this.store.getSession(sessionId);
    if (!session) return null;
    const now = this.store.now();
    if (session.expiresAt <= now) {
      this.store.deleteSession(sessionId);
      return null;
    }
    if (session.lastSeenAt + session.idleTimeoutMs <= now) {
      this.store.deleteSession(sessionId);
      return null;
    }
    this.store.touchSession(sessionId, now);
    const user = this.store.getUser(session.userId);
    return {
      sessionId,
      userId: session.userId,
      csrfToken: session.csrfToken,
      expiresAt: session.expiresAt,
      login: user?.login ?? session.userId,
      isAdmin: false,
    };
  }

  destroySession(cookies: Record<string, string> | string | undefined | null): string {
    const jar = typeof cookies === "string" ? parseCookies(cookies) : cookies;
    const raw = jar?.[SESSION_COOKIE];
    const sessionId = this.verifySessionCookie(raw);
    if (sessionId) this.store.deleteSession(sessionId);
    return serializeCookie(SESSION_COOKIE, "", {
      httpOnly: true,
      secure: this.secure,
      sameSite: "Lax",
      path: "/",
      maxAge: 0,
    });
  }

  // ------------------------------------------------------------------- CSRF

  /** Constant-time CSRF check for state-changing requests. */
  verifyCsrf(principal: Pick<SessionPrincipal, "csrfToken"> | null, provided: string | undefined | null): boolean {
    if (!principal || !provided) return false;
    return timingSafeEqualStr(principal.csrfToken, provided);
  }

  /**
   * Convenience guard used by the HTTP layer: returns the principal only when
   * the request is authenticated and (for non-GET/HEAD/OPTIONS) passes CSRF.
   */
  requireSession(
    method: string,
    cookies: Record<string, string> | string | undefined | null,
    headers: Record<string, string | string[] | undefined> = {},
  ): { ok: true; principal: SessionPrincipal } | { ok: false; status: number; error: string } {
    const principal = this.getSession(cookies);
    if (!principal) return { ok: false, status: 401, error: "unauthorized" };
    const m = method.toUpperCase();
    const safe = m === "GET" || m === "HEAD" || m === "OPTIONS";
    if (!safe) {
      const raw = headers[CSRF_HEADER] ?? headers[CSRF_HEADER.toUpperCase()];
      const token = Array.isArray(raw) ? raw[0] : raw;
      if (!this.verifyCsrf(principal, token ?? undefined)) return { ok: false, status: 403, error: "invalid_csrf" };
    }
    return { ok: true, principal };
  }

  // ------------------------------------------------------- oauth login state

  /**
   * Create a single-use OAuth `state` for the GitHub login redirect, bound to
   * the browser session and to an optional nonce (e.g. PKCE for the GitHub hop).
   */
  createOAuthState(
    sessionId: string,
    opts: { nonce?: string; redirectTo?: string; ttlMs?: number } = {},
  ): { state: string; expiresAt: number } {
    const now = this.store.now();
    const state = randomToken(32);
    const expiresAt = now + (opts.ttlMs ?? OAUTH_STATE_TTL_MS);
    this.store.putLoginState(this.store.hashToken(state), {
      sessionId,
      nonce: opts.nonce,
      redirectTo: opts.redirectTo,
      createdAt: now,
      expiresAt,
    });
    return { state, expiresAt };
  }

  /**
   * Validate + consume an OAuth `state`. Returns the bound record on success.
   * Reusing a state (even after success) fails: single use.
   */
  consumeOAuthState(
    state: string | undefined | null,
    sessionId?: string | null,
    nonce?: string | null,
  ): { ok: true; sessionId: string; redirectTo?: string } | { ok: false; reason: string } {
    if (!state) return { ok: false, reason: "missing_state" };
    const key = this.store.hashToken(state);
    const record = this.store.getLoginState(key);
    if (!record) return { ok: false, reason: "unknown_state" };
    const now = this.store.now();
    if (record.usedAt) return { ok: false, reason: "state_reused" };
    if (record.expiresAt <= now) return { ok: false, reason: "state_expired" };
    if (sessionId !== undefined && sessionId !== null && record.sessionId !== sessionId) {
      return { ok: false, reason: "state_session_mismatch" };
    }
    if (nonce !== undefined && nonce !== null && record.nonce !== undefined && record.nonce !== nonce) {
      return { ok: false, reason: "state_nonce_mismatch" };
    }
    this.store.updateLoginState(key, { usedAt: now });
    return { ok: true, sessionId: record.sessionId, redirectTo: record.redirectTo };
  }
}
