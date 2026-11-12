/**
 * Persistent, file-backed store for the OAuth 2.1 authorization server.
 *
 * Design notes:
 *  - All secrets are either hashed (SHA-256) or encrypted (AES-256-GCM) before
 *    they touch the disk. The JSON file therefore contains no usable secret.
 *  - Writes are atomic (temp file in the same directory + rename) and the file
 *    is created with mode 0600.
 *  - A `now()` clock can be injected for tests.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import type { Config } from "../util/config.js";

export type ClientAuthMethod = "none" | "client_secret_post" | "client_secret_basic";

export interface ClientRecord {
  clientId: string;
  clientSecretHash?: string;
  clientName?: string;
  clientUri?: string;
  softwareId?: string;
  redirectUris: string[];
  grantTypes: string[];
  responseTypes: string[];
  tokenEndpointAuthMethod: ClientAuthMethod;
  /** Space separated scopes the client is allowed to request. */
  scope: string;
  createdAt: number;
}

export type PendingStatus = "pending" | "approved" | "denied";

export interface PendingAuthorizationRecord {
  id: string;
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  codeChallengeMethod: "S256";
  scopes: string[];
  resource: string;
  state?: string;
  createdAt: number;
  expiresAt: number;
  status: PendingStatus;
  userId?: string;
}

export interface AuthorizationCodeRecord {
  clientId: string;
  userId: string;
  redirectUri: string;
  codeChallenge: string;
  codeChallengeMethod: "S256";
  scopes: string[];
  resource: string;
  createdAt: number;
  expiresAt: number;
  usedAt?: number;
  revokedAt?: number;
  /** Token family created by this code (used to revoke on replay). */
  familyId?: string;
}

export interface AccessTokenRecord {
  userId: string;
  clientId: string;
  scopes: string[];
  resource: string;
  createdAt: number;
  expiresAt: number;
  lastUsedAt?: number;
  revokedAt?: number;
  familyId?: string;
  codeHash?: string;
}

export interface RefreshTokenRecord {
  userId: string;
  clientId: string;
  scopes: string[];
  resource: string;
  createdAt: number;
  expiresAt: number;
  familyId: string;
  usedAt?: number;
  revokedAt?: number;
  /** Set when the token was rotated; points at the replacement (hash). */
  replacedBy?: string;
}

export interface UserRecord {
  userId: string;
  login: string;
  name?: string;
  avatarUrl?: string;
  createdAt: number;
  updatedAt: number;
  lastLoginAt?: number;
}

export interface SessionRecord {
  id: string;
  userId: string;
  csrfToken: string;
  createdAt: number;
  lastSeenAt: number;
  expiresAt: number;
  idleTimeoutMs: number;
  userAgent?: string;
  ip?: string;
}

export interface LoginStateRecord {
  sessionId: string;
  nonce?: string;
  redirectTo?: string;
  createdAt: number;
  expiresAt: number;
  usedAt?: number;
}

export interface VaultRecord {
  userId: string;
  /** AES-256-GCM ciphertext of the GitHub access token ("v1.iv.tag.ct"). */
  accessTokenCiphertext: string;
  refreshTokenCiphertext?: string;
  scope: string;
  expiresAt?: number;
  createdAt: number;
  updatedAt: number;
}

export interface AuthDb {
  version: 1;
  clients: Record<string, ClientRecord>;
  pending: Record<string, PendingAuthorizationRecord>;
  codes: Record<string, AuthorizationCodeRecord>;
  accessTokens: Record<string, AccessTokenRecord>;
  refreshTokens: Record<string, RefreshTokenRecord>;
  users: Record<string, UserRecord>;
  sessions: Record<string, SessionRecord>;
  loginStates: Record<string, LoginStateRecord>;
  vault: Record<string, VaultRecord>;
}

const CIPHER_PREFIX = "v1";
const CIPHER_SALT = "uca-auth-vault-v1";
const KEY_FILE = "secret.key";
const DB_FILE = "auth-store.json";
const RETENTION_MS = 24 * 60 * 60 * 1000;

function emptyDb(): AuthDb {
  return {
    version: 1,
    clients: {},
    pending: {},
    codes: {},
    accessTokens: {},
    refreshTokens: {},
    users: {},
    sessions: {},
    loginStates: {},
    vault: {},
  };
}

export function ensureDirSync(dir: string, mode = 0o700): void {
  fs.mkdirSync(dir, { recursive: true, mode });
  try {
    fs.chmodSync(dir, mode);
  } catch {
    /* best effort (e.g. some network filesystems) */
  }
}

/** Atomically replace `filePath` with `data`. Also forces mode 0600. */
export function atomicWriteFileSync(filePath: string, data: string, mode = 0o600): void {
  const dir = path.dirname(filePath);
  ensureDirSync(dir);
  const tmp = path.join(dir, `.${path.basename(filePath)}.${process.pid}.${crypto.randomBytes(6).toString("hex")}.tmp`);
  const fd = fs.openSync(tmp, "wx", mode);
  try {
    fs.writeFileSync(fd, data, { encoding: "utf8" });
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  try {
    fs.renameSync(tmp, filePath);
  } catch (err) {
    try {
      fs.unlinkSync(tmp);
    } catch {
      /* ignore */
    }
    throw err;
  }
  try {
    fs.chmodSync(filePath, mode);
  } catch {
    /* best effort */
  }
}

/** Accept either a base64-encoded 32-byte key file or raw 32 bytes. */
function decodeKeyFile(raw: Buffer): Buffer | null {
  if (raw.length === 32) return raw;
  const text = raw.toString("utf8").trim();
  if (/^[A-Za-z0-9+/=_-]{43,44}$/.test(text)) {
    const decoded = Buffer.from(text, "base64");
    if (decoded.length === 32) return decoded;
    const urlSafe = Buffer.from(text, "base64url");
    if (urlSafe.length === 32) return urlSafe;
  }
  return null;
}

export function sha256Hex(value: string): string {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

export function randomToken(bytes = 32): string {
  return crypto.randomBytes(bytes).toString("base64url");
}

export function timingSafeEqualStr(a: string, b: string): boolean {
  const ba = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

export interface AuthStoreOptions {
  now?: () => number;
  /** Override the database path (tests). Defaults to `<dataDir>/auth-store.json`. */
  filePath?: string;
}

/**
 * JSON file store. Everything is synchronous: the record counts here are tiny
 * (clients, codes, tokens for a single-user/self-hosted agent) and synchronous
 * writes keep the token-endpoint logic free of interleaving races.
 */
export class AuthStore {
  readonly config: Config;
  readonly filePath: string;
  readonly keyFilePath: string;
  private db: AuthDb;
  private key: Buffer | null = null;
  private readonly clock: () => number;

  constructor(config: Config, opts: AuthStoreOptions = {}) {
    this.config = config;
    this.clock = opts.now ?? (() => Date.now());
    ensureDirSync(config.dataDir);
    this.filePath = opts.filePath ?? path.join(config.dataDir, DB_FILE);
    this.keyFilePath = path.join(config.dataDir, KEY_FILE);
    this.db = this.load();
    // Materialise the secret key and the store file (mode 0600) immediately so
    // startup fails fast if the data directory is not writable.
    this.getSecretKey();
    this.persist();
  }

  now(): number {
    return this.clock();
  }

  // ---------------------------------------------------------------- crypto

  /**
   * Key used for AES-256-GCM (token vault) and for HMAC cookie signatures.
   * Derived with scrypt from `config.sessionSecret`, or from a generated
   * 32-byte `<dataDir>/secret.key` (mode 0600) when no secret is configured.
   */
  getSecretKey(): Buffer {
    if (this.key) return this.key;
    const configured = (this.config.sessionSecret ?? "").trim();
    if (configured.length > 0) {
      this.key = crypto.scryptSync(configured, CIPHER_SALT, 32, { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
      return this.key;
    }
    ensureDirSync(this.config.dataDir);
    let raw: Buffer | null = null;
    try {
      raw = fs.readFileSync(this.keyFilePath);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
    }
    const loaded = raw ? decodeKeyFile(raw) : null;
    if (loaded) {
      this.key = loaded;
      return this.key;
    }
    const generated = crypto.randomBytes(32);
    atomicWriteFileSync(this.keyFilePath, generated.toString("base64"), 0o600);
    this.key = generated;
    return this.key;
  }

  /** AES-256-GCM encrypt to a self-describing string. */
  seal(plaintext: string): string {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", this.getSecretKey(), iv);
    const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
    const tag = cipher.getAuthTag();
    return [CIPHER_PREFIX, iv.toString("base64url"), tag.toString("base64url"), ct.toString("base64url")].join(".");
  }

  open(sealed: string): string {
    const parts = sealed.split(".");
    if (parts.length !== 4 || parts[0] !== CIPHER_PREFIX) throw new Error("Unsupported ciphertext format");
    const iv = Buffer.from(parts[1]!, "base64url");
    const tag = Buffer.from(parts[2]!, "base64url");
    const ct = Buffer.from(parts[3]!, "base64url");
    const decipher = crypto.createDecipheriv("aes-256-gcm", this.getSecretKey(), iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]).toString("utf8");
  }

  /** Only the SHA-256 hex digest of a bearer token/code is ever persisted. */
  hashToken(token: string): string {
    return sha256Hex(token);
  }

  // ------------------------------------------------------------ persistence

  private load(): AuthDb {
    if (!fs.existsSync(this.filePath)) return emptyDb();
    const raw = fs.readFileSync(this.filePath, "utf8");
    if (raw.trim() === "") return emptyDb();
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      throw new Error(`Auth store at ${this.filePath} is corrupt (invalid JSON)`);
    }
    if (typeof parsed !== "object" || parsed === null) throw new Error(`Auth store at ${this.filePath} is corrupt`);
    const base = emptyDb();
    const obj = parsed as Partial<AuthDb>;
    return {
      version: 1,
      clients: { ...base.clients, ...(obj.clients ?? {}) },
      pending: { ...base.pending, ...(obj.pending ?? {}) },
      codes: { ...base.codes, ...(obj.codes ?? {}) },
      accessTokens: { ...base.accessTokens, ...(obj.accessTokens ?? {}) },
      refreshTokens: { ...base.refreshTokens, ...(obj.refreshTokens ?? {}) },
      users: { ...base.users, ...(obj.users ?? {}) },
      sessions: { ...base.sessions, ...(obj.sessions ?? {}) },
      loginStates: { ...base.loginStates, ...(obj.loginStates ?? {}) },
      vault: { ...base.vault, ...(obj.vault ?? {}) },
    };
  }

  private persist(): void {
    this.prune();
    atomicWriteFileSync(this.filePath, JSON.stringify(this.db, null, 2), 0o600);
  }

  /** Drop entries well past their expiry; keeps recent ones for replay detection. */
  prune(): void {
    const cutoff = this.now() - RETENTION_MS;
    const drop = <T extends { expiresAt?: number; createdAt?: number }>(map: Record<string, T>): void => {
      for (const [k, v] of Object.entries(map)) {
        const end = v.expiresAt ?? v.createdAt ?? 0;
        if (end < cutoff) delete map[k];
      }
    };
    drop(this.db.codes);
    drop(this.db.accessTokens);
    drop(this.db.refreshTokens);
    drop(this.db.pending);
    drop(this.db.loginStates);
    for (const [k, s] of Object.entries(this.db.sessions)) {
      if (s.expiresAt < this.now()) delete this.db.sessions[k];
    }
  }

  /** Force a flush (normally not needed: every mutator persists). */
  flush(): void {
    this.persist();
  }

  /** Reload from disk (used by tests / multi-process setups). */
  reload(): void {
    this.db = this.load();
  }

  snapshot(): AuthDb {
    return JSON.parse(JSON.stringify(this.db)) as AuthDb;
  }

  // ---------------------------------------------------------------- clients

  putClient(client: ClientRecord): ClientRecord {
    this.db.clients[client.clientId] = client;
    this.persist();
    return client;
  }

  getClient(clientId: string): ClientRecord | null {
    return this.db.clients[clientId] ?? null;
  }

  listClients(): ClientRecord[] {
    return Object.values(this.db.clients);
  }

  deleteClient(clientId: string): boolean {
    if (!this.db.clients[clientId]) return false;
    delete this.db.clients[clientId];
    this.persist();
    return true;
  }

  // ------------------------------------------------------- pending consents

  putPending(record: PendingAuthorizationRecord): PendingAuthorizationRecord {
    this.db.pending[record.id] = record;
    this.persist();
    return record;
  }

  getPending(id: string): PendingAuthorizationRecord | null {
    return this.db.pending[id] ?? null;
  }

  updatePending(id: string, patch: Partial<PendingAuthorizationRecord>): PendingAuthorizationRecord | null {
    const cur = this.db.pending[id];
    if (!cur) return null;
    const next = { ...cur, ...patch };
    this.db.pending[id] = next;
    this.persist();
    return next;
  }

  deletePending(id: string): void {
    delete this.db.pending[id];
    this.persist();
  }

  // ------------------------------------------------------------------ codes

  putCode(codeHash: string, record: AuthorizationCodeRecord): AuthorizationCodeRecord {
    this.db.codes[codeHash] = record;
    this.persist();
    return record;
  }

  getCode(codeHash: string): AuthorizationCodeRecord | null {
    return this.db.codes[codeHash] ?? null;
  }

  updateCode(codeHash: string, patch: Partial<AuthorizationCodeRecord>): AuthorizationCodeRecord | null {
    const cur = this.db.codes[codeHash];
    if (!cur) return null;
    const next = { ...cur, ...patch };
    this.db.codes[codeHash] = next;
    this.persist();
    return next;
  }

  // --------------------------------------------------------------- tokens

  putAccessToken(tokenHash: string, record: AccessTokenRecord): AccessTokenRecord {
    this.db.accessTokens[tokenHash] = record;
    this.persist();
    return record;
  }

  getAccessToken(tokenHash: string): AccessTokenRecord | null {
    return this.db.accessTokens[tokenHash] ?? null;
  }

  updateAccessToken(tokenHash: string, patch: Partial<AccessTokenRecord>): AccessTokenRecord | null {
    const cur = this.db.accessTokens[tokenHash];
    if (!cur) return null;
    const next = { ...cur, ...patch };
    this.db.accessTokens[tokenHash] = next;
    this.persist();
    return next;
  }

  putRefreshToken(tokenHash: string, record: RefreshTokenRecord): RefreshTokenRecord {
    this.db.refreshTokens[tokenHash] = record;
    this.persist();
    return record;
  }

  getRefreshToken(tokenHash: string): RefreshTokenRecord | null {
    return this.db.refreshTokens[tokenHash] ?? null;
  }

  updateRefreshToken(tokenHash: string, patch: Partial<RefreshTokenRecord>): RefreshTokenRecord | null {
    const cur = this.db.refreshTokens[tokenHash];
    if (!cur) return null;
    const next = { ...cur, ...patch };
    this.db.refreshTokens[tokenHash] = next;
    this.persist();
    return next;
  }

  /**
   * Revoke every token (access + refresh) belonging to a rotation family.
   * Returns the number of records revoked.
   */
  revokeTokenFamily(familyId: string, reason?: string): number {
    const at = this.now();
    let count = 0;
    for (const rec of Object.values(this.db.refreshTokens)) {
      if (rec.familyId === familyId && !rec.revokedAt) {
        rec.revokedAt = at;
        if (reason) rec.replacedBy = rec.replacedBy ?? `revoked:${reason}`;
        count += 1;
      }
    }
    for (const rec of Object.values(this.db.accessTokens)) {
      if (rec.familyId === familyId && !rec.revokedAt) {
        rec.revokedAt = at;
        count += 1;
      }
    }
    if (count > 0) this.persist();
    return count;
  }

  /** Revoke all access tokens minted from a given authorization code hash. */
  revokeTokensFromCode(codeHash: string): number {
    const at = this.now();
    let count = 0;
    for (const rec of Object.values(this.db.accessTokens)) {
      if (rec.codeHash === codeHash && !rec.revokedAt) {
        rec.revokedAt = at;
        count += 1;
      }
    }
    if (count > 0) this.persist();
    return count;
  }

  /** Revoke everything a user ever granted (account-wide logout). */
  revokeAllForUser(userId: string): number {
    const at = this.now();
    let count = 0;
    for (const rec of Object.values(this.db.accessTokens)) {
      if (rec.userId === userId && !rec.revokedAt) {
        rec.revokedAt = at;
        count += 1;
      }
    }
    for (const rec of Object.values(this.db.refreshTokens)) {
      if (rec.userId === userId && !rec.revokedAt) {
        rec.revokedAt = at;
        count += 1;
      }
    }
    for (const rec of Object.values(this.db.pending)) {
      if (rec.userId === userId && rec.status === "pending") rec.status = "denied";
    }
    for (const [k, s] of Object.entries(this.db.sessions)) {
      if (s.userId === userId) delete this.db.sessions[k];
    }
    this.persist();
    return count;
  }

  /** Revoke all access + refresh tokens for one user/client pair. */
  revokeGrantsForUserClient(userId: string, clientId: string): number {
    const at = this.now();
    let count = 0;
    for (const rec of Object.values(this.db.accessTokens)) {
      if (rec.userId === userId && rec.clientId === clientId && !rec.revokedAt) {
        rec.revokedAt = at;
        count += 1;
      }
    }
    for (const rec of Object.values(this.db.refreshTokens)) {
      if (rec.userId === userId && rec.clientId === clientId && !rec.revokedAt) {
        rec.revokedAt = at;
        count += 1;
      }
    }
    if (count > 0) this.persist();
    return count;
  }

  /** Active (unrevoked, unexpired) refresh-token families grouped by client. */
  listActiveGrants(userId: string): {
    clientId: string;
    clientName?: string;
    scopes: string[];
    resource: string;
    createdAt: number;
    lastUsedAt: number;
    familyId: string;
  }[] {
    const at = this.now();
    const out = new Map<string, { clientId: string; scopes: Set<string>; resource: string; createdAt: number; lastUsedAt: number; familyId: string }>();
    for (const rec of Object.values(this.db.refreshTokens)) {
      if (rec.userId !== userId) continue;
      if (rec.revokedAt) continue;
      if (rec.expiresAt <= at) continue;
      const key = `${rec.clientId}:${rec.familyId}`;
      const prev = out.get(key);
      const lastUsed = Math.max(rec.createdAt, rec.usedAt ?? 0);
      if (!prev) {
        out.set(key, {
          clientId: rec.clientId,
          scopes: new Set(rec.scopes),
          resource: rec.resource,
          createdAt: rec.createdAt,
          lastUsedAt: lastUsed,
          familyId: rec.familyId,
        });
      } else {
        prev.lastUsedAt = Math.max(prev.lastUsedAt, lastUsed);
        prev.createdAt = Math.min(prev.createdAt, rec.createdAt);
        for (const s of rec.scopes) prev.scopes.add(s);
      }
    }
    return [...out.values()].map((g) => ({
      clientId: g.clientId,
      clientName: this.db.clients[g.clientId]?.clientName,
      scopes: [...g.scopes],
      resource: g.resource,
      createdAt: g.createdAt,
      lastUsedAt: g.lastUsedAt,
      familyId: g.familyId,
    }));
  }

  // ------------------------------------------------------------------ users

  /** Number of users whose id starts with a prefix (used for the guest cap). */
  countUsers(prefix: string): number { return Object.keys(this.db.users).filter((k) => k.startsWith(prefix)).length; }

  upsertUser(user: { userId: string; login: string; name?: string; avatarUrl?: string }): UserRecord {
    const at = this.now();
    const prev = this.db.users[user.userId];
    const next: UserRecord = {
      userId: user.userId,
      login: user.login,
      name: user.name ?? prev?.name,
      avatarUrl: user.avatarUrl ?? prev?.avatarUrl,
      createdAt: prev?.createdAt ?? at,
      updatedAt: at,
      lastLoginAt: at,
    };
    this.db.users[user.userId] = next;
    this.persist();
    return next;
  }

  getUser(userId: string): UserRecord | null {
    return this.db.users[userId] ?? null;
  }

  // --------------------------------------------------------------- sessions

  putSession(session: SessionRecord): SessionRecord {
    this.db.sessions[session.id] = session;
    this.persist();
    return session;
  }

  getSession(sessionId: string): SessionRecord | null {
    return this.db.sessions[sessionId] ?? null;
  }

  touchSession(sessionId: string, at: number): SessionRecord | null {
    const cur = this.db.sessions[sessionId];
    if (!cur) return null;
    cur.lastSeenAt = at;
    this.persist();
    return cur;
  }

  deleteSession(sessionId: string): boolean {
    if (!this.db.sessions[sessionId]) return false;
    delete this.db.sessions[sessionId];
    this.persist();
    return true;
  }

  deleteSessionsForUser(userId: string): number {
    let n = 0;
    for (const [k, s] of Object.entries(this.db.sessions)) {
      if (s.userId === userId) {
        delete this.db.sessions[k];
        n += 1;
      }
    }
    if (n > 0) this.persist();
    return n;
  }

  // ------------------------------------------------------ oauth login state

  putLoginState(stateHash: string, record: LoginStateRecord): LoginStateRecord {
    this.db.loginStates[stateHash] = record;
    this.persist();
    return record;
  }

  getLoginState(stateHash: string): LoginStateRecord | null {
    return this.db.loginStates[stateHash] ?? null;
  }

  updateLoginState(stateHash: string, patch: Partial<LoginStateRecord>): LoginStateRecord | null {
    const cur = this.db.loginStates[stateHash];
    if (!cur) return null;
    const next = { ...cur, ...patch };
    this.db.loginStates[stateHash] = next;
    this.persist();
    return next;
  }

  // ----------------------------------------------------------- github vault

  putVaultEntry(entry: VaultRecord): VaultRecord {
    this.db.vault[entry.userId] = entry;
    this.persist();
    return entry;
  }

  getVaultEntry(userId: string): VaultRecord | null {
    return this.db.vault[userId] ?? null;
  }

  deleteVaultEntry(userId: string): boolean {
    if (!this.db.vault[userId]) return false;
    delete this.db.vault[userId];
    this.persist();
    return true;
  }
}
