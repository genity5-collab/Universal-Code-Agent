/**
 * Encrypted GitHub token vault.
 *
 * Tokens are sealed with AES-256-GCM (see `AuthStore.seal`) before being
 * written to the JSON store, so the on-disk file never contains a usable
 * GitHub credential. Reads check expiry and can transparently refresh through
 * a caller-supplied callback.
 */
import type { AuthStore, VaultRecord } from "./store.js";

export interface GithubToken {
  accessToken: string;
  /** Granted scopes as a space separated string. */
  scope: string;
  refreshToken?: string;
  /** Absolute epoch ms expiry, or undefined for non-expiring tokens. */
  expiresAt?: number;
}

/** Called when the stored token is near/after expiry. Return a fresh token to store. */
export type RefreshCallback = (
  current: { refreshToken?: string; userId: string; scope: string },
) => Promise<GithubToken | null | undefined> | GithubToken | null | undefined;

export interface GithubTokenStatus {
  userId: string;
  scope: string;
  expiresAt?: number;
  hasRefreshToken: boolean;
  updatedAt: number;
  expired: boolean;
}

/** Refresh this many ms before actual expiry. */
const REFRESH_SKEW_MS = 60_000;

export class GithubTokenVault {
  private readonly store: AuthStore;
  private refreshCallback: RefreshCallback | null = null;

  constructor(store: AuthStore, refreshCallback?: RefreshCallback) {
    this.store = store;
    if (refreshCallback) this.refreshCallback = refreshCallback;
  }

  /** Hook (or replace) the refresh callback used by `getGithubToken`. */
  setRefreshCallback(cb: RefreshCallback | null): void {
    this.refreshCallback = cb;
  }

  /**
   * Encrypt and persist a GitHub token for `userId`.
   * Both the access token and (if present) the refresh token are encrypted.
   */
  saveGithubToken(
    userId: string,
    token: string,
    scope: string,
    refreshToken?: string,
    expiresAt?: number,
  ): GithubTokenStatus {
    if (!userId) throw new Error("userId is required");
    if (!token) throw new Error("token is required");
    const at = this.store.now();
    const prev = this.store.getVaultEntry(userId);
    const entry: VaultRecord = {
      userId,
      accessTokenCiphertext: this.store.seal(token),
      refreshTokenCiphertext: refreshToken ? this.store.seal(refreshToken) : prev?.refreshTokenCiphertext,
      scope,
      expiresAt,
      createdAt: prev?.createdAt ?? at,
      updatedAt: at,
    };
    this.store.putVaultEntry(entry);
    return this.toStatus(entry);
  }

  /**
   * Decrypt the user's GitHub token.
   * Returns `null` when absent, unreadable, or expired (after attempting a
   * refresh through the configured callback).
   */
  async getGithubToken(userId: string): Promise<GithubToken | null> {
    const entry = this.store.getVaultEntry(userId);
    if (!entry) return null;
    const now = this.store.now();
    const needsRefresh = typeof entry.expiresAt === "number" && entry.expiresAt - REFRESH_SKEW_MS <= now;

    if (needsRefresh && this.refreshCallback) {
      const refreshed = await this.refreshCallback({
        userId,
        refreshToken: entry.refreshTokenCiphertext ? this.store.open(entry.refreshTokenCiphertext) : undefined,
        scope: entry.scope,
      });
      if (refreshed) {
        this.saveGithubToken(
          userId,
          refreshed.accessToken,
          refreshed.scope,
          refreshed.refreshToken,
          refreshed.expiresAt,
        );
        return {
          accessToken: refreshed.accessToken,
          scope: refreshed.scope,
          refreshToken: refreshed.refreshToken,
          expiresAt: refreshed.expiresAt,
        };
      }
    }

    if (typeof entry.expiresAt === "number" && entry.expiresAt <= now) return null;

    try {
      return {
        accessToken: this.store.open(entry.accessTokenCiphertext),
        scope: entry.scope,
        refreshToken: entry.refreshTokenCiphertext ? this.store.open(entry.refreshTokenCiphertext) : undefined,
        expiresAt: entry.expiresAt,
      };
    } catch {
      // Tampered / key rotated: treat as no credential rather than crashing.
      return null;
    }
  }

  /** Synchronous variant: never refreshes, returns null when expired. */
  getGithubTokenSync(userId: string): GithubToken | null {
    const entry = this.store.getVaultEntry(userId);
    if (!entry) return null;
    if (typeof entry.expiresAt === "number" && entry.expiresAt <= this.store.now()) return null;
    try {
      return {
        accessToken: this.store.open(entry.accessTokenCiphertext),
        scope: entry.scope,
        refreshToken: entry.refreshTokenCiphertext ? this.store.open(entry.refreshTokenCiphertext) : undefined,
        expiresAt: entry.expiresAt,
      };
    } catch {
      return null;
    }
  }

  /** Metadata only — never decrypts or returns the token. */
  status(userId: string): GithubTokenStatus | null {
    const entry = this.store.getVaultEntry(userId);
    return entry ? this.toStatus(entry) : null;
  }

  deleteGithubToken(userId: string): boolean {
    return this.store.deleteVaultEntry(userId);
  }

  private toStatus(entry: VaultRecord): GithubTokenStatus {
    return {
      userId: entry.userId,
      scope: entry.scope,
      expiresAt: entry.expiresAt,
      hasRefreshToken: Boolean(entry.refreshTokenCiphertext),
      updatedAt: entry.updatedAt,
      expired: typeof entry.expiresAt === "number" && entry.expiresAt <= this.store.now(),
    };
  }
}
