import path from "node:path";
import os from "node:os";

export interface Config {
  port: number;
  baseUrl: string;
  dataDir: string;
  workspacesDir: string;
  githubClientId: string;
  githubClientSecret: string;
  githubScopes: string;
  sessionSecret: string;
  accessTokenTtlSec: number;
  refreshTokenTtlSec: number;
  maxChunkBytes: number;
  defaultChunkBytes: number;
  commandTimeoutMs: number;
  maxOutputBytes: number;
  rateLimitPerMin: number;
  /** When true, sensitive ops (delete, push, exec of non-safe commands) need human approval. */
  requireApproval: boolean;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const dataDir = path.resolve(env.UCA_DATA_DIR ?? path.join(process.cwd(), "data"));
  const port = Number(env.PORT ?? 8787);
  return {
    port,
    baseUrl: (env.UCA_BASE_URL || env.RENDER_EXTERNAL_URL || (env.RAILWAY_PUBLIC_DOMAIN ? `https://${env.RAILWAY_PUBLIC_DOMAIN}` : "") || (env.FLY_APP_NAME ? `https://${env.FLY_APP_NAME}.fly.dev` : "") || `http://localhost:${port}`).replace(/\/$/, ""),
    dataDir,
    workspacesDir: path.resolve(env.UCA_WORKSPACES_DIR ?? path.join(dataDir, "workspaces")),
    githubClientId: env.GITHUB_CLIENT_ID ?? "",
    githubClientSecret: env.GITHUB_CLIENT_SECRET ?? "",
    githubScopes: env.UCA_GITHUB_SCOPES ?? "repo read:user workflow codespace",
    sessionSecret: env.UCA_SESSION_SECRET ?? "",
    accessTokenTtlSec: Number(env.UCA_ACCESS_TTL ?? 3600),
    refreshTokenTtlSec: Number(env.UCA_REFRESH_TTL ?? 60 * 60 * 24 * 30),
    maxChunkBytes: Number(env.UCA_MAX_CHUNK ?? 262144),
    defaultChunkBytes: Number(env.UCA_DEFAULT_CHUNK ?? 16384),
    commandTimeoutMs: Number(env.UCA_CMD_TIMEOUT_MS ?? 120000),
    maxOutputBytes: Number(env.UCA_MAX_OUTPUT ?? 200000),
    rateLimitPerMin: Number(env.UCA_RATE_LIMIT ?? 240),
    requireApproval: (env.UCA_REQUIRE_APPROVAL ?? "true") !== "false",
  };
}
export const homeDir = os.homedir();
