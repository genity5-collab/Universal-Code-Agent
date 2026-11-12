/**
 * GitHub Codespaces client.
 *
 * Wraps the public REST endpoints (`/user/codespaces`, `/repos/{o}/{r}/codespaces/machines`,
 * ...) on top of `GitHubClient`, so it inherits auth, error typing, rate-limit
 * awareness and token scrubbing.
 *
 * Honest limits (see `status()`):
 * - Codespaces are **not unlimited**. Every account has a plan-dependent monthly
 *   allowance of compute core-hours and storage; usage above it is **billed**.
 * - The public REST API can create/start/stop/delete/export a Codespace and list
 *   machines, but it exposes **no endpoint to run a command inside one**. There is
 *   no HTTP tunnel in the API. `runCommandViaSsh()` therefore reports
 *   `{ supported: false }` with the supported alternative instead of pretending.
 */

import {
  GitHubClient,
  GitHubError,
  GitHubValidationError,
  type GitHubClientOptions,
  type Query,
} from "./client.js";

/* eslint-disable @typescript-eslint/no-explicit-any */
type Raw = Record<string, any>;

export type CodespaceState = "Unknown" | "Created" | "Queued" | "Provisioning" | "Available" | "Awaiting" | "Unavailable" | "ShuttingDown" | "Archived" | "Starting" | "Exporting" | "Stopping" | "Rebuilding" | "Updating";

export interface CodespaceRepoRef {
  id: number;
  name: string;
  fullName: string;
  private: boolean;
  owner: string;
  defaultBranch: string | null;
}

export interface CodespaceGitStatus {
  ahead: number;
  behind: number;
  ref: string | null;
  hasUncommittedChanges: boolean;
  hasUnpushedChanges: boolean;
}

export interface CodespaceSummary {
  name: string;
  displayName: string | null;
  state: CodespaceState | string;
  idleTimeoutMinutes: number | null;
  retentionPeriodMinutes: number | null;
  machineName: string | null;
  machineDisplayName: string | null;
  cpus: number | null;
  memoryMb: number | null;
  storageGb: number | null;
  location: string | null;
  createdAt: string | null;
  lastUsedAt: string | null;
  updatedAt: string | null;
  webUrl: string | null;
  /** Present when the token may read it; a URL to open in a browser. */
  webUrlFromApi?: string | null;
  billableOwner: string | null;
  repository: CodespaceRepoRef | null;
  gitStatus: CodespaceGitStatus | null;
  prebuild: boolean;
}

export interface MachineSummary {
  name: string;
  displayName: string;
  os: string | null;
  cpus: number;
  memoryMb: number;
  storageGb: number;
  prebuildAvailable: string | null;
}

export interface CreateCodespaceOptions {
  owner: string;
  repo: string;
  /** Branch to check out (defaults to the repo default branch). */
  branch?: string;
  /** Machine type, e.g. "standardLinux32gb" / "basicLinux32gb". */
  machine?: string;
  /** Auto-stop after this many minutes idle (GitHub clamps to its own limits). */
  idleTimeout?: number;
  /** Retain a stopped Codespace this many minutes before deletion. */
  retentionPeriod?: number;
  displayName?: string;
  location?: string;
  devcontainerPath?: string;
  workingDirectory?: string;
  geo?: string;
}

export interface ExportResult {
  exportId: string;
  state: string;
  branch: string | null;
  sha: string | null;
  completedAt: string | null;
  /** Honest note: exports are published as a branch on a temporary repo. */
  note: string;
}

export interface CodespaceExportStatus extends ExportResult {
  htmlUrl: string | null;
}

export interface RunCommandUnsupported {
  supported: false;
  reason: string;
  howTo: string;
}

export interface CodespacesStatus {
  /** Per-tenant constraints, stated plainly. */
  limitations: {
    quota: string;
    billing: string;
    commandExecution: string;
    apiScope: string;
  };
  oauthScopes: string[];
  codespaces: {
    total: number;
    byState: Record<string, number>;
    runningMinutes: number;
  };
  billing: {
    /** The REST API does not expose remaining free-tier core-hours. */
    remainingFreeTierMinutes: null;
    queryable: boolean;
    note: string;
  };
  exportNote: string;
  canRunCommands: false;
  summary: string;
}

const MINUTES_PER_HOUR = 60;

function numOrNull(v: unknown): number | null {
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

function strOrNull(v: unknown): string | null {
  return typeof v === "string" && v !== "" ? v : null;
}

function mapRepoRef(raw: Raw | undefined | null): CodespaceRepoRef | null {
  if (!raw || typeof raw !== "object") return null;
  return {
    id: typeof raw.id === "number" ? raw.id : 0,
    name: typeof raw.name === "string" ? raw.name : "",
    fullName: typeof raw.full_name === "string" ? raw.full_name : "",
    private: raw.private === true,
    owner: typeof raw.owner?.login === "string" ? raw.owner.login : "",
    defaultBranch: strOrNull(raw.default_branch),
  };
}

export function mapCodespace(raw: Raw): CodespaceSummary {
  const machine = (raw.machine ?? {}) as Raw;
  const git = raw.git_status as Raw | undefined;
  return {
    name: typeof raw.name === "string" ? raw.name : "",
    displayName: strOrNull(raw.display_name),
    state: typeof raw.state === "string" ? raw.state : "Unknown",
    idleTimeoutMinutes: numOrNull(raw.idle_timeout_minutes),
    retentionPeriodMinutes: numOrNull(raw.retention_period_minutes),
    machineName: strOrNull(machine.name),
    machineDisplayName: strOrNull(machine.display_name),
    cpus: numOrNull(machine.cpus),
    memoryMb: numOrNull(machine.memory_in_bytes) !== null ? Math.round((numOrNull(machine.memory_in_bytes) as number) / (1024 * 1024)) : null,
    storageGb: numOrNull(machine.storage_in_bytes) !== null ? Math.round((numOrNull(machine.storage_in_bytes) as number) / (1024 * 1024 * 1024)) : null,
    location: strOrNull(raw.location),
    createdAt: strOrNull(raw.created_at),
    lastUsedAt: strOrNull(raw.last_used_at),
    updatedAt: strOrNull(raw.updated_at),
    webUrl: strOrNull(raw.web_url),
    billableOwner: strOrNull(raw.billable_owner?.login),
    repository: mapRepoRef(raw.repository),
    gitStatus: git
      ? {
          ahead: typeof git.ahead === "number" ? git.ahead : 0,
          behind: typeof git.behind === "number" ? git.behind : 0,
          ref: strOrNull(git.ref),
          hasUncommittedChanges: git.has_uncommitted_changes === true,
          hasUnpushedChanges: git.has_unpushed_changes === true,
        }
      : null,
    prebuild: raw.prebuild === true,
  };
}

function mapMachine(raw: Raw): MachineSummary {
  return {
    name: typeof raw.name === "string" ? raw.name : "",
    displayName: typeof raw.display_name === "string" ? raw.display_name : "",
    os: strOrNull(raw.os),
    cpus: typeof raw.cpus === "number" ? raw.cpus : 0,
    memoryMb: numOrNull(raw.memory_in_bytes) !== null ? Math.round((numOrNull(raw.memory_in_bytes) as number) / (1024 * 1024)) : 0,
    storageGb: numOrNull(raw.storage_in_bytes) !== null ? Math.round((numOrNull(raw.storage_in_bytes) as number) / (1024 * 1024 * 1024)) : 0,
    prebuildAvailable: strOrNull(raw.prebuild_availability),
  };
}

const enc = (v: string): string => encodeURIComponent(v);

export class CodespacesClient {
  readonly gh: GitHubClient;

  /** Reuse one client so the same per-user token and rate-limit state are shared. */
  constructor(client: GitHubClient);
  constructor(token: string, options?: GitHubClientOptions);
  constructor(clientOrToken: GitHubClient | string, options?: GitHubClientOptions) {
    this.gh = typeof clientOrToken === "string" ? new GitHubClient(clientOrToken, options ?? {}) : clientOrToken;
  }

  /** Codespaces are billed to the token owner; the shape is summarized, not raw. */
  async listCodespaces(opts: { perPage?: number; page?: number; maxItems?: number } = {}): Promise<{
    items: CodespaceSummary[];
    totalCount: number;
    pages: number;
    truncated: boolean;
    nextUrl: string | null;
  }> {
    if (opts.page !== undefined) {
      const raw = await this.gh.request<Raw>("/user/codespaces", {
        query: { per_page: opts.perPage ?? 30, page: opts.page },
      });
      const items = Array.isArray(raw?.codespaces) ? raw.codespaces.map(mapCodespace) : [];
      return { items, totalCount: numOrNull(raw?.total_count) ?? items.length, pages: 1, truncated: false, nextUrl: null };
    }
    const paged = await this.gh.paginate<Raw>("/user/codespaces", opts.maxItems ?? 100, {
      query: { per_page: opts.perPage ?? 100 },
      wrapKey: "codespaces",
    });
    return {
      items: paged.items.map(mapCodespace),
      totalCount: paged.totalCount ?? paged.items.length,
      pages: paged.pages,
      truncated: paged.truncated,
      nextUrl: paged.nextUrl,
    };
  }

  /**
   * Create a Codespace for a repository. `repository_id` is required by the API,
   * so the repo is resolved first (one extra request).
   */
  async createCodespace(opts: CreateCodespaceOptions): Promise<CodespaceSummary> {
    if (!opts.owner || !opts.repo) {
      throw new GitHubValidationError("createCodespace requires owner and repo");
    }
    const repo = await this.gh.getRepo(opts.owner, opts.repo);
    const body: Record<string, unknown> = { repository_id: repo.id };
    if (opts.branch) body.ref = opts.branch;
    if (opts.machine) body.machine = opts.machine;
    if (opts.idleTimeout !== undefined) body.idle_timeout_minutes = opts.idleTimeout;
    if (opts.retentionPeriod !== undefined) body.retention_period_minutes = opts.retentionPeriod;
    if (opts.displayName) body.display_name = opts.displayName;
    if (opts.location) body.location = opts.location;
    if (opts.devcontainerPath) body.devcontainer_path = opts.devcontainerPath;
    if (opts.workingDirectory) body.working_directory = opts.workingDirectory;
    if (opts.geo) body.geo = opts.geo;

    const raw = await this.gh.request<Raw>("/user/codespaces", { method: "POST", body });
    return mapCodespace(raw ?? {});
  }

  async getCodespace(name: string): Promise<CodespaceSummary> {
    const raw = await this.gh.request<Raw>(`/user/codespaces/${enc(name)}`);
    return mapCodespace(raw ?? {});
  }

  async startCodespace(name: string): Promise<CodespaceSummary> {
    const raw = await this.gh.request<Raw>(`/user/codespaces/${enc(name)}/start`, { method: "POST" });
    return mapCodespace(raw ?? {});
  }

  async stopCodespace(name: string): Promise<CodespaceSummary> {
    const raw = await this.gh.request<Raw>(`/user/codespaces/${enc(name)}/stop`, { method: "POST" });
    return mapCodespace(raw ?? {});
  }

  /** Idempotent from the caller's point of view: a 404 means it is already gone. */
  async deleteCodespace(name: string): Promise<{ name: string; deleted: true; alreadyAbsent: boolean }> {
    try {
      await this.gh.request<void>(`/user/codespaces/${enc(name)}`, { method: "DELETE" });
      return { name, deleted: true, alreadyAbsent: false };
    } catch (err) {
      if (err instanceof GitHubError && err.status === 404) return { name, deleted: true, alreadyAbsent: true };
      throw err;
    }
  }

  /** Machine types available for a repository (billed per compute hour). */
  async listMachines(
    owner: string,
    repo: string,
    opts: { location?: string; clientIp?: string; ref?: string } = {},
  ): Promise<{ items: MachineSummary[]; totalCount: number }> {
    const query: Query = { location: opts.location, client_ip: opts.clientIp, ref: opts.ref };
    const raw = await this.gh.request<Raw>(`/repos/${enc(owner)}/${enc(repo)}/codespaces/machines`, { query });
    const items = Array.isArray(raw?.machines) ? raw.machines.map(mapMachine) : [];
    return { items, totalCount: numOrNull(raw?.total_count) ?? items.length };
  }

  /**
   * Export a Codespace to a new branch on a temporary repository.
   * Returns immediately with an export id; poll `getExportStatus`.
   */
  async exportCodespace(name: string): Promise<ExportResult> {
    const raw = await this.gh.request<Raw>(`/user/codespaces/${enc(name)}/exports`, { method: "POST" });
    return {
      exportId: typeof raw?.id === "string" ? raw.id : String(raw?.id ?? ""),
      state: typeof raw?.state === "string" ? raw.state : "unknown",
      branch: strOrNull(raw?.branch),
      sha: strOrNull(raw?.sha),
      completedAt: strOrNull(raw?.completed_at),
      note:
        "Exports publish one branch on a temporary GitHub-owned repository; download it promptly. " +
        "The branch is not a backup of the Codespace itself (secrets, running processes and uncommitted work outside the repo are not included).",
    };
  }

  async getExportStatus(name: string, exportId: string): Promise<CodespaceExportStatus> {
    const raw = await this.gh.request<Raw>(`/user/codespaces/${enc(name)}/exports/${enc(exportId)}`);
    const base: ExportResult = {
      exportId: typeof raw?.id === "string" ? raw.id : String(raw?.id ?? exportId),
      state: typeof raw?.state === "string" ? raw.state : "unknown",
      branch: strOrNull(raw?.branch),
      sha: strOrNull(raw?.sha),
      completedAt: strOrNull(raw?.completed_at),
      note: "Poll until state is 'succeeded' or 'failed'; the download link is the branch on the temporary repo.",
    };
    return { ...base, htmlUrl: strOrNull(raw?.html_url) };
  }

  /**
   * Running a command inside a Codespace is NOT available through the public
   * REST API. This returns a documented refusal — it never fakes execution.
   * The supported path is the `gh` CLI's SSH bridge (or the VS Code terminal).
   */
  async runCommandViaSsh(codespaceName: string, command: string): Promise<RunCommandUnsupported> {
    if (!codespaceName) throw new GitHubValidationError("runCommandViaSsh requires a codespace name");
    return {
      supported: false,
      reason:
        "GitHub exposes no REST endpoint to execute a command inside a Codespace. Creating a Codespace, starting/stopping it, " +
        "listing machines and exporting are available over REST; interactive exec is not, and there is no API tunnel to fake it with.",
      howTo: `gh codespace ssh -c ${codespaceName} -- ${command}`,
    };
  }

  /**
   * Snapshot of what Codespaces can and cannot do for this token, with explicit
   * quota/billing caveats. `includeBilling` probes the billing endpoint, which
   * usually needs an extra scope and is skipped by default.
   */
  async status(opts: { includeBilling?: boolean } = {}): Promise<CodespacesStatus> {
    const user = await this.gh.getAuthenticatedUser();
    const listed = await this.listCodespaces({ perPage: 100, maxItems: 300 });

    const byState: Record<string, number> = {};
    let runningMinutes = 0;
    for (const cs of listed.items) {
      const key = String(cs.state);
      byState[key] = (byState[key] ?? 0) + 1;
      if (cs.createdAt) {
        const started = Date.parse(cs.createdAt);
        if (Number.isFinite(started)) runningMinutes += Math.max(0, Math.floor((Date.now() - started) / 60000));
      }
    }

    let billingQueryable = false;
    if (opts.includeBilling) {
      try {
        await this.gh.request<Raw>(`/users/${enc(user.login)}/settings/billing/usage`, {
          query: { per_page: 1 },
        });
        billingQueryable = true;
      } catch {
        billingQueryable = false;
      }
    }

    return {
      limitations: {
        quota:
          "Codespaces are quota-bound, not unlimited: each account gets a plan-dependent monthly allowance of compute " +
          `core-hours and storage (${MINUTES_PER_HOUR} min = 1 core-hour for a 2-core machine). Once it is used up, new ` +
          "Codespaces fail to start until the month resets or you raise the spending limit.",
        billing:
          "Usage beyond the included allowance is billed to the account the Codespace belongs to " +
          "(billable_owner). Stopped Codespaces still consume storage until they are deleted or the retention period expires.",
        commandExecution:
          "The public REST API cannot run commands inside a Codespace. Use the VS Code terminal, `gh codespace ssh`, " +
          "or run the work in the sandboxed terminal instead.",
        apiScope:
          "Codespaces endpoints need the `codespace` OAuth scope; create/delete additionally requires the user to own the Codespace.",
      },
      oauthScopes: user.scopes ?? [],
      codespaces: {
        total: listed.totalCount,
        byState,
        runningMinutes,
      },
      billing: {
        remainingFreeTierMinutes: null,
        queryable: billingQueryable,
        note: billingQueryable
          ? "Billing usage is readable for this token; translate usage items into core-hours yourself."
          : "Remaining free-tier core-hours are NOT exposed by the Codespaces REST API. Check the GitHub billing page; " +
            "an unauthenticated-for-billing token cannot read usage.",
      },
      exportNote:
        "`exportCodespace` copies one branch out to a temporary repo. It is not a full machine backup.",
      canRunCommands: false,
      summary: `${listed.totalCount} Codespace(s) on ${user.login}; states: ${
        Object.keys(byState).length ? Object.entries(byState).map(([k, v]) => `${k}=${v}`).join(", ") : "none"
      }. Command execution is not available over REST.`,
    };
  }
}
