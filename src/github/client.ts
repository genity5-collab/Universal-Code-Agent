/**
 * GitHub REST client.
 *
 * Every instance is bound to ONE user's own OAuth access token. There is no
 * shared/global token and no fallback to a server-wide credential: construct a
 * new client per authenticated user (see `src/types.ts` -> `UserContext.githubToken`).
 *
 * Design notes
 * - Pinned REST API version `X-GitHub-Api-Version: 2022-11-28`.
 * - Pagination follows the `Link` header (`rel="next"`); `paginate()` is the
 *   single place that does it, and it always reports whether it stopped early.
 * - Rate limit state is read from `x-ratelimit-*` and surfaced as a typed
 *   `GitHubRateLimitError` (`resetAt`) instead of a bare 403.
 * - Errors are typed (`GitHubError` + subclasses) and **never** contain the
 *   token: every message is scrubbed (token literal + generic secret patterns).
 * - Payloads returned to callers are trimmed summaries, not raw API bodies.
 * - Nothing here pretends to do more than the REST API can: chunked file reads
 *   are explicit (`offset`/`limit`/`hasMore`), and capabilities the API does not
 *   expose are reported as unsupported rather than simulated.
 */

import { redact } from "../util/paths.js";

export const DEFAULT_BASE_URL = "https://api.github.com";
export const GITHUB_API_VERSION = "2022-11-28";
export const DEFAULT_USER_AGENT = "universal-code-agent/0.1.0";

/** Files above this size are served by the git blobs API (contents API empties `content`). */
export const CONTENTS_API_MAX_BYTES = 1024 * 1024;
/** Hard ceiling of the git blobs API (raw or base64) — above this GitHub refuses. */
export const BLOB_API_MAX_BYTES = 100 * 1024 * 1024;

const MAX_PAGES = 25;
const DEFAULT_TIMEOUT_MS = 30_000;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export interface GitHubErrorOptions {
  status: number;
  message: string;
  method?: string;
  /** Path only (never the query string or a token). */
  path?: string;
  code?: string | null;
  documentationUrl?: string | null;
  requestId?: string | null;
  /** Trimmed API `message`/`errors[]`, already scrubbed by the client. */
  apiMessage?: string | null;
}

export class GitHubError extends Error {
  readonly status: number;
  readonly method: string;
  readonly path: string;
  readonly code?: string;
  readonly documentationUrl?: string;
  readonly requestId?: string;
  readonly apiMessage?: string;

  constructor(opts: GitHubErrorOptions) {
    super(opts.message);
    this.name = "GitHubError";
    this.status = opts.status;
    this.method = opts.method ?? "GET";
    this.path = opts.path ?? "";
    if (opts.code) this.code = opts.code;
    if (opts.documentationUrl) this.documentationUrl = opts.documentationUrl;
    if (opts.requestId) this.requestId = opts.requestId;
    if (opts.apiMessage) this.apiMessage = opts.apiMessage;
  }

  get isNotFound(): boolean {
    return this.status === 404;
  }
  get isForbidden(): boolean {
    return this.status === 403;
  }
  get isNotModified(): boolean {
    return this.status === 304;
  }
}

/** 404 — resource missing, or the token cannot see it. */
export class GitHubNotFoundError extends GitHubError {
  constructor(opts: GitHubErrorOptions) {
    super(opts);
    this.name = "GitHubNotFoundError";
  }
}

/** 403 — authenticated but not allowed (not a rate limit). */
export class GitHubForbiddenError extends GitHubError {
  constructor(opts: GitHubErrorOptions) {
    super(opts);
    this.name = "GitHubForbiddenError";
  }
}

/** 304 — only thrown when a conditional request was made and nothing changed. */
export class GitHubNotModifiedError extends GitHubError {
  constructor(opts: GitHubErrorOptions) {
    super(opts);
    this.name = "GitHubNotModifiedError";
  }
}

/** 429/403 with an exhausted (or throttled) quota. */
export class GitHubRateLimitError extends GitHubError {
  /** When the primary quota resets (or when the retry-after window ends). */
  readonly resetAt: Date;
  readonly retryAfterSeconds: number | null;
  readonly limit: number | null;
  readonly remaining: number | null;
  readonly resource: string | null;
  readonly secondary: boolean;

  constructor(opts: GitHubErrorOptions & {
    resetAt: Date;
    retryAfterSeconds?: number | null;
    limit?: number | null;
    remaining?: number | null;
    resource?: string | null;
    secondary?: boolean;
  }) {
    super(opts);
    this.name = "GitHubRateLimitError";
    this.resetAt = opts.resetAt;
    this.retryAfterSeconds = opts.retryAfterSeconds ?? null;
    this.limit = opts.limit ?? null;
    this.remaining = opts.remaining ?? null;
    this.resource = opts.resource ?? null;
    this.secondary = opts.secondary ?? false;
  }
}

/** Local validation (missing argument) — no HTTP request was made (status 0). */
export class GitHubValidationError extends GitHubError {
  constructor(message: string, path = "") {
    super({ status: 0, message, path });
    this.name = "GitHubValidationError";
  }
}

/** GraphQL returned HTTP 200 with an `errors` array. */
export class GitHubGraphQLError extends GitHubError {
  readonly errors: string[];
  constructor(opts: GitHubErrorOptions & { errors: string[] }) {
    super(opts);
    this.name = "GitHubGraphQLError";
    this.errors = opts.errors;
  }
}

// ---------------------------------------------------------------------------
// Shared shapes
// ---------------------------------------------------------------------------

export type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD";
export type Query = Record<string, string | number | boolean | null | undefined>;
export type RepoVisibility = "all" | "public" | "private";
export type ReviewEvent = "APPROVE" | "REQUEST_CHANGES" | "COMMENT";
export type FileEncoding = "utf8" | "base64";

export interface GitHubClientOptions {
  baseUrl?: string;
  /** Defaults to `<baseUrl>/graphql` (i.e. https://api.github.com/graphql). */
  graphqlUrl?: string;
  apiVersion?: string;
  fetchImpl?: typeof fetch;
  userAgent?: string;
  /** Per-request abort timeout. 0 disables. */
  timeoutMs?: number;
  /** Delay before the single retry on 502/503 (and on GET network errors). */
  retryDelayMs?: number;
  /** Safety cap on pages followed by `paginate`. */
  maxPages?: number;
  /** Per-file patch cap in `getCommit`/`compare`/`listPullRequestFiles`. */
  maxPatchChars?: number;
}

export interface RateLimitSnapshot {
  limit: number | null;
  remaining: number | null;
  reset: Date | null;
  used: number | null;
  resource: string | null;
}

export interface Paginated<T> {
  items: T[];
  /** Number of HTTP pages fetched. */
  pages: number;
  /** True when more results existed but `maxItems`/`maxPages` stopped us. */
  truncated: boolean;
  /** Next page URL (absolute) when `truncated`. */
  nextUrl: string | null;
  /** Total reported by the API when available (search endpoints). */
  totalCount?: number;
}

export interface RequestOptions {
  method?: HttpMethod;
  query?: Query;
  body?: unknown;
  headers?: Record<string, string>;
  accept?: string;
  /** Return the body as text instead of parsed JSON. */
  raw?: boolean;
  signal?: AbortSignal;
  redirect?: RequestRedirect;
  /** Statuses that are NOT errors for this call (e.g. [304]). */
  expectStatus?: number[];
}

// ---------------------------------------------------------------------------
// Trimmed payload shapes
// ---------------------------------------------------------------------------

export interface GitHubUser {
  login: string;
  id: number;
  nodeId?: string;
  name: string | null;
  email: string | null;
  avatarUrl: string | null;
  htmlUrl: string;
  type: string;
  company: string | null;
  blog: string | null;
  location: string | null;
  bio: string | null;
  publicRepos: number;
  publicGists: number;
  followers: number;
  following: number;
  createdAt: string;
  updatedAt: string;
  plan?: string | null;
  twoFactorAuthentication?: boolean;
  /** OAuth scopes granted to the token (from `x-oauth-scopes`). */
  scopes?: string[];
  siteAdmin?: boolean;
}

export interface RepoSummary {
  id: number;
  name: string;
  fullName: string;
  owner: string;
  private: boolean;
  fork: boolean;
  archived: boolean;
  visibility: string | null;
  description: string | null;
  defaultBranch: string;
  htmlUrl: string;
  cloneUrl: string;
  sshUrl: string;
  language: string | null;
  stars: number;
  forks: number;
  openIssues: number;
  sizeKb: number;
  topics?: string[];
  pushedAt: string | null;
  updatedAt: string | null;
  permissions?: { admin: boolean; maintain?: boolean; push: boolean; triage?: boolean; pull: boolean };
  license?: string | null;
}

export interface BranchSummary {
  name: string;
  sha: string;
  protected: boolean;
}

export interface TreeEntry {
  path: string;
  mode: string;
  type: string;
  sha: string;
  size?: number;
}

export interface TreeResult {
  sha: string | null;
  ref: string;
  path: string | null;
  entries: TreeEntry[];
  entryCount: number;
  /** GitHub itself truncated the listing (>100k entries / >7MB). */
  apiTruncated: boolean;
  /** We stopped at `maxEntries`. */
  truncated: boolean;
}

export interface FileContentChunk {
  type: "file";
  path: string;
  name: string;
  sha: string;
  /** Full size of the file in bytes. */
  size: number;
  encoding: "base64";
  /** Base64 of the requested byte range. */
  base64: string;
  offset: number;
  /** Requested chunk size, or null for "rest of file". */
  limit: number | null;
  chunkSize: number;
  hasMore: boolean;
  nextOffset: number | null;
  /** True when this payload is a slice — offsets let the caller fetch the rest. */
  truncated: boolean;
  source: "contents" | "blobs";
  htmlUrl: string | null;
  downloadUrl: string | null;
}

export interface DirEntry {
  name: string;
  path: string;
  type: string;
  size: number;
  sha: string;
}

export interface DirContent {
  type: "dir" | "symlink" | "submodule";
  path: string;
  sha: string;
  size: number;
  entries: DirEntry[];
  htmlUrl: string | null;
  downloadUrl: string | null;
}

export type RepoContent = FileContentChunk | DirContent;

export interface DownloadedFile {
  path: string;
  ref: string | null;
  size: number;
  bytesReturned: number;
  /** Raw bytes as base64. */
  base64: string;
  contentType: string | null;
  maxBytes: number;
  /** True when the file exceeded `maxBytes` and only a prefix was returned. */
  truncated: boolean;
  /** False when we stopped reading early and the server sent no Content-Length. */
  sizeExact: boolean;
}

export interface CommitRef {
  sha: string;
  url?: string;
}

export interface WriteFileResult {
  path: string;
  commitSha: string;
  commitUrl: string | null;
  htmlUrl: string | null;
  sha: string;
  size: number;
  branch: string | null;
  message: string;
}

export interface DeleteFileResult {
  path: string;
  commitSha: string;
  commitUrl: string | null;
  deleted: true;
  branch: string | null;
}

export interface FileSpec {
  path: string;
  content: string;
  encoding?: FileEncoding;
  /** Defaults to "100644". */
  mode?: string;
}

export interface MultiFileCommitOptions {
  branch: string;
  message: string;
  files?: FileSpec[];
  /** Paths to remove in the same commit. */
  deletions?: string[];
  /** When set, create `branch` from this ref if it does not exist yet. */
  baseBranch?: string;
  author?: GitIdentity;
  committer?: GitIdentity;
}

export interface GitIdentity {
  name: string;
  email: string;
  date?: string;
}

export interface MultiFileCommitResult {
  commitSha: string;
  commitUrl: string | null;
  treeSha: string;
  baseTreeSha: string;
  branch: string;
  createdBranch: boolean;
  blobs: { path: string; sha: string }[];
  deleted: string[];
  filesChanged: number;
}

export interface CodeSearchItem {
  path: string;
  repo: string;
  name: string;
  sha: string;
  htmlUrl: string;
  score: number;
  fragments?: string[];
}

export interface CodeSearchResult extends Paginated<CodeSearchItem> {
  totalCount: number;
  incompleteResults: boolean;
  query: string;
}

export interface CommitSummary {
  sha: string;
  message: string;
  author: { login: string | null; name: string; email: string; date: string | null } | null;
  committer: { login: string | null; name: string; date: string | null } | null;
  parents: string[];
  htmlUrl: string;
  verified?: boolean;
}

export interface CommitFile {
  filename: string;
  status: string;
  additions: number;
  deletions: number;
  changes: number;
  previousFilename?: string;
  blobUrl?: string;
  patch?: string;
  patchTruncated: boolean;
}

export interface CommitDetail extends CommitSummary {
  stats: { additions: number; deletions: number; total: number } | null;
  files: CommitFile[];
  filesReturned: number;
  /** At least one patch was shortened (see `patchTruncated` per file). */
  truncated: boolean;
}

export interface CompareResult {
  status: string;
  aheadBy: number;
  behindBy: number;
  totalCommits: number;
  commits: CommitSummary[];
  files: CommitFile[];
  commitsTruncated: boolean;
  filesTruncated: boolean;
  permalinkUrl: string | null;
}

export interface IssueSummary {
  number: number;
  title: string;
  state: string;
  stateReason: string | null;
  body: string | null;
  bodyTruncated: boolean;
  user: string | null;
  labels: string[];
  assignees: string[];
  comments: number;
  locked: boolean;
  htmlUrl: string;
  createdAt: string;
  updatedAt: string;
  closedAt: string | null;
  pullRequest: boolean;
}

export interface IssueComment {
  id: number;
  body: string;
  bodyTruncated: boolean;
  user: string | null;
  htmlUrl: string;
  createdAt: string;
  updatedAt: string;
}

export interface PullRequestSummary {
  number: number;
  title: string;
  state: string;
  draft: boolean;
  merged: boolean;
  mergeable: boolean | null;
  mergeableState: string | null;
  body: string | null;
  bodyTruncated: boolean;
  user: string | null;
  head: { ref: string; sha: string; repo: string | null };
  base: { ref: string; sha: string; repo: string | null };
  htmlUrl: string;
  additions: number;
  deletions: number;
  changedFiles: number;
  commits: number;
  createdAt: string;
  updatedAt: string;
  mergedAt: string | null;
  labels: string[];
}

export interface PullRequestFile {
  filename: string;
  status: string;
  additions: number;
  deletions: number;
  changes: number;
  blobUrl?: string;
  previousFilename?: string;
  patch?: string;
  patchTruncated: boolean;
}

export interface PullRequestDiff {
  number: number;
  diff: string;
  length: number;
  bytesReturned: number;
  maxBytes: number;
  truncated: boolean;
}

export interface ReviewCommentInput {
  path: string;
  body: string;
  /** Legacy diff position. Prefer `line` + `side`. */
  position?: number;
  line?: number;
  side?: "LEFT" | "RIGHT";
  startLine?: number;
  startSide?: "LEFT" | "RIGHT";
}

export interface PullRequestReview {
  id: number;
  state: string;
  body: string | null;
  user: string | null;
  htmlUrl: string | null;
  submittedAt: string | null;
  commitId: string | null;
}

export interface DiscussionSummary {
  number: number;
  title: string;
  url: string;
  author: string | null;
  category: string | null;
  answerChosen: boolean;
  comments: number;
  upvotes: number;
  createdAt: string;
  updatedAt: string;
  body?: string;
  bodyTruncated?: boolean;
}

export interface WorkflowSummary {
  id: number;
  name: string;
  path: string;
  state: string;
  htmlUrl: string;
}

export interface WorkflowRunSummary {
  id: number;
  name: string | null;
  workflowId: number;
  runNumber: number;
  runAttempt: number;
  event: string;
  status: string | null;
  conclusion: string | null;
  headBranch: string | null;
  headSha: string;
  actor: string | null;
  htmlUrl: string;
  createdAt: string;
  updatedAt: string;
  runStartedAt: string | null;
  displayTitle: string | null;
}

export interface JobStep {
  number: number;
  name: string;
  status: string;
  conclusion: string | null;
}

export interface JobSummary {
  id: number;
  runId: number;
  name: string;
  status: string;
  conclusion: string | null;
  startedAt: string | null;
  completedAt: string | null;
  htmlUrl: string | null;
  runnerName: string | null;
  labels: string[];
  steps: JobStep[];
}

export interface JobLogs {
  jobId: number;
  /** Total length of the whole log in characters. */
  totalLength: number;
  /** Character offset of `text` within the whole log. */
  offset: number;
  limit: number | null;
  text: string;
  /** UTF-8 byte length of `text` (for transport/context budgeting). */
  bytesReturned: number;
  hasMore: boolean;
  /** Pass as `offset` to fetch the next slice; null when the log is complete. */
  nextOffset: number | null;
  truncated: boolean;
}

export interface ReleaseAsset {
  id: number;
  name: string;
  size: number;
  downloadCount: number;
  contentType: string;
  downloadUrl: string;
}

export interface ReleaseSummary {
  id: number;
  tagName: string;
  name: string | null;
  draft: boolean;
  prerelease: boolean;
  author: string | null;
  body: string | null;
  bodyTruncated: boolean;
  htmlUrl: string;
  tarballUrl: string | null;
  zipballUrl: string | null;
  createdAt: string;
  publishedAt: string | null;
  assets: ReleaseAsset[];
}

export interface CodeScanningAlert {
  number: number;
  state: string;
  ruleId: string | null;
  ruleSeverity: string | null;
  tool: string | null;
  path: string | null;
  startLine: number | null;
  htmlUrl: string | null;
  createdAt: string;
  dismissedReason: string | null;
  mostRecentInstanceRef?: string | null;
}

export interface DependabotAlert {
  number: number;
  state: string;
  packageName: string | null;
  ecosystem: string | null;
  severity: string | null;
  ghsaId: string | null;
  summary: string | null;
  manifestPath: string | null;
  htmlUrl: string | null;
  createdAt: string;
  fixedAt: string | null;
}

export interface SecretScanningAlert {
  number: number;
  state: string;
  secretType: string | null;
  secretTypeDisplay: string | null;
  resolution: string | null;
  htmlUrl: string | null;
  createdAt: string;
  resolvedAt: string | null;
}

/** Security endpoints are gated: report unavailability instead of throwing. */
export type AlertsResult<T> =
  | { available: true; items: T[]; pages: number; truncated: boolean; nextUrl: string | null }
  | { available: false; reason: string; status: number | null; docs: string | null };

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

export function parseLinkHeader(header: string | null): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(",")) {
    const m = /<([^>]+)>\s*;\s*(.*)$/.exec(part.trim());
    if (!m || !m[1]) continue;
    const rel = /rel="?([^";]+)"?/.exec(m[2] ?? "");
    if (rel && rel[1]) out[rel[1].trim()] = m[1];
  }
  return out;
}

const sleep = (ms: number): Promise<void> => (ms > 0 ? new Promise((r) => setTimeout(r, ms)) : Promise.resolve());

function enc(value: string): string {
  return encodeURIComponent(value);
}

function encPath(p: string): string {
  return p.replace(/^\/+/, "").split("/").map(enc).join("/");
}

function asString(v: unknown): string {
  return typeof v === "string" ? v : "";
}

function orNull<T>(v: T | undefined | null): T | null {
  return v === undefined || v === null ? null : v;
}

function numberOr(v: unknown, fallback: number): number {
  return typeof v === "number" && Number.isFinite(v) ? v : fallback;
}

function trimText(text: string | null | undefined, max: number): { text: string | null; truncated: boolean } {
  if (typeof text !== "string") return { text: null, truncated: false };
  if (text.length <= max) return { text, truncated: false };
  return { text: text.slice(0, max), truncated: true };
}

// --- raw -> trimmed mappers -------------------------------------------------

/* eslint-disable @typescript-eslint/no-explicit-any */
type Raw = Record<string, any>;

function mapUser(raw: Raw): GitHubUser {
  const user: GitHubUser = {
    login: asString(raw.login),
    id: numberOr(raw.id, 0),
    name: orNull(raw.name as string | null),
    email: orNull(raw.email as string | null),
    avatarUrl: orNull(raw.avatar_url as string | null),
    htmlUrl: asString(raw.html_url),
    type: asString(raw.type ?? "User"),
    company: orNull(raw.company as string | null),
    blog: orNull(raw.blog as string | null),
    location: orNull(raw.location as string | null),
    bio: orNull(raw.bio as string | null),
    publicRepos: numberOr(raw.public_repos, 0),
    publicGists: numberOr(raw.public_gists, 0),
    followers: numberOr(raw.followers, 0),
    following: numberOr(raw.following, 0),
    createdAt: asString(raw.created_at),
    updatedAt: asString(raw.updated_at),
  };
  if (raw.node_id) user.nodeId = asString(raw.node_id);
  if (raw.plan?.name) user.plan = asString(raw.plan.name);
  if (typeof raw.two_factor_authentication === "boolean") user.twoFactorAuthentication = raw.two_factor_authentication;
  if (typeof raw.site_admin === "boolean") user.siteAdmin = raw.site_admin;
  return user;
}

function mapRepo(raw: Raw): RepoSummary {
  const repo: RepoSummary = {
    id: numberOr(raw.id, 0),
    name: asString(raw.name),
    fullName: asString(raw.full_name),
    owner: asString(raw.owner?.login),
    private: raw.private === true,
    fork: raw.fork === true,
    archived: raw.archived === true,
    visibility: orNull(raw.visibility as string | null),
    description: orNull(raw.description as string | null),
    defaultBranch: asString(raw.default_branch),
    htmlUrl: asString(raw.html_url),
    cloneUrl: asString(raw.clone_url),
    sshUrl: asString(raw.ssh_url),
    language: orNull(raw.language as string | null),
    stars: numberOr(raw.stargazers_count, 0),
    forks: numberOr(raw.forks_count, 0),
    openIssues: numberOr(raw.open_issues_count, 0),
    sizeKb: numberOr(raw.size, 0),
    pushedAt: orNull(raw.pushed_at as string | null),
    updatedAt: orNull(raw.updated_at as string | null),
  };
  if (Array.isArray(raw.topics)) repo.topics = raw.topics.map((t: unknown) => String(t));
  if (raw.license) repo.license = orNull(raw.license.spdx_id as string | null);
  if (raw.permissions && typeof raw.permissions === "object") {
    const p = raw.permissions as Raw;
    repo.permissions = {
      admin: p.admin === true,
      push: p.push === true,
      pull: p.pull === true,
      ...(typeof p.maintain === "boolean" ? { maintain: p.maintain } : {}),
      ...(typeof p.triage === "boolean" ? { triage: p.triage } : {}),
    };
  }
  return repo;
}

function mapCommitSummary(raw: Raw): CommitSummary {
  const commit = (raw.commit ?? {}) as Raw;
  const author = commit.author ?? {};
  const committer = commit.committer ?? {};
  const summary: CommitSummary = {
    sha: asString(raw.sha),
    message: asString(commit.message),
    author: {
      login: orNull((raw.author?.login ?? null) as string | null),
      name: asString(author.name),
      email: asString(author.email),
      date: orNull(author.date as string | null),
    },
    committer: {
      login: orNull((raw.committer?.login ?? null) as string | null),
      name: asString(committer.name),
      date: orNull(committer.date as string | null),
    },
    parents: Array.isArray(raw.parents) ? raw.parents.map((p: Raw) => asString(p.sha)) : [],
    htmlUrl: asString(raw.html_url),
  };
  if (commit.verification && typeof commit.verification.verified === "boolean") {
    summary.verified = commit.verification.verified;
  }
  return summary;
}

function mapCommitFile(raw: Raw, maxPatchChars: number): CommitFile {
  const patch = trimText(raw.patch as string | undefined, maxPatchChars);
  const file: CommitFile = {
    filename: asString(raw.filename),
    status: asString(raw.status),
    additions: numberOr(raw.additions, 0),
    deletions: numberOr(raw.deletions, 0),
    changes: numberOr(raw.changes, 0),
    patchTruncated: patch.truncated,
  };
  if (raw.previous_filename) file.previousFilename = asString(raw.previous_filename);
  if (raw.blob_url) file.blobUrl = asString(raw.blob_url);
  if (patch.text !== null) file.patch = patch.text;
  return file;
}

function mapIssue(raw: Raw, maxBodyChars: number): IssueSummary {
  const body = trimText(raw.body as string | undefined, maxBodyChars);
  return {
    number: numberOr(raw.number, 0),
    title: asString(raw.title),
    state: asString(raw.state),
    stateReason: orNull(raw.state_reason as string | null),
    body: body.text,
    bodyTruncated: body.truncated,
    user: orNull(raw.user?.login as string | null),
    labels: Array.isArray(raw.labels)
      ? raw.labels.map((l: Raw | string) => (typeof l === "string" ? l : asString(l.name)))
      : [],
    assignees: Array.isArray(raw.assignees) ? raw.assignees.map((a: Raw) => asString(a.login)) : [],
    comments: numberOr(raw.comments, 0),
    locked: raw.locked === true,
    htmlUrl: asString(raw.html_url),
    createdAt: asString(raw.created_at),
    updatedAt: asString(raw.updated_at),
    closedAt: orNull(raw.closed_at as string | null),
    pullRequest: Boolean(raw.pull_request),
  };
}

function mapPullRequest(raw: Raw, maxBodyChars: number): PullRequestSummary {
  const body = trimText(raw.body as string | undefined, maxBodyChars);
  return {
    number: numberOr(raw.number, 0),
    title: asString(raw.title),
    state: asString(raw.state),
    draft: raw.draft === true,
    merged: raw.merged === true,
    mergeable: typeof raw.mergeable === "boolean" ? raw.mergeable : null,
    mergeableState: orNull(raw.mergeable_state as string | null),
    body: body.text,
    bodyTruncated: body.truncated,
    user: orNull(raw.user?.login as string | null),
    head: {
      ref: asString(raw.head?.ref),
      sha: asString(raw.head?.sha),
      repo: orNull((raw.head?.repo?.full_name ?? null) as string | null),
    },
    base: {
      ref: asString(raw.base?.ref),
      sha: asString(raw.base?.sha),
      repo: orNull((raw.base?.repo?.full_name ?? null) as string | null),
    },
    htmlUrl: asString(raw.html_url),
    additions: numberOr(raw.additions, 0),
    deletions: numberOr(raw.deletions, 0),
    changedFiles: numberOr(raw.changed_files, 0),
    commits: numberOr(raw.commits, 0),
    createdAt: asString(raw.created_at),
    updatedAt: asString(raw.updated_at),
    mergedAt: orNull(raw.merged_at as string | null),
    labels: Array.isArray(raw.labels)
      ? raw.labels.map((l: Raw | string) => (typeof l === "string" ? l : asString(l.name)))
      : [],
  };
}

function mapWorkflowRun(raw: Raw): WorkflowRunSummary {
  return {
    id: numberOr(raw.id, 0),
    name: orNull(raw.name as string | null),
    workflowId: numberOr(raw.workflow_id, 0),
    runNumber: numberOr(raw.run_number, 0),
    runAttempt: numberOr(raw.run_attempt, 1),
    event: asString(raw.event),
    status: orNull(raw.status as string | null),
    conclusion: orNull(raw.conclusion as string | null),
    headBranch: orNull(raw.head_branch as string | null),
    headSha: asString(raw.head_sha),
    actor: orNull(raw.actor?.login as string | null),
    htmlUrl: asString(raw.html_url),
    createdAt: asString(raw.created_at),
    updatedAt: asString(raw.updated_at),
    runStartedAt: orNull(raw.run_started_at as string | null),
    displayTitle: orNull(raw.display_title as string | null),
  };
}

function mapJob(raw: Raw): JobSummary {
  return {
    id: numberOr(raw.id, 0),
    runId: numberOr(raw.run_id, 0),
    name: asString(raw.name),
    status: asString(raw.status),
    conclusion: orNull(raw.conclusion as string | null),
    startedAt: orNull(raw.started_at as string | null),
    completedAt: orNull(raw.completed_at as string | null),
    htmlUrl: orNull(raw.html_url as string | null),
    runnerName: orNull(raw.runner_name as string | null),
    labels: Array.isArray(raw.labels) ? raw.labels.map((l: unknown) => String(l)) : [],
    steps: Array.isArray(raw.steps)
      ? raw.steps.map((s: Raw) => ({
          number: numberOr(s.number, 0),
          name: asString(s.name),
          status: asString(s.status),
          conclusion: orNull(s.conclusion as string | null),
        }))
      : [],
  };
}

function mapRelease(raw: Raw, maxBodyChars: number): ReleaseSummary {
  const body = trimText(raw.body as string | undefined, maxBodyChars);
  return {
    id: numberOr(raw.id, 0),
    tagName: asString(raw.tag_name),
    name: orNull(raw.name as string | null),
    draft: raw.draft === true,
    prerelease: raw.prerelease === true,
    author: orNull(raw.author?.login as string | null),
    body: body.text,
    bodyTruncated: body.truncated,
    htmlUrl: asString(raw.html_url),
    tarballUrl: orNull(raw.tarball_url as string | null),
    zipballUrl: orNull(raw.zipball_url as string | null),
    createdAt: asString(raw.created_at),
    publishedAt: orNull(raw.published_at as string | null),
    assets: Array.isArray(raw.assets)
      ? raw.assets.map((a: Raw) => ({
          id: numberOr(a.id, 0),
          name: asString(a.name),
          size: numberOr(a.size, 0),
          downloadCount: numberOr(a.download_count, 0),
          contentType: asString(a.content_type),
          downloadUrl: asString(a.browser_download_url),
        }))
      : [],
  };
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

export class GitHubClient {
  /** Base REST URL without trailing slash, e.g. https://api.github.com */
  readonly baseUrl: string;
  readonly graphqlUrl: string;
  readonly apiVersion: string;
  readonly userAgent: string;

  private readonly token: string;
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number;
  private readonly retryDelayMs: number;
  private readonly maxPages: number;
  private readonly maxPatchChars: number;
  private rl: RateLimitSnapshot = { limit: null, remaining: null, reset: null, used: null, resource: null };

  constructor(token: string, options: GitHubClientOptions = {}) {
    if (typeof token !== "string" || token.trim() === "") {
      throw new GitHubValidationError(
        "A per-user GitHub token is required. Pass UserContext.githubToken — never a shared server token.",
      );
    }
    this.token = token.trim();
    this.baseUrl = (options.baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, "");
    this.graphqlUrl =
      options.graphqlUrl ?? (this.baseUrl === DEFAULT_BASE_URL ? `${DEFAULT_BASE_URL}/graphql` : `${this.baseUrl}/graphql`);
    this.apiVersion = options.apiVersion ?? GITHUB_API_VERSION;
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.userAgent = options.userAgent ?? DEFAULT_USER_AGENT;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.retryDelayMs = options.retryDelayMs ?? 400;
    this.maxPages = options.maxPages ?? MAX_PAGES;
    this.maxPatchChars = options.maxPatchChars ?? 4000;
  }

  /** Last observed rate-limit headers (does not make a request). */
  rateLimitInfo(): RateLimitSnapshot {
    return { ...this.rl, reset: this.rl.reset ? new Date(this.rl.reset.getTime()) : null };
  }

  // -- plumbing -------------------------------------------------------------

  /** Remove the token (and anything that looks like a credential) from a string. */
  private scrub(input: string): string {
    let out = input.split(this.token).join("[REDACTED]");
    out = out.replace(/(access_token=)[^&\s]+/gi, "$1[REDACTED]");
    out = out.replace(/(Authorization:\s*)\S+/gi, "$1[REDACTED]");
    return redact(out);
  }

  private pathOnly(path: string): string {
    if (/^https?:\/\//i.test(path)) {
      try {
        return new URL(path).pathname;
      } catch {
        return "[invalid-url]";
      }
    }
    const q = path.indexOf("?");
    return q === -1 ? path : path.slice(0, q);
  }

  private buildUrl(path: string, query?: Query): string {
    const base = /^https?:\/\//i.test(path)
      ? path
      : `${this.baseUrl}${path.startsWith("/") ? "" : "/"}${path}`;
    const url = new URL(base);
    if (query) {
      for (const [key, value] of Object.entries(query)) {
        if (value === undefined || value === null) continue;
        url.searchParams.set(key, String(value));
      }
    }
    return url.toString();
  }

  private captureRateLimit(headers: Headers): void {
    const num = (name: string): number | null => {
      const raw = headers.get(name);
      if (raw === null || raw === "") return null;
      const n = Number(raw);
      return Number.isFinite(n) ? n : null;
    };
    const limit = num("x-ratelimit-limit");
    const remaining = num("x-ratelimit-remaining");
    const reset = num("x-ratelimit-reset");
    const used = num("x-ratelimit-used");
    if (limit !== null) this.rl.limit = limit;
    if (remaining !== null) this.rl.remaining = remaining;
    if (reset !== null) this.rl.reset = new Date(reset * 1000);
    if (used !== null) this.rl.used = used;
    const resource = headers.get("x-ratelimit-resource");
    if (resource) this.rl.resource = resource;
  }

  private async apiError(res: Response, method: string, path: string): Promise<GitHubError> {
    const status = res.status;
    let text = "";
    try {
      text = await res.text();
    } catch {
      text = "";
    }
    let parsed: Raw | null = null;
    if (text) {
      try {
        const candidate = JSON.parse(text) as unknown;
        if (candidate && typeof candidate === "object") parsed = candidate as Raw;
      } catch {
        parsed = null;
      }
    }
    const apiMessage = parsed && typeof parsed.message === "string" ? parsed.message : text.slice(0, 300);
    const docs = parsed && typeof parsed.documentation_url === "string" ? parsed.documentation_url : null;
    const requestId = res.headers.get("x-github-request-id");
    const code = parsed && typeof parsed.errors?.[0]?.code === "string" ? String(parsed.errors[0].code) : null;
    const where = `${method} ${this.pathOnly(path)}`;
    const detail = apiMessage ? `: ${this.scrub(apiMessage)}` : "";
    const base = {
      status,
      method,
      path: this.pathOnly(path),
      code,
      documentationUrl: docs,
      requestId,
      apiMessage: apiMessage ? this.scrub(apiMessage) : null,
    };

    // Rate limiting: primary quota (remaining=0) or secondary/abuse throttle.
    const remaining = Number(res.headers.get("x-ratelimit-remaining") ?? NaN);
    const resetHeader = Number(res.headers.get("x-ratelimit-reset") ?? NaN);
    const retryAfter = res.headers.get("retry-after");
    const retryAfterSeconds = retryAfter !== null && Number.isFinite(Number(retryAfter)) ? Number(retryAfter) : null;
    const looksThrottled = /rate limit|abuse detection|too many requests/i.test(apiMessage);
    const exhausted = Number.isFinite(remaining) && remaining <= 0;
    if (status === 429 || ((status === 403 || status === 429) && (exhausted || looksThrottled))) {
      const resetAt = Number.isFinite(resetHeader) && resetHeader > 0
        ? new Date(resetHeader * 1000)
        : new Date(Date.now() + (retryAfterSeconds ?? 60) * 1000);
      const secondary = !exhausted && looksThrottled;
      return new GitHubRateLimitError({
        ...base,
        message: this.scrub(
          `GitHub rate limit ${secondary ? "throttle" : "exceeded"} on ${where}` +
            (Number.isFinite(remaining) ? ` (${remaining}/${res.headers.get("x-ratelimit-limit") ?? "?"} remaining)` : "") +
            `; resets at ${resetAt.toISOString()}` +
            (secondary && retryAfterSeconds !== null ? ` (retry after ${retryAfterSeconds}s)` : ""),
        ),
        resetAt,
        retryAfterSeconds,
        limit: Number.isFinite(Number(res.headers.get("x-ratelimit-limit") ?? NaN))
          ? Number(res.headers.get("x-ratelimit-limit"))
          : null,
        remaining: Number.isFinite(remaining) ? remaining : null,
        resource: res.headers.get("x-ratelimit-resource"),
        secondary,
      });
    }

    const message = this.scrub(`GitHub API ${where} failed with ${status}${detail}`);

    if (status === 404) {
      return new GitHubNotFoundError({
        ...base,
        message: `${message} (not found, or this token cannot see it)`,
      });
    }
    if (status === 403) return new GitHubForbiddenError({ ...base, message });
    if (status === 304) {
      return new GitHubNotModifiedError({ ...base, message: this.scrub(`GitHub API ${where} returned 304 Not Modified`) });
    }
    return new GitHubError({ ...base, message });
  }

  /**
   * Low-level: build headers, send, retry once on 502/503, map errors.
   * Returns the raw `Response` (body unread).
   */
  private async fetchResponse(
    path: string,
    opts: RequestOptions = {},
  ): Promise<{ res: Response; url: string; method: HttpMethod }> {
    const url = this.buildUrl(path, opts.query);
    const method: HttpMethod = opts.method ?? (opts.body !== undefined ? "POST" : "GET");
    const headers: Record<string, string> = {
      Accept: opts.accept ?? "application/vnd.github+json",
      Authorization: `Bearer ${this.token}`,
      "X-GitHub-Api-Version": this.apiVersion,
      "User-Agent": this.userAgent,
      ...(opts.body !== undefined ? { "Content-Type": "application/json" } : {}),
      ...(opts.headers ?? {}),
    };
    const init: RequestInit = {
      method,
      headers,
      redirect: opts.redirect ?? "follow",
      ...(opts.body !== undefined ? { body: JSON.stringify(opts.body) } : {}),
      ...(opts.signal
        ? { signal: opts.signal }
        : this.timeoutMs > 0
          ? { signal: AbortSignal.timeout(this.timeoutMs) }
          : {}),
    };

    let attempt = 0;
    for (;;) {
      let res: Response;
      try {
        res = await this.fetchImpl(url, init);
      } catch (err) {
        const reason = err instanceof Error ? this.scrub(err.message) : "network error";
        if (attempt === 0 && method === "GET") {
          attempt += 1;
          await sleep(this.retryDelayMs);
          continue;
        }
        throw new GitHubError({
          status: 0,
          method,
          path: this.pathOnly(path),
          message: this.scrub(`GitHub API ${method} ${this.pathOnly(path)} failed before a response: ${reason}`),
          apiMessage: null,
        });
      }
      this.captureRateLimit(res.headers);
      if ((res.status === 502 || res.status === 503) && attempt === 0) {
        attempt += 1;
        await sleep(this.retryDelayMs);
        continue;
      }
      if (opts.expectStatus && opts.expectStatus.includes(res.status)) return { res, url, method };
      if (!res.ok) throw await this.apiError(res, method, path);
      return { res, url, method };
    }
  }

  private async parseBody<T>(res: Response, raw: boolean): Promise<T> {
    if (raw) return (await res.text()) as unknown as T;
    if (res.status === 204) return undefined as unknown as T;
    const text = await res.text();
    if (!text) return undefined as unknown as T;
    try {
      return JSON.parse(text) as T;
    } catch {
      throw new GitHubError({
        status: res.status,
        message: this.scrub(`GitHub API returned a non-JSON body (${text.length} bytes)`),
      });
    }
  }

  /** Single request. `path` may be a REST path ("/user") or an absolute URL. */
  async request<T = unknown>(path: string, opts: RequestOptions = {}): Promise<T> {
    const { res } = await this.fetchResponse(path, opts);
    return this.parseBody<T>(res, opts.raw === true);
  }

  /**
   * Follow `Link: rel="next"` until `maxItems` (or `maxPages`) is reached.
   *
   * `truncated` is honest: it means the API had more and we stopped. Responses
   * may be a bare array or a wrapper object (`{ total_count, items }`,
   * `{ total_count, jobs }`, ...) — the array field is detected automatically,
   * or named explicitly with `wrapKey`.
   */
  async paginate<T>(
    path: string,
    maxItems = 1000,
    opts: { query?: Query; maxPages?: number; wrapKey?: string } = {},
  ): Promise<Paginated<T>> {
    const items: T[] = [];
    const pageCap = opts.maxPages ?? this.maxPages;
    let cursor: string | null = path;
    let pages = 0;
    let more = false;
    let totalCount: number | undefined;

    while (cursor && pages < pageCap) {
      const { res } = await this.fetchResponse(cursor, { query: pages === 0 ? opts.query : undefined });
      pages += 1;
      const data = await this.parseBody<unknown>(res, false);

      let batch: unknown[];
      if (Array.isArray(data)) {
        batch = data;
      } else if (data && typeof data === "object") {
        const obj = data as Raw;
        if (typeof obj.total_count === "number") totalCount = obj.total_count;
        let candidate: unknown = opts.wrapKey ? obj[opts.wrapKey] : undefined;
        if (!Array.isArray(candidate)) {
          const arrays = Object.values(obj).filter(Array.isArray);
          if (arrays.length === 1) candidate = arrays[0];
        }
        batch = Array.isArray(candidate) ? candidate : [];
      } else {
        batch = [];
      }

      const linkNext = parseLinkHeader(res.headers.get("link")).next ?? null;

      for (const entry of batch) {
        if (items.length >= maxItems) {
          more = true;
          break;
        }
        items.push(entry as T);
      }
      if (more) {
        // Stopped mid-page: the remainder of this page is unconsumed.
        cursor = linkNext ?? cursor;
        break;
      }
      if (items.length >= maxItems) {
        more = linkNext !== null;
        cursor = linkNext;
        break;
      }
      cursor = linkNext;
      if (batch.length === 0 && !linkNext) break;
      if (!linkNext && totalCount !== undefined && totalCount > items.length) {
        // No Link header but the API says there is more (defensive).
        more = true;
      }
    }

    const result: Paginated<T> = {
      items,
      pages,
      truncated: more,
      nextUrl: more ? cursor : null,
    };
    if (totalCount !== undefined) result.totalCount = totalCount;
    return result;
  }

  private paginateRaw(path: string, maxItems: number, opts: { query?: Query; wrapKey?: string } = {}): Promise<Paginated<Raw>> {
    return this.paginate<Raw>(path, maxItems, opts);
  }

  /**
   * One explicit page. `truncated` still reflects the `Link` header, so a
   * caller that paged manually is told there are more results.
   */
  private async requestPage<T>(
    path: string,
    query: Query,
    wrapKey?: string,
  ): Promise<Paginated<T>> {
    const { res } = await this.fetchResponse(path, { query });
    const data = await this.parseBody<unknown>(res, false);
    let batch: unknown[];
    let totalCount: number | undefined;
    if (Array.isArray(data)) {
      batch = data;
    } else if (data && typeof data === "object") {
      const obj = data as Raw;
      if (typeof obj.total_count === "number") totalCount = obj.total_count;
      let candidate: unknown = wrapKey ? obj[wrapKey] : undefined;
      if (!Array.isArray(candidate)) {
        const arrays = Object.values(obj).filter(Array.isArray);
        if (arrays.length === 1) candidate = arrays[0];
      }
      batch = Array.isArray(candidate) ? candidate : [];
    } else {
      batch = [];
    }
    const nextUrl = parseLinkHeader(res.headers.get("link")).next ?? null;
    const result: Paginated<T> = {
      items: batch as T[],
      pages: 1,
      truncated: nextUrl !== null,
      nextUrl,
    };
    if (totalCount !== undefined) result.totalCount = totalCount;
    return result;
  }

  // -- user / repos ---------------------------------------------------------

  async getAuthenticatedUser(): Promise<GitHubUser> {
    const { res } = await this.fetchResponse("/user");
    const raw = (await this.parseBody<Raw>(res, false)) ?? {};
    const user = mapUser(raw);
    const scopes = res.headers.get("x-oauth-scopes");
    user.scopes = scopes ? scopes.split(",").map((s) => s.trim()).filter(Boolean) : [];
    return user;
  }

  /**
   * Repos the token can see.
   * Omit `page` to auto-follow pagination up to `maxItems` (default 300).
   */
  async listRepos(
    visibility: RepoVisibility = "all",
    affiliation?: string,
    page?: number,
    perPage = 30,
    maxItems = 300,
  ): Promise<Paginated<RepoSummary>> {
    const query: Query = { visibility, affiliation, per_page: perPage, page };
    if (page !== undefined) {
      const single = await this.requestPage<Raw>("/user/repos", query);
      return { ...single, items: single.items.map(mapRepo) };
    }
    const paged = await this.paginateRaw("/user/repos", maxItems, { query });
    return { ...paged, items: paged.items.map(mapRepo) };
  }

  async getRepo(owner: string, repo: string): Promise<RepoSummary> {
    const raw = await this.request<Raw>(`/repos/${enc(owner)}/${enc(repo)}`);
    return mapRepo(raw ?? {});
  }

  async listBranches(
    owner: string,
    repo: string,
    opts: { page?: number; perPage?: number; protectedOnly?: boolean; maxItems?: number } = {},
  ): Promise<Paginated<BranchSummary>> {
    const path = `/repos/${enc(owner)}/${enc(repo)}/branches`;
    const map = (raws: Raw[]): BranchSummary[] =>
      raws.map((b) => ({ name: asString(b.name), sha: asString(b.commit?.sha), protected: b.protected === true }));
    const paged =
      opts.page !== undefined
        ? await this.requestPage<Raw>(path, { per_page: opts.perPage ?? 30, page: opts.page })
        : await this.paginateRaw(path, opts.maxItems ?? 300, { query: { per_page: opts.perPage ?? 100 } });
    let items = map(paged.items ?? []);
    if (opts.protectedOnly) items = items.filter((b) => b.protected);
    return { items, pages: paged.pages, truncated: paged.truncated, nextUrl: paged.nextUrl };
  }

  /** Recursive tree listing, optionally filtered to a subtree path. */
  async getTree(
    owner: string,
    repo: string,
    ref = "HEAD",
    path?: string,
    opts: { maxEntries?: number } = {},
  ): Promise<TreeResult> {
    const maxEntries = opts.maxEntries ?? 5000;
    const raw = await this.request<Raw>(`/repos/${enc(owner)}/${enc(repo)}/git/trees/${enc(ref)}`, {
      query: { recursive: 1 },
    });
    const prefix = path ? path.replace(/^\/+|\/+$/g, "") : "";
    const all: TreeEntry[] = Array.isArray(raw?.tree)
      ? raw.tree.map((e: Raw) => {
          const entry: TreeEntry = {
            path: asString(e.path),
            mode: asString(e.mode),
            type: asString(e.type),
            sha: asString(e.sha),
          };
          if (typeof e.size === "number") entry.size = e.size;
          return entry;
        })
      : [];
    const filtered = prefix
      ? all
          .filter((e) => e.path === prefix || e.path.startsWith(`${prefix}/`))
          .map((e) => ({ ...e, path: e.path.slice(prefix.length + 1) || e.path }))
      : all;
    const entries = filtered.slice(0, maxEntries);
    return {
      sha: orNull(raw?.sha as string | null),
      ref,
      path: prefix || null,
      entries,
      entryCount: filtered.length,
      apiTruncated: raw?.truncated === true,
      truncated: filtered.length > entries.length,
    };
  }

  /**
   * Read a file (or list a directory).
   *
   * Files > 1MB come back empty from the contents API, so they are read through
   * the git blobs API. The result is a byte range: `offset`/`limit` let callers
   * page through a large file explicitly — we never silently truncate.
   */
  async getContent(
    owner: string,
    repo: string,
    path: string,
    ref?: string,
    opts: { offset?: number; limit?: number } = {},
  ): Promise<RepoContent> {
    const offset = Math.max(0, Math.trunc(opts.offset ?? 0));
    const limit = opts.limit !== undefined ? Math.max(1, Math.trunc(opts.limit)) : null;
    const raw = await this.request<Raw | Raw[]>(
      `/repos/${enc(owner)}/${enc(repo)}/contents/${encPath(path)}`,
      { query: { ref } },
    );

    if (Array.isArray(raw)) {
      return {
        type: "dir",
        path,
        sha: "",
        size: 0,
        htmlUrl: null,
        downloadUrl: null,
        entries: raw.map((e) => ({
          name: asString(e.name),
          path: asString(e.path),
          type: asString(e.type),
          size: numberOr(e.size, 0),
          sha: asString(e.sha),
        })),
      };
    }
    const entry = raw ?? {};
    const type = asString(entry.type) || "file";
    if (type !== "file") {
      return {
        type: type === "symlink" || type === "submodule" ? type : "dir",
        path,
        sha: asString(entry.sha),
        size: numberOr(entry.size, 0),
        htmlUrl: orNull(entry.html_url as string | null),
        downloadUrl: orNull(entry.download_url as string | null),
        entries: [],
      };
    }

    const size = numberOr(entry.size, 0);
    const sha = asString(entry.sha);
    const inline = typeof entry.content === "string" ? entry.content : "";
    const encoding = asString(entry.encoding);
    const needsBlob = size > CONTENTS_API_MAX_BYTES || inline === "" || encoding === "none";

    let buffer: Buffer;
    let source: "contents" | "blobs" = "contents";
    if (!needsBlob) {
      buffer = Buffer.from(inline.replace(/\s+/g, ""), "base64");
    } else {
      if (!sha) {
        throw new GitHubError({
          status: 422,
          message: this.scrub(
            `Cannot read ${path}: the contents API returned no inline content and no blob sha (file may exceed 1MB without a sha)`,
          ),
        });
      }
      source = "blobs";
      buffer = await this.readBlob(owner, repo, sha, size);
    }

    const end = limit === null ? buffer.length : Math.min(buffer.length, offset + limit);
    const start = Math.min(offset, buffer.length);
    const chunk = buffer.subarray(start, end);
    const hasMore = end < buffer.length;
    return {
      type: "file",
      path,
      name: asString(entry.name) || path.split("/").pop() || path,
      sha,
      size: buffer.length,
      encoding: "base64",
      base64: chunk.toString("base64"),
      offset: start,
      limit,
      chunkSize: chunk.length,
      hasMore,
      nextOffset: hasMore ? end : null,
      truncated: hasMore || start > 0,
      source,
      htmlUrl: orNull(entry.html_url as string | null),
      downloadUrl: orNull(entry.download_url as string | null),
    };
  }

  private async readBlob(owner: string, repo: string, sha: string, expectedSize: number): Promise<Buffer> {
    if (expectedSize > BLOB_API_MAX_BYTES) {
      throw new GitHubError({
        status: 413,
        message: this.scrub(
          `File is ${expectedSize} bytes; the git blobs API caps at ${BLOB_API_MAX_BYTES} bytes. ` +
            `Use downloadFile/getContent with an offset range on a smaller ref, or the git clone path.`,
        ),
      });
    }
    const blob = await this.request<Raw>(`/repos/${enc(owner)}/${enc(repo)}/git/blobs/${enc(sha)}`);
    const content = typeof blob?.content === "string" ? blob.content : "";
    if (!content) {
      throw new GitHubError({
        status: 422,
        message: this.scrub(`Blob ${sha} returned no content (size ${numberOr(blob?.size, expectedSize)} bytes)`),
      });
    }
    const decoded = Buffer.from(content.replace(/\s+/g, ""), "base64");
    if (typeof blob?.size === "number" && blob.size !== decoded.length) {
      throw new GitHubError({
        status: 502,
        message: this.scrub(`Blob ${sha} decoded to ${decoded.length} bytes but the API reported ${blob.size}`),
      });
    }
    return decoded;
  }

  /** Raw bytes as base64, with an explicit size cap flag. */
  async downloadFile(
    owner: string,
    repo: string,
    path: string,
    ref?: string,
    opts: { maxBytes?: number } = {},
  ): Promise<DownloadedFile> {
    const maxBytes = opts.maxBytes ?? 8 * 1024 * 1024;
    const { res } = await this.fetchResponse(`/repos/${enc(owner)}/${enc(repo)}/contents/${encPath(path)}`, {
      accept: "application/vnd.github.raw",
      query: { ref },
    });
    // Stream so a huge file cannot be pulled into memory: stop at maxBytes.
    const declared = Number(res.headers.get("content-length") ?? NaN);
    const chunks: Buffer[] = [];
    let total = 0;
    let capped = false;
    if (res.body) {
      const reader = res.body.getReader();
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        if (!value || value.byteLength === 0) continue;
        const already = total;
        total += value.byteLength;
        if (total > maxBytes) {
          const room = maxBytes - already;
          if (room > 0) chunks.push(Buffer.from(value.subarray(0, room)));
          capped = true;
          await reader.cancel().catch(() => undefined);
          break;
        }
        chunks.push(Buffer.from(value));
      }
    }
    const bytes = Buffer.concat(chunks);
    const size = Number.isFinite(declared) && declared >= bytes.length ? declared : total;
    return {
      path,
      ref: ref ?? null,
      size,
      bytesReturned: bytes.length,
      base64: bytes.toString("base64"),
      contentType: res.headers.get("content-type"),
      maxBytes,
      truncated: capped || size > bytes.length,
      sizeExact: Number.isFinite(declared) || !capped,
    };
  }

  // -- writes ---------------------------------------------------------------

  async createOrUpdateFile(
    owner: string,
    repo: string,
    path: string,
    opts: {
      content: string;
      message: string;
      sha?: string;
      branch?: string;
      encoding?: FileEncoding;
      author?: GitIdentity;
      committer?: GitIdentity;
    },
  ): Promise<WriteFileResult> {
    if (!opts.message) throw new GitHubValidationError("createOrUpdateFile requires a commit message", path);
    const body: Record<string, unknown> = {
      message: opts.message,
      content: opts.encoding === "base64" ? opts.content : Buffer.from(opts.content, "utf8").toString("base64"),
    };
    if (opts.sha) body.sha = opts.sha;
    if (opts.branch) body.branch = opts.branch;
    if (opts.author) body.author = opts.author;
    if (opts.committer) body.committer = opts.committer;

    const raw = await this.request<Raw>(`/repos/${enc(owner)}/${enc(repo)}/contents/${encPath(path)}`, {
      method: "PUT",
      body,
    });
    return {
      path,
      commitSha: asString(raw?.commit?.sha),
      commitUrl: orNull(raw?.commit?.html_url as string | null),
      htmlUrl: orNull(raw?.content?.html_url as string | null),
      sha: asString(raw?.content?.sha),
      size: numberOr(raw?.content?.size, 0),
      branch: opts.branch ?? null,
      message: asString(raw?.commit?.message) || opts.message,
    };
  }

  /** Delete a file. `sha` is mandatory (GitHub requires optimistic concurrency). */
  async deleteFile(
    owner: string,
    repo: string,
    path: string,
    opts: { sha: string; message: string; branch?: string },
  ): Promise<DeleteFileResult> {
    if (!opts.sha) {
      throw new GitHubValidationError(
        "deleteFile requires the current blob sha (fetch it with getContent first); GitHub rejects deletes without it.",
        path,
      );
    }
    if (!opts.message) throw new GitHubValidationError("deleteFile requires a commit message", path);
    const body: Record<string, unknown> = { message: opts.message, sha: opts.sha };
    if (opts.branch) body.branch = opts.branch;
    const raw = await this.request<Raw>(`/repos/${enc(owner)}/${enc(repo)}/contents/${encPath(path)}`, {
      method: "DELETE",
      body,
    });
    return {
      path,
      commitSha: asString(raw?.commit?.sha),
      commitUrl: orNull(raw?.commit?.html_url as string | null),
      deleted: true,
      branch: opts.branch ?? null,
    };
  }

  /** Create `branch` from `from` (a branch name, tag name or commit sha). */
  async createBranch(owner: string, repo: string, branch: string, from: string): Promise<{ ref: string; sha: string }> {
    if (!branch || !from) throw new GitHubValidationError("createBranch requires a branch name and a source ref");
    const sha = await this.resolveRefSha(owner, repo, from);
    const raw = await this.request<Raw>(`/repos/${enc(owner)}/${enc(repo)}/git/refs`, {
      method: "POST",
      body: { ref: `refs/heads/${branch}`, sha },
    });
    return { ref: asString(raw?.ref) || `refs/heads/${branch}`, sha: asString(raw?.object?.sha) || sha };
  }

  /**
   * Commit several files atomically: blobs -> tree -> commit -> update ref.
   * Either everything lands or nothing does (the ref moves once, at the end).
   */
  async createCommitMultiFile(
    owner: string,
    repo: string,
    opts: MultiFileCommitOptions,
  ): Promise<MultiFileCommitResult> {
    const files = opts.files ?? [];
    const deletions = opts.deletions ?? [];
    if (!opts.branch) throw new GitHubValidationError("createCommitMultiFile requires a target branch");
    if (!opts.message) throw new GitHubValidationError("createCommitMultiFile requires a commit message");
    if (files.length === 0 && deletions.length === 0) {
      throw new GitHubValidationError("createCommitMultiFile needs at least one file or deletion");
    }
    const base = opts.baseBranch ?? opts.branch;
    const repoPath = `/repos/${enc(owner)}/${enc(repo)}`;

    // 1. Where does the base ref point?
    const baseSha = await this.resolveRefSha(owner, repo, base);

    // 2. Optionally create the target branch at that commit.
    let createdBranch = false;
    if (opts.baseBranch && opts.baseBranch !== opts.branch) {
      await this.request<Raw>(`${repoPath}/git/refs`, {
        method: "POST",
        body: { ref: `refs/heads/${opts.branch}`, sha: baseSha },
      });
      createdBranch = true;
    }

    // 3. The base commit's tree becomes `base_tree`.
    const baseCommit = await this.request<Raw>(`${repoPath}/git/commits/${enc(baseSha)}`);
    const baseTreeSha = asString(baseCommit?.tree?.sha);
    if (!baseTreeSha) {
      throw new GitHubError({ status: 502, message: "Base commit did not include a tree sha" });
    }

    // 4. One blob per file (sequential: deterministic order, gentle on the API).
    const blobs: { path: string; sha: string }[] = [];
    for (const file of files) {
      const content = file.encoding === "base64" ? file.content : Buffer.from(file.content, "utf8").toString("base64");
      const blob = await this.request<Raw>(`${repoPath}/git/blobs`, {
        method: "POST",
        body: { content, encoding: "base64" },
      });
      blobs.push({ path: file.path, sha: asString(blob?.sha) });
    }

    // 5. One tree that adds/updates the blobs and drops the deletions.
    const treeEntries: Record<string, unknown>[] = blobs.map((b) => ({
      path: b.path.replace(/^\/+/, ""),
      mode: files.find((f) => f.path === b.path)?.mode ?? "100644",
      type: "blob",
      sha: b.sha,
    }));
    for (const path of deletions) {
      treeEntries.push({ path: path.replace(/^\/+/, ""), mode: "100644", type: "blob", sha: null });
    }
    const tree = await this.request<Raw>(`${repoPath}/git/trees`, {
      method: "POST",
      body: { base_tree: baseTreeSha, tree: treeEntries },
    });
    const treeSha = asString(tree?.sha);

    // 6. The commit.
    const commitBody: Record<string, unknown> = {
      message: opts.message,
      tree: treeSha,
      parents: [baseSha],
    };
    if (opts.author) commitBody.author = opts.author;
    if (opts.committer) commitBody.committer = opts.committer;
    const commit = await this.request<Raw>(`${repoPath}/git/commits`, { method: "POST", body: commitBody });
    const commitSha = asString(commit?.sha);

    // 7. Move the branch (single ref update == atomic from a reader's view).
    await this.request<Raw>(`${repoPath}/git/refs/heads/${enc(opts.branch)}`, {
      method: "PATCH",
      body: { sha: commitSha, force: false },
    });

    return {
      commitSha,
      commitUrl: orNull(commit?.html_url as string | null),
      treeSha,
      baseTreeSha,
      branch: opts.branch,
      createdBranch,
      blobs,
      deleted: [...deletions],
      filesChanged: blobs.length + deletions.length,
    };
  }

  /** Resolve a branch/tag/sha to a commit sha. */
  async resolveRefSha(owner: string, repo: string, ref: string): Promise<string> {
    const repoPath = `/repos/${enc(owner)}/${enc(repo)}`;
    if (/^[0-9a-f]{40}$/i.test(ref)) return ref;
    for (const prefix of ["heads", "tags"]) {
      try {
        const raw = await this.request<Raw>(`${repoPath}/git/ref/${prefix}/${enc(ref)}`);
        const obj = (raw?.object ?? {}) as Raw;
        if (asString(obj.type) === "tag" && obj.sha) {
          const tag = await this.request<Raw>(`${repoPath}/git/tags/${enc(asString(obj.sha))}`);
          return asString(tag?.object?.sha) || asString(obj.sha);
        }
        return asString(obj.sha);
      } catch (err) {
        if (err instanceof GitHubNotFoundError) continue;
        throw err;
      }
    }
    throw new GitHubNotFoundError({
      status: 404,
      path: `${repoPath}/git/ref/heads/${ref}`,
      message: `Ref ${ref} not found in ${owner}/${repo}`,
    });
  }

  // -- search ---------------------------------------------------------------

  async searchCode(
    q: string,
    opts: { page?: number; perPage?: number; sort?: string; order?: "asc" | "desc"; maxItems?: number } = {},
  ): Promise<CodeSearchResult> {
    if (!q.trim()) throw new GitHubValidationError("searchCode requires a query");
    const query: Query = {
      q,
      per_page: opts.perPage ?? 30,
      page: opts.page,
      sort: opts.sort,
      order: opts.order,
    };
    const map = (raw: Raw): CodeSearchItem => ({
      path: asString(raw.path),
      repo: asString(raw.repository?.full_name),
      name: asString(raw.name),
      sha: asString(raw.sha),
      htmlUrl: asString(raw.html_url),
      score: numberOr(raw.score, 0),
      ...(Array.isArray(raw.text_matches)
        ? { fragments: raw.text_matches.map((m: Raw) => asString(m.fragment)).filter(Boolean) }
        : {}),
    });

    if (opts.page !== undefined) {
      const single = await this.requestPage<Raw>("/search/code", query, "items");
      return {
        items: single.items.map(map),
        totalCount: single.totalCount ?? single.items.length,
        incompleteResults: single.items.some((i) => i.incomplete_results === true),
        query: q,
        pages: single.pages,
        truncated: single.truncated,
        nextUrl: single.nextUrl,
      };
    }
    const paged = await this.paginateRaw("/search/code", opts.maxItems ?? 100, { query, wrapKey: "items" });
    const first = paged.items[0];
    return {
      items: paged.items.map(map),
      totalCount: paged.totalCount ?? paged.items.length,
      incompleteResults: first ? first.incomplete_results === true : false,
      query: q,
      pages: paged.pages,
      truncated: paged.truncated,
      nextUrl: paged.nextUrl,
    };
  }

  // -- commits / compare ----------------------------------------------------

  async listCommits(
    owner: string,
    repo: string,
    opts: {
      sha?: string;
      path?: string;
      author?: string;
      since?: string;
      until?: string;
      page?: number;
      perPage?: number;
      maxItems?: number;
    } = {},
  ): Promise<Paginated<CommitSummary>> {
    const path = `/repos/${enc(owner)}/${enc(repo)}/commits`;
    const query: Query = {
      sha: opts.sha,
      path: opts.path,
      author: opts.author,
      since: opts.since,
      until: opts.until,
      per_page: opts.perPage ?? 30,
      page: opts.page,
    };
    if (opts.page !== undefined) {
      const single = await this.requestPage<Raw>(path, query);
      return { ...single, items: single.items.map(mapCommitSummary) };
    }
    const paged = await this.paginateRaw(path, opts.maxItems ?? 100, { query });
    return { ...paged, items: paged.items.map(mapCommitSummary) };
  }

  async getCommit(owner: string, repo: string, ref: string): Promise<CommitDetail> {
    const raw = await this.request<Raw>(`/repos/${enc(owner)}/${enc(repo)}/commits/${enc(ref)}`);
    const summary = mapCommitSummary(raw ?? {});
    const files = Array.isArray(raw?.files) ? raw.files.map((f: Raw) => mapCommitFile(f, this.maxPatchChars)) : [];
    const stats = raw?.stats
      ? {
          additions: numberOr(raw.stats.additions, 0),
          deletions: numberOr(raw.stats.deletions, 0),
          total: numberOr(raw.stats.total, 0),
        }
      : null;
    return {
      ...summary,
      stats,
      files,
      filesReturned: files.length,
      truncated: files.some((f) => f.patchTruncated),
    };
  }

  async compare(owner: string, repo: string, base: string, head: string): Promise<CompareResult> {
    const raw = await this.request<Raw>(
      `/repos/${enc(owner)}/${enc(repo)}/compare/${enc(base)}...${enc(head)}`,
    );
    const commits = Array.isArray(raw?.commits) ? raw.commits.map(mapCommitSummary) : [];
    const files = Array.isArray(raw?.files) ? raw.files.map((f: Raw) => mapCommitFile(f, this.maxPatchChars)) : [];
    return {
      status: asString(raw?.status),
      aheadBy: numberOr(raw?.ahead_by, 0),
      behindBy: numberOr(raw?.behind_by, 0),
      totalCommits: numberOr(raw?.total_commits, commits.length),
      commits,
      files,
      commitsTruncated: numberOr(raw?.total_commits, commits.length) > commits.length,
      filesTruncated: files.some((f) => f.patchTruncated),
      permalinkUrl: orNull(raw?.permalink_url as string | null),
    };
  }

  // -- issues ---------------------------------------------------------------

  async createIssue(
    owner: string,
    repo: string,
    opts: { title: string; body?: string; labels?: string[]; assignees?: string[]; milestone?: number },
  ): Promise<IssueSummary> {
    if (!opts.title) throw new GitHubValidationError("createIssue requires a title");
    const body: Record<string, unknown> = { title: opts.title };
    if (opts.body !== undefined) body.body = opts.body;
    if (opts.labels?.length) body.labels = opts.labels;
    if (opts.assignees?.length) body.assignees = opts.assignees;
    if (opts.milestone !== undefined) body.milestone = opts.milestone;
    const raw = await this.request<Raw>(`/repos/${enc(owner)}/${enc(repo)}/issues`, { method: "POST", body });
    return mapIssue(raw ?? {}, 8000);
  }

  async listIssues(
    owner: string,
    repo: string,
    opts: {
      state?: "open" | "closed" | "all";
      labels?: string[];
      sort?: "created" | "updated" | "comments";
      direction?: "asc" | "desc";
      since?: string;
      creator?: string;
      assignee?: string;
      milestone?: string | number;
      page?: number;
      perPage?: number;
      maxItems?: number;
      /** Include issues that are actually pull requests. Default false. */
      includePullRequests?: boolean;
    } = {},
  ): Promise<Paginated<IssueSummary>> {
    const path = `/repos/${enc(owner)}/${enc(repo)}/issues`;
    const query: Query = {
      state: opts.state ?? "open",
      labels: opts.labels?.length ? opts.labels.join(",") : undefined,
      sort: opts.sort,
      direction: opts.direction,
      since: opts.since,
      creator: opts.creator,
      assignee: opts.assignee,
      milestone: opts.milestone,
      per_page: opts.perPage ?? 30,
      page: opts.page,
    };
    const paged =
      opts.page !== undefined
        ? await this.requestPage<Raw>(path, query)
        : await this.paginateRaw(path, opts.maxItems ?? 100, { query });
    let items = (paged.items ?? []).map((raw) => mapIssue(raw, 8000));
    if (!opts.includePullRequests) items = items.filter((i) => !i.pullRequest);
    return { items, pages: paged.pages, truncated: paged.truncated, nextUrl: paged.nextUrl };
  }

  async getIssue(owner: string, repo: string, issueNumber: number): Promise<IssueSummary> {
    const raw = await this.request<Raw>(`/repos/${enc(owner)}/${enc(repo)}/issues/${issueNumber}`);
    return mapIssue(raw ?? {}, 20000);
  }

  async commentOnIssue(owner: string, repo: string, issueNumber: number, body: string): Promise<IssueComment> {
    if (!body) throw new GitHubValidationError("commentOnIssue requires a body");
    const raw = await this.request<Raw>(`/repos/${enc(owner)}/${enc(repo)}/issues/${issueNumber}/comments`, {
      method: "POST",
      body: { body },
    });
    const trimmed = trimText(raw?.body as string | undefined, 20000);
    return {
      id: numberOr(raw?.id, 0),
      body: trimmed.text ?? body,
      bodyTruncated: trimmed.truncated,
      user: orNull(raw?.user?.login as string | null),
      htmlUrl: asString(raw?.html_url),
      createdAt: asString(raw?.created_at),
      updatedAt: asString(raw?.updated_at),
    };
  }

  // -- pull requests --------------------------------------------------------

  async createPullRequest(
    owner: string,
    repo: string,
    opts: { title: string; head: string; base: string; body?: string; draft?: boolean; maintainerCanModify?: boolean; issue?: number },
  ): Promise<PullRequestSummary> {
    if (!opts.title || !opts.head || !opts.base) {
      throw new GitHubValidationError("createPullRequest requires title, head and base");
    }
    const body: Record<string, unknown> = { title: opts.title, head: opts.head, base: opts.base };
    if (opts.body !== undefined) body.body = opts.body;
    if (opts.draft !== undefined) body.draft = opts.draft;
    if (opts.maintainerCanModify !== undefined) body.maintainer_can_modify = opts.maintainerCanModify;
    if (opts.issue !== undefined) body.issue = opts.issue;
    const raw = await this.request<Raw>(`/repos/${enc(owner)}/${enc(repo)}/pulls`, { method: "POST", body });
    return mapPullRequest(raw ?? {}, 20000);
  }

  async listPullRequests(
    owner: string,
    repo: string,
    opts: {
      state?: "open" | "closed" | "all";
      head?: string;
      base?: string;
      sort?: "created" | "updated" | "popularity" | "long-running";
      direction?: "asc" | "desc";
      page?: number;
      perPage?: number;
      maxItems?: number;
    } = {},
  ): Promise<Paginated<PullRequestSummary>> {
    const path = `/repos/${enc(owner)}/${enc(repo)}/pulls`;
    const query: Query = {
      state: opts.state ?? "open",
      head: opts.head,
      base: opts.base,
      sort: opts.sort,
      direction: opts.direction,
      per_page: opts.perPage ?? 30,
      page: opts.page,
    };
    const paged =
      opts.page !== undefined
        ? await this.requestPage<Raw>(path, query)
        : await this.paginateRaw(path, opts.maxItems ?? 100, { query });
    return {
      items: (paged.items ?? []).map((raw) => mapPullRequest(raw, 8000)),
      pages: paged.pages,
      truncated: paged.truncated,
      nextUrl: paged.nextUrl,
    };
  }

  async getPullRequest(owner: string, repo: string, pullNumber: number): Promise<PullRequestSummary> {
    const raw = await this.request<Raw>(`/repos/${enc(owner)}/${enc(repo)}/pulls/${pullNumber}`);
    return mapPullRequest(raw ?? {}, 20000);
  }

  async listPullRequestFiles(
    owner: string,
    repo: string,
    pullNumber: number,
    opts: { page?: number; perPage?: number; maxItems?: number } = {},
  ): Promise<Paginated<PullRequestFile>> {
    const path = `/repos/${enc(owner)}/${enc(repo)}/pulls/${pullNumber}/files`;
    const map = (raw: Raw): PullRequestFile => {
      const patch = trimText(raw.patch as string | undefined, this.maxPatchChars);
      return {
        filename: asString(raw.filename),
        status: asString(raw.status),
        additions: numberOr(raw.additions, 0),
        deletions: numberOr(raw.deletions, 0),
        changes: numberOr(raw.changes, 0),
        blobUrl: raw.blob_url ? asString(raw.blob_url) : undefined,
        previousFilename: raw.previous_filename ? asString(raw.previous_filename) : undefined,
        ...(patch.text !== null ? { patch: patch.text } : {}),
        patchTruncated: patch.truncated,
      };
    };
    const paged =
      opts.page !== undefined
        ? await this.requestPage<Raw>(path, { per_page: opts.perPage ?? 30, page: opts.page })
        : await this.paginateRaw(path, opts.maxItems ?? 300, { query: { per_page: opts.perPage ?? 100 } });
    return {
      items: (paged.items ?? []).map(map),
      pages: paged.pages,
      truncated: paged.truncated,
      nextUrl: paged.nextUrl,
    };
  }

  /** Unified diff text (Accept: application/vnd.github.diff), size-capped. */
  async getPullRequestDiff(
    owner: string,
    repo: string,
    pullNumber: number,
    opts: { maxBytes?: number } = {},
  ): Promise<PullRequestDiff> {
    const maxBytes = opts.maxBytes ?? 2 * 1024 * 1024;
    const { res } = await this.fetchResponse(`/repos/${enc(owner)}/${enc(repo)}/pulls/${pullNumber}`, {
      accept: "application/vnd.github.diff",
    });
    const buf = Buffer.from(await res.arrayBuffer());
    const slice = buf.subarray(0, maxBytes);
    return {
      number: pullNumber,
      // Never split a multi-byte character: decode the byte slice leniently.
      diff: slice.toString("utf8"),
      length: buf.length,
      bytesReturned: slice.length,
      maxBytes,
      truncated: buf.length > slice.length,
    };
  }

  async createPullRequestReview(
    owner: string,
    repo: string,
    pullNumber: number,
    review: { event: ReviewEvent; body?: string; comments?: ReviewCommentInput[]; commitId?: string },
  ): Promise<PullRequestReview> {
    const allowed: ReviewEvent[] = ["APPROVE", "REQUEST_CHANGES", "COMMENT"];
    if (!allowed.includes(review.event)) {
      throw new GitHubValidationError(`Review event must be one of ${allowed.join(", ")}`);
    }
    if (review.event === "REQUEST_CHANGES" && !review.body) {
      throw new GitHubValidationError("REQUEST_CHANGES reviews require a body");
    }
    const body: Record<string, unknown> = { event: review.event };
    if (review.body !== undefined) body.body = review.body;
    if (review.commitId) body.commit_id = review.commitId;
    if (review.comments?.length) {
      body.comments = review.comments.map((c) => {
        const out: Record<string, unknown> = { path: c.path, body: c.body };
        if (c.position !== undefined) out.position = c.position;
        if (c.line !== undefined) out.line = c.line;
        if (c.side !== undefined) out.side = c.side;
        if (c.startLine !== undefined) out.start_line = c.startLine;
        if (c.startSide !== undefined) out.start_side = c.startSide;
        return out;
      });
    }
    const raw = await this.request<Raw>(`/repos/${enc(owner)}/${enc(repo)}/pulls/${pullNumber}/reviews`, {
      method: "POST",
      body,
    });
    return {
      id: numberOr(raw?.id, 0),
      state: asString(raw?.state),
      body: orNull(raw?.body as string | null),
      user: orNull(raw?.user?.login as string | null),
      htmlUrl: orNull(raw?.html_url as string | null),
      submittedAt: orNull(raw?.submitted_at as string | null),
      commitId: orNull(raw?.commit_id as string | null),
    };
  }

  // -- GraphQL: discussions -------------------------------------------------

  async graphql<T = Raw>(query: string, variables: Record<string, unknown> = {}): Promise<T> {
    const res = await this.fetchImpl(this.graphqlUrl, {
      method: "POST",
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${this.token}`,
        "Content-Type": "application/json",
        "User-Agent": this.userAgent,
      },
      body: JSON.stringify({ query, variables }),
      ...(this.timeoutMs > 0 ? { signal: AbortSignal.timeout(this.timeoutMs) } : {}),
    });
    this.captureRateLimit(res.headers);
    const text = await res.text();
    let payload: Raw | null = null;
    try {
      payload = text ? (JSON.parse(text) as Raw) : null;
    } catch {
      payload = null;
    }
    if (!res.ok) {
      const msg = typeof payload?.message === "string" ? payload.message : `HTTP ${res.status}`;
      throw new GitHubError({
        status: res.status,
        method: "POST",
        path: "/graphql",
        message: this.scrub(`GitHub GraphQL request failed with ${res.status}: ${msg}`),
        apiMessage: this.scrub(msg),
      });
    }
    if (Array.isArray(payload?.errors) && payload.errors.length > 0) {
      const messages = (payload.errors as Raw[]).map((e) => this.scrub(asString(e.message) || "unknown GraphQL error"));
      throw new GitHubGraphQLError({
        status: res.status,
        method: "POST",
        path: "/graphql",
        errors: messages,
        message: `GitHub GraphQL error: ${messages.join("; ")}`,
      });
    }
    return (payload?.data ?? {}) as T;
  }

  async listDiscussions(
    owner: string,
    repo: string,
    opts: { first?: number; after?: string | null } = {},
  ): Promise<{ items: DiscussionSummary[]; totalCount: number; hasNextPage: boolean; endCursor: string | null }> {
    const query = `
      query($owner: String!, $repo: String!, $first: Int!, $after: String) {
        repository(owner: $owner, name: $repo) {
          discussions(first: $first, after: $after, orderBy: {field: UPDATED_AT, direction: DESC}) {
            totalCount
            pageInfo { hasNextPage endCursor }
            nodes {
              number title url createdAt updatedAt upvotes closed
              author { login }
              category { name }
              comments { totalCount }
              answer { id }
            }
          }
        }
      }`;
    const data = await this.graphql<{ repository: Raw | null }>(query, {
      owner,
      repo,
      first: opts.first ?? 25,
      after: opts.after ?? null,
    });
    if (!data.repository) {
      throw new GitHubNotFoundError({ status: 404, path: "/graphql", message: `Repository ${owner}/${repo} not found` });
    }
    const conn = (data.repository.discussions ?? {}) as Raw;
    const nodes = Array.isArray(conn.nodes) ? (conn.nodes as Raw[]) : [];
    const items: DiscussionSummary[] = nodes.map((n) => ({
      number: numberOr(n.number, 0),
      title: asString(n.title),
      url: asString(n.url),
      author: orNull(n.author?.login as string | null),
      category: orNull(n.category?.name as string | null),
      answerChosen: Boolean(n.answer),
      comments: numberOr(n.comments?.totalCount, 0),
      upvotes: numberOr(n.upvotes, 0),
      createdAt: asString(n.createdAt),
      updatedAt: asString(n.updatedAt),
    }));
    return {
      items,
      totalCount: numberOr(conn.totalCount, items.length),
      hasNextPage: conn.pageInfo?.hasNextPage === true,
      endCursor: orNull(conn.pageInfo?.endCursor as string | null),
    };
  }

  async getDiscussion(owner: string, repo: string, number: number): Promise<DiscussionSummary> {
    const query = `
      query($owner: String!, $repo: String!, $number: Int!) {
        repository(owner: $owner, name: $repo) {
          discussion(number: $number) {
            number title url createdAt updatedAt upvotes closed body
            author { login }
            category { name }
            comments { totalCount }
            answer { id }
          }
        }
      }`;
    const data = await this.graphql<{ repository: Raw | null }>(query, { owner, repo, number });
    const node = data.repository?.discussion as Raw | null | undefined;
    if (!node) {
      throw new GitHubNotFoundError({
        status: 404,
        path: "/graphql",
        message: `Discussion #${number} not found in ${owner}/${repo}`,
      });
    }
    const body = trimText(node.body as string | undefined, 20000);
    return {
      number: numberOr(node.number, number),
      title: asString(node.title),
      url: asString(node.url),
      author: orNull(node.author?.login as string | null),
      category: orNull(node.category?.name as string | null),
      answerChosen: Boolean(node.answer),
      comments: numberOr(node.comments?.totalCount, 0),
      upvotes: numberOr(node.upvotes, 0),
      createdAt: asString(node.createdAt),
      updatedAt: asString(node.updatedAt),
      body: body.text ?? undefined,
      bodyTruncated: body.truncated,
    };
  }

  // -- Actions --------------------------------------------------------------

  async listWorkflows(owner: string, repo: string): Promise<Paginated<WorkflowSummary>> {
    const raw = await this.request<Raw>(`/repos/${enc(owner)}/${enc(repo)}/actions/workflows`, {
      query: { per_page: 100 },
    });
    const items: WorkflowSummary[] = Array.isArray(raw?.workflows)
      ? raw.workflows.map((w: Raw) => ({
          id: numberOr(w.id, 0),
          name: asString(w.name),
          path: asString(w.path),
          state: asString(w.state),
          htmlUrl: asString(w.html_url),
        }))
      : [];
    return {
      items,
      pages: 1,
      truncated: numberOr(raw?.total_count, items.length) > items.length,
      nextUrl: null,
    };
  }

  async listWorkflowRuns(
    owner: string,
    repo: string,
    opts: {
      workflowId?: number | string;
      branch?: string;
      status?: string;
      event?: string;
      actor?: string;
      page?: number;
      perPage?: number;
      maxItems?: number;
    } = {},
  ): Promise<Paginated<WorkflowRunSummary>> {
    const base = opts.workflowId
      ? `/repos/${enc(owner)}/${enc(repo)}/actions/workflows/${enc(String(opts.workflowId))}/runs`
      : `/repos/${enc(owner)}/${enc(repo)}/actions/runs`;
    const query: Query = {
      branch: opts.branch,
      status: opts.status,
      event: opts.event,
      actor: opts.actor,
      per_page: opts.perPage ?? 30,
      page: opts.page,
    };
    const map = (raw: Raw): WorkflowRunSummary => mapWorkflowRun(raw);
    const paged =
      opts.page !== undefined
        ? await this.requestPage<Raw>(base, query, "workflow_runs")
        : await this.paginateRaw(base, opts.maxItems ?? 100, { query });
    return {
      items: (paged.items ?? []).map(map),
      pages: paged.pages,
      truncated: paged.truncated,
      nextUrl: paged.nextUrl,
    };
  }

  async getWorkflowRun(owner: string, repo: string, runId: number): Promise<WorkflowRunSummary> {
    const raw = await this.request<Raw>(`/repos/${enc(owner)}/${enc(repo)}/actions/runs/${runId}`);
    return mapWorkflowRun(raw ?? {});
  }

  async listRunJobs(
    owner: string,
    repo: string,
    runId: number,
    opts: { page?: number; perPage?: number; maxItems?: number } = {},
  ): Promise<Paginated<JobSummary>> {
    const path = `/repos/${enc(owner)}/${enc(repo)}/actions/runs/${runId}/jobs`;
    // The endpoint answers with `{ total_count, jobs: [...] }`, not a bare array.
    const paged =
      opts.page !== undefined
        ? await this.requestPage<Raw>(path, { per_page: opts.perPage ?? 30, page: opts.page }, "jobs")
        : await this.paginateRaw(path, opts.maxItems ?? 100, { query: { per_page: opts.perPage ?? 100 }, wrapKey: "jobs" });
    return {
      items: (paged.items ?? []).map((raw: Raw) => mapJob(raw)),
      pages: paged.pages,
      truncated: paged.truncated,
      nextUrl: paged.nextUrl,
    };
  }

  /**
   * Job logs: the API answers with a 302 to short-lived storage. We follow it
   * WITHOUT the Authorization header (the signed URL rejects credentials) and
   * return text paged by `offset`/`limit` with the full length.
   */
  async getJobLogs(
    owner: string,
    repo: string,
    jobId: number,
    opts: { offset?: number; limit?: number } = {},
  ): Promise<JobLogs> {
    const offset = Math.max(0, Math.trunc(opts.offset ?? 0));
    const limit = opts.limit !== undefined ? Math.max(1, Math.trunc(opts.limit)) : null;
    const { res, url } = await this.fetchResponse(
      `/repos/${enc(owner)}/${enc(repo)}/actions/jobs/${jobId}/logs`,
      { redirect: "manual", expectStatus: [301, 302, 303, 307, 308] },
    );

    let text: string;
    if (res.status >= 300 && res.status < 400) {
      const location = res.headers.get("location");
      if (!location) {
        throw new GitHubError({
          status: 502,
          path: `/repos/${owner}/${repo}/actions/jobs/${jobId}/logs`,
          message: "Log redirect had no Location header",
        });
      }
      const target = new URL(location, url).toString();
      const followed = await this.fetchImpl(target, {
        method: "GET",
        headers: { "User-Agent": this.userAgent },
        ...(this.timeoutMs > 0 ? { signal: AbortSignal.timeout(this.timeoutMs) } : {}),
      }).catch((err: unknown) => {
        throw new GitHubError({
          status: 0,
          path: `/repos/${owner}/${repo}/actions/jobs/${jobId}/logs`,
          message: this.scrub(`Log download failed: ${err instanceof Error ? err.message : "network error"}`),
        });
      });
      if (!followed.ok) {
        throw new GitHubError({
          status: followed.status,
          path: `/repos/${owner}/${repo}/actions/jobs/${jobId}/logs`,
          message: `Log download failed with ${followed.status} (the signed log URL may have expired; retry)`,
        });
      }
      text = await followed.text();
    } else {
      text = await res.text();
    }

    const end = limit === null ? text.length : Math.min(text.length, offset + limit);
    const start = Math.min(offset, text.length);
    const slice = text.slice(start, end);
    const hasMore = end < text.length;
    return {
      jobId,
      totalLength: text.length,
      offset: start,
      limit,
      text: slice,
      bytesReturned: Buffer.byteLength(slice, "utf8"),
      hasMore,
      nextOffset: hasMore ? end : null,
      truncated: hasMore || start > 0,
    };
  }

  async rerunWorkflow(owner: string, repo: string, runId: number): Promise<{ rerun: true; runId: number }> {
    await this.request<void>(`/repos/${enc(owner)}/${enc(repo)}/actions/runs/${runId}/rerun`, {
      method: "POST",
    });
    return { rerun: true, runId };
  }

  // -- releases -------------------------------------------------------------

  async listReleases(
    owner: string,
    repo: string,
    opts: { page?: number; perPage?: number; maxItems?: number } = {},
  ): Promise<Paginated<ReleaseSummary>> {
    const path = `/repos/${enc(owner)}/${enc(repo)}/releases`;
    const paged =
      opts.page !== undefined
        ? await this.requestPage<Raw>(path, { per_page: opts.perPage ?? 30, page: opts.page })
        : await this.paginateRaw(path, opts.maxItems ?? 100, { query: { per_page: opts.perPage ?? 100 } });
    return {
      items: (paged.items ?? []).map((raw) => mapRelease(raw, 8000)),
      pages: paged.pages,
      truncated: paged.truncated,
      nextUrl: paged.nextUrl,
    };
  }

  /** `release` is a numeric id or a tag name. */
  async getRelease(owner: string, repo: string, release: number | string): Promise<ReleaseSummary> {
    const segment = typeof release === "number" ? String(release) : `tags/${enc(release)}`;
    const raw = await this.request<Raw>(`/repos/${enc(owner)}/${enc(repo)}/releases/${segment}`);
    return mapRelease(raw ?? {}, 20000);
  }

  // -- security alerts (gated endpoints: report, do not throw) --------------

  private async alerts<T>(
    path: string,
    map: (raw: Raw) => T,
    opts: { page?: number; perPage?: number; maxItems?: number; query?: Query; docs: string },
  ): Promise<AlertsResult<T>> {
    const query: Query = { per_page: opts.perPage ?? 100, page: opts.page, ...opts.query };
    try {
      const paged =
        opts.page !== undefined
          ? await this.requestPage<Raw>(path, query)
          : await this.paginateRaw(path, opts.maxItems ?? 100, { query });
      return {
        available: true,
        items: (paged.items ?? []).map(map),
        pages: paged.pages,
        truncated: paged.truncated,
        nextUrl: paged.nextUrl,
      };
    } catch (err) {
      // A rate-limit 403 is not "feature disabled" — let it surface.
      if (
        err instanceof GitHubError &&
        !(err instanceof GitHubRateLimitError) &&
        (err.status === 403 || err.status === 404)
      ) {
        return {
          available: false,
          status: err.status,
          reason:
            err.status === 403
              ? `Not enabled or not permitted for this repository: ${err.apiMessage ?? "forbidden"} (GitHub Advanced Security / plan or token scope required).`
              : `Not enabled for this repository: ${err.apiMessage ?? "not found"} (the security feature is off, or the token cannot see alerts).`,
          docs: opts.docs,
        };
      }
      throw err;
    }
  }

  async listCodeScanningAlerts(
    owner: string,
    repo: string,
    opts: {
      state?: string;
      severity?: string;
      ref?: string;
      tool?: string;
      page?: number;
      perPage?: number;
      maxItems?: number;
    } = {},
  ): Promise<AlertsResult<CodeScanningAlert>> {
    const map = (raw: Raw): CodeScanningAlert => ({
      number: numberOr(raw.number, 0),
      state: asString(raw.state),
      ruleId: orNull(raw.rule?.id as string | null),
      ruleSeverity: orNull(raw.rule?.severity as string | null),
      tool: orNull(raw.tool?.name as string | null),
      path: orNull(raw.most_recent_instance?.location?.path as string | null),
      startLine: orNull(raw.most_recent_instance?.location?.start_line as number | null),
      htmlUrl: orNull(raw.html_url as string | null),
      createdAt: asString(raw.created_at),
      dismissedReason: orNull(raw.dismissed_reason as string | null),
      mostRecentInstanceRef: orNull(raw.most_recent_instance?.ref as string | null),
    });
    return this.alerts(`/repos/${enc(owner)}/${enc(repo)}/code-scanning/alerts`, map, {
      page: opts.page,
      perPage: opts.perPage,
      maxItems: opts.maxItems,
      query: {
        state: opts.state,
        severity: opts.severity,
        ref: opts.ref,
        tool_name: opts.tool,
      },
      docs: "https://docs.github.com/rest/code-scanning/code-scanning#list-code-scanning-alerts-for-a-repository",
    });
  }

  async listDependabotAlerts(
    owner: string,
    repo: string,
    opts: {
      state?: string;
      severity?: string;
      ecosystem?: string;
      package?: string;
      manifest?: string;
      page?: number;
      perPage?: number;
      maxItems?: number;
    } = {},
  ): Promise<AlertsResult<DependabotAlert>> {
    const map = (raw: Raw): DependabotAlert => ({
      number: numberOr(raw.number, 0),
      state: asString(raw.state),
      packageName: orNull(raw.dependency?.package?.name as string | null),
      ecosystem: orNull(raw.dependency?.package?.ecosystem as string | null),
      severity: orNull(raw.security_advisory?.severity as string | null),
      ghsaId: orNull(raw.security_advisory?.ghsa_id as string | null),
      summary: orNull(raw.security_advisory?.summary as string | null),
      manifestPath: orNull(raw.dependency?.manifest_path as string | null),
      htmlUrl: orNull(raw.html_url as string | null),
      createdAt: asString(raw.created_at),
      fixedAt: orNull(raw.fixed_at as string | null),
    });
    return this.alerts(`/repos/${enc(owner)}/${enc(repo)}/dependabot/alerts`, map, {
      page: opts.page,
      perPage: opts.perPage,
      maxItems: opts.maxItems,
      query: {
        state: opts.state,
        severity: opts.severity,
        ecosystem: opts.ecosystem,
        package: opts.package,
        manifest: opts.manifest,
      },
      docs: "https://docs.github.com/rest/dependabot/alerts#list-dependabot-alerts-for-a-repository",
    });
  }

  async listSecretScanningAlerts(
    owner: string,
    repo: string,
    opts: {
      state?: string;
      secretType?: string;
      resolution?: string;
      page?: number;
      perPage?: number;
      maxItems?: number;
    } = {},
  ): Promise<AlertsResult<SecretScanningAlert>> {
    const map = (raw: Raw): SecretScanningAlert => ({
      number: numberOr(raw.number, 0),
      state: asString(raw.state),
      secretType: orNull(raw.secret_type as string | null),
      secretTypeDisplay: orNull(raw.secret_type_display_name as string | null),
      resolution: orNull(raw.resolution as string | null),
      htmlUrl: orNull(raw.html_url as string | null),
      createdAt: asString(raw.created_at),
      resolvedAt: orNull(raw.resolved_at as string | null),
    });
    return this.alerts(`/repos/${enc(owner)}/${enc(repo)}/secret-scanning/alerts`, map, {
      page: opts.page,
      perPage: opts.perPage,
      maxItems: opts.maxItems,
      query: {
        state: opts.state,
        secret_type: opts.secretType,
        resolution: opts.resolution,
      },
      docs: "https://docs.github.com/rest/secret-scanning/secret-scanning#list-secret-scanning-alerts-for-a-repository",
    });
  }
}
