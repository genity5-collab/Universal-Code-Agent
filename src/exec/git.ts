/**
 * Git operations.
 *
 * Every call goes through `runCommand`/`runArgv` with a plain argv array -
 * never a shell string - so branch names, paths and messages cannot inject
 * commands. Credentials are supplied by a generated `GIT_ASKPASS` helper that
 * reads the token from the child's environment: the token never appears in
 * argv, in the on-disk log, or in the helper script itself.
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { resolveInside, SecurityError, redact } from "../util/paths.js";
import {
  runArgv,
  type CommandResult,
  type RunOptions,
} from "./runner.js";

export interface GitOptions {
  /** Working directory relative to root (defaults to root). */
  cwd?: string;
  /** Token used for https authentication; injected through env only. */
  token?: string;
  /** Caller already obtained approval for mutating git ops (default true). */
  approved?: boolean;
  timeoutMs?: number;
  maxOutputBytes?: number;
  /** Extra hosts allowed for clone (default: github.com only). */
  allowedHosts?: string[];
  env?: Record<string, string | undefined>;
}

export interface GitResult extends CommandResult {
  ok: boolean;
}

const DEFAULT_ALLOWED_HOSTS = ["github.com", "www.github.com"];
const GIT_USER = "x-access-token";

function gitEnv(opts: GitOptions, root: string): Record<string, string | undefined> {
  const env: Record<string, string | undefined> = { ...(opts.env ?? {}) };

  // Disable interactive prompts and any inherited credential helper, then add
  // our own askpass helper when a token was supplied.
  env.GIT_TERMINAL_PROMPT = "0";
  env.GIT_CONFIG_NOSYSTEM = "1";

  if (opts.token) {
    const dir = path.join(root, ".uca", "git");
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const script = path.join(dir, "askpass.sh");
    if (!fs.existsSync(script)) {
      // Note: the script references the env var; the token itself is never written here.
      const body = [
        "#!/bin/sh",
        "# Sandbox credential helper: reads the token from the environment.",
        'case "$1" in',
        `  *sername*) printf '%s\\n' '${GIT_USER}' ;;`,
        '  *assword*) printf \'%s\\n\' "$UCA_GIT_ASKPASS_TOKEN" ;;',
        '  *) printf \'\\n\' ;;',
        "esac",
        "",
      ].join("\n");
      fs.writeFileSync(script, body, { mode: 0o700 });
      fs.chmodSync(script, 0o700);
    }
    env.GIT_ASKPASS = script;
    env.SSH_ASKPASS = script;
    env.GIT_ASKPASS_REQUIRE = "force";
    env.UCA_GIT_ASKPASS_TOKEN = opts.token;
    // Also disable helpers so an inherited `credential.helper=store` cannot log the token.
    env.GIT_ASKPASS_PROMPT = "1";
    env.GIT_SSH_COMMAND = "ssh -o BatchMode=yes -o StrictHostKeyChecking=yes";
  }
  return env;
}

function toResult(result: CommandResult): GitResult {
  return { ...result, ok: result.exitCode === 0 && !result.timedOut };
}

const excludedRepos = new Set<string>();

/**
 * Keep the sandbox's own bookkeeping (`.uca/` holds logs, the askpass helper and
 * the home dir) out of `git status` by adding it to `.git/info/exclude`.
 * Local-only: never touches the tracked `.gitignore`.
 */
export function ensureLocalExclude(repoDir: string): boolean {
  if (excludedRepos.has(repoDir)) return true;
  const infoDir = path.join(repoDir, ".git", "info");
  const excludeFile = path.join(infoDir, "exclude");
  try {
    if (!fs.existsSync(path.join(repoDir, ".git"))) return false;
    fs.mkdirSync(infoDir, { recursive: true });
    const current = fs.existsSync(excludeFile) ? fs.readFileSync(excludeFile, "utf8") : "";
    if (!/^\.uca\/?$/m.test(current)) {
      const sep = current === "" || current.endsWith("\n") ? "" : "\n";
      fs.writeFileSync(excludeFile, `${current}${sep}.uca/\n`);
    }
    excludedRepos.add(repoDir);
    return true;
  } catch {
    return false;
  }
}

async function git(root: string, args: string[], opts: GitOptions = {}): Promise<GitResult> {
  ensureLocalExclude(opts.cwd ? resolveInside(root, opts.cwd) : root);
  const argv = ["git", "-c", "credential.helper=", "-c", "core.pager=cat", ...args];
  const runOpts: RunOptions = {
    cwd: opts.cwd,
    approved: opts.approved !== false,
    timeoutMs: opts.timeoutMs,
    maxOutputBytes: opts.maxOutputBytes,
    env: gitEnv(opts, root),
  };
  return toResult(await runArgv(root, argv, runOpts));
}

/** Refuse anything that is not a plain https URL on an allowlisted host. */
export function validateRemoteUrl(url: string, allowedHosts: string[] = DEFAULT_ALLOWED_HOSTS): URL {
  if (typeof url !== "string" || url.trim() === "") throw new SecurityError("Remote URL is required");
  if (/[\s;|&$`<>"']/.test(url)) throw new SecurityError("Remote URL contains forbidden characters");
  if (url.includes("@") && url.includes("://") && /:\/\/[^/]*@/.test(url)) {
    throw new SecurityError("Remote URL must not embed credentials");
  }
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new SecurityError(`Invalid remote URL: ${url}`);
  }
  if (parsed.protocol !== "https:") throw new SecurityError("Only https remote URLs are allowed");
  if (!allowedHosts.includes(parsed.hostname)) {
    throw new SecurityError(`Remote host not allowlisted: ${parsed.hostname}`);
  }
  if (parsed.username || parsed.password) throw new SecurityError("Remote URL must not embed credentials");
  return parsed;
}

function ensureBranchName(name: string): string {
  if (!/^[A-Za-z0-9._\-/]+$/.test(name) || name.startsWith("-") || name.includes("..")) {
    throw new SecurityError(`Invalid branch name: ${JSON.stringify(name)}`);
  }
  return name;
}

/* ------------------------------------------------------------------ */
/* Read-only operations                                               */
/* ------------------------------------------------------------------ */

export async function status(root: string, opts: GitOptions = {}): Promise<GitResult> {
  return git(root, ["status", "--porcelain=v1", "--branch"], opts);
}

export async function statusLong(root: string, opts: GitOptions = {}): Promise<GitResult> {
  return git(root, ["status"], opts);
}

export async function diff(root: string, opts: GitOptions & { staged?: boolean; paths?: string[] } = {}): Promise<GitResult> {
  const args = ["diff", "--no-color"];
  if (opts.staged) args.push("--cached");
  if (opts.paths?.length) args.push("--", ...opts.paths.map((p) => resolveInside(root, p)));
  return git(root, args, opts);
}

export async function log(
  root: string,
  opts: GitOptions & { maxCount?: number; format?: string } = {},
): Promise<GitResult> {
  const n = opts.maxCount ?? 20;
  const fmt = opts.format ?? "%h%x09%an%x09%ad%x09%s";
  return git(root, ["log", `--max-count=${n}`, `--pretty=format:${fmt}`, "--date=short", "--no-color"], opts);
}

export async function currentBranch(root: string, opts: GitOptions = {}): Promise<GitResult> {
  return git(root, ["rev-parse", "--abbrev-ref", "HEAD"], opts);
}

export async function remotes(root: string, opts: GitOptions = {}): Promise<GitResult> {
  return git(root, ["remote", "-v"], opts);
}

/* ------------------------------------------------------------------ */
/* Mutating operations                                                */
/* ------------------------------------------------------------------ */

export async function init(root: string, opts: GitOptions & { initialBranch?: string } = {}): Promise<GitResult> {
  const result = await git(root, ["init", `--initial-branch=${ensureBranchName(opts.initialBranch ?? "main")}`], opts);
  const repoDir = opts.cwd ? resolveInside(root, opts.cwd) : root;
  excludedRepos.delete(repoDir);
  ensureLocalExclude(repoDir);
  return result;
}

export async function branchCreate(
  root: string,
  name: string,
  opts: GitOptions & { startPoint?: string } = {},
): Promise<GitResult> {
  const args = ["branch", ensureBranchName(name)];
  if (opts.startPoint) args.push(ensureBranchName(opts.startPoint));
  return git(root, args, opts);
}

export async function checkout(
  root: string,
  target: string,
  opts: GitOptions & { create?: boolean; force?: boolean } = {},
): Promise<GitResult> {
  const ref = target === "--" ? "" : /^[A-Za-z0-9._\-/]+$/.test(target) && !target.startsWith("-") ? target : "";
  if (!ref) throw new SecurityError(`Invalid checkout target: ${JSON.stringify(target)}`);
  const args = ["checkout"];
  if (opts.create) args.push("-b");
  if (opts.force) args.push("-f");
  args.push(ref);
  return git(root, args, opts);
}

/** Stage files (paths relative to root); no paths means `git add -A`. */
export async function add(root: string, paths: string[] = [], opts: GitOptions = {}): Promise<GitResult> {
  if (paths.length === 0) return git(root, ["add", "-A"], opts);
  // Validate every pathspec against the workspace, then express it relative to
  // the repo cwd because that is what git resolves pathspecs against.
  const base = opts.cwd ? resolveInside(root, opts.cwd) : fs.realpathSync(root);
  const rel = paths.map((p) => {
    const abs = resolveInside(root, p);
    const r = path.relative(base, abs).split(path.sep).join("/");
    if (r === "" ) return ".";
    if (r === ".." || r.startsWith("../")) {
      throw new SecurityError(`Pathspec outside the repository: ${p}`);
    }
    return r;
  });
  return git(root, ["add", "--", ...rel], opts);
}

export async function commit(
  root: string,
  message: string,
  author?: { name?: string; email?: string },
  opts: GitOptions = {},
): Promise<GitResult> {
  if (!message || !message.trim()) throw new SecurityError("Commit message is required");
  if (message.length > 8000) throw new SecurityError("Commit message too long");
  const name = (author?.name ?? "UCA Agent").replace(/[\r\n]/g, " ");
  const email = (author?.email ?? "agent@uca.local").replace(/[\r\n]/g, " ");
  if (!/^[^<>]*$/.test(name) || !/^[^<>\s]+@[^<>\s]+$/.test(email)) {
    throw new SecurityError("Invalid author name or email");
  }
  ensureLocalExclude(opts.cwd ? resolveInside(root, opts.cwd) : root);
  const identity = {
    GIT_AUTHOR_NAME: name,
    GIT_AUTHOR_EMAIL: email,
    GIT_COMMITTER_NAME: name,
    GIT_COMMITTER_EMAIL: email,
  };
  // Message via stdin (-F -) so it never appears in argv or in a process list.
  const argv = [
    "git",
    "-c",
    "credential.helper=",
    "-c",
    "core.pager=cat",
    "commit",
    "--no-verify",
    "-F",
    "-",
  ];
  return runArgv(root, argv, {
    cwd: opts.cwd,
    approved: opts.approved !== false,
    timeoutMs: opts.timeoutMs,
    maxOutputBytes: opts.maxOutputBytes,
    env: { ...gitEnv(opts, root), ...identity },
    input: message.endsWith("\n") ? message : `${message}\n`,
  }).then(toResult);
}

export async function push(
  root: string,
  opts: GitOptions & { remote?: string; branch?: string; setUpstream?: boolean; force?: boolean } = {},
): Promise<GitResult> {
  const remote = opts.remote ?? "origin";
  if (!/^[A-Za-z0-9._\-]+$/.test(remote)) throw new SecurityError(`Invalid remote name: ${remote}`);
  const args = ["push", "--porcelain"];
  if (opts.force) args.push("--force-with-lease");
  if (opts.setUpstream) args.push("--set-upstream");
  args.push(remote);
  if (opts.branch) args.push(ensureBranchName(opts.branch));
  return git(root, args, opts);
}

export async function pull(root: string, opts: GitOptions & { remote?: string; branch?: string } = {}): Promise<GitResult> {
  const remote = opts.remote ?? "origin";
  if (!/^[A-Za-z0-9._\-]+$/.test(remote)) throw new SecurityError(`Invalid remote name: ${remote}`);
  const args = ["pull", "--no-rebase", remote];
  if (opts.branch) args.push(ensureBranchName(opts.branch));
  return git(root, args, opts);
}

/** Clone an https repo into `dir` (resolved inside root). */
export async function clone(
  root: string,
  url: string,
  dir: string,
  opts: GitOptions = {},
): Promise<GitResult & { dir: string; url: string }> {
  const hosts = opts.allowedHosts ?? DEFAULT_ALLOWED_HOSTS;
  const parsed = validateRemoteUrl(url, hosts);
  const target = resolveInside(root, dir);
  const rel = path.relative(root, target).split(path.sep).join("/");
  const result = await runArgv(
    root,
    ["git", "-c", "credential.helper=", "clone", "--depth", "1", "--", parsed.toString(), rel],
    {
      cwd: opts.cwd,
      approved: opts.approved !== false,
      timeoutMs: opts.timeoutMs ?? 300_000,
      maxOutputBytes: opts.maxOutputBytes,
      env: gitEnv(opts, root),
    },
  );
  if (result.exitCode === 0) ensureLocalExclude(target);
  return { ...toResult(result), dir: target, url: redact(parsed.toString()) };
}

export async function remoteSet(
  root: string,
  name: string,
  url: string,
  opts: GitOptions = {},
): Promise<GitResult> {
  if (!/^[A-Za-z0-9._\-]+$/.test(name)) throw new SecurityError(`Invalid remote name: ${name}`);
  const parsed = validateRemoteUrl(url, opts.allowedHosts ?? DEFAULT_ALLOWED_HOSTS);
  return git(root, ["remote", "set-url", name, parsed.toString()], opts).then(async (r) => {
    if (r.ok) return r;
    // No such remote yet: add it instead of failing.
    return git(root, ["remote", "add", name, parsed.toString()], opts);
  });
}

/** Deterministic helper id so callers can correlate logs. */
export function gitAuthFingerprint(token: string): string {
  return crypto.createHash("sha256").update(token).digest("hex").slice(0, 12);
}
