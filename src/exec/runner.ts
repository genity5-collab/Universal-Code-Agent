/**
 * Sandboxed command execution.
 *
 * Everything here spawns processes with an explicit argv array and
 * `shell: false`, inside `root`, with a scrubbed environment and a private
 * process group so a timeout can kill the whole tree.
 *
 * Output handling: a byte cap applies to what we return, but the full stream is
 * also appended to `<root>/.uca/logs/<id>.log` so a caller can page through the
 * rest. Every string handed back (and everything read out of a job log) passes
 * through `redact()`.
 */

import { spawn, type ChildProcess } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { resolveInside, redact, SecurityError } from "../util/paths.js";
import { evaluateArgv, tokenize, type Decision } from "./policy.js";

export const DEFAULT_TIMEOUT_MS = 120_000;
export const DEFAULT_MAX_OUTPUT_BYTES = 200_000;
export const DEFAULT_MAX_LOG_BYTES = 8 * 1024 * 1024;

/** Raised when a command's policy decision is `approval` and no approval was passed. */
export class ApprovalRequiredError extends Error {
  readonly command: string;
  readonly reason: string;
  constructor(command: string, reason: string) {
    super(`approval required: ${reason}`);
    this.name = "ApprovalRequiredError";
    this.command = command;
    this.reason = reason;
  }
}

export interface RunOptions {
  /** Working directory, relative to `root` (defaults to root itself). */
  cwd?: string;
  timeoutMs?: number;
  maxOutputBytes?: number;
  /** Extra environment variables; secrets inherited from the parent are stripped. */
  env?: Record<string, string | undefined>;
  /** Skip CLI policy tiering (caller already obtained approval in its own layer). */
  approved?: boolean;
  /** When false, policy is still evaluated for the decision but denial throws only. */
  enforcePolicy?: boolean;
  /** Data written to stdin, then the stream is closed. */
  input?: string;
  /** Upper bound on the persisted log file size. */
  maxLogBytes?: number;
}

export interface CommandResult {
  exitCode: number | null;
  signal: string | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  truncated: boolean;
  durationMs: number;
  /** Absolute path (inside the workspace) of the full, un-capped log. */
  logPath: string;
  logBytes: number;
  logTruncated: boolean;
  command: string;
  argv: string[];
  decision: Decision;
  reason: string;
}

/* ------------------------------------------------------------------ */
/* Environment                                                        */
/* ------------------------------------------------------------------ */

/** Names that may be forwarded from the parent process when explicitly requested. */
const ENV_ALLOW_EXACT = new Set([
  "PATH",
  "LANG",
  "LC_ALL",
  "LC_CTYPE",
  "TZ",
  "TERM",
  "SHELL",
  "TMPDIR",
  "NODE_EXTRA_CA_CERTS",
]);

/** Any inherited key matching one of these is dropped, always. */
const SECRET_KEY_PATTERNS: RegExp[] = [
  /^GITHUB_/i,
  /^GH_/i,
  /^GITLAB_/i,
  /^AWS_/i,
  /^AZURE_/i,
  /^GOOGLE_/i,
  /_TOKEN$/i,
  /_SECRET$/i,
  /_KEY$/i,
  /_PASSWORD$/i,
  /_PASSWD$/i,
  /^NPM_CONFIG_/i,
  /^YARN_/i,
  /_API_KEY$/i,
  /^SSH_AUTH_SOCK$/i,
  /^DOCKER_/i,
];

const DEFAULT_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/** True when an inherited variable name looks like it carries a credential. */
export function isSecretEnvKey(key: string): boolean {
  return SECRET_KEY_PATTERNS.some((re) => re.test(key));
}

export function scrubEnv(
  root: string,
  extra: Record<string, string | undefined> = {},
  parent: NodeJS.ProcessEnv = process.env,
): Record<string, string> {
  const env: Record<string, string> = {};
  const parentPath = parent.PATH ?? (parent.Path as string | undefined) ?? DEFAULT_PATH;

  env.PATH = parentPath;
  for (const key of ENV_ALLOW_EXACT) {
    const value = parent[key];
    if (key !== "PATH" && typeof value === "string" && value !== "" && !isSecretEnvKey(key)) env[key] = value;
  }
  if (!env.PATH) env.PATH = DEFAULT_PATH;

  const home = path.join(root, ".uca", "home");
  const tmp = path.join(root, ".uca", "tmp");
  fs.mkdirSync(home, { recursive: true });
  fs.mkdirSync(tmp, { recursive: true });

  env.HOME = home;
  env.TMPDIR = tmp;
  env.TMP = tmp;
  env.TEMP = tmp;
  env.XDG_CONFIG_HOME = path.join(home, ".config");
  env.XDG_CACHE_HOME = path.join(home, ".cache");
  env.XDG_DATA_HOME = path.join(home, ".local", "share");
  env.NO_COLOR = "1";
  env.TERM = "dumb";
  env.GIT_TERMINAL_PROMPT = "0";
  env.GIT_CONFIG_NOSYSTEM = "1";
  env.GIT_ASKPASS = "/bin/true";
  env.npm_config_yes = "false";
  env.npm_config_audit = "false";
  env.npm_config_fund = "false";
  env.npm_config_update_notifier = "false";
  env.UCA_SANDBOX = "1";

  for (const [key, value] of Object.entries(extra)) {
    if (value === undefined) {
      delete env[key];
      continue;
    }
    env[key] = value;
  }
  return env;
}

/* ------------------------------------------------------------------ */
/* Paths                                                              */
/* ------------------------------------------------------------------ */

function realRoot(root: string): string {
  if (!root || typeof root !== "string") throw new SecurityError("Workspace root is required");
  if (!fs.existsSync(root)) throw new SecurityError(`Workspace root does not exist: ${root}`);
  return fs.realpathSync(root);
}

function ucaDir(root: string, ...segments: string[]): string {
  const dir = path.join(root, ".uca", ...segments);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function resolveCwd(root: string, cwd?: string): string {
  const target = cwd === undefined || cwd === "" ? root : resolveInside(root, cwd);
  let stat: fs.Stats;
  try {
    stat = fs.statSync(target);
  } catch {
    throw new SecurityError(`Working directory does not exist: ${cwd ?? "."}`);
  }
  if (!stat.isDirectory()) throw new SecurityError(`Working directory is not a directory: ${cwd ?? "."}`);
  const real = fs.realpathSync(target);
  if (real !== root && !real.startsWith(`${root}${path.sep}`)) {
    throw new SecurityError("Working directory escapes workspace");
  }
  return real;
}

/* ------------------------------------------------------------------ */
/* Output plumbing                                                    */
/* ------------------------------------------------------------------ */

interface Sink {
  stream: "stdout" | "stderr";
  text: string[];
  bytes: number;
  dropped: number;
}

class OutputCollector {
  readonly sinks: Record<"stdout" | "stderr", Sink> = {
    stdout: { stream: "stdout", text: [], bytes: 0, dropped: 0 },
    stderr: { stream: "stderr", text: [], bytes: 0, dropped: 0 },
  };
  truncated = false;

  constructor(
    private readonly capPerStream: number,
    private readonly fd: number | undefined,
    private readonly maxLogBytes: number,
  ) {}

  logBytes = 0;
  logTruncated = false;

  push(stream: "stdout" | "stderr", chunk: Buffer): void {
    const sink = this.sinks[stream];
    const remaining = this.capPerStream - sink.bytes;
    if (remaining > 0) {
      const slice = chunk.length <= remaining ? chunk : chunk.subarray(0, remaining);
      sink.text.push(slice.toString("utf8"));
      sink.bytes += slice.length;
      if (slice.length < chunk.length) {
        sink.dropped += chunk.length - slice.length;
        this.truncated = true;
      }
    } else {
      sink.dropped += chunk.length;
      this.truncated = true;
    }
    this.writeLog(chunk);
  }

  private writeLog(chunk: Buffer): void {
    if (this.fd === undefined) return;
    if (this.logBytes >= this.maxLogBytes) {
      this.logTruncated = true;
      return;
    }
    const remaining = this.maxLogBytes - this.logBytes;
    const slice = chunk.length <= remaining ? chunk : chunk.subarray(0, remaining);
    if (slice.length < chunk.length) this.logTruncated = true;
    try {
      fs.writeSync(this.fd, slice);
      this.logBytes += slice.length;
    } catch {
      this.logTruncated = true;
    }
  }

  partial(stream: "stdout" | "stderr"): string {
    const sink = this.sinks[stream];
    let text = sink.text.join("");
    if (sink.dropped > 0) {
      text += `\n[output truncated: ${sink.dropped} more bytes in log]\n`;
    }
    return redact(text);
  }

  /** Join both streams for the "combined" accessor used by tests/tools. */
  combined(): string {
    return [this.partial("stdout"), this.partial("stderr")].filter(Boolean).join("\n");
  }
}

/* ------------------------------------------------------------------ */
/* Process groups                                                     */
/* ------------------------------------------------------------------ */

function killGroup(pid: number | undefined, signal: NodeJS.Signals = "SIGKILL"): void {
  if (!pid) return;
  try {
    if (process.platform === "win32") process.kill(pid, signal);
    else process.kill(-pid, signal);
  } catch {
    try {
      process.kill(pid, signal);
    } catch {
      /* already gone */
    }
  }
}

/* ------------------------------------------------------------------ */
/* runCommand                                                         */
/* ------------------------------------------------------------------ */

interface Prepared {
  argv: string[];
  cwd: string;
  env: Record<string, string>;
  logPath: string;
  decision: Decision;
  reason: string;
}

function prepare(rootIn: string, cmd: string, opts: RunOptions): Prepared {
  const root = realRoot(rootIn);
  if (typeof cmd !== "string" || cmd.trim() === "") throw new SecurityError("Command must be a non-empty string");

  const tok = tokenize(cmd);
  if (!tok.ok) throw new SecurityError(`Refusing to run command: ${tok.reason}`);
  const argv = tok.argv;

  const verdict = evaluateArgv(argv, { root });
  if (verdict.decision === "deny") {
    throw new SecurityError(`Command denied by policy: ${verdict.reason}`);
  }
  if (verdict.decision === "approval" && opts.approved !== true) {
    throw new ApprovalRequiredError(argv[0] ?? cmd, verdict.reason);
  }

  const cwd = resolveCwd(root, opts.cwd);
  const env = scrubEnv(root, opts.env);
  const id = `${Date.now().toString(36)}-${crypto.randomBytes(4).toString("hex")}`;
  const logPath = path.join(ucaDir(root, "logs"), `${id}.log`);

  return { argv, cwd, env, logPath, decision: verdict.decision, reason: verdict.reason };
}

export async function runCommand(root: string, cmd: string, opts: RunOptions = {}): Promise<CommandResult> {
  const prep = prepare(root, cmd, opts);
  const started = Date.now();
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const cap = opts.maxOutputBytes ?? DEFAULT_MAX_OUTPUT_BYTES;
  const maxLogBytes = opts.maxLogBytes ?? DEFAULT_MAX_LOG_BYTES;
  const fd = fs.openSync(prep.logPath, "a");
  const collector = new OutputCollector(cap, fd, maxLogBytes);

  let child: ChildProcess;
  try {
    child = spawn(prep.argv[0] as string, prep.argv.slice(1), {
      cwd: prep.cwd,
      env: prep.env,
      shell: false,
      detached: process.platform !== "win32",
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
    });
  } catch (err) {
    fs.closeSync(fd);
    const durationMs = Date.now() - started;
    return {
      exitCode: null,
      signal: null,
      stdout: "",
      stderr: redact(`failed to spawn ${prep.argv[0]}: ${(err as Error).message}`),
      timedOut: false,
      truncated: false,
      durationMs,
      logPath: prep.logPath,
      logBytes: 0,
      logTruncated: false,
      command: cmd,
      argv: prep.argv,
      decision: prep.decision,
      reason: prep.reason,
    };
  }

  let timedOut = false;
  let settled = false;
  let killer: NodeJS.Timeout | undefined;
  let escalation: NodeJS.Timeout | undefined;

  const outcome = await new Promise<{ code: number | null; signal: string | null }>((resolve) => {
    const finish = (code: number | null, signal: NodeJS.Signals | null): void => {
      if (settled) return;
      settled = true;
      if (killer) clearTimeout(killer);
      if (escalation) clearTimeout(escalation);
      resolve({ code, signal: signal ?? null });
    };

    child.stdout?.on("data", (c: Buffer) => collector.push("stdout", c));
    child.stderr?.on("data", (c: Buffer) => collector.push("stderr", c));

    child.on("error", (err: Error) => {
      collector.push("stderr", Buffer.from(`spawn error: ${err.message}\n`));
      finish(null, null);
    });
    child.on("close", (code, signal) => finish(code, signal));

    if (opts.input !== undefined) child.stdin?.end(opts.input);
    else child.stdin?.end();

    if (timeoutMs > 0) {
      killer = setTimeout(() => {
        timedOut = true;
        killGroup(child.pid, "SIGTERM");
        escalation = setTimeout(() => killGroup(child.pid, "SIGKILL"), 1500);
      }, timeoutMs);
    }
  });

  // Reap anything the child left running in its group (dev servers, watch modes).
  if (child.pid) killGroup(child.pid, "SIGKILL");
  try {
    fs.closeSync(fd);
  } catch {
    /* ignore */
  }

  return {
    exitCode: outcome.code,
    signal: outcome.signal,
    stdout: collector.partial("stdout"),
    stderr: collector.partial("stderr"),
    timedOut,
    truncated: collector.truncated,
    durationMs: Date.now() - started,
    logPath: prep.logPath,
    logBytes: collector.logBytes,
    logTruncated: collector.logTruncated,
    command: cmd,
    argv: prep.argv,
    decision: prep.decision,
    reason: prep.reason,
  };
}

/** Convenience: run a pre-parsed argv (used by git.ts and tasks.ts). */
export function argvToCommand(argv: string[]): string {
  return argv.map((a) => (/^[A-Za-z0-9_@%+=:,./-]+$/.test(a) ? a : `'${a.replace(/'/g, `'\\''`)}'`)).join(" ");
}

export function runArgv(root: string, argv: string[], opts: RunOptions = {}): Promise<CommandResult> {
  return runCommand(root, argvToCommand(argv), opts);
}

/* ------------------------------------------------------------------ */
/* Background jobs                                                    */
/* ------------------------------------------------------------------ */

export type JobStatus = "running" | "exited" | "stopped" | "failed";

export interface JobInfo {
  jobId: string;
  command: string;
  argv: string[];
  cwd: string;
  pid: number | undefined;
  startedAt: number;
  endedAt?: number;
  durationMs: number;
  status: JobStatus;
  exitCode: number | null;
  signal: string | null;
  timedOut: boolean;
  truncated: boolean;
  logPath: string;
  logBytes: number;
  reason: string;
}

interface JobRecord {
  info: JobInfo;
  child: ChildProcess;
  collector: OutputCollector;
  fd: number;
  stopRequested: boolean;
  done: Promise<void>;
}

const registries = new Map<string, Map<string, JobRecord>>();
const MAX_JOBS_PER_ROOT = 50;

function registryFor(root: string): Map<string, JobRecord> {
  let reg = registries.get(root);
  if (!reg) {
    reg = new Map();
    registries.set(root, reg);
  }
  return reg;
}

function findJob(jobId: string, root?: string): JobRecord {
  if (root) {
    const job = registryFor(realRoot(root)).get(jobId);
    if (job) return job;
    throw new Error(`Unknown job: ${jobId}`);
  }
  for (const reg of registries.values()) {
    const job = reg.get(jobId);
    if (job) return job;
  }
  throw new Error(`Unknown job: ${jobId}`);
}

function publicInfo(rec: JobRecord): JobInfo {
  const now = rec.info.endedAt ?? Date.now();
  return {
    ...rec.info,
    durationMs: Math.max(0, now - rec.info.startedAt),
    logBytes: rec.collector.logBytes,
    truncated: rec.collector.truncated,
  };
}

/**
 * Start a long-running command (dev server, watcher, test loop).
 * The process runs in its own group; call stopJob or shutdownAll to reap it.
 */
export function startJob(root: string, cmd: string, opts: RunOptions = {}): JobInfo {
  const real = realRoot(root);
  const prep = prepare(real, cmd, opts);
  const fd = fs.openSync(prep.logPath, "a");
  const collector = new OutputCollector(opts.maxOutputBytes ?? DEFAULT_MAX_OUTPUT_BYTES, fd, opts.maxLogBytes ?? DEFAULT_MAX_LOG_BYTES);
  const jobId = `job_${Date.now().toString(36)}_${crypto.randomBytes(3).toString("hex")}`;

  const child = spawn(prep.argv[0] as string, prep.argv.slice(1), {
    cwd: prep.cwd,
    env: prep.env,
    shell: false,
    detached: process.platform !== "win32",
    stdio: ["pipe", "pipe", "pipe"],
    windowsHide: true,
  });

  const rec: JobRecord = {
    info: {
      jobId,
      command: cmd,
      argv: prep.argv,
      cwd: prep.cwd,
      pid: child.pid,
      startedAt: Date.now(),
      durationMs: 0,
      status: "running",
      exitCode: null,
      signal: null,
      timedOut: false,
      truncated: false,
      logPath: prep.logPath,
      logBytes: 0,
      reason: prep.reason,
    },
    child,
    collector,
    fd,
    stopRequested: false,
    done: Promise.resolve(),
  };

  rec.done = new Promise<void>((resolve) => {
    let timer: NodeJS.Timeout | undefined;
    const finalize = (code: number | null, signal: NodeJS.Signals | null, failed = false): void => {
      if (rec.info.status !== "running") return;
      rec.info.endedAt = Date.now();
      rec.info.exitCode = code;
      rec.info.signal = signal;
      rec.info.status = rec.stopRequested ? "stopped" : failed ? "failed" : "exited";
      if (timer) clearTimeout(timer);
      try {
        fs.closeSync(rec.fd);
      } catch {
        /* ignore */
      }
      killGroup(child.pid, "SIGKILL");
      resolve();
    };

    child.stdout?.on("data", (c: Buffer) => collector.push("stdout", c));
    child.stderr?.on("data", (c: Buffer) => collector.push("stderr", c));
    child.on("error", (err: Error) => {
      collector.push("stderr", Buffer.from(`spawn error: ${err.message}\n`));
      finalize(null, null, true);
    });
    child.on("exit", (code, signal) => finalize(code, signal));
    child.on("close", (code, signal) => finalize(code, signal));

    if (opts.input !== undefined) child.stdin?.end(opts.input);
    else child.stdin?.end();

    const timeoutMs = opts.timeoutMs ?? 0;
    if (timeoutMs > 0) {
      timer = setTimeout(() => {
        rec.info.timedOut = true;
        killGroup(child.pid, "SIGTERM");
        setTimeout(() => killGroup(child.pid, "SIGKILL"), 1500).unref?.();
      }, timeoutMs);
    }
  });

  const reg = registryFor(real);
  reg.set(jobId, rec);
  while (reg.size > MAX_JOBS_PER_ROOT) {
    const oldest = reg.keys().next();
    if (oldest.done === true) break;
    reg.delete(oldest.value as string);
  }
  return publicInfo(rec);
}

export function jobStatus(rootOrJobId: string, maybeJobId?: string): JobInfo {
  const rec = maybeJobId === undefined ? findJob(rootOrJobId) : findJob(maybeJobId, rootOrJobId);
  return publicInfo(rec);
}

export interface JobOutputPage {
  jobId: string;
  data: string;
  offset: number;
  nextOffset: number;
  totalBytes: number;
  eof: boolean;
  status: JobStatus;
}

/**
 * Page through a job's log. `offset`/`limit` are byte offsets into the log file
 * so a caller can tail a dev server without re-reading everything.
 */
export function jobOutput(jobId: string, offset = 0, limit = 16_384, root?: string): JobOutputPage {
  const rec = findJob(jobId, root);
  const logPath = rec.info.logPath;
  let size = 0;
  try {
    size = fs.statSync(logPath).size;
  } catch {
    size = 0;
  }
  const start = Math.max(0, Math.min(Math.floor(offset), size));
  const length = Math.max(0, Math.min(Math.floor(limit), Math.max(0, size - start)));
  let data = "";
  if (length > 0) {
    const buf = Buffer.alloc(length);
    const fd = fs.openSync(logPath, "r");
    try {
      fs.readSync(fd, buf, 0, length, start);
    } finally {
      fs.closeSync(fd);
    }
    data = buf.toString("utf8");
  }
  const nextOffset = start + length;
  return {
    jobId,
    data: redact(data),
    offset: start,
    nextOffset,
    totalBytes: size,
    eof: nextOffset >= size && rec.info.status !== "running",
    status: rec.info.status,
  };
}

/** SIGTERM the group, escalate to SIGKILL after a grace period. */
export async function stopJob(jobId: string, root?: string, graceMs = 3000): Promise<JobInfo> {
  const rec = findJob(jobId, root);
  if (rec.info.status !== "running") return publicInfo(rec);
  rec.stopRequested = true;
  killGroup(rec.child.pid, "SIGTERM");
  const escalation = setTimeout(() => killGroup(rec.child.pid, "SIGKILL"), graceMs);
  await Promise.race([rec.done, new Promise<void>((r) => setTimeout(r, graceMs + 1000))]);
  clearTimeout(escalation);
  if (rec.info.status === "running") {
    killGroup(rec.child.pid, "SIGKILL");
    await Promise.race([rec.done, new Promise<void>((r) => setTimeout(r, 1000))]);
  }
  if (rec.info.status === "running") {
    rec.info.status = "stopped";
    rec.info.endedAt = Date.now();
  }
  return publicInfo(rec);
}

export function listJobs(root?: string): JobInfo[] {
  const records: JobRecord[] = [];
  if (root) {
    for (const rec of registryFor(realRoot(root)).values()) records.push(rec);
  } else {
    for (const reg of registries.values()) for (const rec of reg.values()) records.push(rec);
  }
  return records.map(publicInfo).sort((a, b) => b.startedAt - a.startedAt);
}

/** Kill every tracked job (all roots). Safe to call repeatedly. */
export function shutdownAll(): number {
  let killed = 0;
  for (const reg of registries.values()) {
    for (const rec of reg.values()) {
      if (rec.info.status === "running") {
        rec.stopRequested = true;
        killGroup(rec.child.pid, "SIGKILL");
        killed++;
      }
      try {
        fs.closeSync(rec.fd);
      } catch {
        /* ignore */
      }
      rec.info.status = rec.info.status === "running" ? "stopped" : rec.info.status;
      rec.info.endedAt = rec.info.endedAt ?? Date.now();
    }
  }
  return killed;
}

/** Async variant used by graceful shutdown paths. */
export async function shutdownAllAsync(graceMs = 2000): Promise<number> {
  const running = listJobs().filter((j) => j.status === "running");
  const stopped = await Promise.all(running.map((j) => stopJob(j.jobId, undefined, graceMs)));
  return stopped.length;
}

let shutdownInstalled = false;
/** Install process-level cleanup once (opt out with UCA_NO_SIGNAL_HANDLERS=1). */
export function installShutdownHandlers(): void {
  if (shutdownInstalled) return;
  if (process.env.UCA_NO_SIGNAL_HANDLERS === "1") return;
  shutdownInstalled = true;
  process.once("exit", () => {
    shutdownAll();
  });
  for (const sig of ["SIGINT", "SIGTERM"] as const) {
    process.once(sig, () => {
      shutdownAll();
      process.exit(sig === "SIGINT" ? 130 : 143);
    });
  }
}

installShutdownHandlers();
