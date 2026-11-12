/**
 * Higher-level task helpers built on the runner.
 *
 * Each helper auto-detects the project's toolchain from marker files, returns a
 * structured result, and reports which tool it used so the UI can explain
 * itself. None of them invent a tool that isn't installed: they run only when
 * the binary is on PATH and the manifest exists.
 */

import fs from "node:fs";
import path from "node:path";
import { runCommand, runArgv, type CommandResult, type RunOptions } from "./runner.js";

export interface TaskResult {
  task: TaskName;
  tool: string | null;
  detected: boolean;
  ok: boolean;
  skippedReason?: string;
  results: CommandResult[];
  durationMs: number;
  summary: string;
}

export type TaskName =
  | "installDependencies"
  | "runTests"
  | "formatCode"
  | "staticAnalysis"
  | "buildVerify";

export interface TaskOptions {
  /** Subdirectory to operate in (relative to root). */
  cwd?: string;
  timeoutMs?: number;
  maxOutputBytes?: number;
  /** Explicit tool override, e.g. "pnpm". */
  tool?: string;
  /** Extra args appended verbatim to the primary command. */
  extraArgs?: string[];
  approved?: boolean;
}

/* ------------------------------------------------------------------ */
/* Detection                                                          */
/* ------------------------------------------------------------------ */

function existsRel(root: string, rel: string): boolean {
  try {
    return fs.existsSync(path.join(root, rel));
  } catch {
    return false;
  }
}

function readJson(root: string, rel: string): Record<string, unknown> | undefined {
  try {
    return JSON.parse(fs.readFileSync(path.join(root, rel), "utf8")) as Record<string, unknown>;
  } catch {
    return undefined;
  }
}

/** Which files exist at the project root of `cwd` (inside root). */
export interface ProjectShape {
  cwd: string;
  node: boolean;
  npm: boolean;
  pnpm: boolean;
  yarn: boolean;
  python: boolean;
  go: boolean;
  cargo: boolean;
  make: boolean;
  packageManager: string | null;
  scripts: Record<string, string>;
  pythonTool: "pytest" | "ruff" | "mypy" | "python" | null;
  tsconfig: boolean;
}

export function detectProject(root: string, cwd = "."): ProjectShape {
  const base = cwd === "." || cwd === "" ? root : path.join(root, cwd);
  const pkg = readJson(base, "package.json");
  const scripts = (pkg?.scripts as Record<string, string> | undefined) ?? {};
  const lockfiles: [string, string][] = [
    ["pnpm-lock.yaml", "pnpm"],
    ["yarn.lock", "yarn"],
    ["package-lock.json", "npm"],
    ["npm-shrinkwrap.json", "npm"],
  ];
  let packageManager: string | null = pkg ? "npm" : null;
  for (const [file, tool] of lockfiles) {
    if (existsRel(base, file)) {
      packageManager = tool;
      break;
    }
  }
  if (pkg && typeof pkg.packageManager === "string") {
    const declared = pkg.packageManager.split("@")[0];
    if (declared) packageManager = declared;
  }

  const pyproject = existsRel(base, "pyproject.toml");
  const requirements = existsRel(base, "requirements.txt");
  const setupPy = existsRel(base, "setup.py");
  const python = pyproject || requirements || setupPy || existsRel(base, "pytest.ini") || existsRel(base, "tox.ini");

  let pythonTool: ProjectShape["pythonTool"] = null;
  if (python) {
    if (pyproject) pythonTool = "pytest";
    else if (existsRel(base, "pytest.ini") || existsRel(base, "tests")) pythonTool = "pytest";
    else pythonTool = "python";
  }

  return {
    cwd: base,
    node: Boolean(pkg),
    npm: Boolean(pkg),
    pnpm: existsRel(base, "pnpm-lock.yaml"),
    yarn: existsRel(base, "yarn.lock"),
    python: Boolean(python),
    go: existsRel(base, "go.mod"),
    cargo: existsRel(base, "Cargo.toml"),
    make: existsRel(base, "Makefile") || existsRel(base, "makefile"),
    packageManager,
    scripts,
    pythonTool,
    tsconfig: existsRel(base, "tsconfig.json"),
  };
}

/** Is an executable available on PATH? (checked from the sandbox env) */
let toolCache: Map<string, boolean> | undefined;

export function toolAvailable(root: string, tool: string, opts: TaskOptions = {}): boolean {
  if (!toolCache) toolCache = new Map();
  const cached = toolCache.get(tool);
  if (cached !== undefined) return cached;
  // `command -v` would need a shell; use `which` via argv, which is allowlisted.
  const res = require_sync_which(root, tool, opts);
  toolCache.set(tool, res);
  return res;
}

function require_sync_which(root: string, tool: string, opts: TaskOptions): boolean {
  // Synchronous check on PATH entries; avoids spawning during detection.
  const envPath = process.env.PATH ?? "";
  const dirs = envPath.split(path.delimiter).filter(Boolean);
  for (const dir of dirs) {
    const candidate = path.join(dir, tool);
    try {
      const st = fs.statSync(candidate);
      if (st.isFile()) {
        fs.accessSync(candidate, fs.constants.X_OK);
        return true;
      }
    } catch {
      /* keep looking */
    }
  }
  void root;
  void opts;
  return false;
}

/** Reset the PATH probe cache (used by tests). */
export function resetToolCache(): void {
  toolCache = undefined;
}

/* ------------------------------------------------------------------ */
/* Execution helper                                                   */
/* ------------------------------------------------------------------ */

async function exec(
  root: string,
  argv: string[],
  opts: TaskOptions,
  approved = true,
): Promise<CommandResult> {
  const runOpts: RunOptions = {
    cwd: opts.cwd,
    timeoutMs: opts.timeoutMs,
    maxOutputBytes: opts.maxOutputBytes,
    approved: opts.approved ?? approved,
  };
  return runArgv(root, argv, runOpts);
}

function summarize(task: TaskName, tool: string | null, results: CommandResult[], started: number): TaskResult {
  const durationMs = Date.now() - started;
  const ok = results.length > 0 && results.every((r) => r.exitCode === 0 && !r.timedOut);
  const failed = results.find((r) => r.exitCode !== 0 || r.timedOut);
  let summary: string;
  if (results.length === 0) summary = `${task}: nothing to do`;
  else if (ok) summary = `${task}: passed with ${tool ?? "detected tool"} (${durationMs}ms)`;
  else if (failed?.timedOut) summary = `${task}: timed out after ${failed.durationMs}ms`;
  else summary = `${task}: failed (exit ${failed?.exitCode ?? "?"}) with ${tool ?? "detected tool"}`;
  return { task, tool, detected: tool !== null, ok, results, durationMs, summary };
}

function skipped(task: TaskName, reason: string, started: number): TaskResult {
  return {
    task,
    tool: null,
    detected: false,
    ok: false,
    skippedReason: reason,
    results: [],
    durationMs: Date.now() - started,
    summary: `${task}: skipped (${reason})`,
  };
}

/* ------------------------------------------------------------------ */
/* installDependencies                                                */
/* ------------------------------------------------------------------ */

export async function installDependencies(root: string, opts: TaskOptions = {}): Promise<TaskResult> {
  const started = Date.now();
  const shape = detectProject(root, opts.cwd);
  const extra = opts.extraArgs ?? [];
  const tool = opts.tool ?? shape.packageManager ?? (shape.python ? "pip" : shape.go ? "go" : shape.cargo ? "cargo" : null);

  if (tool === "npm" || tool === "pnpm" || tool === "yarn" || tool === "bun") {
    if (!shape.node) return skipped("installDependencies", "no package.json", started);
    const argv =
      tool === "npm"
        ? ["npm", "ci", ...extra]
        : tool === "yarn"
          ? ["yarn", "--frozen-lockfile", ...extra]
          : tool === "pnpm"
            ? ["pnpm", "install", "--frozen-lockfile", ...extra]
            : ["bun", "install", ...extra];
    // A missing lockfile makes `ci --frozen-lockfile` fail; fall back to install.
    const lockfile = tool === "npm" ? "package-lock.json" : tool === "yarn" ? "yarn.lock" : "pnpm-lock.yaml";
    const hasLock = existsRel(shape.cwd, lockfile);
    const finalArgv = hasLock ? argv : argv.map((a) => (a.startsWith("--frozen") ? "--prefer-offline" : a.replace(/^ci$/, "install")));
    const result = await exec(root, finalArgv, opts);
    return summarize("installDependencies", tool, [result], started);
  }

  if (tool === "pip" || tool === "uv" || tool === "poetry") {
    if (!shape.python) return skipped("installDependencies", "no python project markers", started);
    const argv =
      tool === "uv"
        ? ["uv", "sync", ...extra]
        : tool === "poetry"
          ? ["poetry", "install", ...extra]
          : existsRel(shape.cwd, "requirements.txt")
            ? ["pip", "install", "-r", "requirements.txt", ...extra]
            : existsRel(shape.cwd, "pyproject.toml")
              ? ["pip", "install", "-e", ".", ...extra]
              : ["pip", "install", ".", ...extra];
    const result = await exec(root, argv, opts);
    return summarize("installDependencies", tool, [result], started);
  }

  if (tool === "go") {
    if (!shape.go) return skipped("installDependencies", "no go.mod", started);
    const result = await exec(root, ["go", "mod", "download", ...extra], opts);
    return summarize("installDependencies", "go", [result], started);
  }

  if (tool === "cargo") {
    if (!shape.cargo) return skipped("installDependencies", "no Cargo.toml", started);
    const result = await exec(root, ["cargo", "fetch", ...extra], opts);
    return summarize("installDependencies", "cargo", [result], started);
  }

  return skipped("installDependencies", "no supported project manifest found", started);
}

/* ------------------------------------------------------------------ */
/* runTests                                                           */
/* ------------------------------------------------------------------ */

function scriptArg(shape: ProjectShape, names: string[]): string | undefined {
  return names.find((n) => typeof shape.scripts[n] === "string");
}

export async function runTests(root: string, opts: TaskOptions = {}): Promise<TaskResult> {
  const started = Date.now();
  const shape = detectProject(root, opts.cwd);
  const extra = opts.extraArgs ?? [];
  const override = opts.tool;

  if (shape.node && (override === undefined || ["npm", "pnpm", "yarn", "bun"].includes(override))) {
    const pm = override ?? shape.packageManager ?? "npm";
    const script = scriptArg(shape, ["test", "tests", "test:unit"]);
    if (!script) return skipped("runTests", "package.json has no test script", started);
    const argv =
      pm === "npm"
        ? ["npm", "test", "--silent", ...extra]
        : pm === "yarn"
          ? ["yarn", "test", ...extra]
          : pm === "pnpm"
            ? ["pnpm", "test", ...extra]
            : ["bun", "test", ...extra];
    const result = await exec(root, argv, opts);
    return summarize("runTests", pm, [result], started);
  }

  if (shape.go && (override === undefined || override === "go")) {
    const result = await exec(root, ["go", "test", "./...", ...extra], opts);
    return summarize("runTests", "go", [result], started);
  }

  if (shape.cargo && (override === undefined || override === "cargo")) {
    const result = await exec(root, ["cargo", "test", ...extra], opts);
    return summarize("runTests", "cargo", [result], started);
  }

  if (shape.python && (override === undefined || ["pytest", "python", "python3"].includes(override))) {
    if (override === undefined && shape.pythonTool === "python" && !toolAvailable(root, "pytest")) {
      return skipped("runTests", "python project without pytest", started);
    }
    const bin = override !== undefined && override !== "pytest" ? override : "pytest";
    const argv = bin === "pytest" ? ["pytest", "-q", ...extra] : [bin, "-m", "pytest", "-q", ...extra];
    const result = await exec(root, argv, opts);
    return summarize("runTests", "pytest", [result], started);
  }

  if (shape.make && (override === undefined || override === "make")) {
    const result = await exec(root, ["make", "test", ...extra], opts);
    return summarize("runTests", "make", [result], started);
  }

  return skipped("runTests", "no test runner detected", started);
}

/* ------------------------------------------------------------------ */
/* formatCode                                                         */
/* ------------------------------------------------------------------ */

export async function formatCode(root: string, opts: TaskOptions = {}): Promise<TaskResult> {
  const started = Date.now();
  const shape = detectProject(root, opts.cwd);
  const extra = opts.extraArgs ?? [];
  const results: CommandResult[] = [];

  if (opts.tool === "prettier" || (shape.node && toolAvailable(root, "prettier"))) {
    results.push(await exec(root, ["prettier", "--write", ".", ...extra], opts));
    return summarize("formatCode", "prettier", results, started);
  }
  if (opts.tool === "ruff" || (shape.python && toolAvailable(root, "ruff"))) {
    results.push(await exec(root, ["ruff", "format", ".", ...extra], opts));
    return summarize("formatCode", "ruff", results, started);
  }
  if (opts.tool === "gofmt" || (shape.go && toolAvailable(root, "gofmt"))) {
    results.push(await exec(root, ["gofmt", "-w", ".", ...extra], opts));
    return summarize("formatCode", "gofmt", results, started);
  }
  if (shape.cargo) {
    results.push(await exec(root, ["cargo", "fmt", ...extra], opts));
    return summarize("formatCode", "cargo fmt", results, started);
  }
  return skipped("formatCode", "no formatter detected", started);
}

/* ------------------------------------------------------------------ */
/* staticAnalysis                                                     */
/* ------------------------------------------------------------------ */

export async function staticAnalysis(root: string, opts: TaskOptions = {}): Promise<TaskResult> {
  const started = Date.now();
  const shape = detectProject(root, opts.cwd);
  const extra = opts.extraArgs ?? [];
  const results: CommandResult[] = [];
  const tools: string[] = [];

  if (opts.tool === "tsc" || shape.tsconfig) {
    const localTsc = existsRel(shape.cwd, "node_modules/.bin/tsc");
    const argv = localTsc ? ["npx", "tsc", "--noEmit", ...extra] : ["tsc", "--noEmit", ...extra];
    results.push(await exec(root, argv, opts));
    tools.push("tsc");
  }
  if (opts.tool === "eslint" || (shape.node && toolAvailable(root, "eslint"))) {
    results.push(await exec(root, ["eslint", ".", ...extra], opts));
    tools.push("eslint");
  }
  if (opts.tool === "ruff" || (shape.python && toolAvailable(root, "ruff"))) {
    results.push(await exec(root, ["ruff", "check", ".", ...extra], opts));
    tools.push("ruff");
  }
  if (opts.tool === "mypy" || (shape.python && toolAvailable(root, "mypy"))) {
    results.push(await exec(root, ["mypy", ".", ...extra], opts));
    tools.push("mypy");
  }
  if (opts.tool === "go" || shape.go) {
    results.push(await exec(root, ["go", "vet", "./...", ...extra], opts));
    tools.push("go vet");
  }
  if (results.length === 0) return skipped("staticAnalysis", "no analyzer detected", started);
  return summarize("staticAnalysis", tools.join(", "), results, started);
}

/* ------------------------------------------------------------------ */
/* buildVerify                                                        */
/* ------------------------------------------------------------------ */

export async function buildVerify(root: string, opts: TaskOptions = {}): Promise<TaskResult> {
  const started = Date.now();
  const shape = detectProject(root, opts.cwd);
  const extra = opts.extraArgs ?? [];

  if (shape.node && scriptArg(shape, ["build", "compile", "dist"])) {
    const pm = opts.tool ?? shape.packageManager ?? "npm";
    const argv = pm === "npm" ? ["npm", "run", "build", ...extra] : [pm, "build", ...extra];
    const result = await exec(root, argv, opts);
    return summarize("buildVerify", pm, [result], started);
  }
  if (shape.go) {
    const result = await exec(root, ["go", "build", "./...", ...extra], opts);
    return summarize("buildVerify", "go", [result], started);
  }
  if (shape.cargo) {
    const result = await exec(root, ["cargo", "build", ...extra], opts);
    return summarize("buildVerify", "cargo", [result], started);
  }
  if (shape.python && existsRel(shape.cwd, "pyproject.toml")) {
    const result = await exec(root, ["python", "-m", "compileall", "-q", ".", ...extra], opts);
    return summarize("buildVerify", "python", [result], started);
  }
  if (shape.make) {
    const result = await exec(root, ["make", "build", ...extra], opts);
    return summarize("buildVerify", "make", [result], started);
  }
  return skipped("buildVerify", "no build step detected", started);
}

/** Run a free-form command through the same policy gate (used by tools). */
export function runFreeForm(root: string, cmd: string, opts: RunOptions = {}): Promise<CommandResult> {
  return runCommand(root, cmd, opts);
}
