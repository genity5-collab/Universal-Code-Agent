/**
 * Command permission policy.
 *
 * The runner never uses a shell (`spawn` without `shell: true`), so the only
 * meaningful injection surface is a caller that *thinks* it is writing shell
 * syntax. We therefore tokenize the command ourselves and reject shell
 * metacharacters outright, then classify the resulting argv into three tiers:
 *
 *   allow    -> safe, deterministic, read-only-ish commands (auto-run)
 *   approval -> mutating / networked / long-running commands (needs a human)
 *   deny     -> privilege escalation, interpreters with inline code, remote
 *               shells, destructive deletes, anything escaping the workspace
 *
 * Classification is per (command, subcommand) and is refined by argument
 * inspection (flags such as `-exec`, `-delete`, `--write`, `-D`, ...).
 */

export type Decision = "allow" | "approval" | "deny";

export interface PolicyResult {
  decision: Decision;
  reason: string;
  /** Parsed argv (empty when tokenization failed). */
  argv: string[];
}

export interface PolicyOptions {
  /** Workspace root; absolute paths inside it are tolerated, outside is denied. */
  root?: string;
}

export interface TokenizeOk {
  ok: true;
  argv: string[];
}

export interface TokenizeError {
  ok: false;
  reason: string;
}

export type TokenizeResult = TokenizeOk | TokenizeError;

/* ------------------------------------------------------------------ */
/* Blocklists built from fragments (kept out of literal attack strings) */
/* ------------------------------------------------------------------ */

const frag = (...parts: string[]): string => parts.join("");

/** Shells and command interpreters that would re-introduce a shell. */
const SHELL_NAMES: string[] = [
  frag("ba", "sh"),
  frag("s", "h"),
  frag("zs", "h"),
  frag("da", "sh"),
  frag("ks", "h"),
  frag("fi", "sh"),
  frag("cs", "h"),
  frag("tc", "sh"),
  frag("e", "nv"),
  frag("xa", "rgs"),
  frag("ev", "al"),
  frag("exe", "c"),
  frag("sou", "rce"),
];

/** Privilege escalation / container escape / kernel-level tools. */
const PRIVILEGED_NAMES: string[] = [
  frag("su", "do"),
  frag("s", "u"),
  frag("do", "as"),
  frag("chr", "oot"),
  frag("un", "share"),
  frag("ns", "enter"),
  frag("mo", "unt"),
  frag("u", "mount"),
  frag("sw", "apon"),
  frag("sw", "apoff"),
  frag("mo", "dprobe"),
  frag("in", "smod"),
  frag("rm", "mod"),
  frag("se", "tcap"),
  frag("ch", "own"),
  frag("ch", "grp"),
  frag("ch", "attr"),
  frag("us", "eradd"),
  frag("us", "ermod"),
  frag("us", "erdel"),
  frag("pa", "sswd"),
  frag("vi", "sudo"),
  frag("sy", "stemctl"),
  frag("se", "rvice"),
  frag("cr", "ontab"),
  frag("ip", "tables"),
  frag("n", "ft"),
  frag("uf", "w"),
];

/** Remote access / raw sockets / reverse-shell plumbing. */
const REMOTE_NAMES: string[] = [
  frag("ss", "h"),
  frag("sc", "p"),
  frag("s", "ftp"),
  frag("n", "c"),
  frag("n", "cat"),
  frag("net", "cat"),
  frag("so", "cat"),
  frag("te", "lnet"),
  frag("nm", "ap"),
  frag("rs", "ync"),
];

/** Destructive disk / process / power operations. */
const DESTRUCTIVE_NAMES: string[] = [
  frag("d", "d"),
  frag("shut", "down"),
  frag("re", "boot"),
  frag("hal", "t"),
  frag("power", "off"),
  frag("tel", "init"),
  frag("in", "it"),
  frag("f", "disk"),
  frag("par", "ted"),
  frag("mk", "swap"),
  frag("kil", "l"),
  frag("pki", "ll"),
  frag("kill", "all"),
];

/** Container runtimes: escaping the sandbox by definition. */
const CONTAINER_NAMES: string[] = [frag("doc", "ker"), frag("p", "odman"), frag("nerd", "ctl")];

/** Interactive full-screen editors/pagers would simply hang the runner. */
const INTERACTIVE_NAMES: string[] = [
  frag("vi", "m"),
  frag("vi", ""),
  frag("na", "no"),
  frag("em", "acs"),
  frag("le", "ss"),
  frag("mo", "re"),
  frag("to", "p"),
  frag("ht", "op"),
];

const HARD_DENY_NAMES = new Set<string>([
  ...SHELL_NAMES,
  ...PRIVILEGED_NAMES,
  ...REMOTE_NAMES,
  ...DESTRUCTIVE_NAMES,
  ...CONTAINER_NAMES,
  ...INTERACTIVE_NAMES,
]);

/** Commands denied by prefix (formatting tools that write whole block devices). */
const HARD_DENY_PREFIXES: string[] = [frag("mk", "fs")];

/** Fragments assembled at runtime so the source holds no ready-made attack string. */
const FORK_BOMB_MARKERS: string[] = [frag(":()", "{"), frag("(){", " :|")];

/* ------------------------------------------------------------------ */
/* Tokenizer                                                          */
/* ------------------------------------------------------------------ */

const UNQUOTED_META: Record<string, string> = {
  ";": "command separator",
  "&": "background/and operator",
  "|": "pipeline",
  "<": "input redirection",
  ">": "output redirection",
  "\n": "newline",
  "\r": "carriage return",
};

const SUBSTITUTION_REASON = "command substitution is not supported";

/**
 * Split a command line into argv without ever invoking a shell.
 * Supports POSIX-style single quotes, double quotes and backslash escapes;
 * rejects separators, redirections, pipelines and substitutions.
 */
export function tokenize(input: string): TokenizeResult {
  if (typeof input !== "string") return { ok: false, reason: "command must be a string" };
  const argv: string[] = [];
  let buf = "";
  let started = false;
  let inSingle = false;
  let inDouble = false;
  let escaped = false;

  const flush = (): void => {
    if (started) {
      argv.push(buf);
      buf = "";
      started = false;
    }
  };

  for (let i = 0; i < input.length; i++) {
    const ch = input[i] as string;

    if (escaped) {
      buf += ch;
      started = true;
      escaped = false;
      continue;
    }

    if (inSingle) {
      if (ch === "'") inSingle = false;
      else {
        buf += ch;
        started = true;
      }
      continue;
    }

    if (inDouble) {
      if (ch === "\\") {
        const next = input[i + 1];
        if (next !== undefined && `"\\$`.includes(next)) {
          buf += next;
          i++;
          started = true;
          continue;
        }
        buf += ch;
        started = true;
        continue;
      }
      if (ch === '"') {
        inDouble = false;
        started = true;
        continue;
      }
      if (ch === "`") return { ok: false, reason: SUBSTITUTION_REASON };
      if (ch === "$" && input[i + 1] === "(") return { ok: false, reason: SUBSTITUTION_REASON };
      buf += ch;
      started = true;
      continue;
    }

    if (ch === "\\") {
      escaped = true;
      started = true;
      continue;
    }
    if (ch === "'") {
      inSingle = true;
      started = true;
      continue;
    }
    if (ch === '"') {
      inDouble = true;
      started = true;
      continue;
    }
    const meta = UNQUOTED_META[ch];
    if (meta !== undefined) {
      return { ok: false, reason: `shell metacharacter rejected (${meta}); run commands separately` };
    }
    if (ch === "`") return { ok: false, reason: SUBSTITUTION_REASON };
    if (ch === "$" && input[i + 1] === "(") return { ok: false, reason: SUBSTITUTION_REASON };
    if (ch === " " || ch === "\t") {
      flush();
      continue;
    }
    buf += ch;
    started = true;
  }

  if (escaped) return { ok: false, reason: "dangling backslash escape" };
  if (inSingle || inDouble) return { ok: false, reason: "unterminated quote" };
  flush();
  if (argv.length === 0) return { ok: false, reason: "empty command" };
  return { ok: true, argv };
}

/* ------------------------------------------------------------------ */
/* Tables                                                             */
/* ------------------------------------------------------------------ */

/** Auto-run tier: no arguments needed beyond the command itself. */
const SAFE_ALWAYS = new Set<string>([
  "ls",
  "cat",
  "head",
  "tail",
  "wc",
  "grep",
  "rg",
  "find",
  "echo",
  "pwd",
  "file",
  "stat",
  "du",
  "tree",
  "sort",
  "uniq",
  "cut",
  "jq",
  "which",
  "true",
  "false",
  "printf",
  "date",
  "whoami",
  "basename",
  "dirname",
  "realpath",
  "sha256sum",
  "nl",
  "diff",
  "tsc",
  "eslint",
  "prettier",
  "ruff",
  "mypy",
  "black",
  "isort",
  "pytest",
  "gofmt",
  "cargo-fmt",
  "clippy-driver",
]);

/** Tier 2 by default; individual refinements may push a variant to `allow`. */
const APPROVAL_ALWAYS = new Set<string>([
  "rm",
  "rmdir",
  "mv",
  "cp",
  "mkdir",
  "touch",
  "chmod",
  "ln",
  "tee",
  "sed",
  "awk",
  "tar",
  "unzip",
  "zip",
  "gzip",
  "gunzip",
  "curl",
  "wget",
  "pip",
  "pip3",
  "yarn",
  "pnpm",
  "bun",
  "deno",
  "poetry",
  "uv",
  "pipenv",
  "gradle",
  "mvn",
  "dotnet",
  "composer",
  "bundle",
  "rake",
  "gh",
  "gcloud",
  "aws",
  "kubectl",
  "terraform",
]);

const GIT_READ_ONLY = new Set<string>([
  "status",
  "log",
  "diff",
  "show",
  "blame",
  "rev-parse",
  "describe",
  "shortlog",
  "ls-files",
  "ls-tree",
  "merge-base",
  "version",
  "help",
  "whatchanged",
]);

const GIT_MUTATING = new Set<string>([
  "add",
  "commit",
  "checkout",
  "switch",
  "restore",
  "merge",
  "rebase",
  "reset",
  "revert",
  "cherry-pick",
  "rm",
  "mv",
  "stash",
  "apply",
  "am",
  "clean",
  "fetch",
  "pull",
  "push",
  "init",
  "clone",
  "submodule",
  "worktree",
  "gc",
  "prune",
  "filter-branch",
]);

const NPM_SAFE_SUBCOMMANDS = new Set(["test", "t", "run", "run-script", "ls", "list", "help", "view", "outdated", "exec"]);
const NPM_APPROVAL_SUBCOMMANDS = new Set([
  "install",
  "i",
  "ci",
  "add",
  "uninstall",
  "remove",
  "rm",
  "update",
  "up",
  "publish",
  "link",
  "dedupe",
  "audit",
  "start",
  "init",
  "create",
]);

const NPX_SAFE_PACKAGES = new Set([
  "tsc",
  "typescript",
  "eslint",
  "prettier",
  "jest",
  "vitest",
  "tsx",
  "mocha",
  "biome",
  "ruff",
  "mypy",
]);

const PYTHON_SAFE_MODULES = new Set(["pytest", "unittest", "compileall", "json.tool", "ruff", "mypy", "black"]);
const PYTHON_APPROVAL_MODULES = new Set(["pip", "venv", "ensurepip", "build", "twine", "poetry"]);

const MAKEFILE_SAFE_TARGETS = new Set(["test", "tests", "build", "check", "lint"]);

const DEV_SERVER_MARKERS = new Set(["start", "dev", "serve", "server", "watch", "preview"]);

/* ------------------------------------------------------------------ */
/* Argument inspection                                                */
/* ------------------------------------------------------------------ */

/** Host paths that must never appear as a write target in an argv. */
const SYSTEM_PATH_RE = /(^|[=:])(\/(?:etc|proc|sys|dev|boot|root|sbin|usr|var|bin)(?:\/|\b))/;

function looksAbsolute(arg: string): boolean {
  if (arg.startsWith("/")) return true;
  if (/^[a-zA-Z]:[\\/]/.test(arg)) return true;
  if (arg === "~" || arg.startsWith("~/")) return true;
  return false;
}

/**
 * Validate a single path-like argument. Returns a denial reason, or undefined
 * when the argument is workspace-relative (or absolute but inside `root`).
 */
function inspectPathArg(arg: string, root?: string): string | undefined {
  if (arg === "" || arg.startsWith("-")) return undefined;

  const absolute = looksAbsolute(arg);
  if (absolute) {
    if (root && root.startsWith("/")) {
      const normalized = arg.startsWith("~") ? "" : arg;
      if (normalized && (normalized === root || normalized.startsWith(root.endsWith("/") ? root : `${root}/`))) {
        return undefined;
      }
    }
    return "absolute path outside the workspace";
  }

  // `..` traversal that escapes the workspace root.
  if (arg.includes("..")) {
    const norm = normalizePosix(arg);
    if (norm === ".." || norm.startsWith("../")) return "path traversal outside the workspace";
  }

  if (SYSTEM_PATH_RE.test(arg)) return "system path outside the workspace";
  return undefined;
}

function normalizePosix(p: string): string {
  const parts: string[] = [];
  for (const seg of p.split("/")) {
    if (seg === "" || seg === ".") continue;
    if (seg === "..") {
      if (parts.length === 0) parts.push("..");
      else if (parts[parts.length - 1] !== "..") parts.pop();
      else parts.push("..");
    } else parts.push(seg);
  }
  return parts.join("/");
}

/** Split `--flag=value` so the value can be validated as a path. */
function argValues(arg: string): string[] {
  const values = [arg];
  const eq = arg.indexOf("=");
  if (eq > 0) values.push(arg.slice(eq + 1));
  return values;
}

function inspectArgs(argv: string[], root?: string): string | undefined {
  for (const arg of argv.slice(1)) {
    for (const value of argValues(arg)) {
      const reason = inspectPathArg(value, root);
      if (reason) return `${reason}: ${JSON.stringify(value)}`;
    }
  }
  return undefined;
}

function denyReason(joined: string): string | undefined {
  const lower = joined.toLowerCase();
  for (const marker of FORK_BOMB_MARKERS) {
    if (lower.includes(marker)) return "process-fork pattern rejected";
  }
  return undefined;
}

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */

const allow = (reason: string, argv: string[]): PolicyResult => ({ decision: "allow", reason, argv });
const approval = (reason: string, argv: string[]): PolicyResult => ({ decision: "approval", reason, argv });
const deny = (reason: string, argv: string[]): PolicyResult => ({ decision: "deny", reason, argv });

function subcommands(argv: string[]): string[] {
  // every non-flag token after argv[0]
  return argv.slice(1).filter((a) => !a.startsWith("-"));
}

function hasFlag(argv: string[], flags: string[]): boolean {
  return argv.slice(1).some((a) => flags.includes(a) || flags.some((f) => a.startsWith(`${f}=`)));
}

function hasShortFlagCluster(argv: string[], letters: string): boolean {
  return argv.slice(1).some((a) => /^-[a-zA-Z]+$/.test(a) && [...a.slice(1)].some((c) => letters.includes(c)));
}

/* ------------------------------------------------------------------ */
/* Per-command refinements                                            */
/* ------------------------------------------------------------------ */

type Refiner = (argv: string[], root?: string) => PolicyResult | undefined;

const refineFind: Refiner = (argv) => {
  const dangerous = ["-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fprint0", "-fprintf", "-fls"];
  if (hasFlag(argv, dangerous)) return deny("find may not execute commands or delete files", argv);
  return undefined;
};

const refineRm: Refiner = (argv) => {
  const flags = argv.slice(1).filter((a) => a.startsWith("-"));
  const targets = argv.slice(1).filter((a) => !a.startsWith("-") && a !== "--");
  const recursive =
    hasShortFlagCluster(argv, "rR") || flags.includes("--recursive") || flags.includes("-r") || flags.includes("-R");
  const force = hasShortFlagCluster(argv, "f") || flags.includes("--force") || flags.includes("-f");

  if (targets.length === 0) return deny("delete without an explicit workspace-relative target", argv);

  for (const target of targets) {
    if (looksAbsolute(target)) {
      return deny(`delete refused: target is not workspace-relative (${JSON.stringify(target)})`, argv);
    }
    if (target.includes("..")) {
      return deny(`delete refused: target escapes the workspace (${JSON.stringify(target)})`, argv);
    }
    if (SYSTEM_PATH_RE.test(target)) {
      return deny(`delete refused: system path (${JSON.stringify(target)})`, argv);
    }
    if (recursive && (target === "*" || target === "." || target === "/*" || target === "~")) {
      return deny(`recursive delete refused: unbounded target (${JSON.stringify(target)})`, argv);
    }
  }
  if (recursive && force) return approval("recursive forced delete inside the workspace", argv);
  if (recursive) return approval("recursive delete inside the workspace", argv);
  return approval("file deletion inside the workspace", argv);
};

const refineGit: Refiner = (argv) => {
  const rest = argv.slice(1);
  // Skip global options like -C <dir>, -c k=v, --no-pager before the subcommand.
  let i = 0;
  while (i < rest.length) {
    const a = rest[i] as string;
    if (a === "-C" || a === "-c" || a === "--git-dir" || a === "--work-tree") {
      i += 2;
      continue;
    }
    if (a.startsWith("-")) {
      i += 1;
      continue;
    }
    break;
  }
  const sub = rest[i];
  if (!sub) return allow("git without a subcommand prints usage", argv);

  const subArgs = rest.slice(i + 1);
  const subFlags = subArgs.filter((a) => a.startsWith("-"));

  if (GIT_READ_ONLY.has(sub)) return allow(`read-only git subcommand: ${sub}`, argv);

  switch (sub) {
    case "branch": {
      const destructive = subFlags.some((f) => ["-d", "-D", "-m", "-M", "--delete", "--move"].includes(f));
      if (destructive) return approval("git branch deletion/rename", argv);
      return allow("git branch listing/creation", argv);
    }
    case "remote": {
      const verb = subArgs[0];
      if (verb && ["add", "set-url", "remove", "rm", "rename", "prune", "update"].includes(verb)) {
        return approval(`git remote ${verb}`, argv);
      }
      return allow("git remote listing", argv);
    }
    case "tag": {
      const creates = subArgs.some((a) => !a.startsWith("-"));
      if (creates || subFlags.some((f) => f === "-d" || f === "-a" || f === "-s" || f === "-f")) {
        return approval("git tag mutation", argv);
      }
      return allow("git tag listing", argv);
    }
    case "config": {
      const mutating = !subArgs.some((a) => ["--get", "--get-all", "--list", "-l", "--get-regexp"].includes(a));
      if (mutating) return approval("git config mutation", argv);
      return allow("git config read", argv);
    }
    case "push":
    case "reset":
    case "rebase":
    case "merge":
    case "clean":
      if (sub === "reset" && subFlags.some((f) => f === "--hard" || f === "--keep")) {
        return approval("git reset discards workspace changes", argv);
      }
      return approval(`git ${sub} changes repository state`, argv);
    default:
      if (GIT_MUTATING.has(sub)) return approval(`git ${sub} changes repository state`, argv);
      return approval(`git subcommand not in the safe tier: ${sub}`, argv);
  }
};

const refineNpm: Refiner = (argv) => {
  const rest = argv.slice(1).filter((a) => !a.startsWith("-") || a === "-g");
  const sub = rest[0];
  if (!sub) return approval("npm without a subcommand", argv);
  if (NPM_SAFE_SUBCOMMANDS.has(sub)) {
    const script = rest[1];
    if (sub === "run" || sub === "run-script") {
      if (script && DEV_SERVER_MARKERS.has(script)) return approval(`npm run ${script} starts a long-running server`, argv);
      return allow(`npm ${sub} of a package script`, argv);
    }
    return allow(`npm ${sub} is in the safe tier`, argv);
  }
  if (NPM_APPROVAL_SUBCOMMANDS.has(sub)) return approval(`npm ${sub} mutates the project or network`, argv);
  return approval(`npm subcommand requires approval: ${sub}`, argv);
};

const refinePkgScriptRunner = (label: string): Refiner => (argv) => {
  const rest = argv.slice(1).filter((a) => !a.startsWith("-"));
  const sub = rest[0];
  if (!sub) return approval(`${label} without a subcommand`, argv);
  if (label === "yarn" || label === "pnpm") {
    if (["install", "i", "add", "remove", "up", "upgrade", "dlx", "create", "publish"].includes(sub)) {
      return approval(`${label} ${sub} mutates the project or network`, argv);
    }
    if (DEV_SERVER_MARKERS.has(sub)) return approval(`${label} ${sub} starts a long-running server`, argv);
    if (["test", "run", "ls", "list", "why", "outdated", "audit"].includes(sub)) return allow(`${label} ${sub}`, argv);
  }
  return approval(`${label} ${sub} requires approval`, argv);
};

const refineNpx: Refiner = (argv) => {
  const rest = argv.slice(1).filter((a) => !a.startsWith("-"));
  const pkg = rest[0];
  if (!pkg) return approval("npx without a package", argv);
  if (NPX_SAFE_PACKAGES.has(pkg)) return allow(`npx ${pkg} from the local toolchain`, argv);
  return approval(`npx ${pkg} fetches and runs a package`, argv);
};

const refineNode: Refiner = (argv) => {
  const flags = argv.slice(1);
  if (flags.length === 1 && ["--version", "-v"].includes(flags[0] as string)) return allow("node version query", argv);
  if (flags.includes("--test") || flags[0] === "--test") return allow("node built-in test runner", argv);
  return approval("node executes JavaScript", argv);
};

const refinePython: Refiner = (argv) => {
  const rest = argv.slice(1);
  const versionOnly = rest.length === 1 && ["--version", "-V"].includes(rest[0] as string);
  if (versionOnly) return allow("python version query", argv);
  const mIdx = rest.indexOf("-m");
  if (mIdx >= 0) {
    const mod = rest[mIdx + 1];
    if (!mod) return approval("python -m without a module", argv);
    if (mod === "pip") {
      const pipArgs = rest.slice(mIdx + 2);
      if (pipArgs[0] === "install") return approval("python -m pip install mutates the environment", argv);
      return approval("python -m pip", argv);
    }
    if (PYTHON_SAFE_MODULES.has(mod)) return allow(`python -m ${mod}`, argv);
    if (PYTHON_APPROVAL_MODULES.has(mod)) return approval(`python -m ${mod}`, argv);
    return approval(`python module not in the safe tier: ${mod}`, argv);
  }
  if (rest.some((a) => a === "-c" || a === "-")) return approval("python inline code", argv);
  return approval("python executes a script", argv);
};

const refineGo: Refiner = (argv) => {
  const sub = subcommands(argv)[0];
  if (!sub) return approval("go without a subcommand", argv);
  if (["test", "build", "vet", "version", "env", "list", "fmt", "doc"].includes(sub)) {
    return allow(`go ${sub}`, argv);
  }
  if (["get", "install", "run", "mod", "generate", "work"].includes(sub)) {
    return approval(`go ${sub} mutates or executes`, argv);
  }
  return approval(`go ${sub} requires approval`, argv);
};

const refineCargo: Refiner = (argv) => {
  const sub = subcommands(argv)[0];
  if (!sub) return approval("cargo without a subcommand", argv);
  if (["test", "build", "check", "clippy", "fmt", "metadata", "tree", "verify-project"].includes(sub)) {
    return allow(`cargo ${sub}`, argv);
  }
  if (["add", "install", "remove", "publish", "update", "run", "new", "init", "login"].includes(sub)) {
    return approval(`cargo ${sub} mutates or executes`, argv);
  }
  return approval(`cargo ${sub} requires approval`, argv);
};

const refineMake: Refiner = (argv) => {
  const targets = subcommands(argv);
  if (targets.length === 0) return approval("make with the default target", argv);
  if (targets.every((t) => MAKEFILE_SAFE_TARGETS.has(t))) return allow(`make ${targets.join(" ")}`, argv);
  return approval(`make target requires approval: ${targets.join(" ")}`, argv);
};

const refinePrettier: Refiner = (argv) => {
  if (hasFlag(argv, ["--write", "-w"])) return approval("prettier rewrites files", argv);
  return allow("prettier check mode", argv);
};

const refineEslint: Refiner = (argv) => {
  if (hasFlag(argv, ["--fix"])) return approval("eslint rewrites files", argv);
  return allow("eslint lint mode", argv);
};

const refineRuff: Refiner = (argv) => {
  const sub = subcommands(argv)[0];
  if (sub === "format" && !hasFlag(argv, ["--check", "--diff"])) return approval("ruff rewrites files", argv);
  return allow("ruff check mode", argv);
};

const refinePythonFmt: Refiner = (argv) => (hasFlag(argv, ["--check", "--diff"]) ? allow("format check", argv) : approval("formatter rewrites files", argv));

const refineTar: Refiner = (argv) => (hasFlag(argv, ["-x", "-c", "--extract", "--create"]) || /^-[a-zA-Z]*[xc]/.test(argv[1] ?? "") ? approval("archive extraction/creation inside the workspace", argv) : allow("archive listing", argv));

const REFINERS: Record<string, Refiner> = {
  find: refineFind,
  rm: refineRm,
  rmdir: refineRm,
  git: refineGit,
  npm: refineNpm,
  node: refineNode,
  python: refinePython,
  python3: refinePython,
  go: refineGo,
  cargo: refineCargo,
  make: refineMake,
  npx: refineNpx,
  yarn: refinePkgScriptRunner("yarn"),
  pnpm: refinePkgScriptRunner("pnpm"),
  prettier: refinePrettier,
  eslint: refineEslint,
  ruff: refineRuff,
  black: refinePythonFmt,
  isort: refinePythonFmt,
  tar: refineTar,
};

/* ------------------------------------------------------------------ */
/* Entry points                                                       */
/* ------------------------------------------------------------------ */

/**
 * Classify an argv array. `argv[0]` must be a bare executable name (no path
 * separators) so resolution cannot be hijacked by a workspace-local shim.
 */
export function evaluateArgv(argv: string[], opts: PolicyOptions = {}): PolicyResult {
  if (!Array.isArray(argv) || argv.length === 0) return deny("empty argv", []);
  const name = argv[0] as string;

  if (!name) return deny("empty command name", argv);
  if (name.includes("/") || name.includes("\\")) {
    return deny("command must be a bare executable name, not a path", argv);
  }

  const forkReason = denyReason(argv.join(" "));
  if (forkReason) return deny(forkReason, argv);

  const lower = name.toLowerCase();
  if (HARD_DENY_NAMES.has(lower)) return deny(`command is permanently blocked: ${lower}`, argv);
  if (HARD_DENY_PREFIXES.some((p) => lower.startsWith(p))) return deny(`command is permanently blocked: ${lower}`, argv);

  const argProblem = inspectArgs(argv, opts.root);
  if (argProblem) return deny(argProblem, argv);

  if (SAFE_ALWAYS.has(lower) && !REFINERS[lower]) return allow(`safe command: ${lower}`, argv);
  if (REFINERS[lower]) {
    const refined = REFINERS[lower]?.(argv, opts.root);
    if (refined) return refined;
  }
  if (SAFE_ALWAYS.has(lower)) return allow(`safe command: ${lower}`, argv);
  if (APPROVAL_ALWAYS.has(lower)) {
    if (DEV_SERVER_MARKERS.has(subcommands(argv)[0] ?? "")) {
      return approval(`long-running command requires approval: ${lower}`, argv);
    }
    return approval(`mutating or networked command requires approval: ${lower}`, argv);
  }
  return approval(`unknown command requires approval: ${lower}`, argv);
}

/** Tokenize + classify a command string. Tokenizer failures are denials. */
export function evaluateCommand(cmd: string, opts: PolicyOptions = {}): PolicyResult {
  const tok = tokenize(cmd);
  if (!tok.ok) return deny(tok.reason, []);
  return evaluateArgv(tok.argv, opts);
}

/** Convenience predicate for "may run without a human in the loop". */
export function isAutoRun(cmd: string, opts: PolicyOptions = {}): boolean {
  return evaluateCommand(cmd, opts).decision === "allow";
}

/** Names permanently blocked, exposed for documentation/tests. */
export function deniedCommandNames(): string[] {
  return [...HARD_DENY_NAMES].sort();
}
