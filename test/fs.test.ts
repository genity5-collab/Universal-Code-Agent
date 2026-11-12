import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import fsp from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";

import {
  read_file,
  read_file_chunk,
  read_file_range,
  write_file,
  create_file,
  edit_file,
  delete_file,
  list_directory,
  search_files,
  search_content,
  get_file_metadata,
  compare_files,
  walkFiles,
  type ChunkingDescriptor,
} from "../src/fs/files.js";
import { RepoIndex, buildRepoIndex, INDEX_EXCLUDED_DIRS } from "../src/fs/index.js";
import { diffText, diffLineArrays, applyHunks, toHunks } from "../src/fs/diff.js";
import { extractSymbols, fuzzyMatchScore, levenshtein } from "../src/fs/symbols.js";
import { parseManifest, buildDependencyGraph, resolveImport, extractImports } from "../src/fs/depmap.js";
import { globToRegExp, alignEnd, countLines, splitLines, detectLineEnding } from "../src/fs/text.js";
import { detectLanguage, isBinaryBuffer, normalizeLanguage } from "../src/fs/language.js";
import { loadConfig } from "../src/util/config.js";
import { SecurityError, resolveInside, relFrom } from "../src/util/paths.js";

const cfg = loadConfig();

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

let tmpRoots: string[] = [];

async function makeRoot(): Promise<string> {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "uca-fs-"));
  tmpRoots.push(dir);
  return await fsp.realpath(dir);
}

async function put(root: string, rel: string, content: string | Buffer): Promise<void> {
  const abs = path.join(root, rel);
  await fsp.mkdir(path.dirname(abs), { recursive: true });
  await fsp.writeFile(abs, content);
}

test.after(async () => {
  for (const dir of tmpRoots) await fsp.rm(dir, { recursive: true, force: true });
  tmpRoots = [];
});

/** Future mtime so the index can never mistake a write for "unchanged". */
function bumpMtime(target: string): void {
  const future = new Date(Date.now() + 5000);
  fs.utimesSync(target, future, future);
}

// ---------------------------------------------------------------------------
// 1. path traversal is blocked
// ---------------------------------------------------------------------------

test("traversal: ../, absolute paths and symlink escapes are rejected", async () => {
  const root = await makeRoot();
  await put(root, "a.txt", "hello");

  await assert.rejects(() => read_file(root, "../etc/passwd"), SecurityError);
  await assert.rejects(() => read_file(root, "sub/../../etc/passwd"), SecurityError);
  await assert.rejects(() => read_file(root, "/etc/passwd"), SecurityError);
  await assert.rejects(() => write_file(root, "../evil.txt", "x"), SecurityError);
  await assert.rejects(() => create_file(root, "/tmp/evil.txt", "x"), SecurityError);
  await assert.rejects(() => delete_file(root, "../a.txt"), SecurityError);
  await assert.rejects(() => list_directory(root, ".."), SecurityError);
  await assert.rejects(() => read_file(root, "a\0.txt"), SecurityError);

  // A symlink inside the root that points outside must not be followed.
  const outside = await makeRoot();
  await put(outside, "secret.txt", "top secret");
  await fsp.symlink(outside, path.join(root, "escape"), "dir");
  await assert.rejects(() => read_file(root, "escape/secret.txt"), SecurityError);
  // Same for a file symlink.
  await fsp.symlink(path.join(outside, "secret.txt"), path.join(root, "link.txt"));
  await assert.rejects(() => read_file(root, "link.txt"), SecurityError);
  await assert.rejects(() => write_file(root, "link.txt", "pwned"), SecurityError);

  // Writing into .git internals is refused.
  await put(root, ".git/config", "[core]\n");
  await assert.rejects(() => write_file(root, ".git/config", "x"), /git internals/);
  await assert.rejects(() => create_file(root, ".git/hooks/pre-commit", "#!/bin/sh\n"), /git internals/);
  await assert.rejects(() => edit_file(root, ".git/config", { oldString: "[core]", newString: "[x]" }), /git internals/);
  await assert.rejects(() => delete_file(root, ".git/config"), /git internals/);
  // Reading .git is allowed (only writes are refused).
  const gitCfg = await read_file(root, ".git/config");
  assert.equal("content" in gitCfg && gitCfg.content, "[core]\n");

  // resolveInside still allows legitimate nested paths.
  assert.equal(relFrom(root, resolveInside(root, "a.txt")), "a.txt");
  const created = await create_file(root, "deep/nested/dir/new.txt", "ok");
  assert.equal(created.created, true);
});

// ---------------------------------------------------------------------------
// 2 + 3. chunked reads reassemble exactly; no silent truncation
// ---------------------------------------------------------------------------

test("read_file: oversized files return an explicit chunking descriptor (never truncate)", async () => {
  const root = await makeRoot();
  const line = "héllo wörld → 世界 😀 café\n";
  const lines = Array.from({ length: 20000 }, (_, i) => `${i}:${line}`);
  const text = lines.join("");
  await put(root, "big.txt", text);

  const size = Buffer.byteLength(text, "utf8");
  const meta = await get_file_metadata(root, "big.txt");
  assert.equal(meta.size, size);
  assert.equal(meta.binary, false);
  assert.equal(meta.lines, 20000);
  assert.equal(meta.sha256, crypto.createHash("sha256").update(Buffer.from(text, "utf8")).digest("hex"));

  const res = await read_file(root, "big.txt");
  assert.equal("requiresChunking" in res, true);
  const desc = res as ChunkingDescriptor;
  assert.equal(desc.truncated, false);
  assert.equal(desc.requiresChunking, true);
  assert.equal(desc.totalBytes, size);
  assert.equal(desc.totalLines, 20000);
  assert.equal(desc.maxChunkBytes, cfg.maxChunkBytes);
  assert.equal(desc.defaultChunkBytes, cfg.defaultChunkBytes);
  assert.equal(desc.language, "text");
  assert.ok(desc.hint.includes("read_file_chunk"));

  // A file that fits is returned whole with truncated:false and full content.
  const small = await read_file(root, "big.txt", { maxBytes: size + 1 });
  assert.ok("content" in small);
  assert.equal(small.truncated, false);
  assert.equal(small.content, text);
  assert.equal(small.totalBytes, size);
  assert.equal(small.totalLines, 20000);
  assert.equal(small.encoding, "utf8");
});

test("read_file_chunk: byte chunks reassemble a >1MB multibyte file exactly", async () => {
  const root = await makeRoot();
  const unit = "héllo→世界😀";
  const parts: string[] = [];
  for (let i = 0; i < 60000; i++) parts.push(`${i % 97}:${unit}`);
  const text = parts.join("|");
  await put(root, "multi.txt", text);
  const totalBytes = Buffer.byteLength(text, "utf8");
  assert.ok(totalBytes > 1024 * 1024, `file should be >1MB, got ${totalBytes}`);

  // Chunk size deliberately not a multiple of anything meaningful.
  const chunkSize = 4099;
  const chunks: Buffer[] = [];
  let offset = 0;
  let iterations = 0;
  for (;;) {
    const chunk = await read_file_chunk(root, "multi.txt", { offset, size: chunkSize });
    iterations++;
    assert.ok(iterations < 10000, "must terminate");
    assert.equal(chunk.eof, offset + chunk.bytesRead >= totalBytes);
    if (chunk.bytesRead === 0) {
      assert.equal(chunk.eof, true);
      break;
    }
    // No chunk may be larger than requested, nor exceed the configured cap.
    assert.ok(chunk.bytesRead <= chunkSize, `chunk too large: ${chunk.bytesRead}`);
    assert.ok(chunk.bytesRead <= cfg.maxChunkBytes);
    // Each chunk must decode without replacement characters.
    assert.ok(!chunk.content.includes("\uFFFD"), "chunk split a UTF-8 character");
    chunks.push(Buffer.from(chunk.content, "utf8"));
    offset = chunk.nextOffset;
    if (chunk.eof) break;
  }
  const reassembled = Buffer.concat(chunks).toString("utf8");
  assert.equal(reassembled, text);
  assert.equal(reassembled.length, text.length);
  assert.equal(Buffer.byteLength(reassembled, "utf8"), totalBytes);

  // Requesting more than maxChunkBytes is clamped, not honoured.
  const clamped = await read_file_chunk(root, "multi.txt", { offset: 0, size: cfg.maxChunkBytes * 10 });
  assert.equal(clamped.bytesRead <= cfg.maxChunkBytes, true);
  assert.equal(clamped.requestedSize, cfg.maxChunkBytes * 10);

  // Default size is defaultChunkBytes.
  const dflt = await read_file_chunk(root, "multi.txt");
  assert.ok(dflt.bytesRead <= cfg.defaultChunkBytes);

  // An offset pointing into the middle of a character snaps forward instead of
  // emitting garbage; the byte at that offset is a continuation byte.
  const buf = Buffer.from(text, "utf8");
  let midChar = -1;
  for (let i = 1; i < 200; i++) {
    const b = buf[i];
    if ((b & 0xc0) === 0x80) { midChar = i; break; }
  }
  assert.ok(midChar > 0);
  const snapped = await read_file_chunk(root, "multi.txt", { offset: midChar, size: 64 });
  assert.ok(snapped.offset > midChar);
  assert.ok(!snapped.content.includes("\uFFFD"));
  assert.equal(buf.subarray(snapped.offset, snapped.offset + snapped.bytesRead).toString("utf8"), snapped.content);

  // Reading at/after EOF is a clean stop, not an error.
  const atEof = await read_file_chunk(root, "multi.txt", { offset: totalBytes, size: 10 });
  assert.equal(atEof.eof, true);
  assert.equal(atEof.bytesRead, 0);

  // base64 encoding round-trips bytes losslessly.
  const b64 = await read_file_chunk(root, "multi.txt", { offset: 0, size: 1000, encoding: "base64" });
  assert.deepEqual(Buffer.from(b64.content, "base64"), buf.subarray(0, b64.bytesRead));
});

test("read_file_range: line pagination reports totalLines and continues correctly", async () => {
  const root = await makeRoot();
  const lines = Array.from({ length: 250 }, (_, i) => `line ${i + 1}`);
  await put(root, "lines.txt", lines.join("\n") + "\n");

  const page1 = await read_file_range(root, "lines.txt", { startLine: 1, maxLines: 100 });
  assert.equal(page1.totalLines, 250);
  assert.equal(page1.lines.length, 100);
  assert.equal(page1.lines[0], "line 1");
  assert.equal(page1.lines[99], "line 100");
  assert.equal(page1.startLine, 1);
  assert.equal(page1.endLine, 100);
  assert.equal(page1.hasMore, true);
  assert.equal(page1.nextStartLine, 101);

  const page2 = await read_file_range(root, "lines.txt", { startLine: page1.nextStartLine as number, maxLines: 100 });
  assert.equal(page2.lines[0], "line 101");
  assert.equal(page2.hasMore, true);
  assert.equal(page2.nextStartLine, 201);

  const page3 = await read_file_range(root, "lines.txt", { startLine: 201, maxLines: 100 });
  assert.equal(page3.lines.length, 50);
  assert.equal(page3.lines[49], "line 250");
  assert.equal(page3.hasMore, false);
  assert.equal(page3.nextStartLine, null);

  const joined = [...page1.lines, ...page2.lines, ...page3.lines];
  assert.deepEqual(joined, lines);

  const explicit = await read_file_range(root, "lines.txt", { startLine: 10, endLine: 12, includeLineNumbers: true });
  assert.deepEqual(explicit.lines, ["line 10", "line 11", "line 12"]);
  assert.equal(explicit.text, "10│line 10\n11│line 11\n12│line 12");

  const past = await read_file_range(root, "lines.txt", { startLine: 500 });
  assert.deepEqual(past.lines, []);
  assert.equal(past.totalLines, 250);
  assert.equal(past.hasMore, false);
});

test("no silent truncation: maxBytes forces a descriptor, never a cut-off string", async () => {
  const root = await makeRoot();
  const text = "x".repeat(500);
  await put(root, "f.txt", text);
  const res = await read_file(root, "f.txt", { maxBytes: 100 });
  assert.equal("requiresChunking" in res && res.requiresChunking, true);
  assert.equal("content" in res, false, "truncated content must not be returned");
  assert.equal((res as ChunkingDescriptor).totalBytes, 500);
  assert.equal((res as ChunkingDescriptor).totalLines, 1);
});

// ---------------------------------------------------------------------------
// 4. write / create / edit / delete
// ---------------------------------------------------------------------------

test("write_file and create_file: create semantics and overwrite rules", async () => {
  const root = await makeRoot();

  const w1 = await write_file(root, "a/b/new.txt", "one\n");
  assert.equal(w1.created, true);
  assert.equal(w1.bytesWritten, 4);
  assert.equal(w1.size, 4);

  const w2 = await write_file(root, "a/b/new.txt", "two\n");
  assert.equal(w2.created, false);
  await assert.rejects(() => write_file(root, "a/b/new.txt", "three", { overwrite: false }), /EEXIST/);

  const c1 = await create_file(root, "a/b/created.txt", "hi");
  assert.equal(c1.created, true);
  assert.equal(await fsp.readFile(path.join(root, "a/b/created.txt"), "utf8"), "hi");
  await assert.rejects(() => create_file(root, "a/b/created.txt", "again"), /EEXIST/);
  await assert.rejects(() => create_file(root, "a/b/new.txt", "again"), /EEXIST/);

  // Non-existent parent without createDirs fails loudly.
  await assert.rejects(() => write_file(root, "nope/deep/x.txt", "x", { createDirs: false }), /parent directory/);

  // No temp files are left behind by the atomic write.
  const leftovers = (await fsp.readdir(path.join(root, "a/b"))).filter((n) => n.endsWith(".tmp"));
  assert.deepEqual(leftovers, []);

  const d = await delete_file(root, "a/b/created.txt");
  assert.equal(d.deleted, true);
  await assert.rejects(() => read_file(root, "a/b/created.txt"));
  await assert.rejects(() => delete_file(root, "a/b"), /ENOTEMPTY/);
  const rd = await delete_file(root, "a", { recursive: true });
  assert.equal(rd.type, "dir");
  assert.equal(fs.existsSync(path.join(root, "a")), false);
});

test("edit_file: requires a unique match unless replaceAll or a line range is given", async () => {
  const root = await makeRoot();
  const original = ["function a() {", "  return 1;", "}", "", "function b() {", "  return 1;", "}", ""].join("\n");
  await put(root, "src/code.ts", original);

  // 0 matches → clear error mentioning the string, nothing written.
  await assert.rejects(
    () => edit_file(root, "src/code.ts", { oldString: "return 42;", newString: "return 43;" }),
    (e: Error & { code?: string }) => e.code === "ENOMATCH" && /not found/.test(e.message),
  );
  assert.equal(await fsp.readFile(path.join(root, "src/code.ts"), "utf8"), original);

  // >1 matches → ambiguous error telling the caller how to disambiguate.
  await assert.rejects(
    () => edit_file(root, "src/code.ts", { oldString: "return 1;", newString: "return 2;" }),
    (e: Error & { code?: string }) => e.code === "EAMBIGUOUS" && /appears 2 times/.test(e.message) && /replaceAll/.test(e.message),
  );
  assert.equal(await fsp.readFile(path.join(root, "src/code.ts"), "utf8"), original);

  // Unique match succeeds.
  const unique = await edit_file(root, "src/code.ts", {
    oldString: "function a() {",
    newString: "function alpha() {",
  });
  assert.equal(unique.replacements, 1);
  assert.equal(unique.firstChangedLine, 1);
  assert.match(unique.diff, /^--- a\/src\/code\.ts$/m);
  assert.match(unique.diff, /^\+function alpha\(\) \{$/m);
  assert.equal((await read_file(root, "src/code.ts") as { content: string }).content.includes("function alpha() {"), true);

  // replaceAll replaces every occurrence and reports the count.
  const all = await edit_file(root, "src/code.ts", { oldString: "return 1;", newString: "return 7;", replaceAll: true });
  assert.equal(all.replacements, 2);
  const afterAll = (await read_file(root, "src/code.ts") as { content: string }).content;
  assert.equal((afterAll.match(/return 7;/g) ?? []).length, 2);

  // Line-range edit: replace lines 5..7 (function b) wholesale.
  const ranged = await edit_file(root, "src/code.ts", {
    startLine: 5,
    endLine: 7,
    newString: "function b() {\n  return 9;\n}",
  });
  assert.equal(ranged.replacements, 1);
  const afterRange = (await read_file(root, "src/code.ts") as { content: string }).content;
  assert.match(afterRange, /function b\(\) \{\n {2}return 9;\n\}/);

  // Line-range + oldString: scoped uniqueness (same string appears twice in the
  // file but only once inside the range).
  await put(root, "two.txt", "x = 1\nkeep\nx = 1\n");
  const scoped = await edit_file(root, "two.txt", { startLine: 3, endLine: 3, oldString: "x = 1", newString: "x = 2" });
  assert.equal(scoped.replacements, 1);
  assert.equal(await fsp.readFile(path.join(root, "two.txt"), "utf8"), "x = 1\nkeep\nx = 2\n");

  // Out-of-range line start is an explicit error.
  await assert.rejects(() => edit_file(root, "two.txt", { startLine: 99, endLine: 100, newString: "y" }), /past end of file/);
});

// ---------------------------------------------------------------------------
// 5. diff correctness
// ---------------------------------------------------------------------------

test("diff: LCS-based unified diff is minimal and round-trips", async () => {
  // Known case: one changed line in the middle, 7-line context window.
  const a = "a\nb\nc\nd\ne\nf\ng";
  const b = "a\nb\nc\nD\ne\nf\ng";
  const d = diffText(a, b, { aLabel: "a/f", bLabel: "b/f" });
  assert.equal(d.identical, false);
  assert.equal(d.stats.added, 1);
  assert.equal(d.stats.removed, 1);
  assert.equal(d.stats.unchanged, 6);
  assert.equal(d.hunks.length, 1);
  assert.equal(d.hunks[0].header, "@@ -1,7 +1,7 @@");
  assert.equal(d.hunks[0].aStart, 1);
  assert.equal(d.hunks[0].bLength, 7);
  assert.match(d.unified, /^-d$/m);
  assert.match(d.unified, /^\+D$/m);
  assert.match(d.unified, /^--- a\/f$/m);
  assert.match(d.unified, /^\+\+\+ b\/f$/m);
  assert.equal(applyHunks(a, d), b);

  // Minimality: a single insertion must produce exactly one add line, not a
  // remove+add of the whole tail (this is what a real LCS buys us).
  const ins = diffText("1\n2\n3\n", "1\n2\nX\n3\n");
  assert.equal(ins.stats.added, 1);
  assert.equal(ins.stats.removed, 0);
  assert.equal(ins.stats.unchanged, 3);
  assert.equal(ins.hunks[0].header, "@@ -1,3 +1,4 @@");
  assert.equal(applyHunks("1\n2\n3\n", ins), "1\n2\nX\n3");

  // Deletion at the very start: with context 0 the b-side is empty and the
  // unified convention points at the line before the range (+0,0).
  const del = diffText("gone\nstay\n", "stay\n", { context: 0 });
  assert.equal(del.stats.removed, 1);
  assert.equal(del.stats.added, 0);
  assert.equal(del.hunks[0].header, "@@ -1,1 +0,0 @@");
  assert.equal(del.hunks[0].bLength, 0);
  assert.equal(applyHunks("gone\nstay\n", del), "stay");
  // With default context the surviving line is part of the hunk.
  const del3 = diffText("gone\nstay\n", "stay\n");
  assert.equal(del3.hunks[0].header, "@@ -1,2 +1,1 @@");
  assert.equal(applyHunks("gone\nstay\n", del3), "stay");

  // Identical inputs produce no hunks and an empty unified body.
  const same = diffText("x\ny\n", "x\ny\n");
  assert.equal(same.identical, true);
  assert.equal(same.unified, "");
  assert.equal(same.hunks.length, 0);
  assert.equal(same.stats.added + same.stats.removed, 0);

  // Two distant changes produce two separate hunks (context 3).
  const longA = Array.from({ length: 40 }, (_, i) => `l${i}`).join("\n");
  const longB = longA.split("\n").map((l, i) => (i === 2 || i === 30 ? `${l}!` : l)).join("\n");
  const two = diffText(longA, longB);
  assert.equal(two.hunks.length, 2);
  assert.equal(two.stats.added, 2);
  assert.equal(two.stats.removed, 2);
  assert.equal(applyHunks(longA, two), longB);

  // Randomized round-trip + independent LCS check.
  let seed = 12345;
  const rnd = (): number => {
    seed = (seed * 1103515245 + 12345) & 0x7fffffff;
    return seed / 0x7fffffff;
  };
  for (let iter = 0; iter < 60; iter++) {
    const len = 1 + Math.floor(rnd() * 25);
    const aLines = Array.from({ length: len }, () => String(Math.floor(rnd() * 6)));
    const bLines = aLines.filter(() => rnd() > 0.25).map((l) => (rnd() > 0.7 ? `${l}x` : l));
    if (rnd() > 0.5) bLines.splice(Math.floor(rnd() * (bLines.length + 1)), 0, "new");
    const aText = aLines.join("\n");
    const bText = bLines.join("\n");

    const r = diffText(aText, bText);
    const applied = applyHunks(aText, r);
    assert.deepEqual(splitLines(applied), splitLines(bText), `round-trip failed: ${JSON.stringify({ aText, bText, unified: r.unified })}`);

    // Independent LCS length via plain DP.
    const dp: number[][] = Array.from({ length: aLines.length + 1 }, () => new Array<number>(bLines.length + 1).fill(0));
    for (let i = 1; i <= aLines.length; i++) {
      for (let j = 1; j <= bLines.length; j++) {
        dp[i][j] = aLines[i - 1] === bLines[j - 1] ? dp[i - 1][j - 1] + 1 : Math.max(dp[i - 1][j], dp[i][j - 1]);
      }
    }
    assert.equal(r.stats.unchanged, dp[aLines.length][bLines.length]);
    assert.equal(r.stats.added, bLines.length - dp[aLines.length][bLines.length]);
    assert.equal(r.stats.removed, aLines.length - dp[aLines.length][bLines.length]);
  }

  // compare_files ties the same engine to two real files on disk.
  const root = await makeRoot();
  await put(root, "v1.txt", "alpha\nbeta\ngamma\n");
  await put(root, "v2.txt", "alpha\nBETA\ngamma\ndelta\n");
  const cmp = await compare_files(root, "v1.txt", "v2.txt");
  assert.equal(cmp.identical, false);
  assert.equal(cmp.stats.added, 2);
  assert.equal(cmp.stats.removed, 1);
  assert.match(cmp.unified, /^-beta$/m);
  assert.match(cmp.unified, /^\+BETA$/m);
  assert.match(cmp.unified, /^\+delta$/m);
  assert.equal(cmp.a.path, "v1.txt");
  assert.equal(cmp.b.path, "v2.txt");
  assert.equal(cmp.a.lines, 3);
  assert.equal(cmp.b.lines, 4);

  const sameFiles = await compare_files(root, "v1.txt", "v1.txt");
  assert.equal(sameFiles.identical, true);
  assert.equal(sameFiles.unified, "");

  // ignoreWhitespace compares normalized text.
  await put(root, "w1.txt", "a  b\n");
  await put(root, "w2.txt", "a b\n");
  assert.equal((await compare_files(root, "w1.txt", "w2.txt")).identical, false);
  assert.equal((await compare_files(root, "w1.txt", "w2.txt", { ignoreWhitespace: true })).identical, true);
});

test("diff internals: hunk grouping and header arithmetic", () => {
  const { lines } = diffLineArrays(["a", "b", "c"], ["a", "x", "c"]);
  const hunks = toHunks(lines, 0);
  assert.equal(hunks.length, 1);
  assert.equal(hunks[0].aStart, 2);
  assert.equal(hunks[0].aLength, 1);
  assert.equal(hunks[0].bStart, 2);
  assert.equal(hunks[0].bLength, 1);
  assert.equal(hunks[0].header, "@@ -2,1 +2,1 @@");

  // Large inputs fall back to a coarse diff instead of blowing up memory.
  const bigA = Array.from({ length: 3000 }, (_, i) => `a${i}`);
  const bigB = Array.from({ length: 3000 }, (_, i) => `b${i}`);
  const big = diffLineArrays(bigA, bigB, { maxCells: 1000 });
  assert.equal(big.simplified, true);
});

// ---------------------------------------------------------------------------
// 6. content search
// ---------------------------------------------------------------------------

test("search_content: literal and regex search with context, binary skip and pagination", async () => {
  const root = await makeRoot();
  await put(root, "src/a.ts", "const alpha = 1;\n// TODO: fix alpha\nfunction beta() {}\n");
  await put(root, "src/b.ts", "export const gamma = 2;\n// todo later\n");
  await put(root, "src/c.py", "def handler():\n    pass  # TODO handle\n");
  await put(root, "node_modules/dep/index.js", "// TODO should be ignored\n");
  await put(root, "src/bin.dat", Buffer.from([0x00, 0x01, 0x02, 0x54, 0x4f, 0x44, 0x4f]));
  await put(root, "readme.md", "# TODO at top\n\nalpha again\n");

  const literal = await search_content(root, "TODO");
  // node_modules is skipped, binary is skipped, case-insensitive by default.
  assert.deepEqual(literal.matches.map((m) => `${m.path}:${m.line}`).sort(), [
    "readme.md:1",
    "src/a.ts:2",
    "src/b.ts:2",
    "src/c.py:2",
  ]);
  assert.equal(literal.hasMore, false);
  assert.equal(literal.nextCursor, null);
  assert.equal(literal.filesWithMatches, 4);
  assert.ok(literal.filesScanned >= 4);
  assert.equal(literal.matches.find((m) => m.path === "src/a.ts")?.column, 4);
  assert.equal(literal.matches.find((m) => m.path === "src/a.ts")?.text, "// TODO: fix alpha");

  // Case sensitive: only the uppercase occurrences.
  const cs = await search_content(root, "TODO", { caseSensitive: true });
  assert.deepEqual(cs.matches.map((m) => m.path).sort(), ["readme.md", "src/a.ts", "src/c.py"]);

  // Regex + glob filter.
  const re = await search_content(root, "const\\s+(alpha|gamma)", { regex: true, glob: "src/*.ts" });
  assert.deepEqual(re.matches.map((m) => `${m.path}:${m.line}`).sort(), ["src/a.ts:1", "src/b.ts:1"]);
  await assert.rejects(() => search_content(root, "([unclosed", { regex: true }), /Invalid regex/);

  // Context lines.
  const ctx = await search_content(root, "TODO: fix", { contextLines: 1 });
  assert.equal(ctx.matches.length, 1);
  assert.deepEqual(ctx.matches[0].before, ["const alpha = 1;"]);
  assert.deepEqual(ctx.matches[0].after, ["function beta() {}"]);

  // Pagination via opaque cursor: every page is disjoint and complete.
  const page1 = await search_content(root, "alpha", { limit: 1 });
  assert.equal(page1.matches.length, 1);
  assert.equal(page1.hasMore, true);
  assert.ok(page1.nextCursor);
  const page2 = await search_content(root, "alpha", { limit: 1, cursor: page1.nextCursor as string });
  assert.equal(page2.matches.length, 1);
  const all = [...page1.matches, ...page2.matches];
  assert.equal(new Set(all.map((m) => `${m.path}:${m.line}:${m.column}`)).size, 2);
  assert.deepEqual(all.map((m) => `${m.path}:${m.line}`).sort(), ["readme.md:3", "src/a.ts:1"]);
  // Three "alpha" occurrences exist, so a 1-per-page read still has more to come.
  assert.equal(page2.hasMore, true);

  // A full sweep across small pages finds every occurrence exactly once.
  const collected: string[] = [];
  let cursor: string | null = null;
  for (let guard = 0; guard < 20; guard++) {
    const page = await search_content(root, "alpha", { limit: 1, cursor: cursor ?? undefined });
    collected.push(...page.matches.map((m) => `${m.path}:${m.line}:${m.column}`));
    if (!page.hasMore || !page.nextCursor) break;
    cursor = page.nextCursor;
  }
  assert.equal(collected.length, new Set(collected).size);
  assert.deepEqual(collected.sort(), ["readme.md:3:1", "src/a.ts:1:7", "src/a.ts:2:14"]);

  // Zero matches is an empty (not error) result.
  const none = await search_content(root, "zzz-not-present");
  assert.equal(none.matches.length, 0);
  assert.equal(none.hasMore, false);
});

// ---------------------------------------------------------------------------
// 7. listing, glob search, metadata
// ---------------------------------------------------------------------------

test("list_directory and search_files: pagination, ignored dirs and globbing", async () => {
  const root = await makeRoot();
  for (const f of ["a.ts", "b.ts", "sub/c.ts", "sub/deep/d.ts", "node_modules/x/y.ts", "dist/z.js", ".git/config"]) {
    await put(root, f, "// x\n");
  }
  await put(root, "sub/notes.md", "# n\n");

  const top = await list_directory(root, ".");
  assert.deepEqual(top.entries.map((e) => e.path).sort(), ["a.ts", "b.ts", "sub"]);
  assert.equal(top.entries.find((e) => e.path === "a.ts")?.language, "typescript");
  assert.equal(top.entries.find((e) => e.path === "sub")?.type, "dir");
  assert.equal(top.total, 3);

  const withIgnored = await list_directory(root, ".", { includeIgnored: true });
  assert.ok(withIgnored.entries.some((e) => e.path === "node_modules"));
  assert.ok(withIgnored.entries.some((e) => e.path === ".git"));
  assert.ok(withIgnored.entries.some((e) => e.path === "dist"));

  const paged = await list_directory(root, ".", { limit: 1, offset: 0 });
  assert.equal(paged.entries.length, 1);
  assert.equal(paged.hasMore, true);
  assert.equal(paged.nextOffset, 1);
  const paged2 = await list_directory(root, ".", { limit: 1, offset: 1 });
  assert.equal(paged2.nextOffset, 2);
  assert.notEqual(paged.entries[0].path, paged2.entries[0].path);

  const recursive = await list_directory(root, ".", { recursive: true, maxDepth: 3 });
  assert.ok(recursive.entries.some((e) => e.path === "sub/deep/d.ts"));
  assert.ok(recursive.entries.some((e) => e.path === "sub/deep"));

  await assert.rejects(() => list_directory(root, "a.ts"), /ENOTDIR/);

  const byExt = await search_files(root, "*.ts");
  assert.deepEqual(byExt.matches.map((m) => m.path).sort(), ["a.ts", "b.ts", "sub/c.ts", "sub/deep/d.ts"]);
  assert.equal(byExt.total, 4);

  const byPath = await search_files(root, "sub/**/*.md", { matchPath: true });
  assert.deepEqual(byPath.matches.map((m) => m.path), ["sub/notes.md"]);

  // `?` matches exactly one character — against the basename by default, so it
  // matches c.ts/d.ts in subdirectories too.
  const q = await search_files(root, "?.ts");
  assert.deepEqual(q.matches.map((m) => m.path).sort(), ["a.ts", "b.ts", "sub/c.ts", "sub/deep/d.ts"]);
  // matchPath: true anchors the pattern to the whole relative path instead.
  const qPath = await search_files(root, "?.ts", { matchPath: true });
  assert.deepEqual(qPath.matches.map((m) => m.path).sort(), ["a.ts", "b.ts"]);

  // Braces + regex modes.
  const braces = await search_files(root, "*.{md,markdown}");
  assert.deepEqual(braces.matches.map((m) => m.path), ["sub/notes.md"]);
  const regex = await search_files(root, "^[ab]\\.ts$", { regex: true });
  assert.deepEqual(regex.matches.map((m) => m.path).sort(), ["a.ts", "b.ts"]);

  const dirs = await search_files(root, "sub*", { types: "dir" });
  assert.deepEqual(dirs.matches.map((m) => m.path), ["sub"]);
  assert.equal(dirs.matches[0].type, "dir");

  const pagedSearch = await search_files(root, "*.ts", { limit: 2, offset: 0 });
  assert.equal(pagedSearch.matches.length, 2);
  assert.equal(pagedSearch.hasMore, true);
  assert.equal(pagedSearch.nextOffset, 2);
  const pagedSearch2 = await search_files(root, "*.ts", { limit: 2, offset: 2 });
  assert.equal(pagedSearch2.matches.length, 2);
  assert.equal(pagedSearch2.hasMore, false);

  // walkFiles never yields ignored dirs and never follows symlinks.
  await fsp.symlink(path.join(root, "sub"), path.join(root, "sub-link"));
  const walked: string[] = [];
  for await (const e of walkFiles(root)) walked.push(e.path);
  assert.equal(walked.some((p) => p.startsWith("node_modules/")), false);
  assert.equal(walked.some((p) => p.startsWith(".git/")), false);
  assert.equal(walked.some((p) => p.startsWith("sub-link/")), false);
  assert.equal(walked.includes("sub-link"), true, "symlink itself is listed but not traversed");
});

test("get_file_metadata: size, lines, language, sha256 and binary detection", async () => {
  const root = await makeRoot();
  await put(root, "app.py", "def a():\n    return 1\n");
  const md = await get_file_metadata(root, "app.py");
  assert.equal(md.size, 22);
  assert.equal(md.lines, 2);
  assert.equal(md.language, "python");
  assert.equal(md.binary, false);
  assert.equal(md.type, "file");
  assert.equal(md.sha256, crypto.createHash("sha256").update("def a():\n    return 1\n").digest("hex"));
  assert.ok(md.mtimeIso.endsWith("Z"));

  const bin = Buffer.from([0x00, 0x01, 0x02, 0x03, 0x00]);
  await put(root, "blob.bin", bin);
  const bmd = await get_file_metadata(root, "blob.bin");
  assert.equal(bmd.binary, true);
  assert.equal(bmd.sha256, crypto.createHash("sha256").update(bin).digest("hex"));
  assert.equal(bmd.lines, 0);

  const asRead = await read_file(root, "blob.bin");
  assert.equal("content" in asRead && asRead.binary, true);
  assert.equal("content" in asRead && asRead.encoding, "base64");

  const dirMd = await get_file_metadata(root, ".");
  assert.equal(dirMd.type, "dir");
});

// ---------------------------------------------------------------------------
// 8. symbol extraction + finding
// ---------------------------------------------------------------------------

test("symbols: extraction across languages, then find_symbol", async () => {
  const ts = [
    "export interface User { id: string }",
    "export type Role = 'admin' | 'user';",
    "export class AccountService {",
    "  constructor(private repo: Repo) {}",
    "  async getAccount(id: string): Promise<Account> {",
    "    return this.repo.load(id);",
    "  }",
    "}",
    "export async function loadUser(id: string) { return id; }",
    "export const MAX_RETRIES = 3;",
    "export const helper = (x: number) => x * 2;",
  ].join("\n");
  const tsSyms = extractSymbols("src/account.ts", ts);
  const names = tsSyms.map((s) => `${s.kind}:${s.name}`);
  assert.ok(names.includes("interface:User"));
  assert.ok(names.includes("type:Role"));
  assert.ok(names.includes("class:AccountService"));
  assert.ok(names.includes("method:getAccount"));
  assert.ok(names.includes("function:loadUser"));
  assert.ok(names.includes("function:helper"));
  assert.ok(names.includes("const:MAX_RETRIES"));
  assert.equal(names.includes("method:constructor"), false);
  assert.equal(names.includes("function:if"), false);
  assert.equal(tsSyms.find((s) => s.name === "loadUser")?.line, 9);

  const py = "class Handler:\n    def __init__(self):\n        pass\n    def run(self):\n        pass\n\ndef helper():\n    pass\nMAX = 10\n";
  const pySyms = extractSymbols("svc.py", py).map((s) => `${s.kind}:${s.name}`);
  assert.ok(pySyms.includes("class:Handler"));
  assert.ok(pySyms.includes("method:__init__"));
  assert.ok(pySyms.includes("method:run"));
  assert.ok(pySyms.includes("function:helper"));
  assert.ok(pySyms.includes("const:MAX"));

  const go = "package main\n\nfunc main() {}\n\nfunc (s *Server) Start() error { return nil }\n\ntype Server struct{}\n\ntype Store interface{}\n";
  const goSyms = extractSymbols("main.go", go).map((s) => `${s.kind}:${s.name}`);
  assert.ok(goSyms.includes("function:main"));
  assert.ok(goSyms.includes("method:Start"));
  assert.ok(goSyms.includes("class:Server"));
  assert.ok(goSyms.includes("interface:Store"));

  const rs = "pub struct Engine;\nimpl Engine {\n    pub fn start(&self) {}\n}\npub trait Runnable {}\npub enum State { A }\nconst LIMIT: usize = 1;\n";
  const rsSyms = extractSymbols("src/engine.rs", rs).map((s) => `${s.kind}:${s.name}`);
  assert.ok(rsSyms.includes("class:Engine"));
  assert.ok(rsSyms.includes("function:start"));
  assert.ok(rsSyms.includes("interface:Runnable"));
  assert.ok(rsSyms.includes("type:State"));
  assert.ok(rsSyms.includes("const:LIMIT"));

  const java = "public class Service {\n    private int count;\n    public void run(int x) {\n    }\n}\ninterface Api {}\n";
  const javaSyms = extractSymbols("Service.java", java).map((s) => `${s.kind}:${s.name}`);
  assert.ok(javaSyms.includes("class:Service"));
  assert.ok(javaSyms.includes("method:run"));
  assert.ok(javaSyms.includes("interface:Api"));

  const ruby = "class Client\n  def self.build\n  end\n  def call(x)\n  end\nend\nVERSION = '1.0'\n";
  const rbSyms = extractSymbols("client.rb", ruby).map((s) => `${s.kind}:${s.name}`);
  assert.ok(rbSyms.includes("class:Client"));
  assert.ok(rbSyms.includes("method:call"));
  assert.ok(rbSyms.includes("const:VERSION"));

  const php = "<?php\nclass Repo {\n    public function find($id) {}\n}\nconst LIMIT = 5;\n";
  const phpSyms = extractSymbols("Repo.php", php).map((s) => `${s.kind}:${s.name}`);
  assert.ok(phpSyms.includes("class:Repo"));
  assert.ok(phpSyms.includes("function:find"));
  assert.ok(phpSyms.includes("const:LIMIT"));

  const c = "int add(int a, int b) {\n  return a + b;\n}\nstruct Point { int x; };\n#define MAX 8\n";
  const cSyms = extractSymbols("math.c", c).map((s) => `${s.kind}:${s.name}`);
  assert.ok(cSyms.includes("function:add"));
  assert.ok(cSyms.includes("class:Point"));
  assert.ok(cSyms.includes("const:MAX"));

  // Unsupported language yields nothing rather than throwing.
  assert.deepEqual(extractSymbols("notes.txt", "hello"), []);

  // Fuzzy scoring helpers.
  assert.ok(fuzzyMatchScore("load", "loadUser") > fuzzyMatchScore("load", "downloadUser"));
  assert.equal(fuzzyMatchScore("ldusr", "loadUser") > 0, true);
  assert.equal(levenshtein("loadUser", "loaduser", 2), 1);
  assert.equal(levenshtein("abc", "xyz", 1), 2);

  // find_symbol over a real indexed repo.
  const root = await makeRoot();
  await put(root, "src/user.ts", "export class UserRepo {\n  findUser(id: string) { return id; }\n}\nexport function createUser() {}\n");
  await put(root, "src/account.ts", "export class AccountRepo {}\nexport function findAccount() {}\n");
  const index = await buildRepoIndex(root);

  const exact = index.findSymbol("findUser");
  assert.equal(exact.length, 1);
  assert.equal(exact[0].path, "src/user.ts");
  assert.equal(exact[0].kind, "method");
  assert.equal(exact[0].line, 2);

  const byKind = index.findSymbol("user", "class");
  assert.deepEqual(byKind.map((h) => `${h.path}:${h.kind}:${h.name}`), ["src/user.ts:class:UserRepo"]);

  const multi = index.findSymbol("find");
  assert.deepEqual(multi.map((h) => h.name).sort(), ["findAccount", "findUser"]);

  const fuzzy = index.findSymbol("usrrepo", undefined, true);
  assert.ok(fuzzy.some((h) => h.name === "UserRepo"), `expected fuzzy hit, got ${JSON.stringify(fuzzy)}`);

  assert.deepEqual(index.findSymbol("noSuchSymbolAnywhere"), []);
  assert.throws(() => index.findSymbol("x", "bogus-kind"), /Unknown symbol kind/);
  assert.deepEqual(index.symbolsInFile("src/account.ts").map((s) => s.name).sort(), ["AccountRepo", "findAccount"]);
});

// ---------------------------------------------------------------------------
// 9. incremental indexing
// ---------------------------------------------------------------------------

test("RepoIndex: only changed files are re-parsed, cache persists, excludes are honoured", async () => {
  const root = await makeRoot();
  await put(root, "src/a.ts", "export function alpha() {}\n");
  await put(root, "src/b.ts", "export class Beta {}\n");
  await put(root, "src/c.py", "def gamma():\n    pass\n");
  await put(root, "README.md", "# hi\n");
  await put(root, "package.json", JSON.stringify({ name: "t", dependencies: { zod: "^3.0.0" } }));
  await put(root, "node_modules/dep/index.js", "export function ignored() {}\n");
  await put(root, ".git/config", "[core]\n");
  await put(root, "dist/bundle.js", "export function built() {}\n");
  await put(root, "build/out.js", "export function built2() {}\n");
  await put(root, ".uca/index.json", "{}");

  const index = new RepoIndex(root);
  assert.equal(await index.load(), false, "no cache yet");

  const first = await index.update();
  // 5 indexable files: src/a.ts, src/b.ts, src/c.py, README.md, package.json —
  // nothing from node_modules/.git/dist/build/.uca.
  assert.equal(first.scanned, 5, `unexpected scan set: ${index.files().map((f) => f.path).join(",")}`);
  assert.equal(first.parsed, 5);
  assert.equal(first.reused, 0);
  assert.equal(first.full, true);
  assert.deepEqual(
    index.files().map((f) => f.path),
    ["README.md", "package.json", "src/a.ts", "src/b.ts", "src/c.py"],
    "index must exclude node_modules/.git/dist/build/.uca",
  );
  for (const excluded of INDEX_EXCLUDED_DIRS) {
    assert.equal(index.files().some((f) => f.path.startsWith(`${excluded}/`)), false, `${excluded} must be excluded`);
  }
  assert.deepEqual(index.getFile("src/a.ts")?.symbols.map((s) => s.name), ["alpha"]);
  assert.deepEqual(index.getFile("src/b.ts")?.symbols.map((s) => s.name), ["Beta"]);
  assert.deepEqual(index.getFile("src/c.py")?.symbols.map((s) => s.name), ["gamma"]);
  assert.equal(index.getFile("src/a.ts")?.language, "typescript");
  assert.equal(index.getFile("src/a.ts")?.size, 27);

  // Cache file was written.
  assert.equal(fs.existsSync(path.join(root, ".uca/index.json")), true);
  const cacheJson = JSON.parse(await fsp.readFile(path.join(root, ".uca/index.json"), "utf8")) as { version: number; files: unknown[] };
  assert.equal(cacheJson.version, 1);
  assert.equal(cacheJson.files.length, 5);

  // Second pass with no changes: zero parses.
  const second = await index.update();
  assert.equal(second.parsed, 0, "unchanged files must not be re-parsed");
  assert.equal(second.reused, 5);
  assert.equal(second.full, false);

  // Touch one file's content: exactly one parse.
  await fsp.writeFile(path.join(root, "src/a.ts"), "export function alpha() {}\nexport function alphaTwo() {}\n");
  bumpMtime(path.join(root, "src/a.ts"));
  const third = await index.update();
  assert.equal(third.parsed, 1, "only the changed file is re-parsed");
  assert.equal(third.reused, 4);
  assert.deepEqual(index.getFile("src/a.ts")?.symbols.map((s) => s.name), ["alpha", "alphaTwo"]);

  // A size change alone (mtime forced back to the old value) is still detected.
  const stBefore = fs.statSync(path.join(root, "src/b.ts"));
  await fsp.writeFile(path.join(root, "src/b.ts"), "export class Beta {}\nexport class BetaTwo {}\n");
  fs.utimesSync(path.join(root, "src/b.ts"), stBefore.atime, stBefore.mtime);
  const fourth = await index.update();
  assert.equal(fourth.parsed, 1, "size change must invalidate the cache even with an unchanged mtime");
  assert.deepEqual(index.getFile("src/b.ts")?.symbols.map((s) => s.name), ["Beta", "BetaTwo"]);

  // A brand new file is parsed and a deleted one disappears.
  await put(root, "src/d.ts", "export const D = 1;\n");
  await fsp.rm(path.join(root, "src/c.py"));
  const fifth = await index.update();
  assert.equal(fifth.parsed, 1);
  assert.equal(fifth.removed, 1);
  assert.equal(fifth.scanned, 5);
  assert.equal(index.getFile("src/c.py"), undefined);
  assert.deepEqual(index.getFile("src/d.ts")?.symbols.map((s) => s.name), ["D"]);

  // force re-parses everything.
  const forced = await index.update({ force: true });
  assert.equal(forced.parsed, 5);
  assert.equal(forced.reused, 0);

  // A fresh instance hydrates from disk and reuses every cached record.
  const reloaded = new RepoIndex(root);
  assert.equal(await reloaded.load(), true);
  assert.equal(reloaded.indexedAt > 0, true);
  assert.deepEqual(reloaded.files().map((f) => f.path), index.files().map((f) => f.path));
  assert.deepEqual(reloaded.getFile("src/d.ts")?.symbols, index.getFile("src/d.ts")?.symbols);
  const afterReload = await reloaded.update();
  assert.equal(afterReload.parsed, 0);
  assert.equal(afterReload.reused, 5);

  // A corrupt cache degrades to a full scan instead of throwing.
  await fsp.writeFile(path.join(root, ".uca/index.json"), "{not json");
  const broken = new RepoIndex(root);
  assert.equal(await broken.load(), false);
  const rescan = await broken.update();
  assert.equal(rescan.parsed, 5);
});

// ---------------------------------------------------------------------------
// 10. change tracking
// ---------------------------------------------------------------------------

test("RepoIndex: change tracking reports added/modified/deleted since the snapshot", async () => {
  const root = await makeRoot();
  await put(root, "keep.ts", "export const keep = 1;\n");
  await put(root, "mod.ts", "export const mod = 1;\n");
  await put(root, "gone.ts", "export const gone = 1;\n");

  const index = new RepoIndex(root);
  await index.refresh();

  let changes = index.changes();
  assert.deepEqual(changes.added, []);
  assert.deepEqual(changes.modified, []);
  assert.deepEqual(changes.deleted, []);
  assert.equal(changes.unchanged, 3);
  assert.equal(changes.total, 0);
  assert.ok(changes.since !== null);

  await put(root, "new.ts", "export function fresh() { return 1; }\n");
  await fsp.writeFile(path.join(root, "mod.ts"), "export const mod = 2;\n// edited\n");
  bumpMtime(path.join(root, "mod.ts"));
  await fsp.rm(path.join(root, "gone.ts"));

  await index.update();
  changes = index.changes();
  assert.deepEqual(changes.added, ["new.ts"]);
  assert.deepEqual(changes.modified, ["mod.ts"]);
  assert.deepEqual(changes.deleted, ["gone.ts"]);
  assert.equal(changes.unchanged, 1);
  assert.equal(changes.total, 3);
  assert.ok(changes.since !== null);
  assert.deepEqual(index.getFile("new.ts")?.symbols.map((s) => s.name), ["fresh"]);

  // Committing the snapshot clears the diff.
  index.commitSnapshot();
  const cleared = index.changes();
  assert.equal(cleared.total, 0);
  assert.equal(cleared.unchanged, 3);

  // refresh() both updates and re-baselines in one call.
  await put(root, "another.ts", "export const another = 1;\n");
  const stats = await index.refresh();
  assert.equal(stats.parsed, 1);
  assert.equal(index.changes().total, 0);
});

// ---------------------------------------------------------------------------
// 11. repo map + dependency map
// ---------------------------------------------------------------------------

test("repoMap: tree, language stats, entrypoints and important files", async () => {
  const root = await makeRoot();
  await put(root, "package.json", JSON.stringify({ name: "demo", dependencies: { zod: "^3.0.0" }, devDependencies: { typescript: "^5.0.0" } }));
  await put(root, "README.md", "# demo\n");
  await put(root, "Dockerfile", "FROM node:24\n");
  await put(root, "src/index.ts", "import { helper } from './helper.js';\nexport function main() { helper(); }\n");
  await put(root, "src/helper.ts", "export function helper() {}\nexport class Widget {}\n");
  await put(root, "src/util/math.py", "def add(a, b):\n    return a + b\n");
  await put(root, "test/index.test.ts", "import { main } from '../src/index.js';\n");
  await put(root, "node_modules/x/index.js", "// ignored\n");

  const index = await buildRepoIndex(root);
  const map = index.repoMap();

  assert.equal(map.fileCount, 7, `files: ${index.files().map((f) => f.path).join(",")}`);
  assert.ok(map.dirCount >= 3);
  assert.ok(map.languages.some((l) => l.language === "typescript" && l.files === 3));
  assert.ok(map.languages.some((l) => l.language === "python" && l.files === 1));
  assert.ok(map.languages.some((l) => l.language === "json"));
  const totalPct = map.languages.reduce((s, l) => s + l.percentage, 0);
  assert.ok(totalPct > 99 && totalPct < 101, `percentages should sum to ~100, got ${totalPct}`);

  assert.ok(map.entrypoints.includes("src/index.ts"));
  assert.ok(map.importantFiles.includes("package.json"));
  assert.ok(map.importantFiles.includes("README.md"));
  assert.ok(map.importantFiles.includes("Dockerfile"));
  assert.ok(map.tests.includes("test/index.test.ts"));
  assert.equal(map.tree.type, "dir");
  const srcDir = map.tree.children?.find((c) => c.name === "src");
  assert.equal(srcDir?.type, "dir");
  assert.ok(srcDir?.children?.some((c) => c.name === "index.ts" && c.language === "typescript"));
  assert.equal(map.tree.children?.some((c) => c.name === "node_modules"), false);
  assert.ok(map.keyFiles.some((f) => f.path === "src/helper.ts" && f.symbolCount === 2));

  const rendered = index.renderRepoMap();
  assert.match(rendered, /Languages:/);
  assert.match(rendered, /src\//);
  assert.match(rendered, /Entrypoints:.*src\/index\.ts/);
});

test("dependencyMap: manifests and local import graph", async () => {
  const root = await makeRoot();
  await put(
    root,
    "package.json",
    JSON.stringify({
      name: "demo",
      dependencies: { zod: "^3.23.8", "@modelcontextprotocol/sdk": "^1.12.0" },
      devDependencies: { typescript: "^5.6.0" },
    }),
  );
  await put(root, "src/index.ts", "import { helper } from './helper.js';\nimport { z } from 'zod';\nimport fs from 'node:fs';\nexport const run = () => helper();\n");
  await put(root, "src/helper.ts", "import type { Widget } from './widget.js';\nexport function helper() {}\n");
  await put(root, "src/widget.ts", "export interface Widget { id: string }\n");
  await put(root, "requirements.txt", "flask==3.0.0\nrequests>=2.31\n# comment\n-r extra.txt\n");
  await put(root, "pyproject.toml", "[project]\nname = \"demo\"\ndependencies = [\n  \"httpx>=0.27\",\n  \"pydantic==2.6.0\",\n]\n\n[tool.poetry.dependencies]\npython = \">=3.11\"\nrich = \"^13.7\"\n");
  await put(root, "go.mod", "module example.com/demo\n\ngo 1.22\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.1\n\tgolang.org/x/text v0.14.0 // indirect\n)\n");
  await put(root, "Cargo.toml", "[package]\nname = \"demo\"\n\n[dependencies]\nserde = { version = \"1.0\", features = [\"derive\"] }\ntokio = \"1.36\"\n\n[dev-dependencies]\nproptest = \"1.4\"\n");

  const index = await buildRepoIndex(root);
  const graph = await index.dependencyMap();

  // Local import edges resolve through the .js -> .ts convention.
  assert.deepEqual(graph.imports["src/index.ts"], ["src/helper.ts"]);
  assert.deepEqual(graph.imports["src/helper.ts"], ["src/widget.ts"]);
  assert.deepEqual(graph.importedBy["src/helper.ts"], ["src/index.ts"]);
  assert.deepEqual(graph.importedBy["src/widget.ts"], ["src/helper.ts"]);
  assert.equal(graph.edgeCount, 2);
  assert.equal(graph.nodeCount, 2);
  const edge = graph.edges.find((e) => e.from === "src/index.ts");
  assert.equal(edge?.specifier, "./helper.js");
  assert.equal(edge?.to, "src/helper.ts");

  // External packages are recorded separately, node: builtins are not.
  assert.ok(graph.external["zod"]);
  assert.deepEqual(graph.external["zod"], ["src/index.ts"]);
  assert.equal(graph.external["node:fs"], undefined);

  // Declared dependencies from every manifest format.
  const npm = graph.manifests.find((m) => m.manifest === "package.json");
  assert.ok(npm);
  assert.equal(npm?.ecosystem, "npm");
  assert.deepEqual(npm?.dependencies.map((d) => `${d.name}@${d.scope}`).sort(), [
    "@modelcontextprotocol/sdk@runtime",
    "typescript@dev",
    "zod@runtime",
  ]);

  const pip = graph.manifests.find((m) => m.manifest === "requirements.txt");
  assert.deepEqual(pip?.dependencies.map((d) => d.name), ["flask", "requests"]);
  assert.equal(pip?.dependencies.find((d) => d.name === "flask")?.spec, "3.0.0");

  const pyproject = graph.manifests.find((m) => m.manifest === "pyproject.toml");
  const pyNames = pyproject?.dependencies.map((d) => d.name).sort() ?? [];
  assert.ok(pyNames.includes("httpx"), `pyproject names: ${pyNames.join(",")}`);
  assert.ok(pyNames.includes("pydantic"));
  assert.ok(pyNames.includes("rich"));
  assert.equal(pyNames.includes("python"), false, "python version must not be a dependency");

  const go = graph.manifests.find((m) => m.manifest === "go.mod");
  assert.deepEqual(go?.dependencies.map((d) => d.name).sort(), ["github.com/gin-gonic/gin", "golang.org/x/text"]);
  assert.equal(go?.dependencies.find((d) => d.name === "golang.org/x/text")?.scope, "optional");

  const cargo = graph.manifests.find((m) => m.manifest === "Cargo.toml");
  assert.deepEqual(cargo?.dependencies.map((d) => `${d.name}=${d.spec}`).sort(), ["proptest=1.4", "serde=1.0", "tokio=1.36"]);
  assert.equal(cargo?.dependencies.find((d) => d.name === "proptest")?.scope, "dev");

  // Cached on the instance until the next update.
  assert.equal(await index.dependencyMap(), graph);
});

test("depmap helpers: import extraction and specifier resolution", () => {
  assert.deepEqual(extractImports("a.ts", "import x from './b.js';\nexport * from '../c';\nconst d = require('./d');\n"), [
    "./b.js",
    "../c",
    "./d",
  ]);
  assert.deepEqual(extractImports("a.py", "from .pkg import x\nimport os\nimport pkg.mod as m\n"), [".pkg", "os", "pkg.mod"]);
  assert.deepEqual(extractImports("a.c", '#include "local.h"\n#include <stdio.h>\n'), ["local.h"]);

  const known = new Set(["src/b.ts", "src/c/index.ts", "src/d.py", "src/pkg/__init__.py"]);
  assert.equal(resolveImport("src/a.ts", "./b.js", known), "src/b.ts");
  assert.equal(resolveImport("src/a.ts", "../src/c", known), "src/c/index.ts");
  assert.equal(resolveImport("src/a.ts", "zod", known), null);
  assert.equal(resolveImport("src/a.py", ".d", known), "src/d.py");
  assert.equal(resolveImport("src/a.py", ".pkg", known), "src/pkg/__init__.py");

  const manifest = parseManifest("nested/package.json", JSON.stringify({ dependencies: { a: "1" }, devDependencies: { b: "2" } }));
  assert.equal(manifest.ecosystem, "npm");
  assert.deepEqual(manifest.dependencies.map((d) => `${d.manifest}:${d.name}:${d.scope}`), [
    "nested/package.json:a:runtime",
    "nested/package.json:b:dev",
  ]);
  assert.deepEqual(parseManifest("package.json", "{bad json").dependencies, []);
  assert.deepEqual(parseManifest("random.txt", "x").dependencies, []);

  const graph = buildDependencyGraph([
    { path: "a.ts", content: "import './b.js';\nimport 'react';\n" },
    { path: "b.ts", content: "export const b = 1;\n" },
  ]);
  assert.equal(graph.edgeCount, 1);
  assert.deepEqual(graph.external, { react: ["a.ts"] });
});

// ---------------------------------------------------------------------------
// 12. pure helpers
// ---------------------------------------------------------------------------

test("helpers: language detection, binary sniffing, line/byte utilities", () => {
  assert.equal(detectLanguage("src/x.ts"), "typescript");
  assert.equal(detectLanguage("Dockerfile"), "dockerfile");
  assert.equal(detectLanguage("Makefile"), "make");
  assert.equal(detectLanguage("Cargo.toml"), "toml");
  assert.equal(detectLanguage("noext"), "text");
  assert.equal(normalizeLanguage("TS"), "typescript");
  assert.equal(normalizeLanguage("c++"), "cpp");

  assert.equal(isBinaryBuffer(Buffer.from("plain text")), false);
  assert.equal(isBinaryBuffer(Buffer.from([0x41, 0x00, 0x42])), true);
  assert.equal(isBinaryBuffer(Buffer.from([0xff, 0xfe, 0xfd, 0xfc, 0x00])), true);
  assert.equal(isBinaryBuffer(Buffer.alloc(0)), false);

  assert.equal(countLines(""), 0);
  assert.equal(countLines("a"), 1);
  assert.equal(countLines("a\n"), 1);
  assert.equal(countLines("a\nb"), 2);
  assert.equal(countLines("a\nb\n"), 2);
  assert.deepEqual(splitLines("a\nb\n"), ["a", "b"]);
  assert.deepEqual(splitLines(""), []);

  assert.equal(detectLineEnding("a\nb\n"), "lf");
  assert.equal(detectLineEnding("a\r\nb\r\n"), "crlf");
  assert.equal(detectLineEnding("a\rb\r"), "cr");
  assert.equal(detectLineEnding("a\r\nb\n"), "mixed");
  assert.equal(detectLineEnding("abc"), "none");

  // alignEnd never splits a 4-byte emoji.
  const buf = Buffer.from("😀😀", "utf8");
  assert.equal(alignEnd(buf, 0, 2), 4);
  assert.equal(alignEnd(buf, 0, 5), 4);
  assert.equal(alignEnd(buf, 0, 8), 8);
  assert.equal(alignEnd(buf, 4, 6), 8, "a char larger than the window is emitted whole");

  // Glob compilation basics.
  assert.equal(globToRegExp("*.ts").test("a.ts"), true);
  assert.equal(globToRegExp("*.ts").test("src/a.ts"), false);
  assert.equal(globToRegExp("**/*.ts").test("src/deep/a.ts"), true);
  assert.equal(globToRegExp("**/*.ts").test("a.ts"), true);
  assert.equal(globToRegExp("src/**").test("src/a/b/c.ts"), true);
  assert.equal(globToRegExp("?.ts").test("ab.ts"), false);
  assert.equal(globToRegExp("[ab].ts").test("b.ts"), true);
  assert.equal(globToRegExp("*.{ts,js}").test("x.js"), true);
  assert.equal(globToRegExp("A.TS", { caseSensitive: false }).test("a.ts"), true);
});
