/**
 * Workspace-confined filesystem tools.
 *
 * Every path argument goes through `resolveInside()` (util/paths.ts), so absolute
 * paths, `..` traversal and symlink escapes are rejected before any I/O happens.
 * Reads never silently truncate: oversized files return an explicit descriptor
 * that tells the caller to page with `read_file_chunk` / `read_file_range`.
 */
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import readline from "node:readline";
import { loadConfig } from "../util/config.js";
import { relFrom, resolveInside } from "../util/paths.js";
import { FsError, PolicyError, wrapFsError } from "./errors.js";
import { detectLanguage, isBinaryBuffer, normalizeLanguage } from "./language.js";
import {
  alignEnd,
  alignStart,
  compareStrings,
  countLines,
  detectLineEnding,
  escapeRegExp,
  globToRegExp,
  hasGlobMeta,
  intOption,
  splitLines,
} from "./text.js";
import { diffText, type DiffResult } from "./diff.js";

const cfg = loadConfig();

/** Directories skipped by listing/search/walk unless the caller opts in. */
export const DEFAULT_IGNORED_DIRS: readonly string[] = [
  "node_modules",
  ".git",
  "dist",
  "build",
  ".uca",
];

/** Paths that may never be written or deleted (git internals). */
const WRITE_DENY_SEGMENTS: readonly string[] = [".git"];

const MAX_RANGE_LINES = 5000;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ReadFileOptions {
  /** Files larger than this are not returned whole (default: config.maxOutputBytes). */
  maxBytes?: number;
  /** Also return the raw base64 payload for binary files (default true). */
  allowBinary?: boolean;
}

export interface ReadFileResult {
  path: string;
  size: number;
  mtimeMs: number;
  language: string;
  binary: boolean;
  /** Text content, or base64 when `binary` is true. */
  content: string;
  encoding: "utf8" | "base64";
  totalBytes: number;
  totalLines: number;
  truncated: boolean;
  /** Present only when the file is too large to return whole. */
  requiresChunking?: boolean;
  lineEnding?: string;
  sha256?: string;
}

/** Descriptor returned instead of content for files above the size limit. */
export interface ChunkingDescriptor {
  path: string;
  truncated: false;
  requiresChunking: true;
  totalBytes: number;
  totalLines: number;
  language: string;
  binary: boolean;
  maxChunkBytes: number;
  defaultChunkBytes: number;
  hint: string;
}

export interface ReadChunkOptions {
  offset?: number;
  size?: number;
  encoding?: "utf8" | "base64";
}

export interface ReadChunkResult {
  path: string;
  /** Actual byte offset the returned content starts at (may be > requested offset). */
  offset: number;
  requestedOffset: number;
  requestedSize: number;
  bytesRead: number;
  nextOffset: number;
  eof: boolean;
  totalBytes: number;
  content: string;
  encoding: "utf8" | "base64";
}

export interface ReadRangeOptions {
  startLine?: number;
  endLine?: number;
  /** Page size when `endLine` is omitted (default 200, max 5000). */
  maxLines?: number;
  includeLineNumbers?: boolean;
}

export interface ReadRangeResult {
  path: string;
  startLine: number;
  endLine: number;
  lines: string[];
  /** `lines` with `<n>│` prefixes when `includeLineNumbers` is set. */
  text: string;
  totalLines: number;
  hasMore: boolean;
  nextStartLine: number | null;
  totalBytes: number;
}

export interface WriteFileOptions {
  /** Create parent directories (default true). */
  createDirs?: boolean;
  /** Refuse to overwrite an existing file (default false). */
  overwrite?: boolean;
  /** Write atomically via temp file + rename (default true). */
  atomic?: boolean;
}

export interface WriteFileResult {
  path: string;
  bytesWritten: number;
  created: boolean;
  size: number;
  mtimeMs: number;
}

export interface EditFileOptions {
  oldString?: string;
  newString?: string;
  /** Replace every occurrence instead of requiring a single unique match. */
  replaceAll?: boolean;
  /** Restrict the search to this 1-based inclusive line range. */
  startLine?: number;
  endLine?: number;
}

export interface EditFileResult {
  path: string;
  replacements: number;
  bytesBefore: number;
  bytesAfter: number;
  firstChangedLine: number;
  diff: string;
}

export interface DeleteFileOptions {
  /** Delete a directory tree (default false: files and empty dirs only). */
  recursive?: boolean;
}

export interface DeleteFileResult {
  path: string;
  type: "file" | "dir" | "symlink";
  deleted: true;
}

export interface DirEntry {
  name: string;
  path: string;
  type: "file" | "dir" | "symlink" | "other";
  size: number;
  mtimeMs: number;
  language?: string;
}

export interface ListDirectoryOptions {
  limit?: number;
  offset?: number;
  /** Include the dirs in DEFAULT_IGNORED_DIRS (default false). */
  includeIgnored?: boolean;
  /** Extra directory names to skip. */
  ignoreDirs?: string[];
  /** Sort key (default "name"). */
  sort?: "name" | "size" | "mtime";
  descending?: boolean;
  /** Recurse into subdirectories (default false). */
  recursive?: boolean;
  maxDepth?: number;
}

export interface ListDirectoryResult {
  path: string;
  entries: DirEntry[];
  total: number;
  limit: number;
  offset: number;
  hasMore: boolean;
  nextOffset: number | null;
}

export interface SearchFilesOptions {
  limit?: number;
  offset?: number;
  /** Match the whole relative path instead of just the basename (default false). */
  matchPath?: boolean;
  caseSensitive?: boolean;
  /** Treat `pattern` as a regex source (default false: glob-ish). */
  regex?: boolean;
  /** Extra directory names to skip. */
  ignoreDirs?: string[];
  maxDepth?: number;
  types?: "file" | "dir" | "both";
}

export interface SearchFilesResult {
  pattern: string;
  matches: { path: string; type: "file" | "dir"; size: number; mtimeMs: number }[];
  total: number;
  limit: number;
  offset: number;
  hasMore: boolean;
  nextOffset: number | null;
}

export interface SearchContentOptions {
  /** Regex source instead of a literal substring (default false). */
  regex?: boolean;
  caseSensitive?: boolean;
  /** Context lines before/after each match (default 0). */
  contextLines?: number;
  limit?: number;
  /** Opaque cursor from a previous page. */
  cursor?: string;
  /** Only search files whose path matches this glob. */
  glob?: string;
  /** Max file size considered, in bytes (default 2 MiB). */
  maxFileBytes?: number;
  ignoreDirs?: string[];
  maxMatchesPerFile?: number;
}

export interface ContentMatch {
  path: string;
  line: number;
  column: number;
  text: string;
  before: string[];
  after: string[];
}

export interface SearchContentResult {
  pattern: string;
  matches: ContentMatch[];
  filesScanned: number;
  filesWithMatches: number;
  /** Total matches on this page. */
  count: number;
  limit: number;
  hasMore: boolean;
  nextCursor: string | null;
}

export interface FileMetadata {
  path: string;
  type: "file" | "dir" | "symlink";
  size: number;
  mtimeMs: number;
  mtimeIso: string;
  birthtimeMs: number;
  ctimeMs: number;
  mode: number;
  language: string;
  lines: number;
  binary: boolean;
  sha256: string;
  lineEnding: string;
}

export interface CompareFilesOptions {
  /** Diff context lines (default 3). */
  context?: number;
  /** Ignore runs of whitespace differences (default false). */
  ignoreWhitespace?: boolean;
}

export interface CompareFilesResult {
  identical: boolean;
  a: { path: string; size: number; lines: number };
  b: { path: string; size: number; lines: number };
  unified: string;
  stats: DiffResult["stats"];
  hunks: number;
}

// ---------------------------------------------------------------------------
// Guards / helpers
// ---------------------------------------------------------------------------

function abs(root: string, rel: string): string {
  return resolveInside(root, rel);
}

function rel(root: string, target: string): string {
  try {
    return relFrom(root, target);
  } catch {
    return target;
  }
}

function assertWritable(root: string, target: string): void {
  const parts = rel(root, target).split("/");
  for (const seg of WRITE_DENY_SEGMENTS) {
    if (parts.includes(seg)) {
      throw new PolicyError(`Refusing to modify git internals: ${rel(root, target)}`);
    }
  }
}

function isIgnoredRel(relPath: string, extras: readonly string[]): boolean {
  const parts = relPath.split("/");
  for (const part of parts) {
    if (DEFAULT_IGNORED_DIRS.includes(part) || extras.includes(part)) return true;
  }
  return false;
}

async function statOrThrow(target: string, display: string): Promise<fs.Stats> {
  try {
    return await fsp.stat(target);
  } catch (e) {
    throw wrapFsError(e, display);
  }
}

/** Stream a file to count newline bytes without loading it into memory. */
async function countFileLines(target: string, size: number): Promise<number> {
  if (size === 0) return 0;
  let newlines = 0;
  let lastByte = -1;
  const stream = fs.createReadStream(target, { highWaterMark: 1 << 16 });
  for await (const chunk of stream as AsyncIterable<Buffer>) {
    for (let i = 0; i < chunk.length; i++) if (chunk[i] === 0x0a) newlines++;
    if (chunk.length > 0) lastByte = chunk[chunk.length - 1];
  }
  return lastByte === 0x0a ? newlines : newlines + 1;
}

async function sha256OfFile(target: string): Promise<string> {
  const hash = crypto.createHash("sha256");
  const stream = fs.createReadStream(target);
  for await (const chunk of stream as AsyncIterable<Buffer>) hash.update(chunk);
  return hash.digest("hex");
}

async function readWholeBuffer(target: string): Promise<Buffer> {
  return fsp.readFile(target);
}

export interface WalkEntry {
  /** POSIX-style path relative to root. */
  path: string;
  abs: string;
  type: "file" | "dir" | "symlink" | "other";
  size: number;
  mtimeMs: number;
}

/**
 * Depth-first walk of `root`, skipping ignored dirs and never following symlinks.
 * Deterministic (lexical order per directory).
 */
export async function* walkFiles(
  root: string,
  opts: { ignoreDirs?: string[]; maxDepth?: number; includeDirs?: boolean; startRel?: string } = {},
): AsyncGenerator<WalkEntry> {
  const extras = opts.ignoreDirs ?? [];
  const maxDepth = opts.maxDepth ?? Number.POSITIVE_INFINITY;
  const startAbs = opts.startRel ? abs(root, opts.startRel) : abs(root, ".");

  async function* recurse(dir: string, depth: number): AsyncGenerator<WalkEntry> {
    let names: string[];
    try {
      names = await fsp.readdir(dir);
    } catch (e) {
      throw wrapFsError(e, rel(root, dir));
    }
    names.sort(compareStrings);
    for (const name of names) {
      const full = path.join(dir, name);
      const relPath = rel(root, full);
      let st: fs.Stats;
      try {
        st = await fsp.lstat(full);
      } catch {
        continue;
      }
      const type: WalkEntry["type"] = st.isSymbolicLink()
        ? "symlink"
        : st.isDirectory()
          ? "dir"
          : st.isFile()
            ? "file"
            : "other";
      if (type === "dir") {
        if (DEFAULT_IGNORED_DIRS.includes(name) || extras.includes(name)) continue;
        if (opts.includeDirs) {
          yield { path: relPath, abs: full, type, size: st.size, mtimeMs: st.mtimeMs };
        }
        if (depth < maxDepth) yield* recurse(full, depth + 1);
      } else {
        yield { path: relPath, abs: full, type, size: st.size, mtimeMs: st.mtimeMs };
      }
    }
  }

  const st = await statOrThrow(startAbs, opts.startRel ?? ".");
  if (st.isDirectory()) {
    yield* recurse(startAbs, 0);
  } else {
    yield { path: rel(root, startAbs), abs: startAbs, type: "file", size: st.size, mtimeMs: st.mtimeMs };
  }
}

// ---------------------------------------------------------------------------
// read_file
// ---------------------------------------------------------------------------

export async function read_file(
  root: string,
  relPath: string,
  opts: ReadFileOptions = {},
): Promise<ReadFileResult | ChunkingDescriptor> {
  const target = abs(root, relPath);
  const display = rel(root, target);
  const st = await statOrThrow(target, display);
  if (st.isDirectory()) throw new FsError(`EISDIR: ${display} is a directory (use list_directory)`, "EISDIR");

  const maxBytes = intOption(opts.maxBytes, cfg.maxOutputBytes, 1);
  const language = detectLanguage(display);

  if (st.size > maxBytes) {
    const totalLines = await countFileLines(target, st.size);
    const head = Buffer.alloc(Math.min(st.size, 4096));
    const fd = await fsp.open(target, "r");
    try {
      await fd.read(head, 0, head.length, 0);
    } finally {
      await fd.close();
    }
    return {
      path: display,
      truncated: false,
      requiresChunking: true,
      totalBytes: st.size,
      totalLines,
      language,
      binary: isBinaryBuffer(head),
      maxChunkBytes: cfg.maxChunkBytes,
      defaultChunkBytes: cfg.defaultChunkBytes,
      hint: `File is ${st.size} bytes (> ${maxBytes}). Use read_file_chunk(offset,size) or read_file_range(startLine,endLine).`,
    };
  }

  const buf = await readWholeBuffer(target);
  const binary = isBinaryBuffer(buf);
  const text = buf.toString("utf8");
  return {
    path: display,
    size: st.size,
    mtimeMs: st.mtimeMs,
    language,
    binary,
    content: binary ? buf.toString("base64") : text,
    encoding: binary ? "base64" : "utf8",
    totalBytes: st.size,
    totalLines: binary ? 0 : countLines(text),
    truncated: false,
    lineEnding: binary ? "binary" : detectLineEnding(text),
    sha256: crypto.createHash("sha256").update(buf).digest("hex"),
  };
}

// ---------------------------------------------------------------------------
// read_file_chunk
// ---------------------------------------------------------------------------

export async function read_file_chunk(
  root: string,
  relPath: string,
  opts: ReadChunkOptions = {},
): Promise<ReadChunkResult> {
  const target = abs(root, relPath);
  const display = rel(root, target);
  const st = await statOrThrow(target, display);
  if (st.isDirectory()) throw new FsError(`EISDIR: ${display} is a directory`, "EISDIR");

  const requestedOffset = intOption(opts.offset, 0, 0);
  const requestedSize = intOption(opts.size, cfg.defaultChunkBytes, 1);
  // Hard clamp: a single chunk can never exceed maxChunkBytes.
  const size = Math.min(requestedSize, cfg.maxChunkBytes);
  const encoding = opts.encoding ?? "utf8";
  const totalBytes = st.size;

  if (requestedOffset >= totalBytes) {
    return {
      path: display,
      offset: totalBytes,
      requestedOffset,
      requestedSize,
      bytesRead: 0,
      nextOffset: totalBytes,
      eof: true,
      totalBytes,
      content: "",
      encoding,
    };
  }

  // Read size+4 bytes so we can detect a multi-byte char straddling the boundary.
  const windowLen = Math.min(size + 4, totalBytes - requestedOffset);
  const buf = Buffer.alloc(windowLen);
  const handle = await fsp.open(target, "r");
  try {
    await handle.read(buf, 0, windowLen, requestedOffset);
  } finally {
    await handle.close();
  }

  // Never start inside a multi-byte character.
  const startInBuf = encoding === "base64" ? 0 : alignStart(buf, 0);
  const offset = requestedOffset + startInBuf;
  const payload = buf.subarray(startInBuf);
  const endInPayload = encoding === "base64" ? Math.min(size, payload.length) : alignEnd(payload, 0, Math.min(size, payload.length));
  const slice = payload.subarray(0, endInPayload);
  const nextOffset = offset + slice.length;

  return {
    path: display,
    offset,
    requestedOffset,
    requestedSize,
    bytesRead: slice.length,
    nextOffset,
    eof: nextOffset >= totalBytes,
    totalBytes,
    content: encoding === "base64" ? slice.toString("base64") : slice.toString("utf8"),
    encoding,
  };
}

// ---------------------------------------------------------------------------
// read_file_range
// ---------------------------------------------------------------------------

export async function read_file_range(
  root: string,
  relPath: string,
  opts: ReadRangeOptions = {},
): Promise<ReadRangeResult> {
  const target = abs(root, relPath);
  const display = rel(root, target);
  const st = await statOrThrow(target, display);
  if (st.isDirectory()) throw new FsError(`EISDIR: ${display} is a directory`, "EISDIR");

  const startLine = intOption(opts.startLine, 1, 1);
  const pageSize = Math.min(intOption(opts.maxLines, 200, 1), MAX_RANGE_LINES);
  const requestedEnd = opts.endLine === undefined ? undefined : intOption(opts.endLine, startLine, 1);
  const endLine = requestedEnd === undefined ? startLine + pageSize - 1 : Math.min(requestedEnd, startLine + MAX_RANGE_LINES - 1);

  const collected: string[] = [];
  let totalLines = 0;
  const rl = readline.createInterface({
    input: fs.createReadStream(target, { encoding: "utf8" }),
    crlfDelay: Infinity,
  });
  try {
    for await (const line of rl) {
      totalLines++;
      if (totalLines >= startLine && totalLines <= endLine) collected.push(line);
    }
  } finally {
    rl.close();
  }

  const lastReturned = collected.length > 0 ? startLine + collected.length - 1 : startLine - 1;
  const hasMore = totalLines > Math.max(endLine, lastReturned);
  const text = opts.includeLineNumbers
    ? collected.map((l, i) => `${startLine + i}│${l}`).join("\n")
    : collected.join("\n");

  return {
    path: display,
    startLine,
    endLine: lastReturned,
    lines: collected,
    text,
    totalLines,
    hasMore,
    nextStartLine: hasMore ? Math.max(endLine, lastReturned) + 1 : null,
    totalBytes: st.size,
  };
}

// ---------------------------------------------------------------------------
// write_file / create_file
// ---------------------------------------------------------------------------

async function ensureParent(target: string, createDirs: boolean): Promise<void> {
  const dir = path.dirname(target);
  if (createDirs) {
    await fsp.mkdir(dir, { recursive: true });
    return;
  }
  try {
    await fsp.access(dir);
  } catch {
    throw new FsError(`ENOENT: parent directory does not exist (${path.basename(dir)})`, "ENOENT");
  }
}

export async function write_file(
  root: string,
  relPath: string,
  content: string,
  opts: WriteFileOptions = {},
): Promise<WriteFileResult> {
  const target = abs(root, relPath);
  const display = rel(root, target);
  assertWritable(root, target);
  if (typeof content !== "string") throw new FsError("content must be a string", "EINVAL");

  const existed = fs.existsSync(target);
  if (existed) {
    const st = await statOrThrow(target, display);
    if (st.isDirectory()) throw new FsError(`EISDIR: ${display} is a directory`, "EISDIR");
    if (opts.overwrite === false) {
      throw new FsError(`EEXIST: ${display} already exists (use edit_file to modify it)`, "EEXIST");
    }
  }
  await ensureParent(target, opts.createDirs !== false);

  const data = Buffer.from(content, "utf8");
  if (opts.atomic === false) {
    await fsp.writeFile(target, data);
  } else {
    const tmp = path.join(path.dirname(target), `.${path.basename(target)}.${process.pid}.${Date.now()}.tmp`);
    try {
      await fsp.writeFile(tmp, data, { mode: existed ? (await fsp.stat(target)).mode : 0o644 });
      await fsp.rename(tmp, target);
    } catch (e) {
      await fsp.rm(tmp, { force: true }).catch(() => {});
      throw wrapFsError(e, display);
    }
  }
  const st = await statOrThrow(target, display);
  return { path: display, bytesWritten: data.length, created: !existed, size: st.size, mtimeMs: st.mtimeMs };
}

/** Create a new file; fails if the path already exists (atomic `wx` open). */
export async function create_file(
  root: string,
  relPath: string,
  content = "",
  opts: { createDirs?: boolean } = {},
): Promise<WriteFileResult> {
  const target = abs(root, relPath);
  const display = rel(root, target);
  assertWritable(root, target);
  if (fs.existsSync(target)) {
    throw new FsError(`EEXIST: ${display} already exists`, "EEXIST");
  }
  await ensureParent(target, opts.createDirs !== false);
  const data = Buffer.from(content, "utf8");
  let handle: fsp.FileHandle | undefined;
  try {
    handle = await fsp.open(target, "wx", 0o644);
    await handle.writeFile(data);
  } catch (e) {
    throw wrapFsError(e, display);
  } finally {
    await handle?.close();
  }
  const st = await statOrThrow(target, display);
  return { path: display, bytesWritten: data.length, created: true, size: st.size, mtimeMs: st.mtimeMs };
}

// ---------------------------------------------------------------------------
// edit_file
// ---------------------------------------------------------------------------

function countOccurrences(haystack: string, needle: string): number {
  if (needle.length === 0) return 0;
  let count = 0;
  let idx = haystack.indexOf(needle);
  while (idx !== -1) {
    count++;
    idx = haystack.indexOf(needle, idx + needle.length);
  }
  return count;
}

export async function edit_file(
  root: string,
  relPath: string,
  edit: EditFileOptions,
): Promise<EditFileResult> {
  const target = abs(root, relPath);
  const display = rel(root, target);
  assertWritable(root, target);
  const st = await statOrThrow(target, display);
  if (st.isDirectory()) throw new FsError(`EISDIR: ${display} is a directory`, "EISDIR");

  const original = await fsp.readFile(target, "utf8");
  const newString = edit.newString ?? "";
  const rangeMode = edit.startLine !== undefined || edit.endLine !== undefined;

  let updated: string;
  let replacements = 0;
  let firstChangedLine = 1;

  if (rangeMode) {
    const lines = original.split("\n");
    const startLine = intOption(edit.startLine, 1, 1);
    const endLine = intOption(edit.endLine, lines.length, 1);
    if (startLine > endLine) throw new FsError(`Invalid line range ${startLine}..${endLine}`, "EINVAL");
    if (startLine > lines.length) {
      throw new FsError(`Line range starts past end of file (${lines.length} lines)`, "ERANGE");
    }
    const from = startLine - 1;
    const to = Math.min(endLine, lines.length);
    const scoped = lines.slice(from, to).join("\n");
    const oldString = edit.oldString;

    if (oldString === undefined || oldString === "") {
      // Whole-range replacement.
      updated = [...lines.slice(0, from), ...newString.split("\n"), ...lines.slice(to)].join("\n");
      replacements = 1;
      firstChangedLine = startLine;
    } else {
      const hits = countOccurrences(scoped, oldString);
      if (hits === 0) {
        throw new FsError(
          `oldString not found in ${display} within lines ${startLine}-${to}`,
          "ENOMATCH",
        );
      }
      if (hits > 1 && !edit.replaceAll) {
        throw new FsError(
          `oldString appears ${hits} times in ${display} within lines ${startLine}-${to}; ` +
            `provide more context or set replaceAll: true`,
          "EAMBIGUOUS",
        );
      }
      const scopedUpdated = edit.replaceAll
        ? scoped.split(oldString).join(newString)
        : scoped.replace(oldString, newString);
      updated = [...lines.slice(0, from), ...scopedUpdated.split("\n"), ...lines.slice(to)].join("\n");
      replacements = hits;
      firstChangedLine = startLine + scoped.slice(0, scoped.indexOf(oldString)).split("\n").length - 1;
    }
  } else {
    const oldString = edit.oldString;
    if (typeof oldString !== "string" || oldString.length === 0) {
      throw new FsError("oldString is required (non-empty) unless startLine/endLine is given", "EINVAL");
    }
    const hits = countOccurrences(original, oldString);
    if (hits === 0) throw new FsError(`oldString not found in ${display}`, "ENOMATCH");
    if (hits > 1 && !edit.replaceAll) {
      throw new FsError(
        `oldString appears ${hits} times in ${display}; include more surrounding context or set replaceAll: true`,
        "EAMBIGUOUS",
      );
    }
    if (edit.replaceAll) {
      updated = original.split(oldString).join(newString);
      replacements = hits;
    } else {
      updated = original.replace(oldString, newString);
      replacements = 1;
    }
    const idx = original.indexOf(oldString);
    firstChangedLine = idx <= 0 ? 1 : original.slice(0, idx).split("\n").length;
  }

  await fsp.writeFile(target, updated, "utf8");
  const d = diffText(original, updated, { context: 2, aLabel: `a/${display}`, bLabel: `b/${display}` });
  return {
    path: display,
    replacements,
    bytesBefore: Buffer.byteLength(original, "utf8"),
    bytesAfter: Buffer.byteLength(updated, "utf8"),
    firstChangedLine,
    diff: d.unified,
  };
}

// ---------------------------------------------------------------------------
// delete_file
// ---------------------------------------------------------------------------

export async function delete_file(
  root: string,
  relPath: string,
  opts: DeleteFileOptions = {},
): Promise<DeleteFileResult> {
  const target = abs(root, relPath);
  const display = rel(root, target);
  assertWritable(root, target);
  if (path.resolve(target) === path.resolve(root)) {
    throw new PolicyError("Refusing to delete the workspace root");
  }
  const st = await statOrThrow(target, display);
  if (st.isDirectory()) {
    const children = await fsp.readdir(target);
    if (!opts.recursive && children.length > 0) {
      throw new FsError(
        `ENOTEMPTY: ${display} is a non-empty directory (pass recursive: true)`,
        "ENOTEMPTY",
      );
    }
    if (opts.recursive) {
      // Guard against deleting a directory that contains a protected segment.
      for (const part of rel(root, target).split("/")) {
        if (WRITE_DENY_SEGMENTS.includes(part)) {
          throw new PolicyError(`Refusing to delete git internals: ${display}`);
        }
      }
      await fsp.rm(target, { recursive: true, force: false });
    } else {
      await fsp.rmdir(target);
    }
    return { path: display, type: "dir", deleted: true };
  }
  await fsp.unlink(target);
  return { path: display, type: st.isSymbolicLink() ? "symlink" : "file", deleted: true };
}

// ---------------------------------------------------------------------------
// list_directory
// ---------------------------------------------------------------------------

function entryType(st: fs.Stats): DirEntry["type"] {
  if (st.isSymbolicLink()) return "symlink";
  if (st.isDirectory()) return "dir";
  if (st.isFile()) return "file";
  return "other";
}

export async function list_directory(
  root: string,
  relPath = ".",
  opts: ListDirectoryOptions = {},
): Promise<ListDirectoryResult> {
  const target = abs(root, relPath);
  const display = rel(root, target);
  const st = await statOrThrow(target, display);
  if (!st.isDirectory()) throw new FsError(`ENOTDIR: ${display} is not a directory`, "ENOTDIR");

  const extras = opts.ignoreDirs ?? [];
  const limit = intOption(opts.limit, 200, 1);
  const offset = intOption(opts.offset, 0, 0);
  const recursive = opts.recursive === true;
  const maxDepth = intOption(opts.maxDepth, recursive ? 10 : 1, 0);

  const all: DirEntry[] = [];
  const collect = async (dir: string, depth: number): Promise<void> => {
    const names = (await fsp.readdir(dir)).sort(compareStrings);
    for (const name of names) {
      const full = path.join(dir, name);
      let est: fs.Stats;
      try {
        est = await fsp.lstat(full);
      } catch {
        continue;
      }
      const type = entryType(est);
      if (type === "dir" && (DEFAULT_IGNORED_DIRS.includes(name) || extras.includes(name)) && !opts.includeIgnored) {
        continue;
      }
      const entry: DirEntry = {
        name,
        path: rel(root, full),
        type,
        size: est.size,
        mtimeMs: est.mtimeMs,
      };
      if (type === "file") entry.language = detectLanguage(name);
      all.push(entry);
      if (recursive && type === "dir" && depth + 1 < maxDepth) await collect(full, depth + 1);
    }
  };
  await collect(target, 0);

  const sortKey = opts.sort ?? "name";
  all.sort((a, b) => {
    // Directories first, then by the chosen key.
    if ((a.type === "dir") !== (b.type === "dir")) return a.type === "dir" ? -1 : 1;
    let cmp = 0;
    if (sortKey === "size") cmp = a.size - b.size;
    else if (sortKey === "mtime") cmp = a.mtimeMs - b.mtimeMs;
    else cmp = compareStrings(a.path, b.path);
    if (cmp === 0) cmp = compareStrings(a.path, b.path);
    return opts.descending ? -cmp : cmp;
  });

  const page = all.slice(offset, offset + limit);
  const hasMore = offset + page.length < all.length;
  return {
    path: display,
    entries: page,
    total: all.length,
    limit,
    offset,
    hasMore,
    nextOffset: hasMore ? offset + page.length : null,
  };
}

// ---------------------------------------------------------------------------
// search_files
// ---------------------------------------------------------------------------

export async function search_files(
  root: string,
  pattern: string,
  opts: SearchFilesOptions = {},
): Promise<SearchFilesResult> {
  if (!pattern || pattern.length === 0) throw new FsError("pattern is required", "EINVAL");
  const limit = intOption(opts.limit, 200, 1);
  const offset = intOption(opts.offset, 0, 0);
  const matchPath = opts.matchPath === true;
  const wantDirs = opts.types === "dir";

  let test: (candidate: string) => boolean;
  if (opts.regex) {
    let re: RegExp;
    try {
      re = new RegExp(pattern, opts.caseSensitive ? "" : "i");
    } catch (e) {
      throw new FsError(`Invalid regex: ${(e as Error).message}`, "EINVAL");
    }
    test = (s) => re.test(s);
  } else {
    const re = globToRegExp(pattern, { caseSensitive: opts.caseSensitive });
    const literal = pattern.toLowerCase();
    test = (s) => re.test(s) || (hasGlobMeta(pattern) ? false : s.toLowerCase().includes(literal));
  }

  const all: SearchFilesResult["matches"] = [];
  for await (const entry of walkFiles(root, {
    ignoreDirs: opts.ignoreDirs,
    maxDepth: opts.maxDepth,
    includeDirs: true,
  })) {
    if (entry.type === "symlink" || entry.type === "other") continue;
    if (wantDirs && entry.type !== "dir") continue;
    if (opts.types !== "both" && opts.types !== "dir" && entry.type !== "file") continue;
    const candidate = matchPath ? entry.path : path.posix.basename(entry.path);
    if (!test(candidate)) continue;
    all.push({ path: entry.path, type: entry.type === "dir" ? "dir" : "file", size: entry.size, mtimeMs: entry.mtimeMs });
  }
  all.sort((a, b) => compareStrings(a.path, b.path));

  const page = all.slice(offset, offset + limit);
  const hasMore = offset + page.length < all.length;
  return {
    pattern,
    matches: page,
    total: all.length,
    limit,
    offset,
    hasMore,
    nextOffset: hasMore ? offset + page.length : null,
  };
}

// ---------------------------------------------------------------------------
// search_content
// ---------------------------------------------------------------------------

interface ContentCursor {
  /** Last file path that was (partially) consumed. */
  p: string;
  /** Line number of the last emitted match. */
  l: number;
  /** Index of the last emitted match on that line. */
  i: number;
}

function encodeCursor(c: ContentCursor): string {
  return Buffer.from(JSON.stringify(c), "utf8").toString("base64url");
}

function decodeCursor(cursor: string): ContentCursor {
  try {
    const parsed = JSON.parse(Buffer.from(cursor, "base64url").toString("utf8")) as ContentCursor;
    if (typeof parsed.p !== "string" || typeof parsed.l !== "number") throw new Error("bad shape");
    return { p: parsed.p, l: parsed.l, i: typeof parsed.i === "number" ? parsed.i : 0 };
  } catch {
    throw new FsError("Invalid cursor", "EINVAL");
  }
}

export async function search_content(
  root: string,
  pattern: string,
  opts: SearchContentOptions = {},
): Promise<SearchContentResult> {
  if (!pattern || pattern.length === 0) throw new FsError("pattern is required", "EINVAL");

  let re: RegExp;
  if (opts.regex) {
    try {
      re = new RegExp(pattern, opts.caseSensitive ? "g" : "gi");
    } catch (e) {
      throw new FsError(`Invalid regex: ${(e as Error).message}`, "EINVAL");
    }
  } else {
    re = new RegExp(escapeRegExp(pattern), opts.caseSensitive ? "g" : "gi");
  }

  const limit = intOption(opts.limit, 100, 1);
  const contextLines = intOption(opts.contextLines, 0, 0);
  const maxFileBytes = intOption(opts.maxFileBytes, 2 * 1024 * 1024, 1);
  const maxMatchesPerFile = intOption(opts.maxMatchesPerFile, 200, 1);
  const globRe = opts.glob ? globToRegExp(opts.glob) : null;
  const cursor = opts.cursor ? decodeCursor(opts.cursor) : null;

  const matches: ContentMatch[] = [];
  let filesScanned = 0;
  let filesWithMatches = 0;
  let hasMore = false;
  let lastCursor: ContentCursor | null = null;

  const files: { path: string; abs: string; size: number }[] = [];
  for await (const entry of walkFiles(root, { ignoreDirs: opts.ignoreDirs })) {
    if (entry.type !== "file") continue;
    if (globRe && !globRe.test(entry.path)) continue;
    files.push({ path: entry.path, abs: entry.abs, size: entry.size });
  }
  files.sort((a, b) => compareStrings(a.path, b.path));

  outer: for (const file of files) {
    if (cursor && file.path < cursor.p) continue;
    if (file.size > maxFileBytes) continue;

    let buf: Buffer;
    try {
      buf = await fsp.readFile(file.abs);
    } catch {
      continue;
    }
    if (isBinaryBuffer(buf)) continue;
    filesScanned++;

    const lines = splitLines(buf.toString("utf8"));
    let fileMatches = 0;
    let sawMatch = false;

    for (let li = 0; li < lines.length; li++) {
      const lineNo = li + 1;
      if (cursor && file.path === cursor.p && lineNo < cursor.l) continue;
      const line = lines[li];
      re.lastIndex = 0;
      let m: RegExpExecArray | null;
      let matchIndexOnLine = 0;
      while ((m = re.exec(line)) !== null) {
        matchIndexOnLine++;
        if (cursor && file.path === cursor.p && lineNo === cursor.l && matchIndexOnLine <= cursor.i) {
          if (m[0].length === 0) re.lastIndex++;
          continue;
        }
        if (matches.length >= limit) {
          hasMore = true;
          break outer;
        }
        sawMatch = true;
        fileMatches++;
        const before = contextLines > 0 ? lines.slice(Math.max(0, li - contextLines), li) : [];
        const after = contextLines > 0 ? lines.slice(li + 1, li + 1 + contextLines) : [];
        matches.push({
          path: file.path,
          line: lineNo,
          column: m.index + 1,
          text: line,
          before,
          after,
        });
        lastCursor = { p: file.path, l: lineNo, i: matchIndexOnLine };
        if (fileMatches >= maxMatchesPerFile) break;
        // Zero-length matches would loop forever.
        if (m[0].length === 0) re.lastIndex++;
      }
      if (fileMatches >= maxMatchesPerFile) break;
    }
    if (sawMatch) filesWithMatches++;
  }

  // `nextCursor` points at the last emitted match so the next page resumes after it.
  const nextCursor: string | null = hasMore && lastCursor ? encodeCursor(lastCursor) : null;

  return {
    pattern,
    matches,
    filesScanned,
    filesWithMatches,
    count: matches.length,
    limit,
    hasMore,
    nextCursor,
  };
}

// ---------------------------------------------------------------------------
// get_file_metadata
// ---------------------------------------------------------------------------

export async function get_file_metadata(
  root: string,
  relPath: string,
  opts: { includeHash?: boolean } = {},
): Promise<FileMetadata> {
  const target = abs(root, relPath);
  const display = rel(root, target);
  const st = await statOrThrow(target, display);
  const type: FileMetadata["type"] = st.isDirectory() ? "dir" : st.isSymbolicLink() ? "symlink" : "file";
  const language = type === "dir" ? "dir" : detectLanguage(display);

  if (type !== "file") {
    return {
      path: display,
      type,
      size: st.size,
      mtimeMs: st.mtimeMs,
      mtimeIso: new Date(st.mtimeMs).toISOString(),
      birthtimeMs: st.birthtimeMs,
      ctimeMs: st.ctimeMs,
      mode: st.mode,
      language,
      lines: 0,
      binary: false,
      sha256: "",
      lineEnding: "none",
    };
  }

  let binary = false;
  let lines = 0;
  let lineEnding = "none";
  let sha256 = "";
  const head = Buffer.alloc(Math.min(st.size, 8192));
  const handle = await fsp.open(target, "r");
  try {
    await handle.read(head, 0, head.length, 0);
  } finally {
    await handle.close();
  }
  binary = isBinaryBuffer(head);
  if (!binary) {
    const buf = await fsp.readFile(target);
    const text = buf.toString("utf8");
    lines = countLines(text);
    lineEnding = detectLineEnding(text);
    if (opts.includeHash === false) sha256 = "";
    else sha256 = crypto.createHash("sha256").update(buf).digest("hex");
  } else if (opts.includeHash !== false) {
    sha256 = await sha256OfFile(target);
  }

  return {
    path: display,
    type,
    size: st.size,
    mtimeMs: st.mtimeMs,
    mtimeIso: new Date(st.mtimeMs).toISOString(),
    birthtimeMs: st.birthtimeMs,
    ctimeMs: st.ctimeMs,
    mode: st.mode,
    language,
    lines,
    binary,
    sha256,
    lineEnding,
  };
}

// ---------------------------------------------------------------------------
// compare_files
// ---------------------------------------------------------------------------

function normalizeWhitespace(text: string): string {
  return text
    .split("\n")
    .map((l) => l.replace(/[ \t]+/g, " ").trimEnd())
    .join("\n");
}

export async function compare_files(
  root: string,
  relPathA: string,
  relPathB: string,
  opts: CompareFilesOptions = {},
): Promise<CompareFilesResult> {
  const aAbs = abs(root, relPathA);
  const bAbs = abs(root, relPathB);
  const aRel = rel(root, aAbs);
  const bRel = rel(root, bAbs);

  const [aSt, bSt] = await Promise.all([statOrThrow(aAbs, aRel), statOrThrow(bAbs, bRel)]);
  if (aSt.isDirectory() || bSt.isDirectory()) {
    throw new FsError("compare_files only supports files (directories are not diffed)", "EISDIR");
  }

  const [aRaw, bRaw] = await Promise.all([fsp.readFile(aAbs, "utf8"), fsp.readFile(bAbs, "utf8")]);
  const aText = opts.ignoreWhitespace ? normalizeWhitespace(aRaw) : aRaw;
  const bText = opts.ignoreWhitespace ? normalizeWhitespace(bRaw) : bRaw;

  const d = diffText(aText, bText, {
    context: opts.context ?? 3,
    aLabel: `a/${aRel}`,
    bLabel: `b/${bRel}`,
  });

  return {
    identical: d.identical,
    a: { path: aRel, size: aSt.size, lines: countLines(aText) },
    b: { path: bRel, size: bSt.size, lines: countLines(bText) },
    unified: d.unified,
    stats: d.stats,
    hunks: d.hunks.length,
  };
}

export { normalizeLanguage };
