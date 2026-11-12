/**
 * Incremental repository indexer.
 *
 * A `RepoIndex` scans a workspace, keeps a per-file record in memory and in
 * `<root>/.uca/index.json`, and only re-parses file contents when the size or
 * mtime changed. Change tracking compares the current scan against the stored
 * snapshot.
 */
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import { relFrom, resolveInside } from "../util/paths.js";
import { FsError, wrapFsError } from "./errors.js";
import { detectLanguage, isBinaryBuffer, SYMBOL_LANGUAGES } from "./language.js";
import { extractSymbols, fuzzyMatchScore, levenshtein, isSymbolKind, type SymbolKind, type SymbolRecord } from "./symbols.js";
import {
  buildDependencyGraph,
  isManifestPath,
  parseManifest,
  type DependencyGraph,
  type ManifestDependencies,
} from "./depmap.js";
import { compareStrings } from "./text.js";

export const INDEX_DIR = ".uca";
export const INDEX_FILE = "index.json";
export const INDEX_VERSION = 1;

/** Directories never indexed. */
export const INDEX_EXCLUDED_DIRS: readonly string[] = ["node_modules", ".git", "dist", "build", ".uca"];

/** Files larger than this are recorded but not parsed for symbols. */
const MAX_PARSE_BYTES = 1024 * 1024;
const MAX_INDEXED_FILE_BYTES = 8 * 1024 * 1024;

export interface FileIndexRecord {
  path: string;
  size: number;
  mtimeMs: number;
  language: string;
  symbols: SymbolRecord[];
  binary?: boolean;
  /** Set when the file was skipped for symbol parsing. */
  skipped?: "too-large" | "binary" | "unreadable";
}

export interface IndexSnapshotMeta {
  /** Epoch ms of the last completed index. */
  indexedAt: number;
  version: number;
  fileCount: number;
  totalBytes: number;
}

export interface SymbolHit extends SymbolRecord {
  path: string;
  language: string;
}

export interface RepoMapFile {
  path: string;
  size: number;
  language: string;
  symbolCount: number;
  /** Top-level symbols (first few) for at-a-glance orientation. */
  symbols: string[];
}

export interface RepoMapTreeNode {
  name: string;
  type: "dir" | "file";
  path: string;
  size?: number;
  language?: string;
  children?: RepoMapTreeNode[];
}

export interface RepoMapLanguageStat {
  language: string;
  files: number;
  bytes: number;
  percentage: number;
}

export interface RepoMap {
  root: string;
  fileCount: number;
  dirCount: number;
  totalBytes: number;
  languages: RepoMapLanguageStat[];
  tree: RepoMapTreeNode;
  entrypoints: string[];
  importantFiles: string[];
  tests: string[];
  /** Files with the most symbols (structural centers). */
  keyFiles: RepoMapFile[];
  generatedAt: number;
}

export interface ChangeSet {
  added: string[];
  modified: string[];
  deleted: string[];
  unchanged: number;
  /** Timestamp of the snapshot the comparison was made against. */
  since: number | null;
  currentIndexedAt: number;
  total: number;
}

export interface IndexScanStats {
  scanned: number;
  parsed: number;
  reused: number;
  skipped: number;
  removed: number;
  durationMs: number;
  full: boolean;
}

export class RepoIndex {
  private readonly rootArg: string;
  private records = new Map<string, FileIndexRecord>();
  private meta: IndexSnapshotMeta = { indexedAt: 0, version: INDEX_VERSION, fileCount: 0, totalBytes: 0 };
  /** Snapshot used for change tracking (the state as of the last `update()`). */
  private snapshot: Map<string, FileIndexRecord> = new Map();
  private lastStats: IndexScanStats | null = null;
  private dependencyCache: DependencyGraph | null = null;

  constructor(root: string) {
    this.rootArg = root;
  }

  /** Absolute, symlink-resolved workspace root. */
  get root(): string {
    return fs.realpathSync(this.rootArg);
  }

  get indexPath(): string {
    return path.join(this.root, INDEX_DIR, INDEX_FILE);
  }

  /** Stats from the most recent `update()`, or null when never indexed. */
  get stats(): IndexScanStats | null {
    return this.lastStats;
  }

  get indexedAt(): number {
    return this.meta.indexedAt;
  }

  // -------------------------------------------------------------------------
  // Scan
  // -------------------------------------------------------------------------

  private async scanDisk(): Promise<Map<string, { size: number; mtimeMs: number }>> {
    const root = this.root;
    const found = new Map<string, { size: number; mtimeMs: number }>();
    const walk = async (dir: string): Promise<void> => {
      let names: string[];
      try {
        names = await fsp.readdir(dir);
      } catch {
        return;
      }
      names.sort(compareStrings);
      for (const name of names) {
        if (INDEX_EXCLUDED_DIRS.includes(name)) continue;
        const full = path.join(dir, name);
        let st: fs.Stats;
        try {
          st = await fsp.lstat(full);
        } catch {
          continue;
        }
        if (st.isSymbolicLink()) continue; // never follow links (escape + cycles)
        if (st.isDirectory()) {
          await walk(full);
        } else if (st.isFile() && st.size <= MAX_INDEXED_FILE_BYTES) {
          const relPath = path.relative(root, full).split(path.sep).join("/");
          found.set(relPath, { size: st.size, mtimeMs: st.mtimeMs });
        }
      }
    };
    await walk(root);
    return found;
  }

  private async parseFile(relPath: string, abs: string, size: number): Promise<FileIndexRecord> {
    const language = detectLanguage(relPath);
    const base: FileIndexRecord = { path: relPath, size, mtimeMs: 0, language, symbols: [] };
    if (size === 0) return base;
    if (size > MAX_PARSE_BYTES) return { ...base, skipped: "too-large" };
    if (!SYMBOL_LANGUAGES.has(language)) return base;
    let buf: Buffer;
    try {
      buf = await fsp.readFile(abs);
    } catch {
      return { ...base, skipped: "unreadable" };
    }
    if (isBinaryBuffer(buf)) return { ...base, binary: true, skipped: "binary" };
    return { ...base, symbols: extractSymbols(relPath, buf.toString("utf8")) };
  }

  // -------------------------------------------------------------------------
  // Persistence
  // -------------------------------------------------------------------------

  private static isValidRecord(value: unknown): value is FileIndexRecord {
    if (typeof value !== "object" || value === null) return false;
    const v = value as Record<string, unknown>;
    return (
      typeof v.path === "string" &&
      typeof v.size === "number" &&
      typeof v.mtimeMs === "number" &&
      typeof v.language === "string" &&
      Array.isArray(v.symbols)
    );
  }

  /** Load the persisted cache. Missing/corrupt cache is not an error: it starts empty. */
  async load(): Promise<boolean> {
    const file = this.indexPath;
    let raw: string;
    try {
      raw = await fsp.readFile(file, "utf8");
    } catch {
      return false;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      return false;
    }
    if (typeof parsed !== "object" || parsed === null) return false;
    const obj = parsed as { version?: unknown; meta?: unknown; files?: unknown };
    if (obj.version !== INDEX_VERSION || !Array.isArray(obj.files)) return false;
    const records = new Map<string, FileIndexRecord>();
    for (const item of obj.files) {
      if (!RepoIndex.isValidRecord(item)) continue;
      records.set(item.path, {
        path: item.path,
        size: item.size,
        mtimeMs: item.mtimeMs,
        language: item.language,
        symbols: Array.isArray(item.symbols) ? item.symbols : [],
        ...(item.binary ? { binary: true } : {}),
        ...(item.skipped ? { skipped: item.skipped } : {}),
      });
    }
    this.records = records;
    this.snapshot = new Map(records);
    const m = obj.meta as Partial<IndexSnapshotMeta> | undefined;
    this.meta = {
      indexedAt: typeof m?.indexedAt === "number" ? m.indexedAt : 0,
      version: INDEX_VERSION,
      fileCount: records.size,
      totalBytes: typeof m?.totalBytes === "number" ? m.totalBytes : 0,
    };
    return true;
  }

  /** Persist the cache to `<root>/.uca/index.json`. */
  async save(): Promise<void> {
    const dir = path.join(this.root, INDEX_DIR);
    await fsp.mkdir(dir, { recursive: true });
    const payload = {
      version: INDEX_VERSION,
      meta: this.meta,
      files: [...this.records.values()].sort((a, b) => compareStrings(a.path, b.path)),
    };
    const tmp = path.join(dir, `${INDEX_FILE}.${process.pid}.tmp`);
    await fsp.writeFile(tmp, JSON.stringify(payload, null, 0), "utf8");
    await fsp.rename(tmp, this.indexPath);
  }

  // -------------------------------------------------------------------------
  // Update
  // -------------------------------------------------------------------------

  /**
   * Scan the workspace and refresh records. Files whose size+mtime are unchanged
   * keep their cached symbols (no re-parse). `force` re-parses everything.
   */
  async update(opts: { force?: boolean; save?: boolean } = {}): Promise<IndexScanStats> {
    const started = Date.now();
    const root = this.root;
    const disk = await this.scanDisk();
    const previous = this.records;
    const next = new Map<string, FileIndexRecord>();
    let parsed = 0;
    let reused = 0;
    let skipped = 0;

    const entries = [...disk.entries()].sort((a, b) => compareStrings(a[0], b[0]));
    const concurrency = 16;
    for (let i = 0; i < entries.length; i += concurrency) {
      const batch = entries.slice(i, i + concurrency);
      const results = await Promise.all(
        batch.map(async ([relPath, info]) => {
          const cached = previous.get(relPath);
          if (
            !opts.force &&
            cached &&
            cached.size === info.size &&
            cached.mtimeMs === info.mtimeMs
          ) {
            reused++;
            return cached;
          }
          const abs = resolveInside(root, relPath);
          const rec = await this.parseFile(relPath, abs, info.size);
          rec.mtimeMs = info.mtimeMs;
          parsed++;
          if (rec.skipped) skipped++;
          return rec;
        }),
      );
      for (const rec of results) next.set(rec.path, rec);
    }

    let removed = 0;
    for (const key of previous.keys()) if (!disk.has(key)) removed++;

    this.records = next;
    this.dependencyCache = null;
    this.meta = {
      indexedAt: Date.now(),
      version: INDEX_VERSION,
      fileCount: next.size,
      totalBytes: [...next.values()].reduce((sum, r) => sum + r.size, 0),
    };
    this.lastStats = {
      scanned: disk.size,
      parsed,
      reused,
      skipped,
      removed,
      durationMs: Date.now() - started,
      full: opts.force === true || previous.size === 0,
    };
    if (opts.save !== false) await this.save();
    return this.lastStats;
  }

  /** Update and then roll the change-tracking snapshot forward to the new state. */
  async refresh(opts: { force?: boolean } = {}): Promise<IndexScanStats> {
    const stats = await this.update(opts);
    this.snapshot = new Map(this.records);
    return stats;
  }

  // -------------------------------------------------------------------------
  // Queries
  // -------------------------------------------------------------------------

  files(): FileIndexRecord[] {
    return [...this.records.values()].sort((a, b) => compareStrings(a.path, b.path));
  }

  getFile(relPath: string): FileIndexRecord | undefined {
    return this.records.get(relPath.replace(/\\/g, "/"));
  }

  /**
   * Search indexed symbols. `kind` filters by symbol kind, `fuzzy` enables
   * subsequence/typo-tolerant matching, `substring` (default) matches anywhere.
   */
  findSymbol(
    name: string,
    kind?: SymbolKind | string,
    fuzzy = false,
    opts: { limit?: number; pathGlob?: string } = {},
  ): SymbolHit[] {
    if (!name || name.length === 0) return [];
    if (kind !== undefined && kind !== "" && !isSymbolKind(kind)) {
      throw new FsError(`Unknown symbol kind: ${kind}`, "EINVAL");
    }
    const limit = opts.limit ?? 100;
    const query = name.toLowerCase();
    const hits: { hit: SymbolHit; score: number }[] = [];
    const globRe = opts.pathGlob ? new RegExp(opts.pathGlob.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*")) : null;

    for (const rec of this.records.values()) {
      if (globRe && !globRe.test(rec.path)) continue;
      for (const sym of rec.symbols) {
        if (kind && sym.kind !== kind) continue;
        const lower = sym.name.toLowerCase();
        let score = 0;
        if (fuzzy) {
          score = fuzzyMatchScore(query, sym.name);
          if (score === 0 && levenshtein(query, lower, Math.max(1, Math.floor(query.length / 3))) <= Math.max(1, Math.floor(query.length / 3))) {
            score = 50;
          }
        } else {
          score = lower === query ? 3 : lower.includes(query) ? 2 : 0;
        }
        if (score <= 0) continue;
        hits.push({ hit: { ...sym, path: rec.path, language: rec.language }, score });
      }
    }
    hits.sort((a, b) => b.score - a.score || compareStrings(a.hit.name, b.hit.name) || compareStrings(a.hit.path, b.hit.path));
    return hits.slice(0, limit).map((h) => h.hit);
  }

  /** All symbols of one file. */
  symbolsInFile(relPath: string): SymbolRecord[] {
    return this.getFile(relPath)?.symbols ?? [];
  }

  // -------------------------------------------------------------------------
  // Repo map
  // -------------------------------------------------------------------------

  private static isEntrypointCandidate(p: string): boolean {
    const base = path.posix.basename(p).toLowerCase();
    return (
      /^(main|index|app|server|cli|program|mod)\.(ts|tsx|js|mjs|cjs|py|go|rs|java|rb|php|c|cc|cpp)$/.test(base) ||
      base === "__main__.py" ||
      base === "main.go" ||
      base === "main.rs" && p.split("/").length <= 2 ||
      base === "dockerfile" ||
      p === "src/main.rs" ||
      p === "cmd/main.go"
    );
  }

  private static isTestPath(p: string): boolean {
    return /(^|\/)(test|tests|__tests__|spec)\//.test(p) || /\.(test|spec)\.[a-z]+$/i.test(p) || /_test\.(go|py)$/.test(p);
  }

  private static isImportantPath(p: string): boolean {
    const base = path.posix.basename(p).toLowerCase();
    return (
      base === "package.json" ||
      base === "readme.md" ||
      base === "dockerfile" ||
      base === "tsconfig.json" ||
      base === "pyproject.toml" ||
      base === "go.mod" ||
      base === "cargo.toml" ||
      base === "makefile" ||
      base === "requirements.txt" ||
      base === "composer.json" ||
      base === ".env.example" ||
      /^readme(\.[a-z]+)?$/.test(base) ||
      p === ".github/workflows" ||
      /^\.github\/workflows\/.+\.ya?ml$/.test(p)
    );
  }

  /** Build a compact repo map: tree, language stats, entrypoints, important files. */
  repoMap(opts: { maxFiles?: number; maxSymbolsPerFile?: number } = {}): RepoMap {
    const maxFiles = opts.maxFiles ?? 5000;
    const maxSymbolsPerFile = opts.maxSymbolsPerFile ?? 5;
    const files = this.files().slice(0, maxFiles);
    const root = this.root;

    const tree: RepoMapTreeNode = { name: path.basename(root) || "/", type: "dir", path: "", children: [] };
    const dirNodes = new Map<string, RepoMapTreeNode>([["", tree]]);
    const dirSet = new Set<string>();

    const ensureDir = (dirPath: string): RepoMapTreeNode => {
      const existing = dirNodes.get(dirPath);
      if (existing) return existing;
      const parentPath = path.posix.dirname(dirPath) === "." ? "" : path.posix.dirname(dirPath);
      const parent = ensureDir(parentPath);
      const node: RepoMapTreeNode = {
        name: path.posix.basename(dirPath),
        type: "dir",
        path: dirPath,
        children: [],
      };
      parent.children?.push(node);
      dirNodes.set(dirPath, node);
      dirSet.add(dirPath);
      return node;
    };

    const langStats = new Map<string, { files: number; bytes: number }>();
    for (const rec of files) {
      const dir = path.posix.dirname(rec.path);
      const parent = dir === "." ? tree : ensureDir(dir);
      parent.children?.push({
        name: path.posix.basename(rec.path),
        type: "file",
        path: rec.path,
        size: rec.size,
        language: rec.language,
      });
      const stat = langStats.get(rec.language) ?? { files: 0, bytes: 0 };
      stat.files++;
      stat.bytes += rec.size;
      langStats.set(rec.language, stat);
    }

    const sortTree = (node: RepoMapTreeNode): void => {
      if (!node.children) return;
      node.children.sort((a, b) => {
        if (a.type !== b.type) return a.type === "dir" ? -1 : 1;
        return compareStrings(a.name, b.name);
      });
      for (const child of node.children) sortTree(child);
    };
    sortTree(tree);

    const totalBytes = files.reduce((sum, r) => sum + r.size, 0);
    const languages: RepoMapLanguageStat[] = [...langStats.entries()]
      .map(([language, s]) => ({
        language,
        files: s.files,
        bytes: s.bytes,
        percentage: totalBytes === 0 ? 0 : Math.round((s.bytes / totalBytes) * 1000) / 10,
      }))
      .sort((a, b) => b.bytes - a.bytes || compareStrings(a.language, b.language));

    const entrypoints = files
      .map((f) => f.path)
      .filter((p) => RepoIndex.isEntrypointCandidate(p))
      .slice(0, 50);
    const importantFiles = files.map((f) => f.path).filter((p) => RepoIndex.isImportantPath(p)).slice(0, 50);
    const tests = files.map((f) => f.path).filter((p) => RepoIndex.isTestPath(p)).slice(0, 100);

    const keyFiles: RepoMapFile[] = files
      .filter((f) => f.symbols.length > 0)
      .sort((a, b) => b.symbols.length - a.symbols.length || compareStrings(a.path, b.path))
      .slice(0, 25)
      .map((f) => ({
        path: f.path,
        size: f.size,
        language: f.language,
        symbolCount: f.symbols.length,
        symbols: f.symbols.slice(0, maxSymbolsPerFile).map((s) => `${s.kind} ${s.name}`),
      }));

    return {
      root,
      fileCount: this.records.size,
      dirCount: dirSet.size,
      totalBytes,
      languages,
      tree,
      entrypoints,
      importantFiles,
      tests,
      keyFiles,
      generatedAt: this.meta.indexedAt,
    };
  }

  /** Render the repo map as an indented text tree (LLM friendly). */
  renderRepoMap(opts: { maxDepth?: number; maxEntriesPerDir?: number } = {}): string {
    const map = this.repoMap();
    const maxDepth = opts.maxDepth ?? 4;
    const maxEntries = opts.maxEntriesPerDir ?? 40;
    const lines: string[] = [];
    const walk = (node: RepoMapTreeNode, depth: number, prefix: string): void => {
      if (depth > maxDepth) return;
      const kids = node.children ?? [];
      const shown = kids.slice(0, maxEntries);
      for (let i = 0; i < shown.length; i++) {
        const child = shown[i];
        const last = i === shown.length - 1 && kids.length <= maxEntries;
        const branch = last ? "└─ " : "├─ ";
        const suffix = child.type === "file" ? ` (${child.language}, ${child.size}B)` : "/";
        lines.push(`${prefix}${branch}${child.name}${suffix}`);
        if (child.type === "dir") walk(child, depth + 1, `${prefix}${last ? "   " : "│  "}`);
      }
      if (kids.length > maxEntries) lines.push(`${prefix}└─ … ${kids.length - maxEntries} more`);
    };
    lines.push(`${map.tree.name}/ (${map.fileCount} files, ${map.totalBytes} bytes)`);
    walk(map.tree, 1, "");
    lines.push("");
    lines.push("Languages:");
    for (const l of map.languages.slice(0, 12)) {
      lines.push(`  ${l.language}: ${l.files} files, ${l.percentage}%`);
    }
    if (map.entrypoints.length) lines.push(`Entrypoints: ${map.entrypoints.join(", ")}`);
    if (map.importantFiles.length) lines.push(`Important: ${map.importantFiles.join(", ")}`);
    return lines.join("\n");
  }

  // -------------------------------------------------------------------------
  // Dependency map
  // -------------------------------------------------------------------------

  /** Dependency graph from manifests + local imports (cached until next update). */
  async dependencyMap(opts: { useCache?: boolean } = {}): Promise<DependencyGraph> {
    if (opts.useCache !== false && this.dependencyCache) return this.dependencyCache;
    const root = this.root;
    const manifests: ManifestDependencies[] = [];
    const sourceFiles: { path: string; content: string }[] = [];

    for (const rec of this.files()) {
      if (rec.size > MAX_PARSE_BYTES || rec.binary || rec.skipped === "unreadable") continue;
      if (!SYMBOL_LANGUAGES.has(rec.language)) continue;
      let content: string;
      try {
        content = await fsp.readFile(resolveInside(root, rec.path), "utf8");
      } catch {
        continue;
      }
      sourceFiles.push({ path: rec.path, content });
    }

    for (const rec of this.files()) {
      if (!isManifestPath(rec.path)) continue;
      if (rec.size > MAX_PARSE_BYTES) continue;
      let content: string;
      try {
        content = await fsp.readFile(resolveInside(root, rec.path), "utf8");
      } catch {
        continue;
      }
      const parsed = parseManifest(rec.path, content);
      if (parsed.dependencies.length > 0 || parsed.ecosystem !== "unknown") manifests.push(parsed);
    }

    this.dependencyCache = buildDependencyGraph(sourceFiles, manifests);
    return this.dependencyCache;
  }

  // -------------------------------------------------------------------------
  // Change tracking
  // -------------------------------------------------------------------------

  /** Files added/modified/deleted relative to the snapshot taken at the last `refresh()`. */
  changes(): ChangeSet {
    const added: string[] = [];
    const modified: string[] = [];
    const deleted: string[] = [];
    let unchanged = 0;

    for (const [p, rec] of this.records) {
      const prev = this.snapshot.get(p);
      if (!prev) added.push(p);
      else if (prev.size !== rec.size || prev.mtimeMs !== rec.mtimeMs) modified.push(p);
      else unchanged++;
    }
    for (const p of this.snapshot.keys()) if (!this.records.has(p)) deleted.push(p);

    added.sort();
    modified.sort();
    deleted.sort();
    return {
      added,
      modified,
      deleted,
      unchanged,
      since: this.meta.indexedAt || null,
      currentIndexedAt: this.meta.indexedAt,
      total: added.length + modified.length + deleted.length,
    };
  }

  /** Re-baseline change tracking to the current records without re-scanning. */
  commitSnapshot(): void {
    this.snapshot = new Map(this.records);
  }
}

/** Convenience: load (or create) and update an index for `root`. */
export async function buildRepoIndex(
  root: string,
  opts: { force?: boolean } = {},
): Promise<RepoIndex> {
  const index = new RepoIndex(root);
  await index.load();
  await index.refresh(opts);
  return index;
}

export { wrapFsError };
