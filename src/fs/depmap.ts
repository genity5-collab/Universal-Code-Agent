/**
 * Manifest parsing and local import-graph construction.
 * Pure functions over text + path lists: no filesystem access here.
 */
import path from "node:path";
import { detectLanguage } from "./language.js";

export type DependencyEcosystem =
  | "npm"
  | "pip"
  | "pyproject"
  | "go"
  | "cargo"
  | "composer"
  | "gem"
  | "unknown";

export interface Dependency {
  name: string;
  /** Version constraint / requirement spec as written (may be empty). */
  spec: string;
  scope: "runtime" | "dev" | "peer" | "optional" | "unknown";
  ecosystem: DependencyEcosystem;
  /** Manifest that declared it, relative to root. */
  manifest: string;
}

export interface ManifestDependencies {
  manifest: string;
  ecosystem: DependencyEcosystem;
  dependencies: Dependency[];
}

export interface ImportEdge {
  /** Importing file (relative path). */
  from: string;
  /** Imported file (relative path), resolved within the repo. */
  to: string;
  /** Raw specifier as written. */
  specifier: string;
}

export interface DependencyGraph {
  /** Local file -> files it imports. */
  imports: Record<string, string[]>;
  /** Local file -> files importing it. */
  importedBy: Record<string, string[]>;
  edges: ImportEdge[];
  /** External package imports grouped by specifier. */
  external: Record<string, string[]>;
  /** Declared dependencies from package manifests. */
  manifests: ManifestDependencies[];
  /** Files that import at least one local file. */
  nodeCount: number;
  edgeCount: number;
}

export function detectEcosystem(manifestPath: string): DependencyEcosystem {
  const base = path.posix.basename(manifestPath).toLowerCase();
  if (base === "package.json") return "npm";
  if (base === "requirements.txt" || base.startsWith("requirements")) return "pip";
  if (base === "pyproject.toml") return "pyproject";
  if (base === "go.mod") return "go";
  if (base === "cargo.toml") return "cargo";
  if (base === "composer.json") return "composer";
  if (base === "gemfile") return "gem";
  return "unknown";
}

/** Strip a version range down to the bare package name where manifests allow decoration. */
function cleanName(raw: string): string {
  return raw
    .replace(/^["']|["']$/g, "")
    .replace(/^@/, "@")
    .trim();
}

function npmDeps(manifest: string, content: string): ManifestDependencies {
  const out: ManifestDependencies = { manifest, ecosystem: "npm", dependencies: [] };
  let json: unknown;
  try {
    json = JSON.parse(content);
  } catch {
    return out;
  }
  if (typeof json !== "object" || json === null) return out;
  const obj = json as Record<string, unknown>;
  const sections: [string, Dependency["scope"]][] = [
    ["dependencies", "runtime"],
    ["devDependencies", "dev"],
    ["peerDependencies", "peer"],
    ["optionalDependencies", "optional"],
  ];
  for (const [key, scope] of sections) {
    const block = obj[key];
    if (typeof block !== "object" || block === null) continue;
    for (const [name, spec] of Object.entries(block as Record<string, unknown>)) {
      out.dependencies.push({
        name: cleanName(name),
        spec: typeof spec === "string" ? spec : String(spec),
        scope,
        ecosystem: "npm",
        manifest,
      });
    }
  }
  return out;
}

function requirementsDeps(manifest: string, content: string): ManifestDependencies {
  const dependencies: Dependency[] = [];
  for (const rawLine of content.split("\n")) {
    const line = rawLine.split("#")[0].trim();
    if (!line || line.startsWith("-")) continue;
    // name[extras]==1.2.3 ; marker
    const m = /^([A-Za-z0-9_.\-\[\]]+)\s*(.*)$/.exec(line);
    if (!m) continue;
    const name = m[1].replace(/\[.*\]$/, "");
    dependencies.push({
      name,
      spec: m[2].replace(/^[=<>!~ ]+/, "").trim(),
      scope: "runtime",
      ecosystem: "pip",
      manifest,
    });
  }
  return { manifest, ecosystem: "pip", dependencies };
}

/** Minimal TOML reader for dependency tables (no external parser). */
function pyprojectDeps(manifest: string, content: string): ManifestDependencies {
  const dependencies: Dependency[] = [];
  let section = "";
  let inArray: string | null = null;
  const arrayBuf: string[] = [];

  const pushSpec = (spec: string): void => {
    const cleaned = spec.trim().replace(/^["']+|["']+$/g, "").trim();
    if (!cleaned) return;
    const m = /^([A-Za-z0-9_.\-]+(?:\[[^\]]*\])?)\s*(.*)$/.exec(cleaned);
    if (!m) return;
    const scope: Dependency["scope"] = section.includes("dev") || section.includes("test") ? "dev" : "runtime";
    dependencies.push({
      name: m[1].replace(/\[.*\]$/, ""),
      spec: m[2].replace(/^[=<>!~ ]+/, "").trim(),
      scope,
      ecosystem: "pyproject",
      manifest,
    });
  };

  for (const rawLine of content.split("\n")) {
    const line = rawLine.trim();
    if (inArray !== null) {
      if (line.includes("]")) {
        const before = line.slice(0, line.indexOf("]"));
        if (before.trim()) arrayBuf.push(before);
        for (const entry of arrayBuf.join(" ").split(",")) pushSpec(entry);
        arrayBuf.length = 0;
        inArray = null;
      } else {
        arrayBuf.push(line);
      }
      const parts = arrayBuf.join(" ").split(",");
      void parts;
      continue;
    }
    if (line.startsWith("[") && line.endsWith("]") && !line.includes("=")) {
      section = line.slice(1, -1).trim().toLowerCase();
      continue;
    }
    const kv = /^([A-Za-z0-9_.\-]+)\s*=\s*(.*)$/.exec(line);
    if (!kv) continue;
    const key = kv[1].toLowerCase();
    let value = kv[2];
    if (value.startsWith("[") && !value.includes("]")) {
      inArray = key;
      arrayBuf.push(value.slice(1));
      continue;
    }
    if (value.startsWith("[")) {
      const inner = value.slice(1, value.lastIndexOf("]"));
      for (const entry of inner.split(",")) pushSpec(entry);
      continue;
    }
    if (key === "requires" || key === "dependencies") {
      // poetry style: requires = ">=3.8" (python version) is not a dependency name
      if (section.includes("dependencies") || section === "project") continue;
    }
    // poetry [tool.poetry.dependencies] name = "^1.0"
    if (section.includes("dependencies") && key !== "python") {
      pushSpec(`${key} ${value.replace(/^["']|["']$/g, "")}`);
    }
  }
  return { manifest, ecosystem: "pyproject", dependencies };
}

function goModDeps(manifest: string, content: string): ManifestDependencies {
  const dependencies: Dependency[] = [];
  let inBlock = false;
  for (const rawLine of content.split("\n")) {
    const line = rawLine.trim();
    if (line.startsWith("require (")) { inBlock = true; continue; }
    if (inBlock && line === ")") { inBlock = false; continue; }
    const body = inBlock ? line : line.startsWith("require ") ? line.slice("require ".length).trim() : "";
    if (!body || body.startsWith("//")) continue;
    const m = /^(\S+)\s+(\S+)/.exec(body);
    if (!m) continue;
    dependencies.push({
      name: m[1],
      spec: m[2],
      scope: body.includes("// indirect") ? "optional" : "runtime",
      ecosystem: "go",
      manifest,
    });
  }
  return { manifest, ecosystem: "go", dependencies };
}

function cargoDeps(manifest: string, content: string): ManifestDependencies {
  const dependencies: Dependency[] = [];
  let section = "";
  for (const rawLine of content.split("\n")) {
    const line = rawLine.trim();
    if (line.startsWith("[") && line.endsWith("]")) {
      section = line.slice(1, -1).trim().toLowerCase();
      continue;
    }
    if (!section.includes("dependencies")) continue;
    const kv = /^([A-Za-z0-9_\-]+)\s*=\s*(.+)$/.exec(line);
    if (!kv) continue;
    const spec = kv[2].startsWith("{")
      ? (/version\s*=\s*"([^"]*)"/.exec(kv[2])?.[1] ?? "")
      : kv[2].replace(/^["']|["']$/g, "");
    dependencies.push({
      name: kv[1],
      spec,
      scope: section.includes("dev") ? "dev" : section.includes("build") ? "optional" : "runtime",
      ecosystem: "cargo",
      manifest,
    });
  }
  return { manifest, ecosystem: "cargo", dependencies };
}

/** Parse any supported manifest; returns an empty list for unknown formats. */
export function parseManifest(manifestPath: string, content: string): ManifestDependencies {
  switch (detectEcosystem(manifestPath)) {
    case "npm":
      return npmDeps(manifestPath, content);
    case "composer": {
      // composer.json: require / require-dev
      const out: ManifestDependencies = { manifest: manifestPath, ecosystem: "composer", dependencies: [] };
      try {
        const json = JSON.parse(content) as Record<string, unknown>;
        for (const [key, scope] of [["require", "runtime"], ["require-dev", "dev"]] as [string, Dependency["scope"]][]) {
          const block = json[key];
          if (typeof block !== "object" || block === null) continue;
          for (const [name, spec] of Object.entries(block as Record<string, unknown>)) {
            out.dependencies.push({ name, spec: String(spec), scope, ecosystem: "composer", manifest: manifestPath });
          }
        }
      } catch {
        /* ignore malformed json */
      }
      return out;
    }
    case "pip":
      return requirementsDeps(manifestPath, content);
    case "pyproject":
      return pyprojectDeps(manifestPath, content);
    case "go":
      return goModDeps(manifestPath, content);
    case "cargo":
      return cargoDeps(manifestPath, content);
    default:
      return { manifest: manifestPath, ecosystem: "unknown", dependencies: [] };
  }
}

/** Manifest files the dependency map reads. */
export function isManifestPath(p: string): boolean {
  const base = path.posix.basename(p).toLowerCase();
  return (
    base === "package.json" ||
    base === "requirements.txt" ||
    (base.startsWith("requirements") && base.endsWith(".txt")) ||
    base === "pyproject.toml" ||
    base === "go.mod" ||
    base === "cargo.toml" ||
    base === "composer.json"
  );
}

// ---------------------------------------------------------------------------
// Import extraction
// ---------------------------------------------------------------------------

const IMPORT_RULES: Record<string, RegExp[]> = {
  typescript: [
    /^\s*import\s+(?:type\s+)?(?:[\w*{}\s,$]+?\s+from\s+)?["']([^"']+)["']/gm,
    /^\s*export\s+(?:\*|\{[^}]*\})\s+from\s+["']([^"']+)["']/gm,
    /\brequire\(\s*["']([^"']+)["']\s*\)/g,
    /\bimport\(\s*["']([^"']+)["']\s*\)/g,
  ],
  python: [
    /^\s*from\s+([.\w]+)\s+import\b/gm,
    /^\s*import\s+([.\w]+)(?:\s+as\s+\w+)?/gm,
  ],
  go: [/^\s*import\s+"([^"]+)"/gm, /^\s*import\s+\(/gm],
  rust: [/^\s*use\s+([\w:]+)/gm, /^\s*mod\s+([\w]+)\s*;/gm, /^\s*extern\s+crate\s+([\w]+)/gm],
  java: [/^\s*import\s+(?:static\s+)?([\w.]+)\s*;/gm],
  ruby: [/^\s*require(?:_relative)?\s+["']([^"']+)["']/gm],
  php: [/^\s*use\s+([\w\\]+)\s*;/gm, /require(?:_once)?\s*\(?\s*["']([^"']+)["']/g],
  c: [/^\s*#include\s+"([^"]+)"/gm],
  cpp: [/^\s*#include\s+"([^"]+)"/gm],
};

/** Language-specific import specifiers found in `content`. */
export function extractImports(filePath: string, content: string): string[] {
  const language = detectLanguage(filePath);
  const rules = IMPORT_RULES[language];
  if (!rules) return [];
  const found: string[] = [];
  const seen = new Set<string>();
  for (const re of rules) {
    const scanner = new RegExp(re.source, re.flags.includes("m") ? re.flags : re.flags + "m");
    let m: RegExpExecArray | null;
    while ((m = scanner.exec(content)) !== null) {
      const spec = m[1];
      if (!spec) continue;
      if (!seen.has(spec)) {
        seen.add(spec);
        found.push(spec);
      }
      if (m[0].length === 0) scanner.lastIndex++;
    }
  }
  return found;
}

/** Go multi-line import block: `import (\n "a"\n "b"\n)`. */
export function extractGoImports(content: string): string[] {
  const out: string[] = [];
  const blockRe = /^\s*import\s*\(([\s\S]*?)^\s*\)/gm;
  let m: RegExpExecArray | null;
  while ((m = blockRe.exec(content)) !== null) {
    const inner = /"([^"]+)"/g;
    let im: RegExpExecArray | null;
    while ((im = inner.exec(m[1])) !== null) out.push(im[1]);
  }
  return out;
}

/**
 * Resolve an import specifier written in `fromPath` to a file that exists in
 * `knownPaths` (a set of relative POSIX paths). Returns null for externals.
 */
export function resolveImport(
  fromPath: string,
  specifier: string,
  knownPaths: ReadonlySet<string>,
  extraSuffixes: readonly string[] = [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py", ".go", ".rs"],
): string | null {
  const fromDir = path.posix.dirname(fromPath.replace(/\\/g, "/"));
  const language = detectLanguage(fromPath);

  const tryCandidate = (base: string): string | null => {
    const normalized = path.posix.normalize(base).replace(/^\.\//, "");
    const candidates = [
      normalized,
      ...extraSuffixes.map((s) => `${normalized}${s}`),
      // TS/ESM style: ./x.js on disk is ./x.ts
      ...["ts", "tsx", "js", "jsx", "mts", "cts", "mjs", "cjs"].map((s) => normalized.replace(/\.(js|mjs|cjs)$/, `.${s}`)),
      ...["index.ts", "index.tsx", "index.js", "index.jsx", "index.mjs", "index.cjs", "mod.rs", "__init__.py", "index.py"].map(
        (s) => `${normalized.replace(/\/$/, "")}/${s}`,
      ),
    ];
    for (const c of candidates) {
      if (knownPaths.has(c)) return c;
    }
    return null;
  };

  if (language === "python") {
    if (specifier.startsWith(".")) {
      const dots = /^\.+/.exec(specifier)?.[0].length ?? 1;
      let base = fromDir;
      for (let i = 1; i < dots; i++) base = path.posix.dirname(base);
      const rest = specifier.slice(dots).replace(/\./g, "/");
      return tryCandidate(rest ? `${base}/${rest}` : base);
    }
    // Absolute python imports resolve from the repo root.
    return tryCandidate(specifier.replace(/\./g, "/")) ?? tryCandidate(`${fromDir}/${specifier.replace(/\./g, "/")}`);
  }

  if (specifier.startsWith(".") || specifier.startsWith("/")) {
    return tryCandidate(specifier.startsWith("/") ? specifier.slice(1) : `${fromDir}/${specifier}`);
  }

  if (language === "go") {
    // Package imports: match any directory suffix.
    for (const known of knownPaths) {
      const dir = path.posix.dirname(known);
      if (specifier.endsWith(dir) && dir !== ".") return known;
    }
    return null;
  }

  if (language === "rust") {
    const head = specifier.split("::")[0];
    if (head === "crate" || head === "super" || head === "self") {
      const rest = specifier.split("::").slice(1);
      const base = head === "self" ? fromDir : head === "super" ? path.posix.dirname(fromDir) : "src";
      return tryCandidate([base, ...rest].join("/")) ?? tryCandidate([base, "src", ...rest].join("/"));
    }
    return tryCandidate(`${fromDir}/${head}`) ?? tryCandidate(head.replace(/::/g, "/"));
  }

  if (language === "c" || language === "cpp") {
    for (const prefix of ["", "include/", "src/", fromDir, `${fromDir}/../include`]) {
      const hit = tryCandidate(prefix ? `${prefix}/${specifier}` : specifier);
      if (hit) return hit;
    }
    return null;
  }

  if (language === "ruby" || language === "php") {
    const base = specifier.split(/[\\/]/).pop() ?? specifier;
    for (const known of knownPaths) {
      if (path.posix.basename(known).replace(/\.[^.]+$/, "") === base.replace(/\.[^.]+$/, "")) return known;
    }
    return null;
  }

  if (language === "java") {
    const asPath = specifier.replace(/\./g, "/");
    for (const known of knownPaths) if (known.endsWith(`${asPath}.java`)) return known;
  }
  // Aliased absolute imports (tsconfig paths) — try root-relative.
  return tryCandidate(specifier);
}

/** Is this specifier a local (in-repo) import rather than a package? */
export function isLocalSpecifier(specifier: string, language: string): boolean {
  if (specifier.startsWith(".") || specifier.startsWith("/")) return true;
  if (language === "python" && specifier.startsWith(".")) return true;
  if (language === "c" || language === "cpp") return true;
  if (language === "rust") return /^(crate|super|self)::/.test(specifier) || !specifier.includes("::");
  if (language === "go") return specifier.includes("/") && !/^[a-z0-9.-]+\.[a-z]{2,}\//i.test(specifier);
  return false;
}

/**
 * Build the dependency graph from `{path, content}` pairs plus known paths.
 * Local edges are resolved with `resolveImport`; unresolved specifiers are
 * collected under `external`.
 */
export function buildDependencyGraph(
  files: readonly { path: string; content: string }[],
  manifests: readonly ManifestDependencies[] = [],
): DependencyGraph {
  const knownPaths = new Set(files.map((f) => f.path));
  const imports: Record<string, string[]> = {};
  const importedBy: Record<string, string[]> = {};
  const external: Record<string, string[]> = {};
  const edges: ImportEdge[] = [];
  const seenEdge = new Set<string>();

  for (const file of files) {
    const language = detectLanguage(file.path);
    const specs = extractImports(file.path, file.content);
    if (language === "go") specs.push(...extractGoImports(file.content));
    if (specs.length === 0) continue;
    imports[file.path] = [];

    for (const spec of specs) {
      // Node builtins ("node:fs") are neither a local file nor a package dependency.
      if (spec.startsWith("node:")) continue;
      const local = resolveImport(file.path, spec, knownPaths);
      if (local && local !== file.path) {
        const key = `${file.path}->${local}`;
        if (!seenEdge.has(key)) {
          seenEdge.add(key);
          edges.push({ from: file.path, to: local, specifier: spec });
          imports[file.path].push(local);
          (importedBy[local] ??= []).push(file.path);
        }
      } else if (!local && !isLocalSpecifier(spec, language)) {
        (external[spec] ??= []).push(file.path);
      }
    }
    imports[file.path].sort();
  }
  for (const key of Object.keys(importedBy)) importedBy[key].sort();

  return {
    imports,
    importedBy,
    edges,
    external,
    manifests: [...manifests],
    nodeCount: Object.keys(imports).length,
    edgeCount: edges.length,
  };
}
