/** Language detection and binary sniffing. No I/O: works on paths and Buffers. */

const EXT_LANGUAGE: Record<string, string> = {
  ts: "typescript",
  tsx: "typescript",
  mts: "typescript",
  cts: "typescript",
  js: "javascript",
  jsx: "javascript",
  mjs: "javascript",
  cjs: "javascript",
  py: "python",
  pyi: "python",
  go: "go",
  rs: "rust",
  java: "java",
  kt: "kotlin",
  kts: "kotlin",
  scala: "scala",
  c: "c",
  h: "c",
  cc: "cpp",
  cpp: "cpp",
  cxx: "cpp",
  hpp: "cpp",
  hh: "cpp",
  hxx: "cpp",
  cs: "csharp",
  rb: "ruby",
  php: "php",
  swift: "swift",
  m: "objective-c",
  mm: "objective-c",
  sh: "shell",
  bash: "shell",
  zsh: "shell",
  ps1: "powershell",
  json: "json",
  jsonc: "jsonc",
  json5: "json5",
  yml: "yaml",
  yaml: "yaml",
  toml: "toml",
  ini: "ini",
  md: "markdown",
  mdx: "markdown",
  rst: "rst",
  html: "html",
  htm: "html",
  css: "css",
  scss: "scss",
  sass: "sass",
  less: "less",
  vue: "vue",
  svelte: "svelte",
  sql: "sql",
  graphql: "graphql",
  gql: "graphql",
  proto: "protobuf",
  lua: "lua",
  r: "r",
  dart: "dart",
  el: "lisp",
  clj: "clojure",
  ex: "elixir",
  exs: "elixir",
  erl: "erlang",
  hs: "haskell",
  ml: "ocaml",
  zig: "zig",
  nim: "nim",
  txt: "text",
  log: "text",
  csv: "csv",
  tsv: "tsv",
  xml: "xml",
  svg: "xml",
  env: "dotenv",
  lock: "lock",
  wasm: "wasm",
  ipynb: "jupyter",
};

const FILENAME_LANGUAGE: Record<string, string> = {
  dockerfile: "dockerfile",
  containerfile: "dockerfile",
  makefile: "make",
  gnumakefile: "make",
  rakefile: "ruby",
  gemfile: "ruby",
  "cmakelists.txt": "cmake",
  "package.json": "json",
  "tsconfig.json": "jsonc",
  "go.mod": "gomod",
  "go.sum": "gosum",
  "cargo.toml": "toml",
  "cargo.lock": "toml",
  "pyproject.toml": "toml",
  "poetry.lock": "toml",
  "requirements.txt": "requirements",
  ".gitignore": "gitignore",
  ".dockerignore": "gitignore",
  ".npmrc": "ini",
  ".env": "dotenv",
  ".editorconfig": "ini",
};

const LANGUAGE_ALIASES: Record<string, string> = {
  ts: "typescript",
  js: "javascript",
  py: "python",
  rb: "ruby",
  rs: "rust",
  golang: "go",
  sh: "shell",
  yml: "yaml",
  md: "markdown",
  "c++": "cpp",
  "c#": "csharp",
};

/** Canonical language id for a path (lower-case, extension driven). */
export function detectLanguage(filePath: string): string {
  const base = filePath.split(/[\\/]/).pop() ?? "";
  const lowerBase = base.toLowerCase();
  const byName = FILENAME_LANGUAGE[lowerBase];
  if (byName) return byName;
  // Dockerfile.dev / Dockerfile.prod etc.
  if (lowerBase.startsWith("dockerfile")) return "dockerfile";
  const dot = lowerBase.lastIndexOf(".");
  if (dot <= 0 || dot === lowerBase.length - 1) return "text";
  const ext = lowerBase.slice(dot + 1);
  return EXT_LANGUAGE[ext] ?? "text";
}

/** Normalize a user supplied language name/alias. */
export function normalizeLanguage(language: string): string {
  const l = language.toLowerCase().trim();
  return LANGUAGE_ALIASES[l] ?? l;
}

/** Languages whose files the indexer knows how to extract symbols from. */
export const SYMBOL_LANGUAGES: ReadonlySet<string> = new Set([
  "typescript",
  "javascript",
  "python",
  "go",
  "rust",
  "java",
  "c",
  "cpp",
  "ruby",
  "php",
]);

/** Languages where a `#` line comment is used (kept for future tooling). */
export const HASH_COMMENT_LANGUAGES: ReadonlySet<string> = new Set([
  "python",
  "ruby",
  "shell",
  "yaml",
  "toml",
  "make",
  "dockerfile",
  "requirements",
]);

/**
 * Heuristic binary detection: a NUL byte in the sample, or a high share of
 * control bytes / invalid UTF-8 replacement characters.
 */
export function isBinaryBuffer(buf: Buffer): boolean {
  if (buf.length === 0) return false;
  const sample = buf.subarray(0, Math.min(buf.length, 8192));
  let suspicious = 0;
  for (let i = 0; i < sample.length; i++) {
    const b = sample[i];
    if (b === 0) return true;
    // allow \t(9) \n(10) \v(11) \f(12) \r(13) and printable
    if (b < 7 || (b > 13 && b < 32)) suspicious++;
  }
  if (suspicious / sample.length > 0.1) return true;
  // Invalid UTF-8 shows up as U+FFFD replacement characters after decoding.
  const decoded = sample.toString("utf8");
  let replacement = 0;
  for (const ch of decoded) if (ch === "\uFFFD") replacement++;
  return replacement > 0 && replacement / Math.max(decoded.length, 1) > 0.02;
}
