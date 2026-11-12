/**
 * Regex-based symbol extraction for the languages the indexer supports.
 * Deliberately heuristic: fast, dependency-free, good enough for a repo map.
 */
import { detectLanguage } from "./language.js";

export type SymbolKind = "function" | "class" | "method" | "interface" | "type" | "const";

export interface SymbolRecord {
  name: string;
  kind: SymbolKind;
  /** 1-based line number. */
  line: number;
}

export function isSymbolKind(v: string): v is SymbolKind {
  return v === "function" || v === "class" || v === "method" || v === "interface" || v === "type" || v === "const";
}

const KEYWORDS = new Set([
  "if", "for", "while", "switch", "catch", "return", "function", "else", "do", "try",
  "new", "delete", "typeof", "await", "yield", "super", "this", "with", "case", "throw",
  "constructor", "sizeof", "defined", "static_assert",
]);

interface Rule {
  re: RegExp;
  kind: SymbolKind;
  /** Capture group holding the name (default 1). */
  group?: number;
  /** Only apply when the line indent is > 0. */
  indentedOnly?: boolean;
  /** Reject captures that look like keywords. */
  filterKeywords?: boolean;
}

function rulesFor(language: string): Rule[] {
  switch (language) {
    case "typescript":
    case "javascript":
      return [
        { re: /^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)/, kind: "function" },
        {
          re: /^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::\s*[^=]+)?=\s*(?:async\s*)?(?:function\b|\([^)]*\)\s*(?::\s*[^=]+)?=>|[A-Za-z_$][\w$]*\s*=>)/,
          kind: "function",
        },
        { re: /^\s*(?:export\s+)?(?:default\s+)?(?:abstract\s+)?class\s+([A-Za-z_$][\w$]*)/, kind: "class" },
        { re: /^\s*(?:export\s+)?interface\s+([A-Za-z_$][\w$]*)/, kind: "interface" },
        { re: /^\s*(?:export\s+)?(?:type|enum)\s+([A-Za-z_$][\w$]*)\s*(?:=|\{|extends)/, kind: "type" },
        {
          re: /^\s{2,}(?:(?:public|private|protected|static|async|readonly|override|get|set)\s+)*([A-Za-z_$][\w$]*)\s*(?:<[^>]*>)?\s*\([^)]*\)\s*(?::\s*[^{]+)?\{/,
          kind: "method",
          indentedOnly: true,
          filterKeywords: true,
        },
        { re: /^\s*(?:export\s+)?const\s+([A-Z_][A-Z0-9_]*)\s*(?::|=)/, kind: "const" },
      ];
    case "python":
      return [
        { re: /^(\s*)(?:async\s+)?def\s+([A-Za-z_]\w*)/, kind: "function", group: 2, indentedOnly: false },
        { re: /^(\s*)class\s+([A-Za-z_]\w*)/, kind: "class", group: 2 },
        { re: /^([A-Z][A-Z0-9_]*)\s*(?::[^=]+)?=/, kind: "const" },
      ];
    case "go":
      return [
        { re: /^func\s+\([^)]*\)\s*([A-Za-z_]\w*)/, kind: "method" },
        { re: /^func\s+([A-Za-z_]\w*)/, kind: "function" },
        { re: /^type\s+([A-Za-z_]\w*)\s+struct\b/, kind: "class" },
        { re: /^type\s+([A-Za-z_]\w*)\s+interface\b/, kind: "interface" },
        { re: /^type\s+([A-Za-z_]\w*)\s+/, kind: "type" },
        { re: /^(?:const|var)\s+([A-Za-z_]\w*)/, kind: "const" },
      ];
    case "rust":
      return [
        { re: /^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?(?:const\s+)?fn\s+([A-Za-z_]\w*)/, kind: "function" },
        { re: /^\s*(?:pub(?:\([^)]*\))?\s+)?struct\s+([A-Za-z_]\w*)/, kind: "class" },
        { re: /^\s*(?:pub(?:\([^)]*\))?\s+)?trait\s+([A-Za-z_]\w*)/, kind: "interface" },
        { re: /^\s*(?:pub(?:\([^)]*\))?\s+)?(?:enum|type)\s+([A-Za-z_]\w*)/, kind: "type" },
        { re: /^\s*(?:pub(?:\([^)]*\))?\s+)?(?:const|static)\s+([A-Za-z_]\w*)/, kind: "const" },
      ];
    case "java":
      return [
        { re: /^\s*(?:(?:public|private|protected|final|abstract|static)\s+)*(?:class|record)\s+(\w+)/, kind: "class" },
        { re: /^\s*(?:(?:public|private|protected|static|final|abstract)\s+)*interface\s+(\w+)/, kind: "interface" },
        { re: /^\s*(?:(?:public|private|protected|static|final|abstract)\s+)*enum\s+(\w+)/, kind: "type" },
        {
          re: /^\s+(?:(?:public|private|protected|static|final|synchronized|native|abstract)\s+)+[\w<>\[\],.?\s]+\s+(\w+)\s*\([^;]*\)\s*(?:throws\s+[\w,\s.]+)?\{/,
          kind: "method",
          filterKeywords: true,
        },
        { re: /^\s*(?:(?:public|private|protected)\s+)?static\s+final\s+[\w<>\[\]]+\s+(\w+)\s*=/, kind: "const" },
      ];
    case "c":
    case "cpp":
      return [
        { re: /^\s*(?:class|struct)\s+([A-Za-z_]\w*)\s*(?:[:{]|$)/, kind: "class" },
        { re: /^\s*(?:template\s*<[^>]*>\s*)?(?:typedef\s+[\w:*&<>\s]+|using\s+\w+\s*=|enum(?:\s+class)?\s+)([A-Za-z_]\w*)/, kind: "type" },
        {
          re: /^\s*(?:[\w:*&<>,]+\s+)+[*&]*([A-Za-z_]\w*)\s*\([^;]*\)\s*(?:const\s*)?(?:noexcept\s*)?\{?\s*$/,
          kind: "function",
          filterKeywords: true,
        },
        { re: /^\s*#define\s+([A-Za-z_]\w*)/, kind: "const" },
      ];
    case "ruby":
      return [
        { re: /^\s*def\s+(?:self\.)?([A-Za-z_]\w*[?!=]?)/, kind: "method" },
        { re: /^\s*(?:class|module)\s+([A-Z]\w*)/, kind: "class" },
        { re: /^\s*([A-Z][A-Z0-9_]*)\s*=/, kind: "const" },
      ];
    case "php":
      return [
        {
          re: /^\s*(?:(?:public|private|protected|static|final|abstract)\s+)*function\s+([A-Za-z_]\w*)/,
          kind: "function",
          filterKeywords: true,
        },
        { re: /^\s*(?:(?:final|abstract)\s+)*class\s+([A-Za-z_]\w*)/, kind: "class" },
        { re: /^\s*interface\s+([A-Za-z_]\w*)/, kind: "interface" },
        { re: /^\s*trait\s+([A-Za-z_]\w*)/, kind: "type" },
        { re: /^\s*(?:const\s+|define\s*\(\s*['"])([A-Za-z_]\w*)/, kind: "const" },
      ];
    default:
      return [];
  }
}

const RULE_CACHE = new Map<string, Rule[]>();

function rules(language: string): Rule[] {
  const cached = RULE_CACHE.get(language);
  if (cached) return cached;
  const built = rulesFor(language).map((r) => ({ ...r, re: new RegExp(r.re.source) }));
  RULE_CACHE.set(language, built);
  return built;
}

/** Extract symbols from source text. Returns [] for unsupported languages. */
export function extractSymbols(languageOrPath: string, content: string): SymbolRecord[] {
  const language = detectLanguage(languageOrPath);
  const rs = rules(language);
  if (rs.length === 0) return [];
  const lines = content.split("\n");
  const out: SymbolRecord[] = [];
  const seen = new Set<string>();

  for (let li = 0; li < lines.length; li++) {
    const line = lines[li];
    if (line.length > 2000) continue;
    const trimmed = line.trimStart();
    if (trimmed.startsWith("//") || trimmed.startsWith("#!") || trimmed.startsWith("*")) continue;
    const indent = line.length - trimmed.length;

    for (const rule of rs) {
      const m = rule.re.exec(line);
      if (!m) continue;
      const name = m[rule.group ?? 1];
      if (!name) continue;
      if (rule.filterKeywords && KEYWORDS.has(name)) continue;
      if (rule.indentedOnly && indent === 0) continue;

      let kind = rule.kind;
      // Python: a def nested in a class body is a method.
      if (language === "python" && kind === "function" && indent > 0) kind = "method";

      const key = `${kind}:${name}:${li + 1}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ name, kind, line: li + 1 });
      break; // first matching rule wins for a given line
    }
  }
  return out;
}

/** Fuzzy match: substring (case-insensitive), then subsequence, then edit-distance-ish. */
export function fuzzyMatchScore(query: string, candidate: string): number {
  const q = query.toLowerCase();
  const c = candidate.toLowerCase();
  if (q === c) return 1000;
  if (c.startsWith(q)) return 800 - c.length;
  if (c.includes(q)) return 600 - c.length;
  // subsequence
  let qi = 0;
  for (let i = 0; i < c.length && qi < q.length; i++) if (c[i] === q[qi]) qi++;
  if (qi === q.length) return 300 - c.length;
  // prefix-of-prefix typo tolerance: share the first 3 chars
  if (q.length >= 3 && c.length >= 3 && q.slice(0, 3) === c.slice(0, 3)) return 100 - c.length;
  return 0;
}

/** Levenshtein distance capped at `max` (returns max+1 when exceeded). */
export function levenshtein(a: string, b: string, max = 3): number {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  const prev = new Array<number>(b.length + 1);
  const cur = new Array<number>(b.length + 1);
  for (let j = 0; j <= b.length; j++) prev[j] = j;
  for (let i = 1; i <= a.length; i++) {
    cur[0] = i;
    let rowMin = cur[0];
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost);
      if (cur[j] < rowMin) rowMin = cur[j];
    }
    if (rowMin > max) return max + 1;
    for (let j = 0; j <= b.length; j++) prev[j] = cur[j];
  }
  return prev[b.length];
}
