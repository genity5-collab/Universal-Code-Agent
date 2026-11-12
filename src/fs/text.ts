/** Small pure text/byte helpers shared by the filesystem layer. No I/O. */

/** Number of lines in `text` (a trailing newline does not start a new line). */
export function countLines(text: string): number {
  if (text.length === 0) return 0;
  let n = 1;
  let idx = text.indexOf("\n");
  while (idx !== -1) {
    n++;
    idx = text.indexOf("\n", idx + 1);
  }
  return text.endsWith("\n") ? n - 1 : n;
}

/** Split into lines, dropping the phantom empty line produced by a trailing \n. */
export function splitLines(text: string): string[] {
  if (text.length === 0) return [];
  const lines = text.split("\n");
  if (lines.length > 1 && lines[lines.length - 1] === "") lines.pop();
  return lines;
}

export type LineEnding = "lf" | "crlf" | "cr" | "mixed" | "none";

export function detectLineEnding(text: string): LineEnding {
  const crlf = (text.match(/\r\n/g) ?? []).length;
  const lf = (text.match(/(?<!\r)\n/g) ?? []).length;
  const cr = (text.match(/\r(?!\n)/g) ?? []).length;
  const kinds = [crlf > 0, lf > 0, cr > 0].filter(Boolean).length;
  if (kinds === 0) return "none";
  if (kinds > 1) return "mixed";
  if (crlf > 0) return "crlf";
  if (cr > 0) return "cr";
  return "lf";
}

/** True when `byte` is a UTF-8 continuation byte (0b10xxxxxx). */
export function isUtf8Continuation(byte: number): boolean {
  return (byte & 0xc0) === 0x80;
}

/**
 * Find the first char boundary at or after `index` in `buf` (start alignment).
 * Returns `index` unchanged when the byte there already starts a character.
 */
export function alignStart(buf: Buffer, index: number): number {
  let i = index;
  while (i < buf.length && isUtf8Continuation(buf[i])) i++;
  return i;
}

/**
 * Shrink `end` (exclusive) so the slice `buf.subarray(start, end)` never ends
 * inside a multi-byte UTF-8 sequence. Never returns less than `start`.
 */
export function alignEnd(buf: Buffer, start: number, end: number): number {
  let e = Math.min(end, buf.length);
  while (e > start && e < buf.length && isUtf8Continuation(buf[e])) e--;
  if (e === start && end > start && start < buf.length) {
    // The window is smaller than one character: emit that whole character
    // rather than returning an empty (or invalid) slice.
    let next = start + 1;
    while (next < buf.length && isUtf8Continuation(buf[next])) next++;
    e = next;
  }
  return e;
}

/** Escape a string so it can be embedded in a RegExp source. */
export function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

const GLOB_META = /[*?[\]{}]/;

export function hasGlobMeta(pattern: string): boolean {
  return GLOB_META.test(pattern);
}

/** Expand simple `{a,b}` alternatives into separate patterns. */
function expandBraces(pattern: string): string[] {
  const open = pattern.indexOf("{");
  if (open === -1) return [pattern];
  let depth = 0;
  let close = -1;
  for (let i = open; i < pattern.length; i++) {
    if (pattern[i] === "{") depth++;
    else if (pattern[i] === "}") {
      depth--;
      if (depth === 0) { close = i; break; }
    }
  }
  if (close === -1) return [pattern];
  const head = pattern.slice(0, open);
  const body = pattern.slice(open + 1, close);
  const tail = pattern.slice(close + 1);
  const parts: string[] = [];
  let depthInner = 0;
  let cur = "";
  for (const ch of body) {
    if (ch === "," && depthInner === 0) { parts.push(cur); cur = ""; continue; }
    if (ch === "{") depthInner++;
    if (ch === "}") depthInner--;
    cur += ch;
  }
  parts.push(cur);
  const out: string[] = [];
  for (const p of parts) for (const t of expandBraces(head + p + tail)) out.push(t);
  return out;
}

/**
 * Compile a glob-ish pattern to a RegExp.
 * `*` matches within one path segment, `**` matches across segments,
 * `**​/` also matches zero segments, `?` matches one non-slash char,
 * `[...]` is a character class and `{a,b}` alternates.
 */
export function globToRegExp(pattern: string, opts: { caseSensitive?: boolean } = {}): RegExp {
  const alternatives = expandBraces(pattern.replace(/\\/g, "/"));
  const sources = alternatives.map((alt) => {
    let src = "";
    for (let i = 0; i < alt.length; i++) {
      const ch = alt[i];
      if (ch === "*") {
        if (alt[i + 1] === "*") {
          i++;
          if (alt[i + 1] === "/") {
            i++;
            src += "(?:[^/]+/)*";
          } else {
            src += ".*";
          }
        } else {
          src += "[^/]*";
        }
      } else if (ch === "?") {
        src += "[^/]";
      } else if (ch === "[") {
        const close = alt.indexOf("]", i + 1);
        if (close === -1) { src += "\\["; continue; }
        let body = alt.slice(i + 1, close);
        if (body.startsWith("!")) body = "^" + body.slice(1);
        src += `[${body}]`;
        i = close;
      } else {
        src += escapeRegExp(ch);
      }
    }
    return src;
  });
  return new RegExp(`^(?:${sources.join("|")})$`, opts.caseSensitive ? "" : "i");
}

/** Numeric option coercion with a floor and default. */
export function intOption(value: unknown, fallback: number, min = 0): number {
  const n = typeof value === "number" ? value : Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.trunc(n));
}

/** Deterministic lexical comparison by code unit (stable across platforms). */
export function compareStrings(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** Prefix/suffix trimming used by the diff to keep LCS work small. */
export function commonPrefixLen(a: readonly string[], b: readonly string[]): number {
  const max = Math.min(a.length, b.length);
  let i = 0;
  while (i < max && a[i] === b[i]) i++;
  return i;
}

export function commonSuffixLen(a: readonly string[], b: readonly string[], fromStart: number): number {
  let i = 0;
  const max = Math.min(a.length, b.length) - fromStart;
  while (i < max && a[a.length - 1 - i] === b[b.length - 1 - i]) i++;
  return i;
}
