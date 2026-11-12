/**
 * Line diffing with a real LCS (dynamic-programming longest common subsequence)
 * plus common prefix/suffix trimming. No external dependencies.
 */
import { commonPrefixLen, commonSuffixLen, splitLines } from "./text.js";

export type DiffOp = "equal" | "add" | "remove";

export interface DiffLine {
  op: DiffOp;
  /** 1-based line number in `a`, null for added lines. */
  aLine: number | null;
  /** 1-based line number in `b`, null for removed lines. */
  bLine: number | null;
  text: string;
}

export interface DiffHunk {
  /** 1-based start line on the a-side; for pure insertions it is the line *before* the insertion (may be 0). */
  aStart: number;
  aLength: number;
  bStart: number;
  bLength: number;
  header: string;
  lines: DiffLine[];
}

export interface DiffStats {
  added: number;
  removed: number;
  unchanged: number;
  hunks: number;
}

export interface DiffResult {
  identical: boolean;
  unified: string;
  hunks: DiffHunk[];
  stats: DiffStats;
  /** True when the LCS was skipped because the inputs were too large. */
  simplified: boolean;
}

export interface DiffOptions {
  /** Context lines around each change (default 3). */
  context?: number;
  /** Labels used in the --- / +++ header. */
  aLabel?: string;
  bLabel?: string;
  /** Max LCS cells (n*m) before falling back to a coarse replace (default 4e6). */
  maxCells?: number;
}

const DEFAULT_MAX_CELLS = 4_000_000;

/** Core LCS edit script over line arrays (indices refer to the trimmed segments). */
function lcsOps(a: readonly string[], b: readonly string[]): DiffOp[] {
  const n = a.length;
  const m = b.length;
  const width = m + 1;
  // dp[i*width + j] = LCS length of a[i..] and b[j..]
  const dp = new Uint32Array((n + 1) * width);
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      dp[i * width + j] =
        a[i] === b[j]
          ? dp[(i + 1) * width + j + 1] + 1
          : Math.max(dp[(i + 1) * width + j], dp[i * width + j + 1]);
    }
  }
  const ops: DiffOp[] = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      ops.push("equal");
      i++;
      j++;
    } else if (dp[(i + 1) * width + j] >= dp[i * width + j + 1]) {
      ops.push("remove");
      i++;
    } else {
      ops.push("add");
      j++;
    }
  }
  while (i < n) { ops.push("remove"); i++; }
  while (j < m) { ops.push("add"); j++; }
  return ops;
}

/** Produce a flat line-by-line diff. */
export function diffLineArrays(
  aLines: readonly string[],
  bLines: readonly string[],
  opts: DiffOptions = {},
): { lines: DiffLine[]; simplified: boolean } {
  const maxCells = opts.maxCells ?? DEFAULT_MAX_CELLS;
  const prefix = commonPrefixLen(aLines, bLines);
  const suffix = commonSuffixLen(aLines, bLines, prefix);
  const aMid = aLines.slice(prefix, aLines.length - suffix);
  const bMid = bLines.slice(prefix, bLines.length - suffix);

  const out: DiffLine[] = [];
  for (let i = 0; i < prefix; i++) {
    out.push({ op: "equal", aLine: i + 1, bLine: i + 1, text: aLines[i] });
  }

  let simplified = false;
  let midOps: DiffOp[];
  if (aMid.length === 0) {
    midOps = bMid.map(() => "add" as DiffOp);
  } else if (bMid.length === 0) {
    midOps = aMid.map(() => "remove" as DiffOp);
  } else if (aMid.length * bMid.length > maxCells) {
    simplified = true;
    midOps = [
      ...aMid.map(() => "remove" as DiffOp),
      ...bMid.map(() => "add" as DiffOp),
    ];
  } else {
    midOps = lcsOps(aMid, bMid);
  }

  let aCursor = prefix;
  let bCursor = prefix;
  for (const op of midOps) {
    if (op === "equal") {
      out.push({ op, aLine: aCursor + 1, bLine: bCursor + 1, text: aLines[aCursor] });
      aCursor++;
      bCursor++;
    } else if (op === "remove") {
      out.push({ op, aLine: aCursor + 1, bLine: null, text: aLines[aCursor] });
      aCursor++;
    } else {
      out.push({ op, aLine: null, bLine: bCursor + 1, text: bLines[bCursor] });
      bCursor++;
    }
  }

  for (let i = aLines.length - suffix; i < aLines.length; i++) {
    out.push({ op: "equal", aLine: i + 1, bLine: bCursor + 1, text: aLines[i] });
    bCursor++;
  }
  return { lines: out, simplified };
}

/** Group a flat diff into unified-style hunks with context. */
export function toHunks(lines: readonly DiffLine[], context = 3): DiffHunk[] {
  // Precompute how many a-side / b-side lines are consumed before each index.
  const aBefore = new Array<number>(lines.length + 1).fill(0);
  const bBefore = new Array<number>(lines.length + 1).fill(0);
  for (let i = 0; i < lines.length; i++) {
    aBefore[i + 1] = aBefore[i] + (lines[i].op === "add" ? 0 : 1);
    bBefore[i + 1] = bBefore[i] + (lines[i].op === "remove" ? 0 : 1);
  }

  const changed: number[] = [];
  for (let i = 0; i < lines.length; i++) if (lines[i].op !== "equal") changed.push(i);
  if (changed.length === 0) return [];

  const groups: { start: number; end: number }[] = [];
  let groupStart = Math.max(0, changed[0] - context);
  let groupEnd = Math.min(lines.length - 1, changed[0] + context);
  for (let k = 1; k < changed.length; k++) {
    const idx = changed[k];
    if (idx - context <= groupEnd + 1) {
      groupEnd = Math.min(lines.length - 1, idx + context);
    } else {
      groups.push({ start: groupStart, end: groupEnd });
      groupStart = Math.max(0, idx - context);
      groupEnd = Math.min(lines.length - 1, idx + context);
    }
  }
  groups.push({ start: groupStart, end: groupEnd });

  const hunks: DiffHunk[] = [];
  for (const g of groups) {
    const slice = lines.slice(g.start, g.end + 1);
    const aBeforeHunk = aBefore[g.start];
    const bBeforeHunk = bBefore[g.start];
    const aLength = aBefore[g.end + 1] - aBeforeHunk;
    const bLength = bBefore[g.end + 1] - bBeforeHunk;
    // Unified convention: an empty side points at the line *before* the range.
    const aStart = aLength === 0 ? aBeforeHunk : aBeforeHunk + 1;
    const bStart = bLength === 0 ? bBeforeHunk : bBeforeHunk + 1;
    hunks.push({
      aStart,
      aLength,
      bStart,
      bLength,
      header: `@@ -${aStart},${aLength} +${bStart},${bLength} @@`,
      lines: slice,
    });
  }
  return hunks;
}

function hunkToString(hunk: DiffHunk): string {
  const body = hunk.lines
    .map((l) => (l.op === "add" ? `+${l.text}` : l.op === "remove" ? `-${l.text}` : ` ${l.text}`))
    .join("\n");
  return `${hunk.header}\n${body}`;
}

/** Compare two line arrays / strings and return a unified-style diff. */
export function diffText(aText: string, bText: string, opts: DiffOptions = {}): DiffResult {
  const context = opts.context ?? 3;
  const aLines = splitLines(aText);
  const bLines = splitLines(bText);
  const { lines, simplified } = diffLineArrays(aLines, bLines, opts);
  const hunks = toHunks(lines, context);
  const stats: DiffStats = {
    added: lines.filter((l) => l.op === "add").length,
    removed: lines.filter((l) => l.op === "remove").length,
    unchanged: lines.filter((l) => l.op === "equal").length,
    hunks: hunks.length,
  };
  const identical = stats.added === 0 && stats.removed === 0;
  let unified = "";
  if (!identical) {
    const aLabel = opts.aLabel ?? "a";
    const bLabel = opts.bLabel ?? "b";
    unified = [`--- ${aLabel}`, `+++ ${bLabel}`, ...hunks.map(hunkToString)].join("\n") + "\n";
  }
  return { identical, unified, hunks, stats, simplified };
}

/**
 * Re-apply a diff's hunks onto `aText`, producing the b-side text.
 * Used to prove diff correctness (apply(a, diff(a,b)) === b).
 */
export function applyHunks(aText: string, result: DiffResult): string {
  if (result.identical) return aText;
  const aLines = splitLines(aText);
  const out: string[] = [];
  let cursor = 0; // 0-based index into aLines
  for (const hunk of result.hunks) {
    const gapEnd = hunk.aLength === 0 ? hunk.aStart : hunk.aStart - 1;
    while (cursor < gapEnd && cursor < aLines.length) out.push(aLines[cursor++]);
    for (const l of hunk.lines) {
      if (l.op === "equal") out.push(l.text);
      else if (l.op === "add") out.push(l.text);
    }
    if (hunk.aLength > 0) cursor += hunk.aLength;
  }
  while (cursor < aLines.length) out.push(aLines[cursor++]);
  return out.join("\n");
}
