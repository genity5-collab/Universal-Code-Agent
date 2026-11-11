import fs from "node:fs";
import path from "node:path";

export class SecurityError extends Error {
  constructor(msg: string) { super(msg); this.name = "SecurityError"; }
}

/** Reject names that could escape or confuse the filesystem. */
export function safeSegment(name: string): string {
  if (!name || name === "." || name === ".." || /[\\/\0]/.test(name)) {
    throw new SecurityError(`Invalid name: ${JSON.stringify(name)}`);
  }
  return name;
}

/**
 * Resolve a user-supplied relative path inside `root`. Blocks absolute paths,
 * `..` traversal, NUL bytes and symlink escapes (checks the deepest existing ancestor).
 */
export function resolveInside(root: string, rel: string): string {
  if (typeof rel !== "string") throw new SecurityError("Path must be a string");
  if (rel.includes("\0")) throw new SecurityError("NUL byte in path");
  const realRoot = fs.realpathSync(root);
  const cleaned = rel.replace(/\\/g, "/");
  if (path.isAbsolute(cleaned) || /^[a-zA-Z]:/.test(cleaned)) {
    throw new SecurityError("Absolute paths are not allowed");
  }
  const target = path.resolve(realRoot, cleaned);
  if (target !== realRoot && !target.startsWith(realRoot + path.sep)) {
    throw new SecurityError("Path escapes workspace");
  }
  // symlink check on deepest existing ancestor
  let probe = target;
  while (!fs.existsSync(probe)) {
    const parent = path.dirname(probe);
    if (parent === probe) break;
    probe = parent;
  }
  const realProbe = fs.realpathSync(probe);
  if (realProbe !== realRoot && !realProbe.startsWith(realRoot + path.sep)) {
    throw new SecurityError("Symlink escapes workspace");
  }
  return target;
}

export function relFrom(root: string, abs: string): string {
  return path.relative(fs.realpathSync(root), abs).split(path.sep).join("/") || ".";
}

const SECRET_PATTERNS = [
  /gh[pousr]_[A-Za-z0-9]{20,}/g,
  /github_pat_[A-Za-z0-9_]{20,}/g,
  /sk-[A-Za-z0-9]{20,}/g,
  /AKIA[0-9A-Z]{16}/g,
  /(Bearer\s+)[A-Za-z0-9._\-]{20,}/gi,
];
export function redact(text: string): string {
  let out = text;
  for (const re of SECRET_PATTERNS) out = out.replace(re, (m, p1) => (p1 ? `${p1}[REDACTED]` : "[REDACTED]"));
  return out;
}
