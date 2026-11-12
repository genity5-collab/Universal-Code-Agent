/** Error type used by the filesystem layer. Carries a stable machine-readable code. */
export class FsError extends Error {
  readonly code: string;
  constructor(message: string, code = "EFS") {
    super(message);
    this.name = "FsError";
    this.code = code;
  }
}

/** Permission/policy refusal (e.g. writing inside .git). */
export class PolicyError extends FsError {
  constructor(message: string) {
    super(message, "EPOLICY");
    this.name = "PolicyError";
  }
}

export function isNodeError(e: unknown): e is NodeJS.ErrnoException {
  return e instanceof Error && typeof (e as NodeJS.ErrnoException).code === "string";
}

/** Wrap a raw node fs error into an FsError that mentions the offending relative path. */
export function wrapFsError(e: unknown, relPath: string): FsError {
  if (e instanceof FsError) return e;
  if (isNodeError(e)) {
    const code = e.code ?? "EFS";
    const map: Record<string, string> = {
      ENOENT: "not found",
      EACCES: "permission denied",
      EPERM: "operation not permitted",
      EISDIR: "is a directory",
      ENOTDIR: "not a directory",
      EEXIST: "already exists",
    };
    const why = map[code] ?? e.message;
    return new FsError(`${code}: ${relPath} ${why}`, code);
  }
  return new FsError(`${relPath}: ${e instanceof Error ? e.message : String(e)}`, "EFS");
}
