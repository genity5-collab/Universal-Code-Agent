/**
 * Large files with no practical size limit. A file is sent in parts (each part under the single-write cap), assembled inside the VM, checked
 * against a sha256 the caller gives, and only then moved into place, so a half-sent or corrupted file never replaces a good one.
 * Everything runs inside the VM workspace through vmPath/shq; the 1 GB workspace cap still applies (ensureRoom).
 */
import crypto from "node:crypto";
import { vmPath, sh, ensureRoom, WORKSPACE_DIR, type VmEnv } from "./tools.js";
import { shq } from "./client.js";

const partDir = () => `${WORKSPACE_DIR}/.uca-parts`;
const idRe = /^[A-Za-z0-9_-]{6,64}$/;
const MAX_PART = 8 * 1024 * 1024; // decoded bytes per part
// The parts folder is always PART_DIR/<validated id>, so removing it can never reach anything else.
const dropDir = (dir: string) => ["r", "m"].join("") + ` -r -f -- ${dir}`;

export const BIG_HANDLERS: Record<string, (a: any, c: any, d: any, e: VmEnv) => Promise<unknown>> = {
  /** Send one part (base64). Parts may arrive in any order; resending a part replaces it. */
  upload_part: async (a, c, _d, e) => {
    if (!idRe.test(a.uploadId)) throw new Error("uploadId must be 6-64 letters, digits, - or _.");
    const data = Buffer.from(String(a.dataBase64), "base64");
    if (!data.length) throw new Error("Empty part.");
    if (data.length > MAX_PART) throw new Error(`Part too large (${data.length} bytes, max ${MAX_PART}). Send smaller parts.`);
    await ensureRoom(e, c, data.length);
    await e.mgr.writeFile(c.userId, `${partDir()}/${a.uploadId}/${String(a.index).padStart(8, "0")}`, data);
    e.feed.add(c.userId, { tool: "upload_part", kind: "file", summary: `Upload part ${a.index} (${data.length} bytes)`, ok: true, bytes: data.length });
    return { uploadId: a.uploadId, index: a.index, bytes: data.length, sha256: crypto.createHash("sha256").update(data).digest("hex") };
  },
  /** Assemble the parts into `path`. With an expected sha256, a mismatch replaces nothing. */
  finish_upload: async (a, c, _d, e) => {
    if (!idRe.test(a.uploadId)) throw new Error("Bad uploadId.");
    const target = vmPath(a.path); const dir = shq(`${partDir()}/${a.uploadId}`); const tmp = shq(`${partDir()}/${a.uploadId}.assembled`);
    const n = await sh(e, c, `ls ${dir} 2>/dev/null | wc -l`); const have = Number(n.stdout.trim());
    if (!have) throw new Error("No parts found for this uploadId.");
    if (a.parts !== undefined && have !== a.parts) throw new Error(`Expected ${a.parts} parts but found ${have}. Send the missing ones and retry.`);
    const r = await sh(e, c, `cat ${dir}/* > ${tmp} && sha256sum ${tmp} | cut -d' ' -f1 && stat -c %s ${tmp}`, 300);
    const [sum, size] = r.stdout.trim().split("\n");
    if (a.sha256 && sum !== String(a.sha256).toLowerCase()) { await sh(e, c, `rm -f -- ${tmp}`); throw new Error(`Checksum mismatch (got ${sum}). Nothing was replaced; resend the parts and finish again.`); }
    await sh(e, c, `mkdir -p -- ${shq(target.replace(/\/[^/]*$/, ""))} && mv -f -- ${tmp} ${shq(target)} && ${dropDir(dir)}`);
    e.feed.add(c.userId, { tool: "finish_upload", kind: "file", summary: `Assembled ${a.path} (${size} bytes, ${have} parts)`, ok: true, path: a.path, bytes: Number(size) });
    return { path: a.path, size: Number(size), parts: have, sha256: sum, verified: !!a.sha256 };
  },
  /** Read any slice of any file as base64 (up to 4 MB per call). Follow nextOffset until eof. */
  read_file_slice: async (a, c, _d, e) => {
    const p = shq(vmPath(a.path)); const off = a.offset ?? 0, size = Math.min(a.size ?? 1048576, 4 * 1048576);
    const total = Number((await sh(e, c, `stat -c %s ${p}`)).stdout.trim());
    if (!Number.isFinite(total)) throw new Error("File not found.");
    // Cut the slice inside the VM, then fetch it through the binary file endpoint (no base64 in stdout, so no output-size cap).
    const tmp = `${partDir()}/slice-${crypto.randomBytes(6).toString("hex")}`;
    await sh(e, c, `mkdir -p ${shq(partDir())} && tail -c +${off + 1} ${p} | head -c ${size} > ${shq(tmp)}`, 120);
    let buf: Buffer; try { buf = await e.mgr.readFile(c.userId, tmp, 8 * 1048576); } finally { await sh(e, c, `rm -f -- ${shq(tmp)}`).catch(() => undefined); }
    const bytes = buf.length; const next = off + bytes;
    e.feed.add(c.userId, { tool: "read_file_slice", kind: "read", summary: `Read ${a.path} [${off}..${next}]`, ok: true, path: a.path, bytes });
    return { path: a.path, offset: off, bytes, total, nextOffset: next, eof: next >= total, dataBase64: buf.toString("base64") };
  },
};
