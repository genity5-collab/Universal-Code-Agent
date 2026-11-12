/**
 * Safe documentation research for provider onboarding.
 * - Public https only; DNS is resolved and every address must be public (blocks SSRF to localhost / cloud metadata / LAN).
 * - Redirects are followed manually (max 4), re-checking every hop.
 * - Size and time limits. HTML is reduced to text. Output is labelled untrusted so page text cannot act as instructions.
 * - NO credentials are ever attached here.
 */
import dns from "node:dns/promises";
import net from "node:net";

export class DocsError extends Error {}

export function isPrivateIp(ip: string): boolean {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split(".").map(Number);
    return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || a >= 224;
  }
  if (net.isIPv6(ip)) {
    const x = ip.toLowerCase();
    if (x === "::1" || x === "::" || x.startsWith("fe80") || x.startsWith("fc") || x.startsWith("fd")) return true;
    const m = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(x); if (m) return isPrivateIp(m[1]);
    return false;
  }
  return true;
}

export type Resolver = (host: string) => Promise<string[]>;
const defaultResolver: Resolver = async (h) => (await dns.lookup(h, { all: true })).map((r) => r.address);

export async function assertPublicUrl(raw: string, resolve: Resolver = defaultResolver): Promise<URL> {
  let u: URL; try { u = new URL(raw); } catch { throw new DocsError("Invalid URL."); }
  if (u.protocol !== "https:") throw new DocsError("Only https:// URLs can be read.");
  if (u.username || u.password) throw new DocsError("Credentials in URLs are not allowed.");
  if (u.port && u.port !== "443") throw new DocsError("Only the default HTTPS port is allowed.");
  const host = u.hostname.replace(/^\[|\]$/g, "");
  if (net.isIP(host)) { if (isPrivateIp(host)) throw new DocsError("That address is not public."); return u; }
  if (/^(localhost|.*\.local|.*\.internal|.*\.localhost)$/i.test(host)) throw new DocsError("That host is not public.");
  let addrs: string[]; try { addrs = await resolve(host); } catch { throw new DocsError("Could not resolve that host."); }
  if (!addrs.length || addrs.some(isPrivateIp)) throw new DocsError("That host resolves to a non-public address.");
  return u;
}

export function htmlToText(html: string): string {
  return html
    .replace(/<(script|style|noscript|svg|head)[\s\S]*?<\/\1>/gi, " ")
    .replace(/<!--[\s\S]*?-->/g, " ")
    .replace(/<\/(p|div|li|h[1-6]|tr|pre|section|article|br)>/gi, "\n").replace(/<br\s*\/?>/gi, "\n")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/g, " ").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#39;/g, "'")
    .replace(/[ \t\f\v]+/g, " ").replace(/ *\n */g, "\n").replace(/\n{2,}/g, "\n\n").trim();
}

export interface FetchedDoc { url: string; status: number; contentType: string; text: string; truncated: boolean; links: string[] }

export async function fetchPublicDoc(raw: string, opts: { fetchImpl?: typeof fetch; resolve?: Resolver; maxChars?: number; offset?: number } = {}): Promise<FetchedDoc> {
  const f = opts.fetchImpl ?? fetch; let cur = raw;
  for (let hop = 0; hop < 5; hop++) {
    const u = await assertPublicUrl(cur, opts.resolve);
    const ctl = new AbortController(); const t = setTimeout(() => ctl.abort(), 20_000);
    try {
      const r = await f(u.toString(), { redirect: "manual", signal: ctl.signal, headers: { "user-agent": "UniversalCodeAgent-docs/1.0", accept: "text/html,text/markdown,text/plain,application/json;q=0.9" } });
      if (r.status >= 300 && r.status < 400 && r.headers.get("location")) { cur = new URL(r.headers.get("location")!, u).toString(); continue; }
      const ct = (r.headers.get("content-type") ?? "").toLowerCase();
      if (!/text\/|json|xml|markdown/.test(ct) && ct) throw new DocsError(`Unsupported content type: ${ct.slice(0, 60)}`);
      const buf = await r.text(); const raw2 = buf.slice(0, 2_000_000);
      const isHtml = /html/.test(ct) || /^\s*<(!doctype|html)/i.test(raw2);
      const links = isHtml ? [...raw2.matchAll(/href\s*=\s*["']([^"'#]+)["']/gi)].map((m) => { try { return new URL(m[1], u).toString(); } catch { return ""; } }).filter((x) => x.startsWith("https://")).slice(0, 60) : [];
      const text = isHtml ? htmlToText(raw2) : raw2; const off = Math.max(0, opts.offset ?? 0); const max = Math.min(opts.maxChars ?? 12000, 30000);
      return { url: u.toString(), status: r.status, contentType: ct, text: text.slice(off, off + max), truncated: text.length > off + max, links: [...new Set(links)] };
    } catch (e: any) { if (e instanceof DocsError) throw e; throw new DocsError(e?.name === "AbortError" ? "Timed out." : `Fetch failed: ${e?.message ?? e}`); }
    finally { clearTimeout(t); }
  }
  throw new DocsError("Too many redirects.");
}

/** Web search through DuckDuckGo's HTML endpoint (no key needed). Results are untrusted text. */
export async function searchWeb(query: string, opts: { fetchImpl?: typeof fetch; limit?: number } = {}): Promise<{ title: string; url: string; snippet: string }[]> {
  const f = opts.fetchImpl ?? fetch; const q = String(query).slice(0, 200);
  const r = await f(`https://html.duckduckgo.com/html/?q=${encodeURIComponent(q)}`, { headers: { "user-agent": "Mozilla/5.0 UniversalCodeAgent-docs/1.0" }, signal: AbortSignal.timeout(20_000) });
  const html = await r.text(); const out: { title: string; url: string; snippet: string }[] = [];
  const re = /<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>([\s\S]*?)<\/a>[\s\S]*?(?:class="result__snippet"[^>]*>([\s\S]*?)<\/a>)?/gi; let m: RegExpExecArray | null;
  while ((m = re.exec(html)) && out.length < (opts.limit ?? 8)) {
    let href = m[1].replace(/&amp;/g, "&"); const uddg = /[?&]uddg=([^&]+)/.exec(href); if (uddg) href = decodeURIComponent(uddg[1]);
    if (!href.startsWith("https://")) continue;
    out.push({ title: htmlToText(m[2]).slice(0, 160), url: href, snippet: htmlToText(m[3] ?? "").slice(0, 300) });
  }
  return out;
}
