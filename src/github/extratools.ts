/**
 * Extra GitHub tools built on the client's generic request(). Anything that deletes, merges, or changes who can see/access a repo
 * waits for the user's approval; everything else runs directly. Names do not collide with the existing github_* tools (checked by a test).
 */
import { z } from "zod";
import type { ToolDef } from "../mcp/tools.js";
import { gh, needApproval } from "../mcp/tools.js";

const owner = z.string().min(1).max(100).regex(/^[A-Za-z0-9._-]+$/), repo = z.string().min(1).max(100).regex(/^[A-Za-z0-9._-]+$/);
const R = { owner, repo };
const seg = (s: string) => encodeURIComponent(s);
const base = (a: any) => `/repos/${seg(a.owner)}/${seg(a.repo)}`;
const read = (name: string, title: string, description: string, shape: z.ZodRawShape, fn: (a: any, g: any) => Promise<unknown>): ToolDef =>
  ({ name, title, description, scope: "mcp:read", readOnly: true, shape, handler: (a, c, d) => fn(a, gh(c, d)) });
const write = (name: string, title: string, description: string, shape: z.ZodRawShape, fn: (a: any, g: any) => Promise<unknown>, approve?: (a: any) => string, destructive = false): ToolDef =>
  ({ name, title, description, scope: "mcp:write", readOnly: false, destructive, shape, handler: async (a, c, d) => { if (approve) needApproval(c, d, name, approve(a)); return fn(a, gh(c, d)); } });

export const GITHUB_EXTRA_TOOLS: ToolDef[] = [
  // ---- GitHub Pages ----
  read("gh_pages_get", "Get GitHub Pages site", "Pages settings and URL for a repo (404 means Pages is off).", R, (a, g) => g.request(`${base(a)}/pages`)),
  write("gh_pages_enable", "Turn on GitHub Pages", "Enable Pages from a branch and folder (/ or /docs).", { ...R, branch: z.string().default("main"), path: z.enum(["/", "/docs"]).default("/") },
    (a, g) => g.request(`${base(a)}/pages`, { method: "POST", body: { source: { branch: a.branch, path: a.path } } })),
  write("gh_pages_update", "Change GitHub Pages settings", "Change the source branch/folder or custom domain.", { ...R, branch: z.string().optional(), path: z.enum(["/", "/docs"]).optional(), cname: z.string().max(253).optional(), httpsEnforced: z.boolean().optional() },
    (a, g) => g.request(`${base(a)}/pages`, { method: "PUT", body: { ...(a.branch ? { source: { branch: a.branch, path: a.path ?? "/" } } : {}), ...(a.cname !== undefined ? { cname: a.cname } : {}), ...(a.httpsEnforced !== undefined ? { https_enforced: a.httpsEnforced } : {}) } })),
  write("gh_pages_disable", "Turn off GitHub Pages", "Unpublish the Pages site.", R, (a, g) => g.request(`${base(a)}/pages`, { method: "DELETE" }), (a) => `Turn off GitHub Pages for ${a.owner}/${a.repo}`, true),
  write("gh_pages_build", "Rebuild GitHub Pages", "Request a new Pages build.", R, (a, g) => g.request(`${base(a)}/pages/builds`, { method: "POST" })),
  read("gh_pages_builds", "GitHub Pages build history", "Latest Pages builds and their status.", R, async (a, g) => ((await g.request(`${base(a)}/pages/builds`)) as any[]).slice(0, 10)),
  // ---- Codebase search ----
  read("gh_search_code", "Search code on GitHub", "Search code across GitHub, optionally limited to one repo (qualifiers like repo:owner/name, language:ts, path:src work).",
    { q: z.string().min(1).max(256), perPage: z.number().int().min(1).max(50).default(15) },
    async (a, g) => { const r: any = await g.request(`/search/code`, { query: { q: a.q, per_page: a.perPage } }); return { total: r.total_count, items: (r.items ?? []).map((i: any) => ({ repo: i.repository?.full_name, path: i.path, url: i.html_url })) }; }),
  read("gh_search_issues", "Search issues and pull requests", "Search issues/PRs (qualifiers: repo:, is:open, is:pr, author:).",
    { q: z.string().min(1).max(256), perPage: z.number().int().min(1).max(50).default(15) },
    async (a, g) => { const r: any = await g.request(`/search/issues`, { query: { q: a.q, per_page: a.perPage } }); return { total: r.total_count, items: (r.items ?? []).map((i: any) => ({ repo: i.repository_url?.split("/repos/")[1], number: i.number, title: i.title, state: i.state, url: i.html_url })) }; }),
  read("gh_repo_overview", "Repo overview in one call", "Description, default branch, languages, topics, open issue/PR counts, latest release and top-level files.", R, async (a, g) => {
    const [info, langs, tree, rel]: any[] = await Promise.all([g.request(base(a)), g.request(`${base(a)}/languages`).catch(() => ({})), g.request(`${base(a)}/contents`).catch(() => []), g.request(`${base(a)}/releases/latest`).catch(() => null)]);
    return { fullName: info.full_name, description: info.description, defaultBranch: info.default_branch, private: info.private, topics: info.topics, stars: info.stargazers_count, openIssues: info.open_issues_count, languages: langs, latestRelease: rel ? { tag: rel.tag_name, url: rel.html_url } : null, topLevel: Array.isArray(tree) ? tree.map((t: any) => `${t.type === "dir" ? "dir " : ""}${t.name}`) : [] };
  }),
  // ---- Repo management ----
  write("gh_repo_create", "Create a repository", "Create a new repo for the signed-in user.", { name: repo, description: z.string().max(350).optional(), private: z.boolean().default(true), autoInit: z.boolean().default(true) },
    (a, g) => g.request(`/user/repos`, { method: "POST", body: { name: a.name, description: a.description, private: a.private, auto_init: a.autoInit } })),
  write("gh_repo_update", "Edit repo settings", "Change description, homepage, topics-free settings, default branch, issues/wiki toggles. Visibility changes need approval.",
    { ...R, description: z.string().max(350).optional(), homepage: z.string().max(250).optional(), defaultBranch: z.string().optional(), hasIssues: z.boolean().optional(), hasWiki: z.boolean().optional(), private: z.boolean().optional() },
    (a, g) => g.request(base(a), { method: "PATCH", body: { description: a.description, homepage: a.homepage, default_branch: a.defaultBranch, has_issues: a.hasIssues, has_wiki: a.hasWiki, private: a.private } }),
    (a) => a.private !== undefined ? `Change visibility of ${a.owner}/${a.repo} to ${a.private ? "private" : "PUBLIC"}` : "", false),
  write("gh_repo_topics", "Set repo topics", "Replace the repo's topics.", { ...R, topics: z.array(z.string().regex(/^[a-z0-9][a-z0-9-]{0,49}$/)).max(20) }, (a, g) => g.request(`${base(a)}/topics`, { method: "PUT", body: { names: a.topics } })),
  write("gh_repo_delete", "Delete a repository", "Permanently delete a repo. Always needs approval.", R, (a, g) => g.request(base(a), { method: "DELETE" }), (a) => `PERMANENTLY DELETE repository ${a.owner}/${a.repo}`, true),
  write("gh_repo_fork", "Fork a repository", "Fork a repo into the signed-in account.", R, (a, g) => g.request(`${base(a)}/forks`, { method: "POST", body: {} })),
  // ---- Tags and releases ----
  read("gh_tags", "List tags", "Latest tags.", R, async (a, g) => ((await g.request(`${base(a)}/tags`, { query: { per_page: 30 } })) as any[]).map((t) => ({ name: t.name, sha: t.commit?.sha }))),
  read("gh_releases", "List releases", "Latest releases.", R, async (a, g) => ((await g.request(`${base(a)}/releases`, { query: { per_page: 15 } })) as any[]).map((r) => ({ id: r.id, tag: r.tag_name, name: r.name, draft: r.draft, prerelease: r.prerelease, url: r.html_url }))),
  write("gh_release_create", "Create a release", "Create a release (and its tag if missing).", { ...R, tag: z.string().min(1).max(100), name: z.string().max(200).optional(), body: z.string().max(60000).optional(), target: z.string().optional(), draft: z.boolean().default(false), prerelease: z.boolean().default(false) },
    (a, g) => g.request(`${base(a)}/releases`, { method: "POST", body: { tag_name: a.tag, name: a.name ?? a.tag, body: a.body, target_commitish: a.target, draft: a.draft, prerelease: a.prerelease } })),
  write("gh_release_delete", "Delete a release", "Delete a release by id (the tag stays).", { ...R, releaseId: z.number().int() }, (a, g) => g.request(`${base(a)}/releases/${a.releaseId}`, { method: "DELETE" }), (a) => `Delete release ${a.releaseId} of ${a.owner}/${a.repo}`, true),
  // ---- Pull requests ----
  write("gh_pr_merge", "Merge a pull request", "Merge a PR. Always needs approval.", { ...R, number: z.number().int(), method: z.enum(["merge", "squash", "rebase"]).default("squash") },
    (a, g) => g.request(`${base(a)}/pulls/${a.number}/merge`, { method: "PUT", body: { merge_method: a.method } }), (a) => `Merge ${a.owner}/${a.repo}#${a.number} (${a.method})`),
  write("gh_pr_update", "Edit or close a pull request", "Change title/body/base or open/close a PR.", { ...R, number: z.number().int(), title: z.string().max(256).optional(), body: z.string().max(60000).optional(), state: z.enum(["open", "closed"]).optional(), base: z.string().optional() },
    (a, g) => g.request(`${base(a)}/pulls/${a.number}`, { method: "PATCH", body: { title: a.title, body: a.body, state: a.state, base: a.base } })),
  // ---- Actions ----
  read("gh_runs", "List workflow runs", "Latest Actions runs with status.", { ...R, branch: z.string().optional() }, async (a, g) => ((await g.request(`${base(a)}/actions/runs`, { query: { per_page: 15, ...(a.branch ? { branch: a.branch } : {}) } })) as any).workflow_runs.map((r: any) => ({ id: r.id, name: r.name, status: r.status, conclusion: r.conclusion, branch: r.head_branch, url: r.html_url }))),
  write("gh_run_rerun", "Re-run a workflow run", "Re-run an Actions run (or only its failed jobs).", { ...R, runId: z.number().int(), failedOnly: z.boolean().default(false) },
    (a, g) => g.request(`${base(a)}/actions/runs/${a.runId}/${a.failedOnly ? "rerun-failed-jobs" : "rerun"}`, { method: "POST" })),
  write("gh_run_cancel", "Cancel a workflow run", "Cancel an Actions run.", { ...R, runId: z.number().int() }, (a, g) => g.request(`${base(a)}/actions/runs/${a.runId}/cancel`, { method: "POST" })),
  write("gh_workflow_dispatch", "Trigger a workflow", "Start a workflow that has workflow_dispatch.", { ...R, workflow: z.string().min(1).max(200), ref: z.string().default("main"), inputs: z.record(z.string()).optional() },
    (a, g) => g.request(`${base(a)}/actions/workflows/${seg(a.workflow)}/dispatches`, { method: "POST", body: { ref: a.ref, inputs: a.inputs ?? {} } })),
  // ---- Gists ----
  write("gh_gist_create", "Create a gist", "Create a gist from files (path -> content).", { description: z.string().max(300).optional(), public: z.boolean().default(false), files: z.record(z.string().max(60000)).refine((f) => Object.keys(f).length >= 1 && Object.keys(f).length <= 20, "1-20 files") },
    (a, g) => g.request(`/gists`, { method: "POST", body: { description: a.description, public: a.public, files: Object.fromEntries(Object.entries(a.files as Record<string, string>).map(([k, v]) => [k, { content: v }])) } })),
];
