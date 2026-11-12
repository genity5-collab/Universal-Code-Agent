/**
 * Tests for the GitHub REST client, Codespaces client and OAuth helpers.
 *
 * IMPORTANT: every test runs against a local `http.createServer` mock that
 * speaks a small subset of the GitHub API. NO request in this file reaches
 * api.github.com or github.com — these tests prove the client's request shapes,
 * parsing, pagination and error mapping against our own fixtures only.
 */

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";

import {
  GitHubClient,
  GitHubError,
  GitHubNotFoundError,
  GitHubForbiddenError,
  GitHubNotModifiedError,
  GitHubRateLimitError,
  GitHubValidationError,
  GitHubGraphQLError,
  parseLinkHeader,
  GITHUB_API_VERSION,
} from "../src/github/client.js";
import { CodespacesClient } from "../src/github/codespaces.js";
import {
  buildAuthorizeUrl,
  exchangeCode,
  refreshGithubToken,
  revokeGithubToken,
  GitHubOAuthError,
} from "../src/github/oauth.js";

// ---------------------------------------------------------------------------
// Mock server harness
// ---------------------------------------------------------------------------

interface LoggedRequest {
  method: string;
  path: string;
  query: URLSearchParams;
  headers: http.IncomingHttpHeaders;
  body: string;
  json: unknown;
}

interface MockReply {
  status?: number;
  json?: unknown;
  body?: string;
  headers?: Record<string, string | undefined>;
}

type Handler = (req: LoggedRequest, index: number) => MockReply | Promise<MockReply>;

interface MockServer {
  baseUrl: string;
  requests: LoggedRequest[];
  close: () => Promise<void>;
}

async function startMock(handler: Handler): Promise<MockServer> {
  const requests: LoggedRequest[] = [];
  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const body = Buffer.concat(chunks).toString("utf8");
      const url = new URL(req.url ?? "/", "http://127.0.0.1");
      let json: unknown = null;
      try {
        json = body ? JSON.parse(body) : null;
      } catch {
        json = null;
      }
      const logged: LoggedRequest = {
        method: req.method ?? "GET",
        path: url.pathname,
        query: url.searchParams,
        headers: req.headers,
        body,
        json,
      };
      requests.push(logged);
      Promise.resolve()
        .then(() => handler(logged, requests.length - 1))
        .then((reply) => {
          const headers: Record<string, string | undefined> = {
            "content-type": "application/json; charset=utf-8",
            "x-ratelimit-limit": "5000",
            "x-ratelimit-remaining": "4999",
            "x-ratelimit-reset": String(Math.floor(Date.now() / 1000) + 3600),
            ...(reply.headers ?? {}),
          };
          res.writeHead(reply.status ?? 200, headers as Record<string, string>);
          res.end(reply.body ?? (reply.json === undefined ? "" : JSON.stringify(reply.json)));
        })
        .catch(() => {
          res.writeHead(500);
          res.end("mock handler error");
        });
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return {
    baseUrl: `http://127.0.0.1:${port}`,
    requests,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

const TOKEN = "gho_TESTTOKENdo_not_leak_1234567890";

function clientFor(mock: MockServer, extra: Record<string, unknown> = {}): GitHubClient {
  return new GitHubClient(TOKEN, { baseUrl: mock.baseUrl, retryDelayMs: 1, ...extra });
}

// ---------------------------------------------------------------------------
// Headers, versioning, validation
// ---------------------------------------------------------------------------

describe("request plumbing", () => {
  test("sends Bearer auth, API version, JSON accept and no token in the URL", async () => {
    const mock = await startMock(() => ({
      json: {
        login: "octocat",
        id: 1,
        node_id: "MDQ6VXNlcjE=",
        name: "The Octocat",
        email: null,
        avatar_url: "https://avatars.example/u/1",
        html_url: "https://github.com/octocat",
        type: "User",
        company: "@github",
        blog: "",
        location: "San Francisco",
        bio: null,
        public_repos: 8,
        public_gists: 8,
        followers: 100,
        following: 9,
        created_at: "2011-01-25T18:44:36Z",
        updated_at: "2024-01-01T00:00:00Z",
        plan: { name: "pro" },
        private_secret: "should-not-be-returned",
      },
      headers: { "x-oauth-scopes": "repo, read:user, workflow" },
    }));
    try {
      const gh = clientFor(mock);
      const user = await gh.getAuthenticatedUser();
      const req = mock.requests[0]!;
      assert.equal(req.method, "GET");
      assert.equal(req.path, "/user");
      assert.equal(req.headers.authorization, `Bearer ${TOKEN}`);
      assert.equal(req.headers["x-github-api-version"], GITHUB_API_VERSION);
      assert.equal(req.headers["x-github-api-version"], "2022-11-28");
      assert.equal(req.headers.accept, "application/vnd.github+json");
      assert.equal(req.headers["user-agent"], "universal-code-agent/0.1.0");
      assert.ok(!req.body.includes(TOKEN), "token must not be in the body");

      // trimmed payload: raw API fields are dropped
      assert.equal(user.login, "octocat");
      assert.equal(user.plan, "pro");
      assert.deepEqual(user.scopes, ["repo", "read:user", "workflow"]);
      assert.ok(!("private_secret" in user), "payload must be trimmed, not raw");
    } finally {
      await mock.close();
    }
  });

  test("rejects construction without a per-user token", () => {
    assert.throws(() => new GitHubClient(""), GitHubValidationError);
    assert.throws(() => new GitHubClient("   "), GitHubValidationError);
    assert.throws(() => new GitHubClient(undefined as unknown as string), GitHubValidationError);
  });

  test("parses the Link header", () => {
    const links = parseLinkHeader(
      '<https://api.github.com/x?page=2>; rel="next", <https://api.github.com/x?page=5>; rel="last"',
    );
    assert.deepEqual(links, {
      next: "https://api.github.com/x?page=2",
      last: "https://api.github.com/x?page=5",
    });
    assert.deepEqual(parseLinkHeader(null), {});
  });

  test("retries exactly once on 502 then succeeds", async () => {
    const mock = await startMock((_req, index) =>
      index === 0 ? { status: 502, json: { message: "Bad Gateway" } } : { json: { login: "octocat", id: 7 } },
    );
    try {
      const gh = clientFor(mock);
      const user = await gh.getAuthenticatedUser();
      assert.equal(user.login, "octocat");
      assert.equal(mock.requests.length, 2, "one retry, then success");
    } finally {
      await mock.close();
    }
  });

  test("does not retry forever on persistent 503", async () => {
    const mock = await startMock(() => ({ status: 503, json: { message: "Service Unavailable" } }));
    try {
      const gh = clientFor(mock);
      await assert.rejects(() => gh.getRepo("o", "r"), (err: unknown) => {
        assert.ok(err instanceof GitHubError);
        assert.equal(err.status, 503);
        return true;
      });
      assert.equal(mock.requests.length, 2, "initial attempt + exactly one retry");
    } finally {
      await mock.close();
    }
  });
});

// ---------------------------------------------------------------------------
// Pagination
// ---------------------------------------------------------------------------

describe("pagination", () => {
  test("follows Link rel=next across pages and reports truncation", async () => {
    const mock = await startMock((req, index) => {
      const page = Number(req.query.get("page") ?? "1");
      const last = index === 2;
      const link = last ? "" : `<${mock.baseUrl}/user/repos?per_page=2&page=${page + 1}>; rel="next"`;
      return {
        json: [
          { id: page * 10 + 1, name: `r${page}a`, full_name: `o/r${page}a`, owner: { login: "o" }, default_branch: "main" },
          { id: page * 10 + 2, name: `r${page}b`, full_name: `o/r${page}b`, owner: { login: "o" }, default_branch: "main" },
        ],
        headers: link ? { link } : {},
      };
    });
    try {
      const gh = clientFor(mock);
      const res = await gh.listRepos("all", "owner", undefined, 2, 50);
      assert.equal(mock.requests.length, 3, "three pages fetched");
      assert.deepEqual(res.items.map((r) => r.name), ["r1a", "r1b", "r2a", "r2b", "r3a", "r3b"]);
      assert.equal(res.pages, 3);
      assert.equal(res.truncated, false);
      assert.equal(res.nextUrl, null);
      // the first page carries the query, later pages come from the Link URL
      assert.equal(mock.requests[0]!.query.get("visibility"), "all");
      assert.equal(mock.requests[0]!.query.get("affiliation"), "owner");
      assert.equal(mock.requests[1]!.path, "/user/repos");
    } finally {
      await mock.close();
    }
  });

  test("stops at maxItems and says so honestly", async () => {
    const mock = await startMock((req, index) => {
      const link = `<${mock.baseUrl}/user/repos?per_page=2&page=${index + 2}>; rel="next"`;
      return {
        json: [
          { id: index * 2 + 1, name: `r${index}a`, full_name: `o/r${index}a`, owner: { login: "o" } },
          { id: index * 2 + 2, name: `r${index}b`, full_name: `o/r${index}b`, owner: { login: "o" } },
        ],
        headers: { link },
      };
    });
    try {
      const gh = clientFor(mock);
      const res = await gh.listRepos("all", undefined, undefined, 2, 3);
      assert.equal(res.items.length, 3);
      assert.equal(res.truncated, true, "truncated must be true when we stopped early");
      assert.ok(res.nextUrl, "nextUrl should point at unconsumed results");
      assert.equal(mock.requests.length, 2, "no extra page is fetched after hitting the cap");
    } finally {
      await mock.close();
    }
  });

  test("an explicit page still reports Link-based truncation", async () => {
    const mock = await startMock(() => ({
      json: [{ id: 1, name: "only", full_name: "o/only", owner: { login: "o" } }],
      headers: { link: `<${mock.baseUrl}/user/repos?page=3>; rel="next"` },
    }));
    try {
      const gh = clientFor(mock);
      const res = await gh.listRepos("all", undefined, 2, 1);
      assert.equal(res.pages, 1);
      assert.equal(res.truncated, true, "more pages exist after this one");
      assert.ok(res.nextUrl?.includes("page=3"));
      assert.equal(mock.requests[0]!.query.get("page"), "2");
    } finally {
      await mock.close();
    }
  });

  test("paginates a wrapped payload ({ total_count, jobs })", async () => {
    const mock = await startMock((_req, index) => {
      const link = index === 0 ? `<${mock.baseUrl}/repos/o/r/actions/runs/9/jobs?per_page=1&page=2>; rel="next"` : "";
      return {
        json: {
          total_count: 2,
          jobs: [{ id: 100 + index, run_id: 9, name: `job-${index}`, status: "completed", conclusion: "success", steps: [] }],
        },
        headers: link ? { link } : {},
      };
    });
    try {
      const gh = clientFor(mock);
      const res = await gh.listRunJobs("o", "r", 9);
      assert.deepEqual(res.items.map((j) => j.name), ["job-0", "job-1"]);
      assert.equal(res.truncated, false);
    } finally {
      await mock.close();
    }
  });
});

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

describe("error mapping", () => {
  test("403 with exhausted quota becomes GitHubRateLimitError with resetAt", async () => {
    const resetEpoch = Math.floor(Date.now() / 1000) + 900;
    const mock = await startMock(() => ({
      status: 403,
      json: { message: "API rate limit exceeded for user ID 1.", documentation_url: "https://docs.github.com/rest" },
      headers: {
        "x-ratelimit-limit": "5000",
        "x-ratelimit-remaining": "0",
        "x-ratelimit-reset": String(resetEpoch),
        "x-ratelimit-resource": "core",
      },
    }));
    try {
      const gh = clientFor(mock);
      await assert.rejects(
        () => gh.getRepo("octocat", "hello-world"),
        (err: unknown) => {
          assert.ok(err instanceof GitHubRateLimitError, "typed rate limit error");
          assert.equal(err.status, 403);
          assert.equal(err.remaining, 0);
          assert.equal(err.limit, 5000);
          assert.equal(err.resource, "core");
          assert.equal(err.secondary, false);
          assert.equal(err.resetAt.getTime(), resetEpoch * 1000);
          assert.match(err.message, /rate limit/i);
          return true;
        },
      );
    } finally {
      await mock.close();
    }
  });

  test("429 with Retry-After becomes a secondary GitHubRateLimitError", async () => {
    const mock = await startMock(() => ({
      status: 429,
      json: { message: "You have exceeded a secondary rate limit." },
      headers: { "x-ratelimit-remaining": "4500", "retry-after": "30" },
    }));
    try {
      const gh = clientFor(mock);
      await assert.rejects(() => gh.getRepo("o", "r"), (err: unknown) => {
        assert.ok(err instanceof GitHubRateLimitError);
        assert.equal(err.secondary, true);
        assert.equal(err.retryAfterSeconds, 30);
        assert.ok(err.resetAt.getTime() > Date.now());
        return true;
      });
    } finally {
      await mock.close();
    }
  });

  test("404 maps to GitHubNotFoundError (and not to a rate limit)", async () => {
    const mock = await startMock(() => ({ status: 404, json: { message: "Not Found" } }));
    try {
      const gh = clientFor(mock);
      await assert.rejects(() => gh.getRepo("o", "missing"), (err: unknown) => {
        assert.ok(err instanceof GitHubNotFoundError);
        assert.ok(err instanceof GitHubError);
        assert.equal(err.status, 404);
        assert.equal(err.isNotFound, true);
        assert.match(err.message, /404/);
        return true;
      });
    } finally {
      await mock.close();
    }
  });

  test("403 without exhausted quota maps to GitHubForbiddenError", async () => {
    const mock = await startMock(() => ({ status: 403, json: { message: "Resource not accessible by integration" } }));
    try {
      const gh = clientFor(mock);
      await assert.rejects(() => gh.getRepo("o", "r"), (err: unknown) => {
        assert.ok(err instanceof GitHubForbiddenError);
        assert.equal(err.status, 403);
        assert.ok(!(err instanceof GitHubRateLimitError));
        return true;
      });
    } finally {
      await mock.close();
    }
  });

  test("304 maps to GitHubNotModifiedError", async () => {
    const mock = await startMock(() => ({ status: 304, body: "" }));
    try {
      const gh = clientFor(mock);
      await assert.rejects(
        () => gh.request("/repos/o/r", { headers: { "If-None-Match": '"etag"' } }),
        (err: unknown) => {
          assert.ok(err instanceof GitHubNotModifiedError);
          assert.equal(err.status, 304);
          return true;
        },
      );
    } finally {
      await mock.close();
    }
  });

  test("never leaks the token in a thrown error message", async () => {
    const mock = await startMock(() => ({
      status: 422,
      json: {
        message: `Validation failed for token ${TOKEN} with Authorization: Bearer ${TOKEN}`,
        documentation_url: `https://docs.github.com/?access_token=${TOKEN}`,
      },
    }));
    try {
      const gh = clientFor(mock);
      await assert.rejects(() => gh.createIssue("o", "r", { title: "x" }), (err: unknown) => {
        const message = err instanceof Error ? err.message : String(err);
        assert.ok(!message.includes(TOKEN), `error message leaked the token: ${message}`);
        assert.match(message, /\[REDACTED\]/);
        if (err instanceof GitHubError) {
          assert.ok(!(err.apiMessage ?? "").includes(TOKEN));
        }
        return true;
      });
    } finally {
      await mock.close();
    }
  });

  test("network failures are typed and scrubbed", async () => {
    const gh = new GitHubClient("gho_short_lived_token_value_123", {
      baseUrl: "http://127.0.0.1:1",
      retryDelayMs: 1,
      timeoutMs: 1500,
    });
    await assert.rejects(() => gh.getRepo("o", "r"), (err: unknown) => {
      assert.ok(err instanceof GitHubError);
      assert.equal(err.status, 0);
      assert.ok(!err.message.includes("gho_short_lived_token_value_123"));
      return true;
    });
  });
});

// ---------------------------------------------------------------------------
// Content / blobs
// ---------------------------------------------------------------------------

describe("content", () => {
  test("decodes base64 file content from the contents API", async () => {
    const text = "console.log('hi');\n";
    const mock = await startMock(() => ({
      json: {
        type: "file",
        name: "index.ts",
        path: "src/index.ts",
        sha: "abc123",
        size: Buffer.byteLength(text),
        encoding: "base64",
        content: Buffer.from(text, "utf8").toString("base64").replace(/(.{20})/g, "$1\n"),
        html_url: "https://github.com/o/r/blob/main/src/index.ts",
        download_url: "https://raw.example/x",
      },
    }));
    try {
      const gh = clientFor(mock);
      const content = await gh.getContent("o", "r", "src/index.ts", "main");
      assert.equal(mock.requests[0]!.path, "/repos/o/r/contents/src/index.ts");
      assert.equal(mock.requests[0]!.query.get("ref"), "main");
      assert.ok(content.type === "file");
      assert.equal(content.sha, "abc123");
      assert.equal(content.size, Buffer.byteLength(text));
      assert.equal(Buffer.from(content.base64, "base64").toString("utf8"), text);
      assert.equal(content.source, "contents");
      assert.equal(content.hasMore, false);
      assert.equal(content.truncated, false);
    } finally {
      await mock.close();
    }
  });

  test("files >1MB go through the git blobs API and support offset/limit chunking", async () => {
    const big = Buffer.alloc(1_500_000, 0x61); // 1.5MB of "a"
    for (let i = 0; i < big.length; i += 997) big[i] = 0x62;
    const mock = await startMock((req) => {
      if (req.path === "/repos/o/r/contents/big.bin") {
        return {
          json: {
            type: "file",
            name: "big.bin",
            path: "big.bin",
            sha: "bigsha",
            size: big.length,
            encoding: "none",
            content: "",
            download_url: "https://raw.example/big.bin",
          },
        };
      }
      if (req.path === "/repos/o/r/git/blobs/bigsha") {
        return { json: { sha: "bigsha", size: big.length, encoding: "base64", content: big.toString("base64") } };
      }
      return { status: 404, json: { message: "Not Found" } };
    });
    try {
      const gh = clientFor(mock);
      const first = await gh.getContent("o", "r", "big.bin", undefined, { offset: 0, limit: 1024 });
      assert.equal(mock.requests[1]!.path, "/repos/o/r/git/blobs/bigsha", "contents API empty -> blobs API");
      assert.ok(first.type === "file");
      assert.equal(first.source, "blobs");
      assert.equal(first.size, big.length, "reports the true full size");
      assert.equal(first.chunkSize, 1024);
      assert.equal(first.hasMore, true);
      assert.equal(first.nextOffset, 1024);
      assert.equal(first.truncated, true);
      assert.deepEqual(Buffer.from(first.base64, "base64"), big.subarray(0, 1024));

      const middle = await gh.getContent("o", "r", "big.bin", undefined, { offset: 1_000_000, limit: 2048 });
      assert.ok(middle.type === "file");
      assert.equal(middle.offset, 1_000_000);
      assert.deepEqual(Buffer.from(middle.base64, "base64"), big.subarray(1_000_000, 1_002_048));

      const tail = await gh.getContent("o", "r", "big.bin", undefined, { offset: 1_499_000 });
      assert.ok(tail.type === "file");
      assert.equal(tail.hasMore, false);
      assert.equal(tail.nextOffset, null);
      assert.deepEqual(Buffer.from(tail.base64, "base64"), big.subarray(1_499_000));
    } finally {
      await mock.close();
    }
  });

  test("directory listings come back as entries, not file chunks", async () => {
    const mock = await startMock(() => ({
      json: [
        { name: "a.ts", path: "src/a.ts", type: "file", size: 10, sha: "s1" },
        { name: "b", path: "src/b", type: "dir", size: 0, sha: "s2" },
      ],
    }));
    try {
      const gh = clientFor(mock);
      const dir = await gh.getContent("o", "r", "src");
      assert.ok(dir.type === "dir");
      assert.deepEqual(dir.entries.map((e) => e.name), ["a.ts", "b"]);
    } finally {
      await mock.close();
    }
  });

  test("downloadFile returns raw bytes as base64 with a size-cap flag", async () => {
    const payload = Buffer.from("0123456789abcdef", "utf8");
    const mock = await startMock(() => ({
      body: payload.toString("binary"),
      headers: { "content-type": "application/octet-stream" },
    }));
    try {
      const gh = new GitHubClient(TOKEN, { baseUrl: mock.baseUrl, retryDelayMs: 1 });
      const uncapped = await gh.downloadFile("o", "r", "file.bin", "main", { maxBytes: 1024 });
      assert.equal(mock.requests[0]!.headers.accept, "application/vnd.github.raw");
      assert.equal(mock.requests[0]!.query.get("ref"), "main");
      assert.equal(uncapped.truncated, false);
      assert.equal(Buffer.from(uncapped.base64, "base64").toString("utf8"), "0123456789abcdef");

      assert.equal(uncapped.sizeExact, true);

      const capped = await gh.downloadFile("o", "r", "file.bin", undefined, { maxBytes: 4 });
      assert.equal(capped.size, 16, "true size comes from content-length");
      assert.equal(capped.bytesReturned, 4);
      assert.equal(capped.truncated, true);
      assert.equal(Buffer.from(capped.base64, "base64").toString("utf8"), "0123");
    } finally {
      await mock.close();
    }
  });

  test("deleteFile refuses to run without a sha", async () => {
    const mock = await startMock(() => ({ json: {} }));
    try {
      const gh = clientFor(mock);
      await assert.rejects(
        () => gh.deleteFile("o", "r", "x.txt", { sha: "", message: "rm" }),
        (err: unknown) => err instanceof GitHubValidationError,
      );
      assert.equal(mock.requests.length, 0, "no request is made");
    } finally {
      await mock.close();
    }
  });
});

// ---------------------------------------------------------------------------
// Writes / atomic multi-file commit
// ---------------------------------------------------------------------------

describe("writes", () => {
  test("createOrUpdateFile base64-encodes utf8 content and sends the sha", async () => {
    const mock = await startMock(() => ({
      json: {
        content: { sha: "newsha", size: 5, html_url: "https://github.com/o/r/blob/main/a.txt" },
        commit: { sha: "commitsha", html_url: "https://github.com/o/r/commit/commitsha", message: "update a" },
      },
    }));
    try {
      const gh = clientFor(mock);
      const res = await gh.createOrUpdateFile("o", "r", "a.txt", {
        content: "hello",
        message: "update a",
        sha: "oldsha",
        branch: "main",
      });
      const body = mock.requests[0]!.json as Record<string, unknown>;
      assert.equal(mock.requests[0]!.method, "PUT");
      assert.equal(body.content, Buffer.from("hello").toString("base64"));
      assert.equal(body.sha, "oldsha");
      assert.equal(body.branch, "main");
      assert.equal(body.message, "update a");
      assert.equal(res.commitSha, "commitsha");
      assert.equal(res.sha, "newsha");
    } finally {
      await mock.close();
    }
  });

  test("createCommitMultiFile runs blobs -> tree -> commit -> ref update in order", async () => {
    const BASE = "1".repeat(40);
    const mock = await startMock((req) => {
      if (req.method === "GET" && req.path === "/repos/o/r/git/ref/heads/main") {
        return { json: { ref: "refs/heads/main", object: { type: "commit", sha: BASE } } };
      }
      if (req.method === "GET" && req.path === `/repos/o/r/git/commits/${BASE}`) {
        return { json: { sha: BASE, tree: { sha: "BASETREE" } } };
      }
      if (req.method === "POST" && req.path === "/repos/o/r/git/blobs") {
        const n = mock.requests.filter((r) => r.path === "/repos/o/r/git/blobs").length;
        return { status: 201, json: { sha: `BLOB${n}` } };
      }
      if (req.method === "POST" && req.path === "/repos/o/r/git/trees") {
        return { status: 201, json: { sha: "NEWTREE" } };
      }
      if (req.method === "POST" && req.path === "/repos/o/r/git/commits") {
        return { status: 201, json: { sha: "NEWCOMMIT", html_url: "https://github.com/o/r/commit/NEWCOMMIT" } };
      }
      if (req.method === "PATCH" && req.path === "/repos/o/r/git/refs/heads/main") {
        return { json: { ref: "refs/heads/main", object: { sha: "NEWCOMMIT" } } };
      }
      return { status: 404, json: { message: `unexpected ${req.method} ${req.path}` } };
    });
    try {
      const gh = clientFor(mock);
      const result = await gh.createCommitMultiFile("o", "r", {
        branch: "main",
        message: "two files at once",
        files: [
          { path: "src/a.ts", content: "export const a = 1;\n" },
          { path: "src/b.ts", content: "export const b = 2;\n" },
        ],
        deletions: ["src/old.ts"],
      });

      assert.deepEqual(
        mock.requests.map((r) => `${r.method} ${r.path}`),
        [
          "GET /repos/o/r/git/ref/heads/main",
          `GET /repos/o/r/git/commits/${BASE}`,
          "POST /repos/o/r/git/blobs",
          "POST /repos/o/r/git/blobs",
          "POST /repos/o/r/git/trees",
          "POST /repos/o/r/git/commits",
          "PATCH /repos/o/r/git/refs/heads/main",
        ],
        "blobs -> tree -> commit -> single ref update",
      );

      const treeBody = mock.requests[4]!.json as { base_tree: string; tree: Record<string, unknown>[] };
      assert.equal(treeBody.base_tree, "BASETREE");
      assert.equal(treeBody.tree.length, 3, "2 additions + 1 deletion");
      assert.deepEqual(treeBody.tree[0], { path: "src/a.ts", mode: "100644", type: "blob", sha: "BLOB1" });
      assert.deepEqual(treeBody.tree[2], { path: "src/old.ts", mode: "100644", type: "blob", sha: null });

      const commitBody = mock.requests[5]!.json as { parents: string[]; tree: string; message: string };
      assert.deepEqual(commitBody.parents, [BASE]);
      assert.equal(commitBody.tree, "NEWTREE");
      assert.equal(commitBody.message, "two files at once");

      const refBody = mock.requests[6]!.json as { sha: string; force: boolean };
      assert.equal(refBody.sha, "NEWCOMMIT", "ref moves once, at the very end");
      assert.equal(refBody.force, false);

      assert.equal(result.commitSha, "NEWCOMMIT");
      assert.equal(result.filesChanged, 3);
      assert.deepEqual(result.blobs.map((b) => b.sha), ["BLOB1", "BLOB2"]);
      assert.deepEqual(result.deleted, ["src/old.ts"]);
    } finally {
      await mock.close();
    }
  });

  test("createCommitMultiFile refuses an empty change set without calling the API", async () => {
    const mock = await startMock(() => ({ json: {} }));
    try {
      const gh = clientFor(mock);
      await assert.rejects(
        () => gh.createCommitMultiFile("o", "r", { branch: "main", message: "noop" }),
        (err: unknown) => err instanceof GitHubValidationError,
      );
      assert.equal(mock.requests.length, 0);
    } finally {
      await mock.close();
    }
  });

  test("createBranch resolves the source ref then POSTs a new ref", async () => {
    const mock = await startMock((req) => {
      if (req.path === "/repos/o/r/git/ref/heads/main") return { json: { object: { type: "commit", sha: "SRCSHA" } } };
      if (req.method === "POST" && req.path === "/repos/o/r/git/refs") {
        return { status: 201, json: { ref: "refs/heads/feature/x", object: { sha: "SRCSHA" } } };
      }
      return { status: 404, json: { message: "nope" } };
    });
    try {
      const gh = clientFor(mock);
      const res = await gh.createBranch("o", "r", "feature/x", "main");
      assert.equal(res.ref, "refs/heads/feature/x");
      assert.equal(res.sha, "SRCSHA");
      const body = mock.requests[1]!.json as { ref: string; sha: string };
      assert.equal(body.ref, "refs/heads/feature/x");
      assert.equal(body.sha, "SRCSHA");
    } finally {
      await mock.close();
    }
  });
});

// ---------------------------------------------------------------------------
// Commits, issues, PRs
// ---------------------------------------------------------------------------

describe("commits, issues and pull requests", () => {
  test("getCommit trims patches and flags truncation explicitly", async () => {
    const longPatch = "@@ -1,1 +1,1 @@\n" + "+" + "x".repeat(5000);
    const mock = await startMock(() => ({
      json: {
        sha: "c1",
        html_url: "https://github.com/o/r/commit/c1",
        commit: {
          message: "fix: thing",
          author: { name: "A", email: "a@example.com", date: "2024-01-01T00:00:00Z" },
          committer: { name: "A", date: "2024-01-01T00:00:00Z" },
          verification: { verified: true },
        },
        author: { login: "a" },
        committer: { login: "a" },
        parents: [{ sha: "p1" }],
        stats: { additions: 1, deletions: 1, total: 2 },
        files: [
          { filename: "big.ts", status: "modified", additions: 1, deletions: 1, changes: 2, patch: longPatch },
          { filename: "small.ts", status: "added", additions: 1, deletions: 0, changes: 1, patch: "@@ +1 @@" },
        ],
      },
    }));
    try {
      const gh = clientFor(mock, { maxPatchChars: 100 });
      const commit = await gh.getCommit("o", "r", "c1");
      assert.equal(commit.sha, "c1");
      assert.equal(commit.files.length, 2);
      assert.equal(commit.files[0]!.patchTruncated, true);
      assert.equal(commit.files[0]!.patch!.length, 100);
      assert.equal(commit.files[1]!.patchTruncated, false);
      assert.equal(commit.truncated, true);
      assert.equal(commit.verified, true);
      assert.deepEqual(commit.stats, { additions: 1, deletions: 1, total: 2 });
    } finally {
      await mock.close();
    }
  });

  test("listIssues filters pull requests unless asked", async () => {
    const mock = await startMock(() => ({
      json: [
        { number: 1, title: "real issue", state: "open", body: "b", user: { login: "u" }, labels: [{ name: "bug" }], assignees: [] },
        { number: 2, title: "a PR", state: "open", body: "b", user: { login: "u" }, labels: [], assignees: [], pull_request: { url: "x" } },
      ],
    }));
    try {
      const gh = clientFor(mock);
      const plain = await gh.listIssues("o", "r");
      assert.deepEqual(plain.items.map((i) => i.number), [1]);
      assert.deepEqual(plain.items[0]!.labels, ["bug"]);

      const withPrs = await gh.listIssues("o", "r", { includePullRequests: true });
      assert.equal(withPrs.items.length, 2);
      assert.equal(withPrs.items[1]!.pullRequest, true);
    } finally {
      await mock.close();
    }
  });

  test("createPullRequest and review payloads match the API contract", async () => {
    const mock = await startMock((req) => {
      if (req.path === "/repos/o/r/pulls" && req.method === "POST") {
        return {
          status: 201,
          json: {
            number: 42,
            title: "Add feature",
            state: "open",
            draft: false,
            merged: false,
            mergeable: true,
            body: "body",
            user: { login: "me" },
            head: { ref: "feature", sha: "h1", repo: { full_name: "f/r" } },
            base: { ref: "main", sha: "b1", repo: { full_name: "o/r" } },
            html_url: "https://github.com/o/r/pull/42",
            additions: 3,
            deletions: 1,
            changed_files: 2,
            commits: 1,
          },
        };
      }
      if (req.path === "/repos/o/r/pulls/42/reviews") {
        return { status: 200, json: { id: 7, state: "APPROVED", body: "lgtm", user: { login: "me" }, html_url: "x" } };
      }
      return { status: 404, json: { message: "nope" } };
    });
    try {
      const gh = clientFor(mock);
      const pr = await gh.createPullRequest("o", "r", {
        title: "Add feature",
        head: "feature",
        base: "main",
        body: "body",
        draft: false,
      });
      assert.equal(pr.number, 42);
      assert.equal(pr.head.ref, "feature");
      assert.equal(pr.head.repo, "f/r");
      const prBody = mock.requests[0]!.json as Record<string, unknown>;
      assert.deepEqual(Object.keys(prBody).sort(), ["base", "body", "draft", "head", "title"]);

      const review = await gh.createPullRequestReview("o", "r", 42, {
        event: "COMMENT",
        body: "one nit",
        comments: [{ path: "src/a.ts", body: "rename", line: 12, side: "RIGHT" }],
      });
      const reviewBody = mock.requests[1]!.json as { event: string; comments: Record<string, unknown>[] };
      assert.equal(reviewBody.event, "COMMENT");
      assert.deepEqual(reviewBody.comments[0], { path: "src/a.ts", body: "rename", line: 12, side: "RIGHT" });
      assert.equal(review.state, "APPROVED");
    } finally {
      await mock.close();
    }
  });

  test("createPullRequestReview validates the event and REQUEST_CHANGES needs a body", async () => {
    const mock = await startMock(() => ({ json: {} }));
    try {
      const gh = clientFor(mock);
      await assert.rejects(
        () => gh.createPullRequestReview("o", "r", 1, { event: "LGTM" as unknown as "COMMENT" }),
        (err: unknown) => err instanceof GitHubValidationError,
      );
      await assert.rejects(
        () => gh.createPullRequestReview("o", "r", 1, { event: "REQUEST_CHANGES" }),
        (err: unknown) => err instanceof GitHubValidationError,
      );
      assert.equal(mock.requests.length, 0);
    } finally {
      await mock.close();
    }
  });

  test("getPullRequestDiff uses the diff media type and caps size", async () => {
    const diff = "diff --git a/x b/x\n" + "+y\n".repeat(100);
    const mock = await startMock(() => ({ body: diff, headers: { "content-type": "text/plain" } }));
    try {
      const gh = clientFor(mock);
      const full = await gh.getPullRequestDiff("o", "r", 5);
      assert.equal(mock.requests[0]!.headers.accept, "application/vnd.github.diff");
      assert.equal(full.length, diff.length);
      assert.equal(full.truncated, false);
      assert.equal(full.diff, diff);

      const capped = await gh.getPullRequestDiff("o", "r", 5, { maxBytes: 10 });
      assert.equal(capped.truncated, true);
      assert.equal(capped.diff.length, 10);
      assert.equal(capped.length, diff.length);
    } finally {
      await mock.close();
    }
  });
});

// ---------------------------------------------------------------------------
// GraphQL discussions
// ---------------------------------------------------------------------------

describe("discussions (GraphQL)", () => {
  test("listDiscussions posts the query and maps the connection", async () => {
    const mock = await startMock((req) => {
      if (req.path !== "/graphql") return { status: 404, json: { message: "not graphql" } };
      return {
        json: {
          data: {
            repository: {
              discussions: {
                totalCount: 2,
                pageInfo: { hasNextPage: true, endCursor: "CURSOR1" },
                nodes: [
                  {
                    number: 12,
                    title: "How do I deploy?",
                    url: "https://github.com/o/r/discussions/12",
                    createdAt: "2024-02-01T00:00:00Z",
                    updatedAt: "2024-02-02T00:00:00Z",
                    upvotes: 3,
                    author: { login: "asker" },
                    category: { name: "Q&A" },
                    comments: { totalCount: 4 },
                    answer: { id: "A1" },
                  },
                  {
                    number: 11,
                    title: "Ideas",
                    url: "https://github.com/o/r/discussions/11",
                    createdAt: "2024-01-01T00:00:00Z",
                    updatedAt: "2024-01-02T00:00:00Z",
                    upvotes: 0,
                    author: null,
                    category: null,
                    comments: { totalCount: 0 },
                    answer: null,
                  },
                ],
              },
            },
          },
        },
      };
    });
    try {
      const gh = clientFor(mock);
      const res = await gh.listDiscussions("o", "r", { first: 10 });

      const req = mock.requests[0]!;
      assert.equal(req.method, "POST");
      assert.equal(req.path, "/graphql");
      assert.equal(req.headers.authorization, `Bearer ${TOKEN}`);
      const payload = req.json as { query: string; variables: Record<string, unknown> };
      assert.match(payload.query, /query\(\$owner: String!, \$repo: String!, \$first: Int!/);
      assert.match(payload.query, /discussions\(first: \$first, after: \$after/);
      assert.deepEqual(payload.variables, { owner: "o", repo: "r", first: 10, after: null });

      assert.equal(res.totalCount, 2);
      assert.equal(res.hasNextPage, true);
      assert.equal(res.endCursor, "CURSOR1");
      assert.deepEqual(res.items[0], {
        number: 12,
        title: "How do I deploy?",
        url: "https://github.com/o/r/discussions/12",
        author: "asker",
        category: "Q&A",
        answerChosen: true,
        comments: 4,
        upvotes: 3,
        createdAt: "2024-02-01T00:00:00Z",
        updatedAt: "2024-02-02T00:00:00Z",
      });
    } finally {
      await mock.close();
    }
  });

  test("getDiscussion surfaces GraphQL errors as a typed error", async () => {
    const mock = await startMock(() => ({
      json: { data: null, errors: [{ message: `Could not resolve to a Repository (token ${TOKEN})` }] },
    }));
    try {
      const gh = clientFor(mock);
      await assert.rejects(() => gh.getDiscussion("o", "missing", 1), (err: unknown) => {
        assert.ok(err instanceof GitHubGraphQLError);
        assert.equal(err.errors.length, 1);
        assert.ok(!err.message.includes(TOKEN));
        return true;
      });
    } finally {
      await mock.close();
    }
  });

  test("getDiscussion returns null-repository as not found", async () => {
    const mock = await startMock(() => ({ json: { data: { repository: null } } }));
    try {
      const gh = clientFor(mock);
      await assert.rejects(() => gh.getDiscussion("o", "r", 3), (err: unknown) => err instanceof GitHubNotFoundError);
    } finally {
      await mock.close();
    }
  });
});

// ---------------------------------------------------------------------------
// Actions / logs
// ---------------------------------------------------------------------------

describe("actions and logs", () => {
  test("getJobLogs follows the redirect without credentials and pages the text", async () => {
    const logText = Array.from({ length: 200 }, (_, i) => `line ${i}: build step output`).join("\n");
    const mock = await startMock((req) => {
      if (req.path === "/repos/o/r/actions/jobs/77/logs") {
        return { status: 302, headers: { location: `${mock.baseUrl}/log-storage/77?sig=abc` } };
      }
      if (req.path === "/log-storage/77") {
        return { body: logText, headers: { "content-type": "text/plain; charset=utf-8" } };
      }
      return { status: 404, json: { message: "nope" } };
    });
    try {
      const gh = clientFor(mock);
      const page1 = await gh.getJobLogs("o", "r", 77, { offset: 0, limit: 100 });
      assert.equal(mock.requests[0]!.headers.authorization, `Bearer ${TOKEN}`);
      assert.equal(mock.requests[1]!.headers.authorization, undefined, "signed log URL must not receive the token");

      assert.equal(page1.totalLength, logText.length, "reports the full length, not the slice");
      assert.equal(page1.text.length, 100);
      assert.equal(page1.text, logText.slice(0, 100));
      assert.equal(page1.hasMore, true);
      assert.equal(page1.nextOffset, 100);
      assert.equal(page1.truncated, true);

      const page2 = await gh.getJobLogs("o", "r", 77, { offset: 100, limit: 100 });
      assert.equal(page2.text, logText.slice(100, 200));
      assert.equal(page2.offset, 100);

      const tail = await gh.getJobLogs("o", "r", 77, { offset: logText.length - 20 });
      assert.equal(tail.hasMore, false);
      assert.equal(tail.nextOffset, null);
      assert.equal(tail.text, logText.slice(-20));
    } finally {
      await mock.close();
    }
  });

  test("listWorkflows and listWorkflowRuns are trimmed", async () => {
    const mock = await startMock((req) => {
      if (req.path === "/repos/o/r/actions/workflows") {
        return {
          json: {
            total_count: 1,
            workflows: [
              { id: 9, name: "CI", path: ".github/workflows/ci.yml", state: "active", html_url: "https://github.com/o/r/blob/main/.github/workflows/ci.yml", badge_url: "x" },
            ],
          },
        };
      }
      if (req.path === "/repos/o/r/actions/runs") {
        return {
          json: {
            total_count: 1,
            workflow_runs: [
              {
                id: 500,
                name: "CI",
                workflow_id: 9,
                run_number: 3,
                run_attempt: 1,
                event: "push",
                status: "completed",
                conclusion: "failure",
                head_branch: "main",
                head_sha: "deadbeef",
                actor: { login: "me" },
                html_url: "https://github.com/o/r/actions/runs/500",
                created_at: "2024-01-01T00:00:00Z",
                updated_at: "2024-01-01T00:05:00Z",
                display_title: "fix",
                repository: { id: 1 },
                head_commit: { id: "deadbeef", message: "huge payload" },
              },
            ],
          },
        };
      }
      if (req.path === "/repos/o/r/actions/runs/500/rerun") return { status: 201, body: "" };
      return { status: 404, json: { message: "nope" } };
    });
    try {
      const gh = clientFor(mock);
      const wf = await gh.listWorkflows("o", "r");
      assert.equal(wf.items.length, 1);
      assert.deepEqual(Object.keys(wf.items[0]!).sort(), ["htmlUrl", "id", "name", "path", "state"]);

      const runs = await gh.listWorkflowRuns("o", "r", { branch: "main" });
      assert.equal(runs.items.length, 1);
      assert.equal(runs.items[0]!.conclusion, "failure");
      assert.equal(runs.items[0]!.headSha, "deadbeef");
      assert.ok(!("head_commit" in runs.items[0]!), "raw nested payloads are dropped");
      assert.equal(mock.requests[1]!.query.get("branch"), "main");

      const rerun = await gh.rerunWorkflow("o", "r", 500);
      assert.deepEqual(rerun, { rerun: true, runId: 500 });
    } finally {
      await mock.close();
    }
  });
});

// ---------------------------------------------------------------------------
// Security alerts: unavailable instead of throwing
// ---------------------------------------------------------------------------

describe("security alerts", () => {
  test("403 on code scanning => { available:false, reason } and no throw", async () => {
    const mock = await startMock(() => ({
      status: 403,
      json: { message: "Code scanning is not enabled for this repository." },
      headers: { "x-ratelimit-remaining": "4998" },
    }));
    try {
      const gh = clientFor(mock);
      const res = await gh.listCodeScanningAlerts("o", "r");
      assert.equal(res.available, false);
      if (res.available === false) {
        assert.equal(res.status, 403);
        assert.match(res.reason, /not enabled|not permitted/i);
        assert.ok(res.docs);
      }
    } finally {
      await mock.close();
    }
  });

  test("404 on dependabot and secret scanning => available:false", async () => {
    const mock = await startMock(() => ({ status: 404, json: { message: "Not Found" } }));
    try {
      const gh = clientFor(mock);
      const dep = await gh.listDependabotAlerts("o", "r");
      const secret = await gh.listSecretScanningAlerts("o", "r");
      assert.equal(dep.available, false);
      assert.equal(secret.available, false);
      if (dep.available === false) assert.equal(dep.status, 404);
      if (secret.available === false) assert.equal(secret.status, 404);
    } finally {
      await mock.close();
    }
  });

  test("when alerts are enabled the trimmed list is returned", async () => {
    const mock = await startMock(() => ({
      json: [
        {
          number: 1,
          state: "open",
          rule: { id: "js/xss", severity: "error" },
          tool: { name: "CodeQL" },
          most_recent_instance: { ref: "refs/heads/main", location: { path: "src/a.ts", start_line: 10 } },
          html_url: "https://github.com/o/r/security/code-scanning/1",
          created_at: "2024-01-01T00:00:00Z",
          dismissed_reason: null,
        },
      ],
    }));
    try {
      const gh = clientFor(mock);
      const res = await gh.listCodeScanningAlerts("o", "r", { state: "open" });
      assert.equal(res.available, true);
      if (res.available) {
        assert.equal(res.items.length, 1);
        assert.equal(res.items[0]!.ruleId, "js/xss");
        assert.equal(res.items[0]!.path, "src/a.ts");
      }
      assert.equal(mock.requests[0]!.query.get("state"), "open");
    } finally {
      await mock.close();
    }
  });

  test("a rate-limited alerts call is not reported as 'feature disabled'", async () => {
    const mock = await startMock(() => ({
      status: 403,
      json: { message: "API rate limit exceeded" },
      headers: { "x-ratelimit-remaining": "0", "x-ratelimit-reset": String(Math.floor(Date.now() / 1000) + 60) },
    }));
    try {
      const gh = clientFor(mock);
      await assert.rejects(() => gh.listDependabotAlerts("o", "r"), (err: unknown) => {
        assert.ok(err instanceof GitHubRateLimitError);
        return true;
      });
    } finally {
      await mock.close();
    }
  });

  test("other errors still throw (only 403/404 are softened)", async () => {
    const mock = await startMock(() => ({ status: 500, json: { message: "boom" } }));
    try {
      const gh = clientFor(mock);
      await assert.rejects(() => gh.listCodeScanningAlerts("o", "r"), (err: unknown) => {
        assert.ok(err instanceof GitHubError);
        assert.equal(err.status, 500);
        return true;
      });
    } finally {
      await mock.close();
    }
  });
});

// ---------------------------------------------------------------------------
// Codespaces
// ---------------------------------------------------------------------------

describe("codespaces", () => {
  test("createCodespace resolves the repo id and sends the documented body", async () => {
    const mock = await startMock((req) => {
      if (req.path === "/repos/o/r") {
        return { json: { id: 4242, name: "r", full_name: "o/r", owner: { login: "o" }, default_branch: "main" } };
      }
      if (req.path === "/user/codespaces" && req.method === "POST") {
        return {
          status: 201,
          json: {
            name: "o-refactored-space",
            display_name: "refactor",
            state: "Queued",
            idle_timeout_minutes: 30,
            machine: { name: "standardLinux32gb", display_name: "4 cores", cpus: 4, memory_in_bytes: 16 * 1024 ** 3, storage_in_bytes: 32 * 1024 ** 3 },
            repository: { id: 4242, name: "r", full_name: "o/r", owner: { login: "o" }, default_branch: "main" },
            git_status: { ahead: 0, behind: 0, ref: "refs/heads/feature/x" },
            web_url: "https://codespaces.new/o/r",
            billable_owner: { login: "o" },
            created_at: "2024-01-01T00:00:00Z",
          },
        };
      }
      return { status: 404, json: { message: `unexpected ${req.path}` } };
    });
    try {
      const cs = new CodespacesClient(clientFor(mock));
      const created = await cs.createCodespace({
        owner: "o",
        repo: "r",
        branch: "feature/x",
        machine: "standardLinux32gb",
        idleTimeout: 30,
      });
      const body = mock.requests[1]!.json as Record<string, unknown>;
      assert.equal(body.repository_id, 4242);
      assert.equal(body.ref, "feature/x");
      assert.equal(body.machine, "standardLinux32gb");
      assert.equal(body.idle_timeout_minutes, 30);
      assert.equal(created.name, "o-refactored-space");
      assert.equal(created.state, "Queued");
      assert.equal(created.memoryMb, 16384);
      assert.equal(created.storageGb, 32);
      assert.equal(created.repository?.fullName, "o/r");
      assert.equal(created.gitStatus?.ref, "refs/heads/feature/x");
    } finally {
      await mock.close();
    }
  });

  test("lifecycle calls hit the right verbs and paths", async () => {
    const mock = await startMock((req) => {
      if (req.path === "/user/codespaces/space1/start") return { json: { name: "space1", state: "Available" } };
      if (req.path === "/user/codespaces/space1/stop") return { json: { name: "space1", state: "ShuttingDown" } };
      if (req.path === "/user/codespaces/space1" && req.method === "DELETE") return { status: 204, body: "" };
      if (req.path === "/repos/o/r/codespaces/machines") {
        return {
          json: {
            total_count: 1,
            machines: [
              { name: "basicLinux32gb", display_name: "2 cores", os: "linux", cpus: 2, memory_in_bytes: 8 * 1024 ** 3, storage_in_bytes: 32 * 1024 ** 3 },
            ],
          },
        };
      }
      return { status: 404, json: { message: `unexpected ${req.path}` } };
    });
    try {
      const cs = new CodespacesClient(clientFor(mock));
      assert.equal((await cs.startCodespace("space1")).state, "Available");
      assert.equal((await cs.stopCodespace("space1")).state, "ShuttingDown");
      assert.deepEqual(await cs.deleteCodespace("space1"), { name: "space1", deleted: true, alreadyAbsent: false });
      const machines = await cs.listMachines("o", "r", { location: "WestUs2" });
      assert.equal(mock.requests[3]!.query.get("location"), "WestUs2");
      assert.equal(machines.items[0]!.name, "basicLinux32gb");
      assert.equal(machines.items[0]!.memoryMb, 8192);
      assert.deepEqual(
        mock.requests.map((r) => `${r.method} ${r.path}`),
        [
          "POST /user/codespaces/space1/start",
          "POST /user/codespaces/space1/stop",
          "DELETE /user/codespaces/space1",
          "GET /repos/o/r/codespaces/machines",
        ],
      );
    } finally {
      await mock.close();
    }
  });

  test("deleteCodespace treats 404 as already gone", async () => {
    const mock = await startMock(() => ({ status: 404, json: { message: "Not Found" } }));
    try {
      const cs = new CodespacesClient(clientFor(mock));
      assert.deepEqual(await cs.deleteCodespace("gone"), { name: "gone", deleted: true, alreadyAbsent: true });
    } finally {
      await mock.close();
    }
  });

  test("exportCodespace starts an export and can poll its status", async () => {
    const mock = await startMock((req) => {
      if (req.path === "/user/codespaces/space1/exports" && req.method === "POST") {
        return { json: { id: "export-1", state: "in_progress", branch: null, sha: null, completed_at: null } };
      }
      if (req.path === "/user/codespaces/space1/exports/export-1") {
        return {
          json: {
            id: "export-1",
            state: "succeeded",
            branch: "codespace-space1-abc",
            sha: "sha1",
            completed_at: "2024-01-01T00:00:00Z",
            html_url: "https://github.com/exports/export-1",
          },
        };
      }
      return { status: 404, json: { message: "nope" } };
    });
    try {
      const cs = new CodespacesClient(clientFor(mock));
      const started = await cs.exportCodespace("space1");
      assert.equal(started.exportId, "export-1");
      assert.equal(started.state, "in_progress");
      assert.match(started.note, /temporary/i);

      const done = await cs.getExportStatus("space1", "export-1");
      assert.equal(done.state, "succeeded");
      assert.equal(done.branch, "codespace-space1-abc");
    } finally {
      await mock.close();
    }
  });

  test("runCommandViaSsh reports unsupported honestly instead of faking it", async () => {
    const mock = await startMock(() => ({ json: {} }));
    try {
      const cs = new CodespacesClient(clientFor(mock));
      const res = await cs.runCommandViaSsh("space1", "npm test");
      assert.equal(res.supported, false);
      assert.equal(res.howTo, "gh codespace ssh -c space1 -- npm test");
      assert.match(res.reason, /no REST endpoint|not available over REST|no .*endpoint/i);
      assert.equal(mock.requests.length, 0, "no request is attempted for an unsupported capability");
      await assert.rejects(() => cs.runCommandViaSsh("", "ls"), (err: unknown) => err instanceof GitHubValidationError);
    } finally {
      await mock.close();
    }
  });

  test("status() states quota/billing limits plainly", async () => {
    const mock = await startMock((req) => {
      if (req.path === "/user") return { json: { login: "octocat", id: 1 }, headers: { "x-oauth-scopes": "codespace, repo" } };
      if (req.path === "/user/codespaces") {
        return {
          json: {
            total_count: 2,
            codespaces: [
              { name: "a", state: "Available", created_at: new Date(Date.now() - 60 * 60 * 1000).toISOString() },
              { name: "b", state: "ShuttingDown", created_at: new Date(Date.now() - 30 * 60 * 1000).toISOString() },
            ],
          },
        };
      }
      return { status: 404, json: { message: "nope" } };
    });
    try {
      const cs = new CodespacesClient(clientFor(mock));
      const status = await cs.status();
      assert.equal(status.canRunCommands, false);
      assert.equal(status.billing.remainingFreeTierMinutes, null);
      assert.equal(status.billing.queryable, false);
      assert.match(status.limitations.quota, /not unlimited|quota-bound/i);
      assert.match(status.limitations.billing, /billed/i);
      assert.match(status.limitations.commandExecution, /cannot run commands/i);
      assert.deepEqual(status.codespaces.byState, { Available: 1, ShuttingDown: 1 });
      assert.equal(status.codespaces.total, 2);
      assert.deepEqual(status.oauthScopes, ["codespace", "repo"]);
      assert.match(status.summary, /2 Codespace/);
    } finally {
      await mock.close();
    }
  });
});

// ---------------------------------------------------------------------------
// OAuth
// ---------------------------------------------------------------------------

describe("oauth", () => {
  test("buildAuthorizeUrl encodes scope, state and redirect", () => {
    const url = new URL(
      buildAuthorizeUrl({
        clientId: "Iv1.abc",
        redirectUri: "https://app.example/oauth/callback",
        scope: ["repo", "read:user", "workflow"],
        state: "nonce-123",
        allowSignup: false,
      }),
    );
    assert.equal(url.origin + url.pathname, "https://github.com/login/oauth/authorize");
    assert.equal(url.searchParams.get("client_id"), "Iv1.abc");
    assert.equal(url.searchParams.get("redirect_uri"), "https://app.example/oauth/callback");
    assert.equal(url.searchParams.get("scope"), "repo read:user workflow");
    assert.equal(url.searchParams.get("state"), "nonce-123");
    assert.equal(url.searchParams.get("allow_signup"), "false");
    assert.ok(!buildAuthorizeUrl({ clientId: "x", redirectUri: "https://a/b" }).includes("client_secret"));
  });

  test("exchangeCode POSTs the documented form and returns token details", async () => {
    const mock = await startMock(() => ({
      json: {
        access_token: "ghu_new_user_token_abcdef123456",
        token_type: "bearer",
        scope: "repo,read:user",
        refresh_token: "ghr_refresh_abcdef123456",
        expires_in: 28800,
        refresh_token_expires_in: 15897600,
      },
    }));
    try {
      const res = await exchangeCode({
        clientId: "Iv1.abc",
        clientSecret: "shhh-secret",
        code: "code-xyz",
        redirectUri: "https://app.example/oauth/callback",
        tokenUrl: `${mock.baseUrl}/login/oauth/access_token`,
      });
      const req = mock.requests[0]!;
      assert.equal(req.method, "POST");
      assert.equal(req.path, "/login/oauth/access_token");
      assert.equal(req.headers["content-type"], "application/x-www-form-urlencoded");
      assert.equal(req.headers.accept, "application/json");
      const form = new URLSearchParams(req.body);
      assert.equal(form.get("client_id"), "Iv1.abc");
      assert.equal(form.get("client_secret"), "shhh-secret");
      assert.equal(form.get("code"), "code-xyz");
      assert.equal(form.get("redirect_uri"), "https://app.example/oauth/callback");

      assert.equal(res.accessToken, "ghu_new_user_token_abcdef123456");
      assert.equal(res.scope, "repo,read:user");
      assert.equal(res.tokenType, "bearer");
      assert.equal(res.refreshToken, "ghr_refresh_abcdef123456");
      assert.equal(res.expiresIn, 28800);
      assert.ok(res.expiresAt && Date.parse(res.expiresAt) > Date.now());
    } finally {
      await mock.close();
    }
  });

  test("exchangeCode throws a typed error without leaking the secret", async () => {
    const mock = await startMock(() => ({
      status: 200,
      json: { error: "bad_verification_code", error_description: "The code passed is incorrect or expired." },
    }));
    try {
      await assert.rejects(
        () =>
          exchangeCode({
            clientId: "Iv1.abc",
            clientSecret: "super-secret-value",
            code: "code-xyz",
            redirectUri: "https://app.example/cb",
            tokenUrl: `${mock.baseUrl}/login/oauth/access_token`,
          }),
        (err: unknown) => {
          assert.ok(err instanceof GitHubOAuthError);
          assert.equal(err.error, "bad_verification_code");
          assert.match(err.message, /bad_verification_code/);
          assert.ok(!err.message.includes("super-secret-value"));
          return true;
        },
      );
    } finally {
      await mock.close();
    }
  });

  test("refreshGithubToken sends grant_type=refresh_token and rotates the pair", async () => {
    const mock = await startMock(() => ({
      json: {
        access_token: "ghu_rotated_access_123456",
        token_type: "bearer",
        scope: "repo",
        refresh_token: "ghr_rotated_refresh_123456",
        expires_in: 28800,
      },
    }));
    try {
      const res = await refreshGithubToken({
        clientId: "Iv1.abc",
        clientSecret: "shhh",
        refreshToken: "ghr_old_refresh",
        tokenUrl: `${mock.baseUrl}/login/oauth/access_token`,
      });
      const form = new URLSearchParams(mock.requests[0]!.body);
      assert.equal(form.get("grant_type"), "refresh_token");
      assert.equal(form.get("refresh_token"), "ghr_old_refresh");
      assert.equal(form.get("client_id"), "Iv1.abc");
      assert.equal(form.get("client_secret"), "shhh");
      assert.equal(res.accessToken, "ghu_rotated_access_123456");
      assert.equal(res.refreshToken, "ghr_rotated_refresh_123456");
    } finally {
      await mock.close();
    }
  });

  test("revokeGithubToken DELETEs /applications/{client_id}/token with basic auth", async () => {
    const mock = await startMock((req) => {
      if (req.method === "DELETE" && req.path === "/applications/Iv1.abc/token") {
        return { status: 204, body: "" };
      }
      return { status: 404, json: { message: "nope" } };
    });
    try {
      const res = await revokeGithubToken({
        clientId: "Iv1.abc",
        clientSecret: "shhh-secret",
        token: "ghu_revoke_me_123456",
        apiBaseUrl: mock.baseUrl,
      });
      const req = mock.requests[0]!;
      assert.equal(req.method, "DELETE");
      assert.equal(req.path, "/applications/Iv1.abc/token");
      assert.equal(
        req.headers.authorization,
        `Basic ${Buffer.from("Iv1.abc:shhh-secret", "utf8").toString("base64")}`,
      );
      assert.equal(req.headers["x-github-api-version"], "2022-11-28");
      assert.deepEqual(req.json, { access_token: "ghu_revoke_me_123456" });
      assert.deepEqual(res, { revoked: true, status: 204 });
    } finally {
      await mock.close();
    }
  });

  test("failed revoke is typed and does not leak the secret or token", async () => {
    const mock = await startMock(() => ({ status: 401, json: { message: "Bad credentials" } }));
    try {
      await assert.rejects(
        () =>
          revokeGithubToken({
            clientId: "Iv1.abc",
            clientSecret: "shhh-secret",
            token: "ghu_sensitive_token_value",
            apiBaseUrl: mock.baseUrl,
          }),
        (err: unknown) => {
          assert.ok(err instanceof GitHubOAuthError);
          assert.equal(err.status, 401);
          assert.ok(!err.message.includes("shhh-secret"));
          assert.ok(!err.message.includes("ghu_sensitive_token_value"));
          return true;
        },
      );
    } finally {
      await mock.close();
    }
  });
});
