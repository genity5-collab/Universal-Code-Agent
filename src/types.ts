/** Shared contracts between modules. Keep stable: workers build against these. */
export interface UserContext {
  userId: string;          // stable id, e.g. "gh:12345"
  login: string;           // GitHub login
  workspaceRoot: string;   // absolute, per-user isolated directory
  githubToken?: string;    // user's own GitHub token (never shared across users)
}

export interface ToolResult {
  content: { type: "text"; text: string }[];
  isError?: boolean;
}
export const ok = (data: unknown): ToolResult => ({
  content: [{ type: "text", text: typeof data === "string" ? data : JSON.stringify(data, null, 2) }],
});
export const fail = (msg: string): ToolResult => ({ content: [{ type: "text", text: msg }], isError: true });

export interface ApprovalRequest {
  id: string; userId: string; action: string; detail: string;
  status: "pending" | "approved" | "denied"; createdAt: number;
}
