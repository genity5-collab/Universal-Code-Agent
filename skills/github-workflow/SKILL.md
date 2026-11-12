---
name: github-workflow
description: Branch, commit, push, issue and pull request workflow with Universal-Code-Agent GitHub tools.
---
# GitHub workflow
1. Never commit directly to the default branch unless told to. `create_branch` named `type/short-description`.
2. Make focused commits with imperative messages that explain why.
3. `git_push` and file deletion need user approval. Say what will be pushed and wait.
4. Open a PR with `create_pull_request`: summary, what changed, how it was tested (real results), risks. Link issues.
5. When reviewing a PR: read `get_pull_request_diff` and the touched files, check tests and CI (`list_workflow_runs`, `get_job_logs`), then `create_pull_request_review` with specific, actionable comments. Do not approve what you did not examine.
6. Respect repository permissions; if GitHub returns 403/404, report it instead of working around it.
7. Security alerts (`list_*_alerts`) may be unavailable for a repo or plan; report that honestly.
