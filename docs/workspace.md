# Workspace and VM (for the AI to read)

**The AI cannot work without a VM.** Every file, search, git, command, test and job tool runs inside the user's InstaBox machine.
If no VM is attached, those tools refuse and tell you what to do. Nothing is ever read from or written to this server's disk.

## Before you do anything

1. Call `vm_status`. It returns `{ hasKey, running, starting, machineId, workspace, limitBytes }`.
2. `hasKey: false` -> tell the user: open the app, go to **Cloud -> Provider keys -> InstaBox**, paste an InstaBox API key
   (create one at https://dashboard.instabox.sh/dashboard/api-keys with `machines:read`, `machines:write`, `machines:delete`).
   Never ask the user to paste the key into chat. You never see it; the server adds it to calls.
3. `hasKey: true, running: false` -> call `vm_start` (or the user presses **Start VM** in the Workspace tab). It waits until the machine is up.
4. Work normally. `vm_stop` deletes the machine and every file in it, so only do it when the user asks. Tell them to download first.

## Where things live

- Workspace root: `/data/home/workspace` (persists while the machine is paused or stopped). Tool paths are relative to it; `..` and absolute paths outside it are refused.
- Limit: **1 GB** total. A write that would pass it is refused. If the size cannot be measured, writes are refused too (fail closed). Delete files to make room.
- Single file write limit 25 MB. Reads over 25 MB must use `read_file_chunk`.

## What each group of tools does

| Group | Tools | Notes |
| - | - | - |
| Files | `read_file`, `read_file_chunk`, `read_file_range`, `write_file`, `create_file`, `edit_file`, `delete_file`, `list_directory`, `get_file_metadata`, `compare_files` | `delete_file` needs the user's approval |
| Search | `search_files`, `search_content`, `find_symbol`, `index_repo`, `repo_map`, `dependency_map`, `change_tracking` | run with grep/find in the VM |
| Commands | `run_command`, `start_job`, `job_status`, `job_output`, `stop_job`, `list_jobs`, `read_command_log` | one simple command at a time; `&&`, `;`, `|` are rejected, run steps separately |
| Project | `install_dependencies`, `run_tests`, `format_code`, `static_analysis`, `build_verify` | pick the tool for the project's manifest |
| Git | `git_status`, `git_diff`, `git_log`, `git_branch_create`, `git_checkout`, `git_commit`, `git_clone`, `git_pull`, `git_push` | `clone`, `pull`, `push` need approval |
| VM | `vm_status`, `vm_start`, `vm_stop` | |

Dangerous commands (deleting system paths, `sudo`, etc.) are blocked. Installs and anything that changes state outside the workspace wait for the user's approval:
you get `approval_required` with an `approvalId`. Tell the user to approve it in the app's **Approvals** tab, then retry the same call.

## What the user sees

The app's **Workspace** tab shows a live feed of every action you take (commands with their output, files written, reads, git), a file browser,
a usage bar against the 1 GB limit, and download links (single files, or a folder as a zip). So say what you are doing in plain words; they are watching.
Files you create can be downloaded from there, so tell the user the path.

## The InstaBox API (reference, for the server and for your own reading)

Base URL `https://api.instabox.sh`, key in the `X-API-Key` header (the server adds it; you cannot).
`POST /v1/machines` (needs `Idempotency-Key`) answers `202` with an operation; poll `GET /v1/operations/{id}` until `state` is `succeeded`.
`POST /v1/machines/{id}/exec` takes `{cmd, cwd, timeoutSeconds<=600}` and returns `{stdout, stderr, exitCode, timedOut, truncated}`.
`PUT /v1/machines/{id}/files?path=&parents=true` uploads raw bytes; `GET /v1/machines/{id}/files/content?path=` downloads them.
`DELETE /v1/machines/{id}` needs `Idempotency-Key` and `X-Confirm-Delete: <id>`. Full spec: https://api.instabox.sh/v1/openapi.json, docs index: https://instabox.sh/docs/llms.txt.
Use the provider tools (`provider_search_docs`, `provider_read_doc`) to read these pages; do not guess endpoints.

## Errors you may see

- `No InstaBox key` / `No VM is attached` -> see "Before you do anything".
- `The VM no longer exists` or `not running` -> the machine was deleted or stopped; ask the user to press Start VM.
- `Workspace limit reached` -> delete files, or ask the user to download and clear space.
- `InstaBox limit reached` / `no capacity` -> a plan limit or a busy region; wait a minute or ask the user to check their InstaBox plan.
- `Blocked: ...` -> the command was refused by the safety policy; use a safer approach.
