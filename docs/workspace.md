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
| Files | `read_file`, `read_file_chunk`, `read_file_range`, `write_file`, `create_file`, `edit_file`, `delete_file`, `list_directory`, `get_file_metadata`, `compare_files` | only `delete_file` needs the user's approval |
| Search | `search_files`, `search_content`, `find_symbol`, `index_repo`, `repo_map`, `dependency_map`, `change_tracking` | run with grep/find in the VM |
| Commands | `run_command`, `start_job`, `job_status`, `job_output`, `stop_job`, `list_jobs`, `read_command_log` | one simple command at a time; `&&`, `;`, `|` are rejected, run steps separately |
| Project | `install_dependencies`, `run_tests`, `format_code`, `static_analysis`, `build_verify` | pick the tool for the project's manifest |
| Git | `git_status`, `git_diff`, `git_log`, `git_branch_create`, `git_checkout`, `git_commit`, `git_clone`, `git_pull`, `git_push` | run automatically, no approval |
| VM | `vm_status`, `vm_start`, `vm_stop`, `vm_live` | `vm_live` opens a live window of the VM in this chat |

Inside the user's own VM you work freely: writes, installs, git (including push), builds and ordinary commands run **automatically**, with no approval step.
Only **deletes** wait for the user: `delete_file`, `rm`/`rmdir`, `git clean`, `git reset --hard`, and deleting a git branch. For those you get `approval_required`
with an `approvalId`. Tell the user to approve it in the app's **Approvals** tab, then retry the same call.
Some things are blocked outright and never run: `sudo`, deleting system paths or anything outside the workspace, and similar escapes.

## What the user sees

Call `vm_live` once when you start working in the VM. It opens a **live window inside this chat** showing each action as it happens, plus the file list.
If the chat cannot show windows it still returns a text summary, so keep narrating what you do in plain words.


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

## The VM screen (a real Linux desktop)

Some VMs have a graphical Linux desktop (InstaBox `agent-browser` does). Use it for anything visual: browsers, GUI apps, checking how a web page looks.

1. `desktop_start` once (it installs the desktop first if the VM lacks it, about 30 seconds).
2. `desktop_screenshot` returns the screen as an image. Look at it before acting. Coordinates are pixels from the top left of that image.
3. Act with `desktop_click`, `desktop_type` (click the field first), `desktop_press` (e.g. ["ctrl","l"], ["Enter"]), `desktop_scroll`, `desktop_drag`, `desktop_move`, `desktop_open` (http/https only).
4. Take another screenshot after every action to check the result. Do not guess.

`vm_live` opens a live window in the chat that shows this screen, so the user can watch. The user can also watch and click on it in the app's Workspace tab. If a screenshot fails with "no screenshot tool", run `sudo apt-get update && sudo apt-get install -y scrot xdotool`.

## Errors you may see

- `No InstaBox key` / `No VM is attached` -> see "Before you do anything".
- `The VM no longer exists` or `not running` -> the machine was deleted or stopped; ask the user to press Start VM.
- `Workspace limit reached` -> delete files, or ask the user to download and clear space.
- `InstaBox limit reached` / `no capacity` -> a plan limit or a busy region; wait a minute or ask the user to check their InstaBox plan.
- `Blocked: ...` -> the command was refused by the safety policy; use a safer approach.
