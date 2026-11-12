# Using a GitHub Codespace as the AI's Linux VM

A Codespace is a real Linux VM (Ubuntu dev container) with your repo checked out. With this mode, the AI's
files, commands, git and tests run **inside the Codespace** instead of on the UCA server.

## Why an agent inside the Codespace?

GitHub's public REST API can create, start, stop and delete Codespaces, but it **cannot run commands inside one**,
and a Codespace's forwarded ports need browser-style GitHub auth. So UCA does not try to connect *in*.
A small agent (`agent/uca-agent.mjs`, one file, no dependencies) runs inside the Codespace and connects *out* to your
UCA server over HTTPS, long-polling for jobs. No inbound ports, no tunnels.

```
AI (Claude / ChatGPT / Gemini) --MCP--> UCA server --job queue--> uca-agent (in Codespace) --> bash, files, git
```

## Setup (about one minute)

1. Create or pick a Codespace (`codespaces_create`, or any you already have). Make sure it is running (`codespaces_start`).
2. Ask the AI to call **`codespaces_attach`** with the Codespace name. It returns one command, valid for 10 minutes.
3. Paste that command once into the Codespace terminal. It downloads the agent, exchanges the single-use claim code for a private token
   (stored in `~/.uca-agent/env`, mode 600), starts the agent, and adds a hook to `~/.bashrc` so the agent restarts when you open a terminal.
4. Call **`codespaces_agents`**: your Codespace should show `online: true`. Now use the `cs_*` tools.

Note: a stopped Codespace runs nothing. After `codespaces_start`, the agent comes back when a terminal opens (the `.bashrc` hook).
To start it with no terminal, add this to the repo's `.devcontainer/devcontainer.json`:
`"postStartCommand": "$HOME/.uca-agent/start.sh || true"` (this contains no secret; the token lives only in `~/.uca-agent/env`).

## Tools

| Tool | What it does | Approval |
|---|---|---|
| `cs_info` | OS, CPU, memory, user, workspace root | no |
| `cs_exec` | Run a bash command on the VM | risky commands only |
| `cs_read_file` / `cs_list_dir` / `cs_stat` / `cs_search` | Read-only inspection | no |
| `cs_write_file` / `cs_mkdir` | Write files (atomic) | no |
| `cs_delete` | Delete a path | **always** |
| `cs_git` | `git <args>` (read-only subcommands run directly) | commit, push, reset, rebase, clean, ... |
| `codespaces_attach` / `codespaces_agents` / `codespaces_detach` | Pair, list, revoke | no |

If you have exactly one online Codespace you can omit `codespace`; otherwise pass it.

## Security model (honest version)

- **The Codespace is the sandbox.** Commands there run as the Codespace user, with that machine's network access.
  UCA blocks obvious disasters (wiping the root or home directory, formatting disks, shutdown, reading the agent's own token or `gh auth token`)
  and asks you to approve risky things (`sudo`, installs, `git push`, `rm -r`, `docker`, piping curl to a shell, network writes).
  This is a *guard rail, not a proof of containment*: a determined command can still do damage inside the Codespace.
  Keep secrets you do not want exposed out of the Codespace, and use a throwaway Codespace for untrusted work.
- **File tools are confined** to the workspace root, including symlink checks. `cs_exec` is not path-confined (it is a shell).
- **The agent token** is never passed to commands (it is removed from their environment) and `cs_exec` refuses commands that reference it.
  Output is scrubbed for common token patterns.
- **Pairing**: claim codes are single-use and expire in 10 minutes. Re-attaching rotates the token. `codespaces_detach` revokes it instantly
  and the agent exits. Tokens are stored only as SHA-256 hashes on the server.
- **Isolation**: each user can only reach their own paired Codespaces.
- **State is in memory**: if you restart the UCA server, agents reconnect on their own, but pairings made before the restart must be re-created with `codespaces_attach`.
- **Quota**: a running Codespace uses your GitHub Codespaces hours and storage. It auto-stops when idle.

## Not verified against real GitHub

This was tested with the real agent against the real server and a real MCP client, on a normal Linux machine.
It has **not** been run inside an actual GitHub-hosted Codespace, because that needs a live GitHub account. The agent only needs
`bash`, `node` 18+ and `curl`, which the default Codespaces image provides.
