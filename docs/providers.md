# Using other VM providers (Fly.io, DigitalOcean, Hetzner, Render, Freestyle, or any)

Besides GitHub Codespaces, your AI can create and manage VMs on **any provider that has an HTTPS API**.
You give the server your API key in the app. The AI then searches that provider's documentation to learn how to use it.

## How to add a provider

1. Open the app, tap **Cloud**, scroll to **Provider keys**.
2. Pick a recommended provider, or choose **Other** and type the provider name and its API hostname (for example `api.vultr.com`).
3. Paste your API key and tap **Add key**. Use **Test** to check it (available for the recommended providers).
4. Tell your AI: "I added Fly.io, learn how to use it." It calls `provider_search_docs` and `provider_read_docs`, then `provider_request`.

**Never paste a provider key into the chat with the AI.** Chat history is stored by the AI app and outlives this server. Paste it only in the app.

## What happens to your key

| Promise | How it is enforced |
|---|---|
| Stored in memory only | Held in a process-memory map. Never written to disk, logs or the audit file. A test scans the whole data directory for the key. |
| Lost when you leave | Wiped on sign-out, **Revoke all access**, **Forget**, 2 hours without use, and any server restart. |
| The AI never sees it | The AI only gets a handle like `acme-cloud`. The server attaches the key to outgoing requests itself. Every tool result, error and approval text is scrubbed of the key (plain, URL-encoded, base64, JSON-escaped and reversed forms). |
| Cannot be sent elsewhere | The key is pinned to the hostnames you approved. Other hosts, `http://`, URL credentials, IP addresses and `localhost` are refused. Redirects are never followed, so a redirect cannot carry the key to another host. |
| The AI cannot set auth itself | `Authorization`, `Cookie`, `X-Api-Key` headers from the AI are dropped. |
| You approve changes | GET requests run directly. Any POST, PUT, PATCH or DELETE (creating, changing or deleting VMs, which can cost money) waits for your approval in the app, with the AI's stated purpose shown. |

Because of "lost when you leave", you paste the key again next session. That is by design.

## How the AI learns a provider

`provider_search_docs` searches the public web, and `provider_read_docs` reads a public docs page as text and returns links to follow.
Both only fetch public `https://` pages: private, loopback, link-local and cloud-metadata addresses are blocked, DNS is checked, redirects are re-checked on every hop, and no credentials are ever attached.
Page text is labelled untrusted so instructions hidden in a web page should not be followed.

## Honest limits

- This is a **guard rail, not a guarantee**. A key you give an AI-driven tool can be used for anything the key allows on the approved host. Use a **scoped or low-limit key**, and prefer a throwaway project or account. Delete the key at the provider when you are done.
- The AI can read approved write requests' effects only through the provider's responses. Review each approval before tapping Approve, because a request can create billable resources.
- Web search uses DuckDuckGo's public HTML page. It can fail or be rate limited, and the AI can still read docs URLs directly.
- If you run more than one server instance, keys are per instance. Use one instance (the Render blueprint does).
- The server operator (you) can read process memory. Do not give this server to people you do not trust with their keys.
- Not tested against any real provider. Tests use mock servers.
