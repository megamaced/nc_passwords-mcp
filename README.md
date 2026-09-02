# passwords-mcp

A [Model Context Protocol](https://modelcontextprotocol.io) server for the [Nextcloud Passwords](https://git.mdns.eu/nextcloud/passwords) app. It lets Claude and other MCP-compatible clients read and manage entries in your Nextcloud password vault — listing/searching by metadata, revealing a single secret on request, and creating, updating, and (reversibly) deleting and restoring passwords and folders.

> ⚠️ **This project is 100% AI-written.** All source code, tests, CI configuration, and this documentation were written by AI (Claude). Review it yourself before pointing it at a real password vault. It is provided as-is, with no warranty (see [LICENSE](LICENSE)).

> 🔓 **Requires client-side encryption (CSE) to be OFF.** This server only works with accounts where the Passwords app's client-side (end-to-end) encryption is **disabled**. See [Encryption requirement](#encryption-requirement) below.

## Security model

This is a password-manager bridge, so it is built defensively even though it can now write:

- **Reads never bulk-expose secrets.** `list_passwords` and `search_passwords` return **metadata only** (label, username, URL, folder, timestamps). The plaintext secret, notes, and custom fields are stripped at a single choke point (`toPasswordMeta`). Only `get_password`, called with one specific id, ever returns a secret. Folder results pass through the equivalent `toFolderMeta` allowlist.
- **Search ignores secrets.** Searching matches on label / username / URL only — never on the password, notes, or custom fields.
- **Deletes are soft and reversible.** `delete_password` / `delete_folder` move items to the trash. They first fetch the item and **refuse if it is already trashed**, so this server can never permanently delete anything — empty the trash from the Passwords app if you really mean it. `restore_password` / `restore_folder` are the undo; they only lift an item out of the trash and never roll an entry back to an older revision.
- **Updates never blank data.** `update_password` fetches the current entry, merges only the fields you passed, and sends the current `revision` — so an edit can't silently wipe fields, and the server rejects the write if the entry changed underneath it. This includes fields the API would otherwise reset to their defaults: `hidden` on passwords, and `hidden` + `favorite` on folders, are carried across every update.
- **Writes are never retried automatically.** A 5xx or a network failure on a create/update/delete proves nothing about whether the server applied it, so the tool reports an explicit unknown-outcome error instead of replaying the request — a retried create would duplicate an entry, and a retried revision-guarded write would report a false conflict. Reads are still retried with capped, jittered backoff.
- **Optional read-only mode.** Set `PASSWORDS_READONLY=true` to drop all eight write tools from the tool list and refuse them at dispatch (defence in depth).
- **HTTPS enforced.** Plaintext `http://` is refused unless you explicitly set `ALLOW_INSECURE_HTTP=true`, and even then only for a **loopback host** (`localhost`, `127.0.0.0/8`, `::1`) — the opt-in can never send credentials to a remote host in the clear.
- **Redirects refused.** Requests are made with `redirect: 'error'`. Following a redirect would hand the `Authorization` header, and therefore the app-password, to whatever host the `Location` header names. The Passwords API never legitimately redirects, so any 3xx is a hard failure.
- **Error responses are discarded unread.** A Passwords API error body can echo the request that failed, so it is drained and thrown away without ever being inspected. A failure surfaces the status code, a static hint and a random correlation id — to the model and to the log alike. There is no configuration, `DEBUG` included, that routes a response body anywhere.
- **App-password auth.** Authenticates with a revocable Nextcloud app-password over HTTP Basic — never your real account password. `NEXTCLOUD_URL` is rejected if it embeds credentials, a query string, or a fragment; `NEXTCLOUD_USER` is rejected if it contains a colon or control characters.
- **Secrets never logged.** Debug logging (`DEBUG=1`) writes the method, path, status and correlation id to stderr. Credentials, session tokens, response bodies, and secret fields are never logged, cached, or written to disk — a test asserts this with debugging on.
- **`ping` reads nothing.** Connectivity is proved with the session handshake and `session/keepalive`. It deliberately avoids `password/list`, whose default model would pull every decrypted password, note and custom field into this process.
- **Custom fields are validated, not passed through.** They are accepted as structured objects and serialized centrally against the documented API limits, so a malformed or oversized blob can never be written into the vault. Limit violations report lengths, never values.
- **Minimal dependencies.** Only the official MCP SDK and `zod`. Networking uses Node's built-in `fetch`; requests carry a 30s timeout, and no retry wait can exceed 30s regardless of what `Retry-After` asks for.

None of this removes the underlying risk: an app-password that can read and write the vault gives any connected client the same power — reading every secret and modifying entries. Scope and rotate the app-password accordingly, and use `PASSWORDS_READONLY=true` if you only need lookups.

## Encryption requirement

The Nextcloud Passwords app supports two encryption modes:

- **Server-side encryption (SSE)** — encrypted at rest; the server holds the keys and returns plaintext to any authenticated session. **Supported.**
- **Client-side encryption (CSE)** — end-to-end encryption gated by a master password the server never sees. **Not supported.**

This server implements none of the CSE (E2E) cryptography. On startup of each session it asks the server whether a challenge is required (`session/request`); if CSE is enabled it refuses to run with a clear error rather than returning ciphertext. To use this server, disable client-side encryption in the Passwords app settings.

## Tools exposed (14; 6 in read-only mode)

**Read** (always available):

| Tool | Returns | Secret? |
| --- | --- | --- |
| `ping` | Connectivity check; confirms CSE is off. Reads no vault data | No |
| `list_passwords` | All entries as metadata (optionally filtered by folder) | No |
| `search_passwords` | Metadata for entries matching a label/username/URL substring | No |
| `get_password` | A single entry incl. plaintext password, notes, custom fields | **Yes** |
| `list_folders` | All folders | No |
| `get_folder` | A single folder | No |

**Write** (hidden when `PASSWORDS_READONLY=true`):

| Tool | Does |
| --- | --- |
| `create_password` | Create an entry (label + password required; username/url/notes/folder/favorite/hidden/customFields optional) |
| `update_password` | Change specific fields of an entry by id (merge; others preserved) |
| `delete_password` | Move an entry to the trash (reversible; refuses if already trashed) |
| `restore_password` | Take an entry back out of the trash (refuses if not trashed) |
| `create_folder` | Create a folder (label required; optional parent/favorite/hidden) |
| `update_folder` | Rename, re-parent, or change favorite/hidden state of a folder by id |
| `delete_folder` | Move a folder and its contents to the trash (reversible; refuses if already trashed) |
| `restore_folder` | Take a folder back out of the trash (refuses if not trashed) |

Every tool carries MCP [annotations](https://modelcontextprotocol.io/specification/2025-06-18/schema#toolannotations) (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`) so clients can tell a metadata read from a secret disclosure or a vault mutation in their confirmation UI. They are hints for presentation — the read-only enforcement above is what actually blocks writes.

### Writable fields

`customFields` replaces the **entire** set on an entry, so send the complete list rather than a delta. Fields are `{ label, type, value }`, where `type` is one of `text`, `secret`, `email`, `url`, `file`, or `data`.

**Tags are out of scope.** The API leaves tags untouched when the field is omitted, which is what this server does. Editing them would need tag-discovery tools (list/create tags) that do not exist here, and sending a partial list would silently drop tags the model never saw.

## Install

Build a tarball and install it globally:

```bash
pnpm install
pnpm pack:tarball          # produces passwords-mcp-<version>.tgz
npm install -g ./passwords-mcp-0.3.1.tgz
```

This installs the `passwords-mcp` command.

## Configuration

Add to your MCP client config (Claude Code shown):

```json
{
  "mcpServers": {
    "passwords": {
      "command": "passwords-mcp",
      "args": [],
      "env": {
        "NEXTCLOUD_URL": "https://your-nextcloud.example.com",
        "NEXTCLOUD_USER": "your-username",
        "NEXTCLOUD_APP_PASSWORD": "xxxx-xxxx-xxxx-xxxx-xxxx"
      }
    }
  }
}
```

**Generate the app-password** in Nextcloud under Settings → Security → Devices & sessions → "Create new app password". The server only needs an app-password, never your real account password — and you can revoke it at any time without affecting your main login.

### Environment variables

| Variable | Required | Description |
| --- | --- | --- |
| `NEXTCLOUD_URL` | yes | Instance base URL (no trailing slash). Must be `https://`. |
| `NEXTCLOUD_USER` | yes | Nextcloud username. |
| `NEXTCLOUD_APP_PASSWORD` | yes | A dedicated app-password. |
| `PASSWORDS_READONLY` | no | Set to `true` to expose only the read tools and refuse all writes. |
| `DEBUG` | no | Set to any value to log method, path, status and a correlation id to stderr (never secrets or response bodies). |
| `ALLOW_INSECURE_HTTP` | no | Set to `true` to permit plaintext `http://` for a **loopback host only** (localhost testing). Remote hosts are refused regardless. |

## Development

```bash
pnpm install
pnpm dev        # stdio MCP server; point the MCP inspector at it
pnpm test       # unit tests (config validation + secret-stripping guarantees)
pnpm lint       # eslint
pnpm typecheck  # tsc --noEmit
pnpm build      # tsc -> dist/
```

The unit tests are pure and need no server (global `fetch` is stubbed where a request is exercised). They assert:

- metadata projection and search never expose secret fields — the core guarantee
- the config validation rules
- the write-payload builders: hash computation, the merge that preserves untouched fields, and that `hidden`/`favorite` survive an unrelated edit
- custom-field validation and round-tripping
- read-only gating, and that unknown tool names — including ones inherited from `Object.prototype` — return a tool error rather than throwing
- MCP annotations are present and correct on every registered tool
- session handling: one handshake under concurrent first calls, replay of the most recent `X-API-SESSION`, `GET` for `session/close`, and re-open on a 412
- retry policy: reads retry, writes never do, and `Retry-After` is parsed strictly and clamped
- `ping` never requests `password/list`
- with `DEBUG` on, no response body or session token reaches stderr

## License

MIT — see [LICENSE](LICENSE).

## Related

- [Nextcloud Passwords](https://git.mdns.eu/nextcloud/passwords) and its [API reference](https://git.mdns.eu/nextcloud/passwords/-/wikis/Developers/Api/Index)
- [Model Context Protocol](https://modelcontextprotocol.io)
- [`@modelcontextprotocol/sdk`](https://www.npmjs.com/package/@modelcontextprotocol/sdk)
