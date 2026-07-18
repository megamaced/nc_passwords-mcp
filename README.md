# passwords-mcp

A [Model Context Protocol](https://modelcontextprotocol.io) server for the [Nextcloud Passwords](https://git.mdns.eu/nextcloud/passwords) app. It lets Claude and other MCP-compatible clients read and manage entries in your Nextcloud password vault — listing/searching by metadata, revealing a single secret on request, and creating, updating, and (reversibly) deleting passwords and folders.

> ⚠️ **This project is 100% AI-written.** All source code, tests, CI configuration, and this documentation were written by AI (Claude). Review it yourself before pointing it at a real password vault. It is provided as-is, with no warranty (see [LICENSE](LICENSE)).

> 🔓 **Requires client-side encryption (CSE) to be OFF.** This server only works with accounts where the Passwords app's client-side (end-to-end) encryption is **disabled**. See [Encryption requirement](#encryption-requirement) below.

## Security model

This is a password-manager bridge, so it is built defensively even though it can now write:

- **Reads never bulk-expose secrets.** `list_passwords` and `search_passwords` return **metadata only** (label, username, URL, folder, timestamps). The plaintext secret, notes, and custom fields are stripped at a single choke point (`toPasswordMeta`). Only `get_password`, called with one specific id, ever returns a secret.
- **Search ignores secrets.** Searching matches on label / username / URL only — never on the password, notes, or custom fields.
- **Deletes are soft and reversible.** `delete_password` / `delete_folder` move items to the trash. They first fetch the item and **refuse if it is already trashed**, so this server can never permanently delete anything — empty the trash from the Passwords app if you really mean it.
- **Updates never blank data.** `update_password` fetches the current entry, merges only the fields you passed, and sends the current `revision` — so an edit can't silently wipe fields, and the server rejects the write if the entry changed underneath it.
- **Optional read-only mode.** Set `PASSWORDS_READONLY=true` to drop all six write tools from the tool list and refuse them at dispatch (defence in depth).
- **HTTPS enforced.** Plaintext `http://` is refused unless you explicitly set `ALLOW_INSECURE_HTTP=true` (intended for localhost testing only).
- **App-password auth.** Authenticates with a revocable Nextcloud app-password over HTTP Basic — never your real account password.
- **Secrets never logged.** Debug logging (`DEBUG=1`) writes only method + path to stderr. Credentials, session tokens, and secret fields are never logged, cached, or written to disk.
- **Minimal dependencies.** Only the official MCP SDK and `zod`. Networking uses Node's built-in `fetch`; requests carry a 30s timeout.

None of this removes the underlying risk: an app-password that can read and write the vault gives any connected client the same power — reading every secret and modifying entries. Scope and rotate the app-password accordingly, and use `PASSWORDS_READONLY=true` if you only need lookups.

## Encryption requirement

The Nextcloud Passwords app supports two encryption modes:

- **Server-side encryption (SSE)** — encrypted at rest; the server holds the keys and returns plaintext to any authenticated session. **Supported.**
- **Client-side encryption (CSE)** — end-to-end encryption gated by a master password the server never sees. **Not supported.**

This server implements none of the CSE (E2E) cryptography. On startup of each session it asks the server whether a challenge is required (`session/request`); if CSE is enabled it refuses to run with a clear error rather than returning ciphertext. To use this server, disable client-side encryption in the Passwords app settings.

## Tools exposed (12; 6 in read-only mode)

**Read** (always available):

| Tool | Returns | Secret? |
| --- | --- | --- |
| `ping` | Connectivity check + item counts; confirms CSE is off | No |
| `list_passwords` | All entries as metadata (optionally filtered by folder) | No |
| `search_passwords` | Metadata for entries matching a label/username/URL substring | No |
| `get_password` | A single entry incl. plaintext password, notes, custom fields | **Yes** |
| `list_folders` | All folders | No |
| `get_folder` | A single folder | No |

**Write** (hidden when `PASSWORDS_READONLY=true`):

| Tool | Does |
| --- | --- |
| `create_password` | Create an entry (label + password required; username/url/notes/folder/favorite optional) |
| `update_password` | Change specific fields of an entry by id (merge; others preserved) |
| `delete_password` | Move an entry to the trash (reversible; refuses if already trashed) |
| `create_folder` | Create a folder (label required; optional parent) |
| `update_folder` | Rename / re-parent a folder by id |
| `delete_folder` | Move a folder and its contents to the trash (reversible; refuses if already trashed) |

## Install

Build a tarball and install it globally:

```bash
pnpm install
pnpm pack:tarball          # produces passwords-mcp-<version>.tgz
npm install -g ./passwords-mcp-0.2.0.tgz
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
| `DEBUG` | no | Set to any value to log method + path to stderr (never secrets). |
| `ALLOW_INSECURE_HTTP` | no | Set to `true` to permit plaintext `http://` (localhost testing only). |

## Development

```bash
pnpm install
pnpm dev        # stdio MCP server; point the MCP inspector at it
pnpm test       # unit tests (config validation + secret-stripping guarantees)
pnpm lint       # eslint
pnpm typecheck  # tsc --noEmit
pnpm build      # tsc -> dist/
```

The unit tests are pure and need no server. They assert the config validation rules, the write-payload builders (hash computation and the merge that preserves untouched fields), the read-only gating, and — most importantly — that metadata projection and search never expose secret fields.

## License

MIT — see [LICENSE](LICENSE).

## Related

- [Nextcloud Passwords](https://git.mdns.eu/nextcloud/passwords) and its [API reference](https://git.mdns.eu/nextcloud/passwords/-/wikis/Developers/Api/Index)
- [Model Context Protocol](https://modelcontextprotocol.io)
- [`@modelcontextprotocol/sdk`](https://www.npmjs.com/package/@modelcontextprotocol/sdk)
