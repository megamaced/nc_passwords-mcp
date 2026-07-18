# passwords-mcp

A read-only [Model Context Protocol](https://modelcontextprotocol.io) server for the [Nextcloud Passwords](https://git.mdns.eu/nextcloud/passwords) app. It lets Claude and other MCP-compatible clients look up entries in your Nextcloud password vault — listing and searching by metadata, and revealing a single secret on explicit request.

> ⚠️ **This project is 100% AI-written.** All source code, tests, CI configuration, and this documentation were written by AI (Claude). Review it yourself before pointing it at a real password vault. It is provided as-is, with no warranty (see [LICENSE](LICENSE)).

> 🔓 **Requires client-side encryption (CSE) to be OFF.** This server only works with accounts where the Passwords app's client-side (end-to-end) encryption is **disabled**. See [Encryption requirement](#encryption-requirement) below.

## Security model

This is a password manager bridge, so it is built defensively and read-only:

- **Read-only by design.** There are no create / update / delete tools anywhere in the codebase. The absence of write code — not a runtime flag — is the safety boundary.
- **No bulk secret exposure.** `list_passwords` and `search_passwords` return **metadata only** (label, username, URL, folder, timestamps). The plaintext secret, notes, and custom fields are stripped at a single choke point (`toPasswordMeta`). Only `get_password`, called with one specific id, ever returns a secret.
- **Search ignores secrets.** Searching matches on label / username / URL only — never on the password, notes, or custom fields.
- **HTTPS enforced.** Plaintext `http://` is refused unless you explicitly set `ALLOW_INSECURE_HTTP=true` (intended for localhost testing only).
- **App-password auth.** Authenticates with a revocable Nextcloud app-password over HTTP Basic — never your real account password.
- **Secrets never logged.** Debug logging (`DEBUG=1`) writes only method + path to stderr. Credentials, session tokens, and secret fields are never logged, cached, or written to disk.
- **Minimal dependencies.** Only the official MCP SDK and `zod`. Networking uses Node's built-in `fetch`; requests carry a 30s timeout.

None of this removes the underlying risk: an app-password that can read the vault can read every secret in it. Scope and rotate the app-password accordingly, and treat any client connected to this server as capable of revealing individual passwords.

## Encryption requirement

The Nextcloud Passwords app supports two encryption modes:

- **Server-side encryption (SSE)** — encrypted at rest; the server holds the keys and returns plaintext to any authenticated session. **Supported.**
- **Client-side encryption (CSE)** — end-to-end encryption gated by a master password the server never sees. **Not supported.**

This server implements none of the CSE (E2E) cryptography. On startup of each session it asks the server whether a challenge is required (`session/request`); if CSE is enabled it refuses to run with a clear error rather than returning ciphertext. To use this server, disable client-side encryption in the Passwords app settings.

## Tools exposed (6)

| Tool | Returns | Secret? |
| --- | --- | --- |
| `ping` | Connectivity check + item counts; confirms CSE is off | No |
| `list_passwords` | All entries as metadata (optionally filtered by folder) | No |
| `search_passwords` | Metadata for entries matching a label/username/URL substring | No |
| `get_password` | A single entry incl. plaintext password, notes, custom fields | **Yes** |
| `list_folders` | All folders | No |
| `get_folder` | A single folder | No |

## Install

Build a tarball and install it globally:

```bash
pnpm install
pnpm pack:tarball          # produces passwords-mcp-<version>.tgz
npm install -g ./passwords-mcp-0.1.0.tgz
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

The unit tests are pure and need no server. They assert the config validation rules and — most importantly — that metadata projection and search never expose secret fields.

## License

MIT — see [LICENSE](LICENSE).

## Related

- [Nextcloud Passwords](https://git.mdns.eu/nextcloud/passwords) and its [API reference](https://git.mdns.eu/nextcloud/passwords/-/wikis/Developers/Api/Index)
- [Model Context Protocol](https://modelcontextprotocol.io)
- [`@modelcontextprotocol/sdk`](https://www.npmjs.com/package/@modelcontextprotocol/sdk)
