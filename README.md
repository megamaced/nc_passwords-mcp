# passwords-mcp

A metadata-only [Model Context Protocol](https://modelcontextprotocol.io) server
for the [Nextcloud Passwords](https://git.mdns.eu/nextcloud/passwords) app.

The MCP server can list and search identifying metadata, but it has no tool that
reveals, creates, updates, or deletes a password. A separate
`passwords-mcp-keychain` helper can copy one allowlisted vault entry directly
into macOS Keychain or Linux Secret Service without printing the value.

> ⚠️ **This project is AI-written.** Review the source and threat model before
> pointing it at a real password vault. It is provided as-is, with no warranty.

> 🔓 **Requires client-side encryption (CSE) to be off.** The Passwords API
> returns plaintext to authenticated clients when CSE is disabled. This package
> refuses accounts that require a CSE challenge.

## Security boundary

The MCP surface is permanently metadata-only:

| Tool | Result |
| --- | --- |
| `ping` | Connectivity and metadata counts |
| `list_passwords` | Id, label, username, URL, folder, status, and timestamps |
| `search_passwords` | The same metadata, matched only on label/username/URL |
| `list_folders` | Folder metadata |
| `get_folder` | One folder metadata record |

There is no `get_password` tool and no mutation tool. This is not a runtime
toggle: the handlers and schemas do not exist in the MCP registry.

Additional controls:

- The Nextcloud app-password is loaded from an OS credential reference. A
  plaintext `NEXTCLOUD_APP_PASSWORD` environment variable is rejected.
- Tool errors use fixed codes. Remote response bodies and unexpected exception
  messages are never returned through MCP.
- Keychain helper manifests contain references only, use a strict schema, and
  are normalized by profile name. The CLI uses one OS-fixed path and rejects
  caller-supplied paths, symlinks, non-owner files, hard links, and group/world
  permissions.
- The helper accepts only `install`; there is no show, print, export, or
  arbitrary-command mode.
- Credential values are passed to credential-store commands over stdin (hex
  encoded inside macOS `security` interactive mode), never through argv or
  environment variables. Secret buffers are zeroed after use where the runtime
  permits it.
- HTTPS is mandatory and redirects are refused.

The Nextcloud `/password/list` endpoint itself returns full decrypted records.
The server therefore receives secrets in its private process memory before
projecting each record through the metadata allowlist. They are never serialized
into an MCP result.

### Host-access limitation

This design prevents credentials from being returned through MCP or helper
output. It does not make Keychain/libsecret unreadable to arbitrary code running
as the same logged-in OS user. If an agent has unrestricted terminal access, it
may be able to invoke the operating-system lookup utility directly.

For a stronger boundary, run the helper as a separately permissioned broker and
grant the agent only a narrow `install(profile)` IPC operation. On macOS, use a
signed native broker with Keychain access controls. On Linux, use a separate
service identity and service-scoped credentials or Secret Service collection.

## Install

```bash
pnpm install
pnpm pack:tarball
npm install -g ./passwords-mcp-0.3.0.tgz
```

This installs:

- `passwords-mcp` — metadata-only MCP server
- `passwords-mcp-keychain` — out-of-band credential-store installer

## Store the Nextcloud app-password

Generate a dedicated, revocable app-password under Nextcloud
Settings → Security → Devices & sessions.

macOS:

```bash
/usr/bin/security add-generic-password \
  -U \
  -s 'nc-passwords-mcp:cloud.example.com' \
  -a 'alice' \
  -w
```

Enter the app-password at the interactive prompt. Do not put it on the command
line.

Linux with libsecret:

```bash
/usr/bin/secret-tool store \
  --label='Nextcloud Passwords app password' \
  application nc-passwords-mcp \
  service 'nc-passwords-mcp:cloud.example.com' \
  account 'alice'
```

## MCP configuration

Configuration contains credential references, not values:

```json
{
  "mcpServers": {
    "passwords": {
      "command": "passwords-mcp",
      "args": [],
      "env": {
        "NEXTCLOUD_URL": "https://cloud.example.com",
        "NEXTCLOUD_USER": "alice",
        "NEXTCLOUD_CREDENTIAL_SERVICE": "nc-passwords-mcp:cloud.example.com",
        "NEXTCLOUD_CREDENTIAL_ACCOUNT": "alice"
      }
    }
  }
}
```

## Copy an allowlisted entry into the credential store

Create a reference-only manifest locally:

```json
{
  "schema_version": 1,
  "profiles": {
    "github-production": {
      "source_id": "00000000-0000-0000-0000-000000000001",
      "destination": {
        "service": "nc-passwords-mcp:github-production",
        "account": "octocat"
      }
    }
  }
}
```

Install it at the fixed operator-controlled path with private permissions.

macOS:

```bash
mkdir -m 700 "$HOME/Library/Application Support/passwords-mcp"
install -m 600 passwords-install.json \
  "$HOME/Library/Application Support/passwords-mcp/install-manifest.json"
```

Linux:

```bash
mkdir -m 700 "$HOME/.config/passwords-mcp"
install -m 600 passwords-install.json \
  "$HOME/.config/passwords-mcp/install-manifest.json"
```

Then select only the exact allowlisted profile:

```bash
passwords-mcp-keychain install \
  --profile github-production
```

The helper fetches the exact Nextcloud entry, writes its password directly to
the selected OS credential store, verifies the stored value, and returns only:

```json
{"ok":true,"operation":"install","profile":"github-production","destination":{"service":"nc-passwords-mcp:github-production","account":"octocat"}}
```

## Environment variables

| Variable | Required | Description |
| --- | --- | --- |
| `NEXTCLOUD_URL` | yes | Credential-free base URL; HTTPS by default |
| `NEXTCLOUD_USER` | yes | Nextcloud username |
| `NEXTCLOUD_CREDENTIAL_SERVICE` | yes | Exact OS credential-store service |
| `NEXTCLOUD_CREDENTIAL_ACCOUNT` | yes | Exact OS credential-store account |
| `DEBUG` | no | Log method and path only |

`NEXTCLOUD_APP_PASSWORD` and `ALLOW_INSECURE_HTTP` are intentionally
unsupported.

## Development

```bash
pnpm install
pnpm test
pnpm lint
pnpm typecheck
pnpm build
```

Tests use canary secrets to assert that metadata, error results, command
arguments, manifests, and helper receipts do not expose credential values.

## License

MIT — see [LICENSE](LICENSE).
