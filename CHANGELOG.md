# Changelog

## 0.3.0

Audit fixes ([issues #2–#15](https://github.com/megamaced/nc_passwords-mcp/issues)),
plus two new tools. No config changes required.

### Fixed

- **Updates no longer reset hidden/favorite state.** The Passwords API defaults
  `hidden` (passwords) and `hidden` + `favorite` (folders) to `false` on update,
  so renaming a hidden entry silently unhid it. Both are now carried across
  every update. (#3)
- **`session/close` is sent as `GET`.** The upstream route is GET-only, so the
  previous `POST` 404'd and left the session open until it expired. (#4)
- **One session per client, not one per concurrent call.** The in-flight
  handshake is memoized; `ping` previously opened two sessions it could never
  close, against a 6-per-minute rate limit. (#5)
- **The most recent `X-API-SESSION` is replayed.** The token is now captured
  from every response, as the Session API requires, instead of only from
  `session/open`. `session/open` carries the token seeded by `session/request`,
  and `412` joins `401`/`403` as a stale-session signal. (#6)
- **Vault writes are never retried.** A 5xx or network failure on a
  create/update/delete now raises `WriteOutcomeUnknownError` rather than
  replaying a request that may already have been committed. Reads still retry.
  (#7)
- **`Retry-After` can no longer stall a call.** It is parsed strictly
  (`120junk` is rejected), clamped to 30s, and used *instead of* the
  exponential backoff rather than in addition to it. Backoff is jittered,
  failed responses are drained before any wait, and waits abort on shutdown. (#8)
- **Response bodies are never read.** `debugErrorBody` wrote up to 200
  characters of every failed response to stderr under `DEBUG`; bodies are now
  drained and discarded, and failures are identified by status plus a random
  correlation id. (#9)
- **Inherited object keys are rejected.** The tool registry is a `Map`, so
  `toString`, `constructor` and `__proto__` return a normal "Unknown tool"
  result instead of throwing out of the request handler. (#2)
- **`ping` no longer downloads the vault.** It used `password/list`, whose
  default model carries every decrypted password, note and custom field, to
  produce a count. It now proves connectivity with the session handshake and
  `session/keepalive`, and reports no counts. (#13)

### Added

- **`restore_password` and `restore_folder`** complete the reversible-delete
  workflow. Both lift an item out of the trash only — they never roll an entry
  back to an earlier revision — and refuse an item that is not trashed. (#15)
- **MCP annotations on every tool**, so clients can distinguish metadata reads,
  secret disclosure, additive creates and soft deletes in their risk UI. (#11)
- **More writable fields**: `hidden` and `customFields` on password
  create/update, `hidden` and `favorite` on folder create/update. Custom fields
  are structured input validated against the documented API limits, not an
  opaque JSON string. Tags remain out of scope — there are no tag-discovery
  tools, and a partial list would silently drop tags. (#14)

### Security / CI

- **Dependencies refreshed** to clear 16 advisories (7 high, 8 moderate) in the
  locked graph, within the existing semver ranges; `pnpm audit --prod` now runs
  in CI. (#10)
- **GitHub Actions pinned to commit SHAs** with an explicit
  `permissions: contents: read`. (#12)

## 0.2.1

Hardening only — no tool changes, no config changes required.

- **Redirects are refused.** Requests now use `redirect: 'error'`. Previously a
  redirect response would have been followed, handing the Basic auth header
  (and therefore the app-password) to whatever host the `Location` named.
- **Response bodies no longer reach the MCP client.** `HttpError` carries the
  status and a static hint only; a failed response body is logged to stderr
  under `DEBUG=1` instead of being interpolated into the error the model sees.
- **Folder results go through an allowlist.** New `toFolderMeta` pins the shape
  emitted by `list_folders` / `get_folder`, matching the existing
  `toPasswordMeta` choke point, so an unvetted future upstream field cannot
  start flowing into results on its own.
- **Config validation tightened.** `NEXTCLOUD_URL` now rejects embedded
  credentials, query strings and fragments; `NEXTCLOUD_USER` rejects colons and
  control characters (which would split the Basic credential pair or allow
  header injection); and `ALLOW_INSECURE_HTTP` is now honoured only for a
  loopback host, never a remote one.

Adapted from the hardening in [PR #1](https://github.com/megamaced/nc_passwords-mcp/pull/1);
that PR's removal of `get_password` and the write tools is not included.

## 0.2.0

Add write capabilities.

- New tools: `create_password`, `update_password`, `delete_password`,
  `create_folder`, `update_folder`, `delete_folder` (12 tools total).
- Deletes are soft/reversible only — they refuse an already-trashed item, so the
  server can never permanently delete. Updates fetch-merge and pass the current
  revision, so they can't blank fields or clobber concurrent edits.
- New `PASSWORDS_READONLY=true` env var to expose only the read tools and refuse
  all writes.

## 0.1.0

Initial release.

- Read-only MCP server for the Nextcloud Passwords app.
- Tools: `ping`, `list_passwords`, `search_passwords`, `get_password`, `list_folders`, `get_folder`.
- Metadata-only listing/search; single-item secret reveal via `get_password`.
- Refuses to run against accounts with client-side encryption (CSE) enabled.
- HTTPS enforced by default; app-password Basic auth; session auto-renewal.
