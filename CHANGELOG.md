# Changelog

## 0.3.0

Make the MCP surface permanently metadata-only and move secret transfer into an
out-of-band credential-store helper.

- Remove `get_password` and all create/update/delete MCP tools.
- Reject plaintext `NEXTCLOUD_APP_PASSWORD` configuration; resolve the
  Nextcloud app-password from an exact macOS Keychain or Linux Secret Service
  reference.
- Add `passwords-mcp-keychain install`, driven by a strict reference-only
  manifest at an OS-fixed, owner-only path, to copy one exact vault entry into
  the OS credential store without printing it.
- Replace remote response bodies and unexpected exception text with fixed MCP
  error codes.
- Require HTTPS for every connection and refuse redirects.
- Add canary-secret tests for tool registration, error redaction, manifests,
  command arguments, and helper receipts.

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
