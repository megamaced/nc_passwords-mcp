# Changelog

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
