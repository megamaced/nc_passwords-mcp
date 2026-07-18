# Changelog

## 0.1.0

Initial release.

- Read-only MCP server for the Nextcloud Passwords app.
- Tools: `ping`, `list_passwords`, `search_passwords`, `get_password`, `list_folders`, `get_folder`.
- Metadata-only listing/search; single-item secret reveal via `get_password`.
- Refuses to run against accounts with client-side encryption (CSE) enabled.
- HTTPS enforced by default; app-password Basic auth; session auto-renewal.
