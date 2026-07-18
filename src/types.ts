// -----------------------------------------------------------------------------
// Nextcloud Passwords API models
//
// See the API reference at:
// https://git.mdns.eu/nextcloud/passwords/-/wikis/Developers/Api/Index
//
// This server is READ-ONLY. It never sends create/update/delete requests, so
// only the read shapes are modelled here.
// -----------------------------------------------------------------------------

/**
 * A password entry as returned by `password/list` / `password/show`.
 *
 * IMPORTANT: when the account has client-side encryption (CSE) disabled
 * (`cseType === 'none'`, the only mode this server supports), the server
 * returns the `password`, `username`, `notes` and `customFields` fields
 * already decrypted. They are therefore SECRET-BEARING and must never be
 * emitted by list/search tools — see `toPasswordMeta`.
 */
export interface Password {
  id: string;
  label: string;
  username: string;
  /** The plaintext secret (CSE disabled). Secret-bearing. */
  password: string;
  url: string;
  /** Free-text notes. May contain secrets. Secret-bearing. */
  notes: string;
  /** JSON-encoded array of custom fields. May contain secret-typed fields. */
  customFields: string;
  /** Client-side encryption type. This server requires `'none'`. */
  cseType: string;
  /** Server-side encryption type, e.g. `'SSEv1r2'`. */
  sseType: string;
  /** SHA-1 hash of the password (used by the app for duplicate detection). */
  hash: string;
  status: number;
  statusCode: string;
  folder: string;
  edited: number;
  created: number;
  updated: number;
  favorite: boolean;
  shared: boolean;
  hidden: boolean;
  trashed: boolean;
}

/**
 * The non-secret subset of a {@link Password} that is safe to return from
 * list/search tools. Deliberately excludes `password`, `notes` and
 * `customFields`.
 */
export interface PasswordMeta {
  id: string;
  label: string;
  username: string;
  url: string;
  folder: string;
  favorite: boolean;
  shared: boolean;
  status: number;
  statusCode: string;
  edited: number;
  updated: number;
}

/** A folder as returned by `folder/list` / `folder/show`. */
export interface Folder {
  id: string;
  label: string;
  parent: string;
  cseType: string;
  sseType: string;
  edited: number;
  created: number;
  updated: number;
  favorite: boolean;
  hidden: boolean;
  trashed: boolean;
}

/**
 * Project every {@link Password} down to its non-secret {@link PasswordMeta}.
 * This is the single choke point that keeps plaintext secrets out of list and
 * search results — only the explicit `get_password` tool bypasses it.
 */
export function toPasswordMeta(p: Password): PasswordMeta {
  return {
    id: p.id,
    label: p.label,
    username: p.username,
    url: p.url,
    folder: p.folder,
    favorite: p.favorite,
    shared: p.shared,
    status: p.status,
    statusCode: p.statusCode,
    edited: p.edited,
    updated: p.updated,
  };
}
