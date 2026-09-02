// -----------------------------------------------------------------------------
// Nextcloud Passwords API models
//
// See the API reference at:
// https://git.mdns.eu/nextcloud/passwords/-/wikis/Developers/Api/Index
//
// Both read shapes (what list/show return) and the writable value types used
// to build create/update payloads are modelled here.
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
  /** Latest revision id. Passed back on update/delete for conflict safety. */
  revision: string;
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

// -----------------------------------------------------------------------------
// Custom fields
// -----------------------------------------------------------------------------

/**
 * The field types the Passwords app defines. `secret` fields hold password-
 * grade material, which is why custom fields never appear in list/search
 * results.
 */
export const CUSTOM_FIELD_TYPES = ['text', 'secret', 'email', 'url', 'file', 'data'] as const;

export type CustomFieldType = (typeof CUSTOM_FIELD_TYPES)[number];

/**
 * One user-defined field. The API stores these as a JSON string in
 * `Password.customFields`; this server accepts and emits them structured so a
 * caller can never write a malformed or oversized blob into that column.
 */
export interface CustomField {
  label: string;
  type: CustomFieldType;
  value: string;
}

/** Documented server-side limits on the custom fields column. */
export const CUSTOM_FIELD_LIMITS = {
  maxFields: 20,
  maxLabel: 48,
  maxValue: 320,
  /** Combined label+value budget for `data` fields. */
  maxDataCombined: 370,
  maxSerialized: 8192,
} as const;

/**
 * Serialize custom fields to the JSON string the API expects, enforcing the
 * documented limits first. Exceeding them server-side is rejected with an error
 * body this server deliberately never reads, so the check happens here where a
 * useful message can be produced.
 */
export function serializeCustomFields(fields: CustomField[]): string {
  const { maxFields, maxLabel, maxValue, maxDataCombined, maxSerialized } = CUSTOM_FIELD_LIMITS;
  if (fields.length > maxFields) {
    throw new CustomFieldError(
      `at most ${maxFields} custom fields are allowed, got ${fields.length}`,
    );
  }
  for (const field of fields) {
    if (!field.label) {
      throw new CustomFieldError('every custom field needs a non-empty label');
    }
    if (field.label.length > maxLabel) {
      throw new CustomFieldError(
        `custom field label "${field.label.slice(0, 16)}…" exceeds ${maxLabel} characters`,
      );
    }
    // Only lengths are reported — a `secret` field's value must not appear in
    // an error that travels back to the model.
    if (field.value.length > maxValue) {
      throw new CustomFieldError(
        `value of custom field "${field.label}" is ${field.value.length} characters, over the ${maxValue} limit`,
      );
    }
    if (field.type === 'data' && field.label.length + field.value.length > maxDataCombined) {
      throw new CustomFieldError(
        `data field "${field.label}" exceeds the combined ${maxDataCombined}-character label+value limit`,
      );
    }
  }
  const json = JSON.stringify(fields.map((f) => ({ label: f.label, type: f.type, value: f.value })));
  if (json.length > maxSerialized) {
    throw new CustomFieldError(
      `serialized custom fields are ${json.length} characters, over the ${maxSerialized} limit`,
    );
  }
  return json;
}

/** Raised when custom fields would violate a documented API limit. */
export class CustomFieldError extends Error {
  constructor(detail: string) {
    super(`Invalid custom fields: ${detail}.`);
    this.name = 'CustomFieldError';
  }
}

/** A folder as returned by `folder/list` / `folder/show`. */
export interface Folder {
  id: string;
  /** Latest revision id. Passed back on update/delete for conflict safety. */
  revision: string;
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
 * The subset of a {@link Folder} that list/get folder tools return.
 *
 * Folders hold no secret material today, so this is an allowlist for
 * robustness rather than confidentiality: it pins the emitted shape so a future
 * upstream field cannot start flowing into MCP results just because the server
 * began returning it.
 */
export interface FolderMeta {
  id: string;
  label: string;
  parent: string;
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

/** Project a {@link Folder} onto the fixed {@link FolderMeta} allowlist. */
export function toFolderMeta(f: Folder): FolderMeta {
  return {
    id: f.id,
    label: f.label,
    parent: f.parent,
    edited: f.edited,
    created: f.created,
    updated: f.updated,
    favorite: f.favorite,
    hidden: f.hidden,
    trashed: f.trashed,
  };
}
