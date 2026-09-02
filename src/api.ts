import { createHash } from 'node:crypto';

import { HttpError, type PasswordsClient } from './http.js';
import { serializeCustomFields, type CustomField, type Folder, type Password } from './types.js';

/** Marks a call as a vault mutation: no automatic retry — see `http.ts`. */
const MUTATION = { mutation: true } as const;

// -----------------------------------------------------------------------------
// Reads
// -----------------------------------------------------------------------------

/** List all (non-trashed) passwords. Returns full records — callers that emit
 * results to the model must project through `toPasswordMeta` first. */
export function listPasswords(client: PasswordsClient): Promise<Password[]> {
  return client.apiJson<Password[]>('GET', '/password/list');
}

/** Fetch a single password by id, including its plaintext secret. */
export function showPassword(client: PasswordsClient, id: string): Promise<Password> {
  return client.apiJson<Password>('POST', '/password/show', { id });
}

/** List all (non-trashed) folders. */
export function listFolders(client: PasswordsClient): Promise<Folder[]> {
  return client.apiJson<Folder[]>('GET', '/folder/list');
}

/** Fetch a single folder by id. */
export function showFolder(client: PasswordsClient, id: string): Promise<Folder> {
  return client.apiJson<Folder>('POST', '/folder/show', { id });
}

/**
 * Case-insensitive substring match over a password's non-secret, identifying
 * fields only (label, username, url). Deliberately does NOT match against the
 * `password`, `notes` or `customFields` fields so that secret material can
 * never influence — or be inferred from — search behaviour.
 */
export function passwordMatches(p: Password, needle: string): boolean {
  const q = needle.trim().toLowerCase();
  if (!q) return true;
  return (
    p.label.toLowerCase().includes(q) ||
    p.username.toLowerCase().includes(q) ||
    p.url.toLowerCase().includes(q)
  );
}

// -----------------------------------------------------------------------------
// Write payload builders (pure — unit tested)
// -----------------------------------------------------------------------------

/** SHA-1 hex digest, as the Passwords app expects in the `hash` field. */
export function sha1(text: string): string {
  return createHash('sha1').update(text, 'utf8').digest('hex');
}

export interface PasswordCreateInput {
  label: string;
  password: string;
  username?: string;
  url?: string;
  notes?: string;
  folder?: string;
  favorite?: boolean;
  hidden?: boolean;
  customFields?: CustomField[];
}

export interface PasswordChanges {
  label?: string;
  password?: string;
  username?: string;
  url?: string;
  notes?: string;
  folder?: string;
  favorite?: boolean;
  hidden?: boolean;
  customFields?: CustomField[];
}

/** Build the create payload. cseType is pinned to 'none' (CSE unsupported). */
export function buildPasswordCreate(input: PasswordCreateInput): Record<string, unknown> {
  return {
    label: input.label,
    username: input.username ?? '',
    password: input.password,
    url: input.url ?? '',
    notes: input.notes ?? '',
    customFields: serializeCustomFields(input.customFields ?? []),
    folder: input.folder,
    favorite: input.favorite ?? false,
    hidden: input.hidden ?? false,
    hash: sha1(input.password),
    cseType: 'none',
  };
}

/**
 * Build the update payload by merging requested `changes` onto the CURRENT
 * record. The Passwords update action requires `password`, `label` and `hash`
 * even for a one-field edit, so every unspecified field is carried over from
 * `current` — this is what prevents an update from silently blanking data.
 * The current `revision` is included so the server rejects the write if the
 * record changed underneath us.
 *
 * `hidden` must be carried explicitly: the update action defaults it to
 * `false`, so omitting it would un-hide a hidden entry as a side effect of
 * editing an unrelated field. `tags` is deliberately absent — the API leaves
 * tags untouched when the field is missing, and this server has no
 * tag-discovery tools with which to send a meaningful list.
 */
export function buildPasswordUpdate(
  current: Password,
  changes: PasswordChanges,
): Record<string, unknown> {
  const password = changes.password ?? current.password;
  return {
    id: current.id,
    revision: current.revision,
    label: changes.label ?? current.label,
    username: changes.username ?? current.username,
    password,
    url: changes.url ?? current.url,
    notes: changes.notes ?? current.notes,
    customFields:
      changes.customFields !== undefined
        ? serializeCustomFields(changes.customFields)
        : current.customFields,
    folder: changes.folder ?? current.folder,
    favorite: changes.favorite ?? current.favorite,
    hidden: changes.hidden ?? current.hidden,
    hash: sha1(password),
    cseType: 'none',
  };
}

export interface FolderChanges {
  label?: string;
  parent?: string;
  favorite?: boolean;
  hidden?: boolean;
}

/**
 * Build the folder update payload. As with passwords, `hidden` and `favorite`
 * default to `false` in the update action, so both are carried over from the
 * current record unless the caller is deliberately changing them — otherwise a
 * rename would silently un-hide the folder and everything under it.
 */
export function buildFolderUpdate(
  current: Folder,
  changes: FolderChanges,
): Record<string, unknown> {
  return {
    id: current.id,
    revision: current.revision,
    label: changes.label ?? current.label,
    parent: changes.parent ?? current.parent,
    favorite: changes.favorite ?? current.favorite,
    hidden: changes.hidden ?? current.hidden,
    cseType: 'none',
  };
}

// -----------------------------------------------------------------------------
// Writes
//
// Deletes are SOFT ONLY. The Passwords delete action permanently removes an
// item that is already trashed, so every delete here first fetches the record
// and refuses if it is already in the trash — this server can never hard-delete.
// `restorePassword` / `restoreFolder` are the matching undo.
//
// Every call below passes MUTATION, which disables automatic retry: a replayed
// create would duplicate an entry and a replayed revision-guarded write would
// report a false conflict. See `WriteOutcomeUnknownError` in `http.ts`.
// -----------------------------------------------------------------------------

/** Result of a write, echoing the ids the server returns. */
export interface WriteResult {
  id?: string;
  revision?: string;
}

export async function createPassword(
  client: PasswordsClient,
  input: PasswordCreateInput,
): Promise<WriteResult> {
  return client.apiJson<WriteResult>(
    'POST',
    '/password/create',
    buildPasswordCreate(input),
    MUTATION,
  );
}

export async function updatePassword(
  client: PasswordsClient,
  id: string,
  changes: PasswordChanges,
): Promise<WriteResult> {
  const current = await showPassword(client, id);
  return client.apiJson<WriteResult>(
    'PATCH',
    '/password/update',
    buildPasswordUpdate(current, changes),
    MUTATION,
  );
}

export async function trashPassword(client: PasswordsClient, id: string): Promise<WriteResult> {
  const current = await showPassword(client, id);
  if (current.trashed) {
    throw new AlreadyTrashedError('password', id);
  }
  return client.apiJson<WriteResult>(
    'DELETE',
    '/password/delete',
    { id, revision: current.revision },
    MUTATION,
  );
}

/**
 * Take a password out of the trash. Sent without a `revision`, which is what
 * makes the API restore from trash rather than roll the entry back to an
 * arbitrary earlier state — this server never rewinds content the user did not
 * ask it to. Refuses when the entry is not trashed, because the API would
 * silently do nothing.
 */
export async function restorePassword(
  client: PasswordsClient,
  id: string,
): Promise<WriteResult> {
  const current = await showPassword(client, id);
  if (!current.trashed) {
    throw new NotTrashedError('password', id);
  }
  return client.apiJson<WriteResult>('PATCH', '/password/restore', { id }, MUTATION);
}

export interface FolderCreateInput {
  label: string;
  parent?: string;
  favorite?: boolean;
  hidden?: boolean;
}

export async function createFolder(
  client: PasswordsClient,
  input: FolderCreateInput,
): Promise<WriteResult> {
  return client.apiJson<WriteResult>(
    'POST',
    '/folder/create',
    {
      label: input.label,
      parent: input.parent,
      favorite: input.favorite ?? false,
      hidden: input.hidden ?? false,
      cseType: 'none',
    },
    MUTATION,
  );
}

export async function updateFolder(
  client: PasswordsClient,
  id: string,
  changes: FolderChanges,
): Promise<WriteResult> {
  const current = await showFolder(client, id);
  return client.apiJson<WriteResult>(
    'PATCH',
    '/folder/update',
    buildFolderUpdate(current, changes),
    MUTATION,
  );
}

export async function trashFolder(client: PasswordsClient, id: string): Promise<WriteResult> {
  const current = await showFolder(client, id);
  if (current.trashed) {
    throw new AlreadyTrashedError('folder', id);
  }
  return client.apiJson<WriteResult>(
    'DELETE',
    '/folder/delete',
    { id, revision: current.revision },
    MUTATION,
  );
}

/** Take a folder out of the trash. See {@link restorePassword}. */
export async function restoreFolder(client: PasswordsClient, id: string): Promise<WriteResult> {
  const current = await showFolder(client, id);
  if (!current.trashed) {
    throw new NotTrashedError('folder', id);
  }
  return client.apiJson<WriteResult>('PATCH', '/folder/restore', { id }, MUTATION);
}

/** Raised when a delete would be permanent (item is already trashed). */
export class AlreadyTrashedError extends Error {
  constructor(kind: 'password' | 'folder', id: string) {
    super(
      `Refusing to delete ${kind} ${id}: it is already in the trash, and deleting ` +
        `it again would permanently and irreversibly remove it. This server only ` +
        `performs reversible (soft) deletes — use the Passwords app to empty the trash.`,
    );
    this.name = 'AlreadyTrashedError';
  }
}

/** Raised when a restore would be a no-op (the item is not in the trash). */
export class NotTrashedError extends Error {
  constructor(kind: 'password' | 'folder', id: string) {
    super(
      `Nothing to restore: ${kind} ${id} is not in the trash. Restoring an item ` +
        `that is not trashed does nothing on the server, so this is reported ` +
        `rather than silently succeeding.`,
    );
    this.name = 'NotTrashedError';
  }
}

// Re-exported so callers can narrow on it without importing from http.
export { HttpError };
