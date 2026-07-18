import { createHash } from 'node:crypto';

import { HttpError, type PasswordsClient } from './http.js';
import type { Folder, Password } from './types.js';

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
}

export interface PasswordChanges {
  label?: string;
  password?: string;
  username?: string;
  url?: string;
  notes?: string;
  folder?: string;
  favorite?: boolean;
}

/** Build the create payload. cseType is pinned to 'none' (CSE unsupported). */
export function buildPasswordCreate(input: PasswordCreateInput): Record<string, unknown> {
  return {
    label: input.label,
    username: input.username ?? '',
    password: input.password,
    url: input.url ?? '',
    notes: input.notes ?? '',
    folder: input.folder,
    favorite: input.favorite ?? false,
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
    customFields: current.customFields,
    folder: changes.folder ?? current.folder,
    favorite: changes.favorite ?? current.favorite,
    hash: sha1(password),
    cseType: 'none',
  };
}

export interface FolderChanges {
  label?: string;
  parent?: string;
}

export function buildFolderUpdate(
  current: Folder,
  changes: FolderChanges,
): Record<string, unknown> {
  return {
    id: current.id,
    revision: current.revision,
    label: changes.label ?? current.label,
    parent: changes.parent ?? current.parent,
    cseType: 'none',
  };
}

// -----------------------------------------------------------------------------
// Writes
//
// Deletes are SOFT ONLY. The Passwords delete action permanently removes an
// item that is already trashed, so every delete here first fetches the record
// and refuses if it is already in the trash — this server can never hard-delete.
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
  return client.apiJson<WriteResult>('POST', '/password/create', buildPasswordCreate(input));
}

export async function updatePassword(
  client: PasswordsClient,
  id: string,
  changes: PasswordChanges,
): Promise<WriteResult> {
  const current = await showPassword(client, id);
  return client.apiJson<WriteResult>('PATCH', '/password/update', buildPasswordUpdate(current, changes));
}

export async function trashPassword(client: PasswordsClient, id: string): Promise<WriteResult> {
  const current = await showPassword(client, id);
  if (current.trashed) {
    throw new AlreadyTrashedError('password', id);
  }
  return client.apiJson<WriteResult>('DELETE', '/password/delete', {
    id,
    revision: current.revision,
  });
}

export async function createFolder(
  client: PasswordsClient,
  label: string,
  parent?: string,
): Promise<WriteResult> {
  return client.apiJson<WriteResult>('POST', '/folder/create', {
    label,
    parent,
    cseType: 'none',
  });
}

export async function updateFolder(
  client: PasswordsClient,
  id: string,
  changes: FolderChanges,
): Promise<WriteResult> {
  const current = await showFolder(client, id);
  return client.apiJson<WriteResult>('PATCH', '/folder/update', buildFolderUpdate(current, changes));
}

export async function trashFolder(client: PasswordsClient, id: string): Promise<WriteResult> {
  const current = await showFolder(client, id);
  if (current.trashed) {
    throw new AlreadyTrashedError('folder', id);
  }
  return client.apiJson<WriteResult>('DELETE', '/folder/delete', {
    id,
    revision: current.revision,
  });
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

// Re-exported so callers can narrow on it without importing from http.
export { HttpError };
