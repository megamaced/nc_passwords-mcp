import type { PasswordsClient } from './http.js';
import type { Folder, Password } from './types.js';

// -----------------------------------------------------------------------------
// Read-only Passwords API wrappers.
//
// Every function here is a GET or a show/find read. There is intentionally NO
// create / update / delete / restore wrapper anywhere in this project — the
// absence of write code is the primary safety boundary.
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
