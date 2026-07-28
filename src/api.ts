import type { PasswordsClient } from './http.js';
import type { Folder, Password } from './types.js';

/**
 * The upstream list endpoint returns full records. MCP callers must project
 * every result through `toPasswordMeta` before serialization.
 */
export function listPasswords(client: PasswordsClient): Promise<Password[]> {
  return client.apiJson<Password[]>('GET', '/password/list');
}

/**
 * Internal-only secret fetch used by the out-of-band credential-store helper.
 * This function must never be registered as an MCP tool.
 */
export function showPassword(client: PasswordsClient, id: string): Promise<Password> {
  return client.apiJson<Password>('POST', '/password/show', { id });
}

export function listFolders(client: PasswordsClient): Promise<Folder[]> {
  return client.apiJson<Folder[]>('GET', '/folder/list');
}

export function showFolder(client: PasswordsClient, id: string): Promise<Folder> {
  return client.apiJson<Folder>('POST', '/folder/show', { id });
}

/** Search only identifying metadata; never secret-bearing fields. */
export function passwordMatches(p: Password, needle: string): boolean {
  const q = needle.trim().toLowerCase();
  if (!q) return true;
  return (
    p.label.toLowerCase().includes(q) ||
    p.username.toLowerCase().includes(q) ||
    p.url.toLowerCase().includes(q)
  );
}
