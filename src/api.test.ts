import assert from 'node:assert/strict';
import { test } from 'node:test';

import { loadConfig } from './config.js';
import { passwordMatches } from './api.js';
import type { PasswordsClient } from './http.js';
import { dispatchTool, listTools } from './tools.js';
import { toFolderMeta, toPasswordMeta, type Folder, type Password } from './types.js';

const BASE_ENV = {
  NEXTCLOUD_URL: 'https://cloud.example.com',
  NEXTCLOUD_USER: 'alice',
  NEXTCLOUD_CREDENTIAL_SERVICE: 'nc-passwords-mcp:cloud.example.com',
  NEXTCLOUD_CREDENTIAL_ACCOUNT: 'alice',
} as NodeJS.ProcessEnv;

// -----------------------------------------------------------------------------
// config
// -----------------------------------------------------------------------------

test('loadConfig requires URL, user, and credential reference variables', () => {
  assert.throws(() => loadConfig({} as NodeJS.ProcessEnv), /Missing required/);
  assert.throws(
    () => loadConfig({ NEXTCLOUD_URL: 'https://x', NEXTCLOUD_USER: 'a' } as NodeJS.ProcessEnv),
    /NEXTCLOUD_CREDENTIAL_SERVICE/,
  );
});

test('loadConfig rejects a plaintext app-password environment variable', () => {
  assert.throws(
    () =>
      loadConfig({
        ...BASE_ENV,
        NEXTCLOUD_APP_PASSWORD: 'must-not-be-accepted',
      }),
    /plaintext credential environment variables are forbidden/i,
  );
});

test('loadConfig strips trailing slashes from the URL', () => {
  const cfg = loadConfig({ ...BASE_ENV, NEXTCLOUD_URL: 'https://cloud.example.com///' });
  assert.equal(cfg.url, 'https://cloud.example.com');
});

test('loadConfig rejects URL credentials, query strings, and fragments', () => {
  for (const url of [
    'https://alice:secret@cloud.example.com',
    'https://cloud.example.com?token=secret',
    'https://cloud.example.com#secret',
  ]) {
    assert.throws(
      () => loadConfig({ ...BASE_ENV, NEXTCLOUD_URL: url }),
      /credential-free HTTPS origin/i,
    );
  }
});

test('loadConfig refuses http:// even when the legacy override is set', () => {
  assert.throws(
    () =>
      loadConfig({
        ...BASE_ENV,
        NEXTCLOUD_URL: 'http://localhost:8080',
        ALLOW_INSECURE_HTTP: 'true',
      }),
    /must use https/i,
  );
});

test('loadConfig rejects non-http(s) schemes', () => {
  assert.throws(
    () => loadConfig({ ...BASE_ENV, NEXTCLOUD_URL: 'ftp://cloud.example.com' }),
    /must use https/i,
  );
});

// -----------------------------------------------------------------------------
// secret stripping — the core safety guarantee
// -----------------------------------------------------------------------------

function samplePassword(overrides: Partial<Password> = {}): Password {
  return {
    id: 'abc123',
    revision: 'rev-1',
    label: 'GitHub',
    username: 'octocat',
    password: 'super-secret-value',
    url: 'https://github.com',
    notes: 'recovery codes: 1234-5678',
    customFields: '[{"label":"PIN","type":"secret","value":"9999"}]',
    cseType: 'none',
    sseType: 'SSEv1r2',
    hash: 'deadbeef',
    status: 0,
    statusCode: 'GOOD',
    folder: '00000000-0000-0000-0000-000000000000',
    edited: 1,
    created: 1,
    updated: 1,
    favorite: false,
    shared: false,
    hidden: false,
    trashed: false,
    ...overrides,
  };
}

test('toPasswordMeta omits every secret-bearing field', () => {
  const meta = toPasswordMeta(samplePassword());
  const serialised = JSON.stringify(meta);
  assert.ok(!('password' in meta), 'password must not be present');
  assert.ok(!('notes' in meta), 'notes must not be present');
  assert.ok(!('customFields' in meta), 'customFields must not be present');
  assert.ok(!('hash' in meta), 'hash must not be present');
  assert.ok(!serialised.includes('super-secret-value'));
  assert.ok(!serialised.includes('recovery codes'));
  assert.ok(!serialised.includes('9999'));
});

test('toPasswordMeta keeps identifying metadata', () => {
  const meta = toPasswordMeta(samplePassword());
  assert.equal(meta.id, 'abc123');
  assert.equal(meta.label, 'GitHub');
  assert.equal(meta.username, 'octocat');
  assert.equal(meta.url, 'https://github.com');
});

test('toFolderMeta omits unknown secret-bearing runtime fields', () => {
  const folder = {
    id: 'folder-1',
    revision: 'revision-1',
    label: 'Production',
    parent: 'root',
    cseType: 'none',
    sseType: 'SSEv1r2',
    edited: 1,
    created: 1,
    updated: 1,
    favorite: false,
    hidden: false,
    trashed: false,
    password: 'folder-canary-secret',
  } as Folder & { password: string };

  const meta = toFolderMeta(folder);
  assert.ok(!JSON.stringify(meta).includes('folder-canary-secret'));
  assert.deepEqual(meta, {
    id: 'folder-1',
    label: 'Production',
    parent: 'root',
    edited: 1,
    created: 1,
    updated: 1,
    favorite: false,
    hidden: false,
    trashed: false,
  });
});

// -----------------------------------------------------------------------------
// search only matches non-secret fields
// -----------------------------------------------------------------------------

test('passwordMatches matches label, username and url case-insensitively', () => {
  const p = samplePassword();
  assert.ok(passwordMatches(p, 'github'));
  assert.ok(passwordMatches(p, 'OCTOCAT'));
  assert.ok(passwordMatches(p, 'github.com'));
});

test('passwordMatches never matches against the secret, notes or custom fields', () => {
  const p = samplePassword();
  assert.ok(!passwordMatches(p, 'super-secret-value'));
  assert.ok(!passwordMatches(p, 'recovery codes'));
  assert.ok(!passwordMatches(p, '9999'));
});

test('passwordMatches treats an empty query as match-all', () => {
  assert.ok(passwordMatches(samplePassword(), '   '));
});

// -----------------------------------------------------------------------------
// metadata-only tool surface
// -----------------------------------------------------------------------------

test('listTools exposes metadata tools only', () => {
  assert.deepEqual(
    listTools().map((tool) => tool.name),
    ['ping', 'list_passwords', 'search_passwords', 'list_folders', 'get_folder'],
  );
});

test('dispatch replaces unexpected secret-bearing errors with a fixed code', async () => {
  const client = {
    apiJson: async () => {
      throw new Error('remote body contained canary-secret');
    },
  } as unknown as PasswordsClient;
  const result = await dispatchTool('list_passwords', {}, {
    client,
    configSummary: 'https://cloud.example.com as alice',
  });
  const serialised = JSON.stringify(result);
  assert.ok(!serialised.includes('canary-secret'));
  assert.match(serialised, /OPERATION_FAILED/);
});

test('dispatch rejects inherited registry names with the fixed unknown-tool code', async () => {
  const result = await dispatchTool('constructor', {}, {
    client: {} as PasswordsClient,
    configSummary: 'https://cloud.example.com as alice',
  });
  assert.match(JSON.stringify(result), /UNKNOWN_TOOL/);
});

test('folder tools apply the folder metadata allowlist', async () => {
  const folder = {
    id: 'folder-1',
    revision: 'revision-1',
    label: 'Production',
    parent: 'root',
    cseType: 'none',
    sseType: 'SSEv1r2',
    edited: 1,
    created: 1,
    updated: 1,
    favorite: false,
    hidden: false,
    trashed: false,
    password: 'folder-canary-secret',
  };
  const client = {
    apiJson: async (_method: string, path: string) =>
      path === '/folder/list' ? [folder] : folder,
  } as unknown as PasswordsClient;

  for (const [tool, args] of [
    ['list_folders', {}],
    ['get_folder', { id: 'folder-1' }],
  ] as const) {
    const result = await dispatchTool(tool, args, {
      client,
      configSummary: 'https://cloud.example.com as alice',
    });
    assert.ok(!JSON.stringify(result).includes('folder-canary-secret'));
  }
});
