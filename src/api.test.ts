import assert from 'node:assert/strict';
import { test } from 'node:test';

import { loadConfig } from './config.js';
import { passwordMatches } from './api.js';
import { toPasswordMeta, type Password } from './types.js';

const BASE_ENV = {
  NEXTCLOUD_URL: 'https://cloud.example.com',
  NEXTCLOUD_USER: 'alice',
  NEXTCLOUD_APP_PASSWORD: 'aaaa-bbbb-cccc-dddd',
} as NodeJS.ProcessEnv;

// -----------------------------------------------------------------------------
// config
// -----------------------------------------------------------------------------

test('loadConfig requires all three variables', () => {
  assert.throws(() => loadConfig({} as NodeJS.ProcessEnv), /Missing required/);
  assert.throws(
    () => loadConfig({ NEXTCLOUD_URL: 'https://x', NEXTCLOUD_USER: 'a' } as NodeJS.ProcessEnv),
    /NEXTCLOUD_APP_PASSWORD/,
  );
});

test('loadConfig strips trailing slashes from the URL', () => {
  const cfg = loadConfig({ ...BASE_ENV, NEXTCLOUD_URL: 'https://cloud.example.com///' });
  assert.equal(cfg.url, 'https://cloud.example.com');
});

test('loadConfig refuses http:// by default', () => {
  assert.throws(
    () => loadConfig({ ...BASE_ENV, NEXTCLOUD_URL: 'http://cloud.example.com' }),
    /Refusing to send credentials over plaintext/,
  );
});

test('loadConfig allows http:// only with the explicit opt-in', () => {
  const cfg = loadConfig({
    ...BASE_ENV,
    NEXTCLOUD_URL: 'http://localhost:8080',
    ALLOW_INSECURE_HTTP: 'true',
  });
  assert.equal(cfg.url, 'http://localhost:8080');
  assert.equal(cfg.allowInsecureHttp, true);
});

test('loadConfig rejects non-http(s) schemes', () => {
  assert.throws(
    () => loadConfig({ ...BASE_ENV, NEXTCLOUD_URL: 'ftp://cloud.example.com' }),
    /must use http or https/,
  );
});

// -----------------------------------------------------------------------------
// secret stripping — the core safety guarantee
// -----------------------------------------------------------------------------

function samplePassword(overrides: Partial<Password> = {}): Password {
  return {
    id: 'abc123',
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
