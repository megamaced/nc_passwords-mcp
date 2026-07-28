import assert from 'node:assert/strict';
import { test } from 'node:test';

import type { Config } from './config.js';
import { CseUnsupportedError, HttpError, PasswordsClient } from './http.js';

const CONFIG: Config = {
  url: 'https://cloud.example.com',
  user: 'alice',
  credential: {
    service: 'nc-passwords-mcp:cloud.example.com',
    account: 'alice',
  },
};

test('PasswordsClient authenticates, opens a session, parses JSON, and clears input', async (t) => {
  const requests: Array<{ url: string; init?: RequestInit }> = [];
  t.mock.method(globalThis, 'fetch', async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    requests.push({ url, init });
    if (url.endsWith('/session/request')) {
      return new Response('{}', { status: 200 });
    }
    if (url.endsWith('/session/open')) {
      return new Response('', { status: 200, headers: { 'X-API-SESSION': 'opaque-session' } });
    }
    if (url.endsWith('/session/close')) {
      return new Response('', { status: 200 });
    }
    return new Response('[{"id":"one"}]', { status: 200 });
  });

  const appPassword = Buffer.from('canary-app-password');
  const client = new PasswordsClient(CONFIG, appPassword);
  assert.ok(appPassword.every((byte) => byte === 0));
  assert.deepEqual(await client.apiJson('GET', '/password/list'), [{ id: 'one' }]);
  await client.close();

  assert.equal(requests.length, 4);
  for (const request of requests) {
    const authorization = new Headers(request.init?.headers).get('Authorization');
    assert.match(authorization ?? '', /^Basic /);
    assert.ok(!authorization!.includes('canary-app-password'));
    assert.equal(request.init?.redirect, 'error');
  }
});

test('PasswordsClient rejects CSE challenges without returning response data', async (t) => {
  t.mock.method(globalThis, 'fetch', async () =>
    new Response('{"challenge":{"type":"secret"}}', { status: 200 }),
  );
  const client = new PasswordsClient(CONFIG, Buffer.from('app-password'));
  await assert.rejects(client.apiJson('GET', '/password/list'), CseUnsupportedError);
});

test('HttpError discards a secret-bearing response body', async (t) => {
  t.mock.method(globalThis, 'fetch', async () =>
    new Response('remote canary-secret response', {
      status: 400,
      statusText: 'Bad Request',
    }),
  );
  const client = new PasswordsClient(CONFIG, Buffer.from('app-password'));
  await assert.rejects(
    client.apiJson('GET', '/password/list'),
    (error: unknown) =>
      error instanceof HttpError &&
      error.status === 400 &&
      !error.message.includes('canary-secret'),
  );
});
