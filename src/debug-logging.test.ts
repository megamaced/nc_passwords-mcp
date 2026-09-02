// Canary for the "secrets never reach a log" guarantee, with debugging ON.
//
// DEBUG is captured when `http.js` is first evaluated, so it is set here before
// the dynamic import below. This file runs in its own process under
// `node --test`, so it cannot affect the other suites.
process.env.DEBUG = '1';

import assert from 'node:assert/strict';
import { afterEach, test } from 'node:test';

import type { Config } from './config.js';

const { HttpError, PasswordsClient } = await import('./http.js');

const CONFIG: Config = {
  url: 'https://cloud.example.com',
  user: 'alice',
  password: 'aaaa-bbbb-cccc-dddd',
  allowInsecureHttp: false,
  readOnly: false,
};

const realFetch = globalThis.fetch;
const realWrite = process.stderr.write.bind(process.stderr);

afterEach(() => {
  globalThis.fetch = realFetch;
  process.stderr.write = realWrite;
});

/** Capture everything written to stderr while `fn` runs. */
async function captureStderr(fn: () => Promise<void>): Promise<string> {
  let captured = '';
  process.stderr.write = ((chunk: string | Uint8Array) => {
    captured += typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8');
    return true;
  }) as typeof process.stderr.write;
  try {
    await fn();
  } finally {
    process.stderr.write = realWrite;
  }
  return captured;
}

// A Passwords error body can echo the request that failed, so this is exactly
// the shape of value that must never be logged or returned.
const LEAK = 'super-secret-value-from-an-error-body';

test('a failed request logs no part of the response body, even with DEBUG on', async () => {
  globalThis.fetch = (async (input: string | URL | Request) => {
    const url = String(input);
    if (url.endsWith('/session/request')) return Response.json({});
    if (url.endsWith('/session/open')) {
      return new Response('{}', { headers: { 'X-API-SESSION': 'session-token' } });
    }
    return new Response(JSON.stringify({ message: LEAK }), {
      status: 400,
      statusText: 'Bad Request',
    });
  }) as typeof fetch;

  const client = new PasswordsClient(CONFIG);
  let message = '';

  const logged = await captureStderr(async () => {
    try {
      await client.apiJson('POST', '/password/show', { id: 'abc' });
      assert.fail('expected the request to fail');
    } catch (err) {
      assert.ok(err instanceof HttpError);
      message = err.message;
    }
  });

  assert.ok(logged.length > 0, 'DEBUG should still produce diagnostics');
  assert.ok(!logged.includes(LEAK), `response body reached stderr: ${logged}`);
  assert.ok(!message.includes(LEAK), 'response body reached the MCP result');
  // What a debug line may say: the request label, the status and a correlation id.
  assert.match(logged, /POST \/password\/show/);
  assert.match(logged, /HTTP 400/);
  assert.match(message, /ref [0-9a-f]{8}/);
});

test('the session token is never written to the log', async () => {
  const token = 'session-token-that-must-not-be-logged';
  globalThis.fetch = (async (input: string | URL | Request) => {
    const url = String(input);
    if (url.endsWith('/session/request')) return Response.json({});
    if (url.endsWith('/session/open')) {
      return new Response('{}', { headers: { 'X-API-SESSION': token } });
    }
    return Response.json([]);
  }) as typeof fetch;

  const client = new PasswordsClient(CONFIG);
  const logged = await captureStderr(async () => {
    await client.apiJson('GET', '/password/list');
  });

  assert.ok(!logged.includes(token), `session token reached stderr: ${logged}`);
  assert.ok(!logged.includes(CONFIG.password), 'app-password reached stderr');
});
