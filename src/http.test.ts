import assert from 'node:assert/strict';
import { afterEach, test } from 'node:test';

import type { Config } from './config.js';
import {
  HttpError,
  parseRetryAfter,
  PasswordsClient,
  WriteOutcomeUnknownError,
} from './http.js';

const CONFIG: Config = {
  url: 'https://cloud.example.com',
  user: 'alice',
  password: 'aaaa-bbbb-cccc-dddd',
  allowInsecureHttp: false,
  readOnly: false,
};

const realFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = realFetch;
});

interface RecordedCall {
  url: string;
  init: RequestInit;
}

/**
 * Stub global fetch, answering the session handshake so that `apiJson` can
 * reach the endpoint under test. Returns the recorded calls.
 */
function stubFetch(handler: (url: string) => Response): RecordedCall[] {
  const calls: RecordedCall[] = [];
  globalThis.fetch = (async (input: string | URL | Request, init: RequestInit = {}) => {
    const url = String(input);
    calls.push({ url, init });
    if (url.endsWith('/session/request')) {
      return Response.json({});
    }
    if (url.endsWith('/session/open')) {
      return new Response('{}', { headers: { 'X-API-SESSION': 'session-token' } });
    }
    return handler(url);
  }) as typeof fetch;
  return calls;
}

/** The API path of a recorded call, e.g. `/password/list`. */
function path(call: RecordedCall): string {
  return call.url.replace(/^.*\/api\/1\.0/, '');
}

function sessionHeaderOf(call: RecordedCall): string | undefined {
  return (call.init.headers as Record<string, string> | undefined)?.['X-API-SESSION'];
}

test('every request forbids redirects so auth headers cannot follow a Location', async () => {
  const calls = stubFetch(() => Response.json([]));
  const client = new PasswordsClient(CONFIG);

  await client.apiJson('GET', '/password/list');

  assert.ok(calls.length >= 3, 'expected the session handshake plus the API call');
  for (const call of calls) {
    assert.equal(
      call.init.redirect,
      'error',
      `${call.url} must be sent with redirect: 'error'`,
    );
  }
});

test('HttpError carries status and hint but never a response body', () => {
  const err = new HttpError(500, 'Internal Server Error');
  assert.equal(err.status, 500);
  assert.match(err.message, /HTTP 500 Internal Server Error/);
  assert.match(err.hint, /Server error/);
});

test('a failed request does not leak the response body into the thrown error', async () => {
  const leak = 'super-secret-value-from-an-error-body';
  stubFetch(() => new Response(leak, { status: 400, statusText: 'Bad Request' }));
  const client = new PasswordsClient(CONFIG);

  await assert.rejects(
    () => client.apiJson('POST', '/password/show', { id: 'abc' }),
    (err: unknown) => {
      assert.ok(err instanceof HttpError);
      assert.equal(err.status, 400);
      assert.ok(!err.message.includes(leak), 'response body must not reach the error message');
      return true;
    },
  );
});


// -----------------------------------------------------------------------------
// Session handling
// -----------------------------------------------------------------------------

test('session/close is sent as GET, the only verb the Passwords route accepts', async () => {
  const calls = stubFetch(() => Response.json([]));
  const client = new PasswordsClient(CONFIG);
  await client.apiJson('GET', '/password/list');

  await client.close();

  const closeCall = calls.find((c) => path(c) === '/session/close');
  assert.ok(closeCall, 'close must reach the server');
  assert.equal(closeCall.init.method, 'GET');
  assert.equal(sessionHeaderOf(closeCall), 'session-token');
});

test('concurrent first calls share one session handshake', async () => {
  const calls = stubFetch(() => Response.json([]));
  const client = new PasswordsClient(CONFIG);

  await Promise.all([
    client.apiJson('GET', '/password/list'),
    client.apiJson('GET', '/folder/list'),
  ]);

  const paths = calls.map(path);
  assert.equal(paths.filter((p) => p === '/session/request').length, 1);
  assert.equal(paths.filter((p) => p === '/session/open').length, 1);
  for (const call of calls.filter((c) => !c.url.includes('/session/'))) {
    assert.equal(sessionHeaderOf(call), 'session-token');
  }
});

test('the most recent X-API-SESSION header is replayed on the next request', async () => {
  const calls: RecordedCall[] = [];
  let apiCalls = 0;
  globalThis.fetch = (async (input: string | URL | Request, init: RequestInit = {}) => {
    const url = String(input);
    calls.push({ url, init });
    if (url.endsWith('/session/request')) return Response.json({});
    if (url.endsWith('/session/open')) {
      return new Response('{}', { headers: { 'X-API-SESSION': 's1' } });
    }
    // The server rotates the token on the first authenticated response.
    apiCalls += 1;
    return Response.json([], apiCalls === 1 ? { headers: { 'X-API-SESSION': 's2' } } : undefined);
  }) as typeof fetch;

  const client = new PasswordsClient(CONFIG);
  await client.apiJson('GET', '/password/list');
  await client.apiJson('GET', '/folder/list');

  const [first, second] = calls.filter((c) => !c.url.includes('/session/'));
  assert.ok(first && second, 'expected two authenticated calls');
  assert.equal(sessionHeaderOf(first), 's1', 'first call uses the token from session/open');
  assert.equal(sessionHeaderOf(second), 's2', 'second call must use the rotated token');
});

test('session/open carries the token seeded by session/request', async () => {
  const calls: RecordedCall[] = [];
  globalThis.fetch = (async (input: string | URL | Request, init: RequestInit = {}) => {
    const url = String(input);
    calls.push({ url, init });
    if (url.endsWith('/session/request')) {
      return Response.json({}, { headers: { 'X-API-SESSION': 'from-request' } });
    }
    if (url.endsWith('/session/open')) {
      return new Response('{}', { headers: { 'X-API-SESSION': 'from-open' } });
    }
    return Response.json([]);
  }) as typeof fetch;

  const client = new PasswordsClient(CONFIG);
  await client.apiJson('GET', '/password/list');

  const open = calls.find((c) => path(c) === '/session/open');
  assert.ok(open);
  assert.equal(sessionHeaderOf(open), 'from-request');
});

test('a 412 from the session middleware reopens the session and retries once', async () => {
  const calls: RecordedCall[] = [];
  let listAttempts = 0;
  globalThis.fetch = (async (input: string | URL | Request, init: RequestInit = {}) => {
    const url = String(input);
    calls.push({ url, init });
    if (url.endsWith('/session/request')) return Response.json({});
    if (url.endsWith('/session/open')) {
      return new Response('{}', { headers: { 'X-API-SESSION': `s${calls.length}` } });
    }
    listAttempts += 1;
    if (listAttempts === 1) {
      return new Response('nope', { status: 412, statusText: 'Precondition Failed' });
    }
    return Response.json([{ id: 'p1' }]);
  }) as typeof fetch;

  const client = new PasswordsClient(CONFIG);
  const result = await client.apiJson<unknown[]>('GET', '/password/list');

  assert.equal(result.length, 1);
  assert.equal(calls.map(path).filter((p) => p === '/session/open').length, 2);
});

// -----------------------------------------------------------------------------
// Retry policy
// -----------------------------------------------------------------------------

test('parseRetryAfter accepts only delta-seconds or an HTTP-date, and clamps', () => {
  assert.equal(parseRetryAfter(null), null);
  assert.equal(parseRetryAfter('  '), null);
  assert.equal(parseRetryAfter('2'), 2000);
  // parseInt would have accepted this as 120 seconds.
  assert.equal(parseRetryAfter('120junk'), null);
  assert.equal(parseRetryAfter('-5'), null);
  // A server-controlled value can never park a call past the clamp.
  assert.equal(parseRetryAfter('86400'), 30_000);
  const now = Date.parse('2026-01-01T00:00:00Z');
  assert.equal(parseRetryAfter('Thu, 01 Jan 2026 00:00:05 GMT', now), 5000);
  assert.equal(parseRetryAfter('Thu, 01 Jan 2027 00:00:00 GMT', now), 30_000);
  assert.equal(parseRetryAfter('Thu, 01 Jan 2025 00:00:00 GMT', now), 0);
});

test('a 5xx on a read is retried', async () => {
  let attempts = 0;
  const calls = stubFetch(() => {
    attempts += 1;
    if (attempts === 1) return new Response('boom', { status: 503, statusText: 'Unavailable' });
    return Response.json([{ id: 'p1' }]);
  });
  const client = new PasswordsClient(CONFIG);

  const result = await client.apiJson<unknown[]>('GET', '/password/list');

  assert.equal(result.length, 1);
  assert.equal(calls.map(path).filter((p) => p === '/password/list').length, 2);
});

test('a 5xx on a write is NOT retried and reports an unknown outcome', async () => {
  const calls = stubFetch(() => new Response('boom', { status: 502, statusText: 'Bad Gateway' }));
  const client = new PasswordsClient(CONFIG);

  await assert.rejects(
    () => client.apiJson('POST', '/password/create', { label: 'x' }, { mutation: true }),
    (err: unknown) => {
      assert.ok(err instanceof WriteOutcomeUnknownError);
      assert.match(err.message, /may or may not have been applied/);
      return true;
    },
  );

  // Exactly one create request — a retry could have duplicated the entry.
  assert.equal(calls.map(path).filter((p) => p === '/password/create').length, 1);
});

test('a 429 on a write is reported as-is, since the request was never processed', async () => {
  stubFetch(() => new Response('slow down', { status: 429, statusText: 'Too Many Requests' }));
  const client = new PasswordsClient(CONFIG);

  await assert.rejects(
    () => client.apiJson('PATCH', '/password/update', { id: 'x' }, { mutation: true }),
    (err: unknown) => {
      assert.ok(err instanceof HttpError, 'a rejected request is not an ambiguous outcome');
      assert.equal(err.status, 429);
      return true;
    },
  );
});

// -----------------------------------------------------------------------------
// ping must not touch the vault
// -----------------------------------------------------------------------------

test('checkConnectivity never requests the password list', async () => {
  const calls = stubFetch(() => Response.json({ success: true }));
  const client = new PasswordsClient(CONFIG);

  await client.checkConnectivity();

  const paths = calls.map(path);
  assert.ok(!paths.includes('/password/list'), 'a connectivity check must not read secrets');
  assert.ok(!paths.some((p) => p.startsWith('/password/')), `unexpected password call: ${paths}`);
  assert.ok(paths.includes('/session/keepalive'));
});
