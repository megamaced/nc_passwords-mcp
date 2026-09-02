import assert from 'node:assert/strict';
import { test } from 'node:test';

import type { Config } from './config.js';
import { PasswordsClient } from './http.js';
import { dispatchTool, listTools, type Context } from './tools.js';

const CONFIG: Config = {
  url: 'https://cloud.example.com',
  user: 'alice',
  password: 'aaaa-bbbb-cccc-dddd',
  allowInsecureHttp: false,
  readOnly: false,
};

function contextWith(readOnly: boolean, handler: (url: string) => Response): {
  ctx: Context;
  paths: string[];
} {
  const paths: string[] = [];
  globalThis.fetch = (async (input: string | URL | Request) => {
    const url = String(input);
    paths.push(url.replace(/^.*\/api\/1\.0/, ''));
    if (url.endsWith('/session/request')) return Response.json({});
    if (url.endsWith('/session/open')) {
      return new Response('{}', { headers: { 'X-API-SESSION': 'session-token' } });
    }
    return handler(url);
  }) as typeof fetch;

  return {
    paths,
    ctx: {
      client: new PasswordsClient(CONFIG),
      configSummary: 'https://cloud.example.com as alice',
      readOnly,
    },
  };
}

// -----------------------------------------------------------------------------
// Registry lookup
// -----------------------------------------------------------------------------

test('tool names inherited from Object.prototype are rejected, not dispatched', async () => {
  const { ctx } = contextWith(false, () => Response.json([]));

  // On a plain-object registry each of these resolves to a truthy inherited
  // member, sails past the unknown-tool check and crashes on `argsSchema`.
  for (const name of ['toString', 'constructor', '__proto__', 'hasOwnProperty', 'valueOf']) {
    const result = await dispatchTool(name, {}, ctx);
    assert.equal(result.isError, true, `${name} must be an error result, not a throw`);
    assert.match(
      (result.content as { text: string }[])[0]!.text,
      new RegExp(`Unknown tool: ${name.replace('__', '__')}`),
    );
  }
});

test('an ordinary unknown tool name still returns the same error result', async () => {
  const { ctx } = contextWith(false, () => Response.json([]));
  const result = await dispatchTool('no_such_tool', {}, ctx);
  assert.equal(result.isError, true);
  assert.match((result.content as { text: string }[])[0]!.text, /Unknown tool: no_such_tool/);
});

// -----------------------------------------------------------------------------
// ping
// -----------------------------------------------------------------------------

test('ping reports connectivity without ever listing passwords', async () => {
  const { ctx, paths } = contextWith(false, () => Response.json({ success: true }));

  const result = await dispatchTool('ping', {}, ctx);

  assert.notEqual(result.isError, true);
  assert.ok(!paths.includes('/password/list'), `ping must not read the vault: ${paths}`);
  assert.match((result.content as { text: string }[])[0]!.text, /OK — connected to/);
});

// -----------------------------------------------------------------------------
// read-only enforcement
// -----------------------------------------------------------------------------

test('read-only mode hides and refuses the restore tools too', async () => {
  const names = listTools(true).map((t) => t.name);
  assert.ok(!names.includes('restore_password'));
  assert.ok(!names.includes('restore_folder'));

  const { ctx } = contextWith(true, () => Response.json({}));
  for (const name of ['restore_password', 'restore_folder']) {
    const result = await dispatchTool(name, { id: 'x' }, ctx);
    assert.equal(result.isError, true);
    assert.match((result.content as { text: string }[])[0]!.text, /read-only mode/);
  }
});

test('restore refuses an item that is not in the trash', async () => {
  const { ctx } = contextWith(false, (url) =>
    url.endsWith('/password/show')
      ? Response.json({ id: 'p1', trashed: false, revision: 'r1' })
      : Response.json({}),
  );

  const result = await dispatchTool('restore_password', { id: 'p1' }, ctx);

  assert.equal(result.isError, true);
  assert.match((result.content as { text: string }[])[0]!.text, /not in the trash/);
});
