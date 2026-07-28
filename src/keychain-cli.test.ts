import assert from 'node:assert/strict';
import { test } from 'node:test';

import { installProfile, parseCliArgs } from './keychain-cli.js';
import type { InstallManifest } from './install-manifest.js';

const MANIFEST: InstallManifest = {
  schema_version: 1,
  profiles: {
    github: {
      source_id: '00000000-0000-0000-0000-000000000001',
      destination: {
        service: 'nc-passwords-mcp:github',
        account: 'octocat',
      },
    },
  },
};

test('installProfile transfers the secret internally and returns metadata only', async () => {
  let received: Buffer | undefined;
  const receipt = await installProfile(
    MANIFEST,
    'github',
    async () => 'canary-secret',
    async (_destination, secret) => {
      received = secret;
      assert.equal(secret.toString('utf8'), 'canary-secret');
    },
  );

  assert.ok(received);
  assert.ok(received.every((byte) => byte === 0), 'secret buffer must be zeroed after storage');
  assert.ok(!JSON.stringify(receipt).includes('canary-secret'));
  assert.deepEqual(receipt, {
    ok: true,
    operation: 'install',
    profile: 'github',
    destination: {
      service: 'nc-passwords-mcp:github',
      account: 'octocat',
    },
  });
});

test('parseCliArgs accepts only install with one allowlisted profile name', () => {
  assert.deepEqual(
    parseCliArgs(['install', '--profile', 'github']),
    {
      profile: 'github',
    },
  );
  assert.throws(
    () => parseCliArgs(['install', '--manifest', '/tmp/attacker.json', '--profile', 'github']),
    /USAGE/,
  );
});

test('installProfile rejects inherited object property names', async () => {
  await assert.rejects(
    installProfile(
      MANIFEST,
      'toString',
      async () => 'must-not-run',
      async () => {
        throw new Error('must-not-run');
      },
    ),
    /PROFILE_NOT_FOUND/,
  );
});
