import assert from 'node:assert/strict';
import { chmod, mkdir, mkdtemp, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import {
  defaultInstallManifestPath,
  loadInstallManifest,
  parseInstallManifest,
} from './install-manifest.js';

test('manifest parsing normalizes profile order and preserves references only', () => {
  const manifest = parseInstallManifest({
    schema_version: 1,
    profiles: {
      zeta: {
        source_id: '00000000-0000-0000-0000-000000000002',
        destination: {
          service: 'nc-passwords-mcp:zeta',
          account: 'zeta',
        },
      },
      alpha: {
        source_id: '00000000-0000-0000-0000-000000000001',
        destination: {
          service: 'nc-passwords-mcp:alpha',
          account: 'alpha',
        },
      },
    },
  });

  assert.deepEqual(Object.keys(manifest.profiles), ['alpha', 'zeta']);
  assert.deepEqual(Object.keys(manifest.profiles.alpha!), ['source_id', 'destination']);
  assert.deepEqual(Object.keys(manifest.profiles.alpha!.destination), ['service', 'account']);
});

test('manifest parsing rejects extra properties and malformed identifiers', () => {
  assert.throws(
    () =>
      parseInstallManifest({
        schema_version: 1,
        profiles: {
          alpha: {
            source_id: 'valid-id',
            destination: {
              service: 'nc-passwords-mcp:alpha',
              account: 'alpha',
            },
            password: 'must-not-be-accepted',
          },
        },
      }),
    /unsupported profile properties/i,
  );

  assert.throws(
    () =>
      parseInstallManifest({
        schema_version: 1,
        profiles: {
          '../alpha': {
            source_id: 'valid-id',
            destination: {
              service: 'nc-passwords-mcp:alpha',
              account: 'alpha',
            },
          },
        },
      }),
    /invalid profile name/i,
  );
});

test('default manifest path is fixed under the effective user home', () => {
  assert.equal(
    defaultInstallManifestPath('darwin', '/Users/alice'),
    '/Users/alice/Library/Application Support/passwords-mcp/install-manifest.json',
  );
  assert.equal(
    defaultInstallManifestPath('linux', '/home/alice'),
    '/home/alice/.config/passwords-mcp/install-manifest.json',
  );
});

test('secure manifest loading requires a private directory and file', async () => {
  const root = await mkdtemp(join(tmpdir(), 'passwords-mcp-manifest-'));
  const directory = join(root, 'passwords-mcp');
  const path = join(directory, 'install-manifest.json');
  await mkdir(directory, { mode: 0o700 });
  await writeFile(path, JSON.stringify({
    schema_version: 1,
    profiles: {
      github: {
        source_id: 'source-id',
        destination: {
          service: 'nc-passwords-mcp:github',
          account: 'octocat',
        },
      },
    },
  }), { mode: 0o600 });

  assert.equal((await loadInstallManifest(path)).profiles.github!.source_id, 'source-id');
  await chmod(path, 0o644);
  await assert.rejects(loadInstallManifest(path), /private mode/i);
});

test('secure manifest loading rejects symlink substitution', async () => {
  const root = await mkdtemp(join(tmpdir(), 'passwords-mcp-symlink-'));
  const directory = join(root, 'passwords-mcp');
  const target = join(root, 'target.json');
  const path = join(directory, 'install-manifest.json');
  await mkdir(directory, { mode: 0o700 });
  await writeFile(target, '{}', { mode: 0o600 });
  await symlink(target, path);
  await assert.rejects(loadInstallManifest(path), /manifest unavailable/i);
});
