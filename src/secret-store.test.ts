import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  buildLookupCommand,
  buildStoreCommand,
  readSecret,
  validateCredentialRef,
  writeSecret,
  type CommandRunner,
  type CredentialRef,
} from './secret-store.js';

const REF: CredentialRef = {
  service: 'nc-passwords-mcp:github-production',
  account: 'octocat',
};

test('credential references are canonical and reject control characters', () => {
  assert.deepEqual(validateCredentialRef(REF), REF);
  assert.throws(
    () => validateCredentialRef({ service: 'valid\ninjected', account: 'octocat' }),
    /invalid credential service/i,
  );
  assert.throws(
    () => validateCredentialRef({ service: REF.service, account: '--all' }),
    /invalid credential account/i,
  );
});

test('macOS lookup uses fixed executable, exact attributes, and login keychain', () => {
  const command = buildLookupCommand(REF, 'darwin', '/Users/alice');
  assert.equal(command.file, '/usr/bin/security');
  assert.deepEqual(command.args, [
    'find-generic-password',
    '-s',
    REF.service,
    '-a',
    REF.account,
    '-w',
    '/Users/alice/Library/Keychains/login.keychain-db',
  ]);
});

test('macOS store uses interactive stdin and never puts the secret in argv', () => {
  const command = buildStoreCommand(REF, 'darwin');
  assert.equal(command.file, '/usr/bin/security');
  assert.deepEqual(command.args, ['-i']);
  assert.ok(!JSON.stringify(command).includes('canary-secret'));
});

test('Linux lookup and store use an exact libsecret attribute set', () => {
  assert.deepEqual(buildLookupCommand(REF, 'linux', '/home/alice'), {
    file: '/usr/bin/secret-tool',
    args: [
      'lookup',
      'application',
      'nc-passwords-mcp',
      'service',
      REF.service,
      'account',
      REF.account,
    ],
  });
  assert.deepEqual(buildStoreCommand(REF, 'linux'), {
    file: '/usr/bin/secret-tool',
    args: [
      'store',
      '--label=Nextcloud Passwords: github-production',
      'application',
      'nc-passwords-mcp',
      'service',
      REF.service,
      'account',
      REF.account,
    ],
  });
});

test('readSecret strips only the command newline and rejects empty results', async () => {
  const secret = await readSecret(REF, 'linux', async () => Buffer.from('canary-secret\n'));
  assert.equal(secret.toString('utf8'), 'canary-secret');
  secret.fill(0);

  const carriageReturnSecret = await readSecret(
    REF,
    'linux',
    async () => Buffer.from('canary-secret\r\n'),
  );
  assert.equal(carriageReturnSecret.toString('utf8'), 'canary-secret\r');
  carriageReturnSecret.fill(0);

  await assert.rejects(
    readSecret(REF, 'linux', async () => Buffer.from('\n')),
    /CREDENTIAL_UNAVAILABLE/,
  );
});

test('writeSecret uses stdin, verifies the value, and never passes it in argv', async () => {
  const calls: Array<{ args: string[]; input?: Buffer }> = [];
  const runner: CommandRunner = async (spec, input) => {
    calls.push({ args: spec.args, input: input ? Buffer.from(input) : undefined });
    if (spec.args[0] === 'lookup') return Buffer.from('canary-secret\n');
    return Buffer.alloc(0);
  };
  const secret = Buffer.from('canary-secret');
  await writeSecret(REF, secret, 'linux', runner);

  assert.equal(calls.length, 2);
  assert.ok(!JSON.stringify(calls.map((call) => call.args)).includes('canary-secret'));
  assert.equal(calls[0]!.input!.toString('utf8'), 'canary-secret');
});

test('macOS write sends a hex-encoded interactive command and verifies login Keychain', async () => {
  const calls: Array<{ args: string[]; input?: Buffer }> = [];
  const runner: CommandRunner = async (spec, input) => {
    calls.push({ args: spec.args, input: input ? Buffer.from(input) : undefined });
    if (spec.args[0] === 'find-generic-password') return Buffer.from('canary-secret\n');
    return Buffer.alloc(0);
  };
  const secret = Buffer.from('canary-secret');
  await writeSecret(REF, secret, 'darwin', runner);

  assert.deepEqual(calls[0]!.args, ['-i']);
  const interactiveInput = calls[0]!.input!.toString('utf8');
  assert.ok(!interactiveInput.includes('canary-secret'));
  assert.match(interactiveInput, /-X 63616e6172792d736563726574 /);
  assert.match(interactiveInput, /login\.keychain-db/);
});

test('writeSecret fails closed when verification does not match', async () => {
  const runner: CommandRunner = async (spec) =>
    spec.args[0] === 'lookup' ? Buffer.from('different\n') : Buffer.alloc(0);
  await assert.rejects(
    writeSecret(REF, Buffer.from('canary-secret'), 'linux', runner),
    /CREDENTIAL_STORE_FAILED/,
  );
});
