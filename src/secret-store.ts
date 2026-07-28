import { spawn } from 'node:child_process';
import { timingSafeEqual } from 'node:crypto';
import { homedir } from 'node:os';

export type SupportedSecretStorePlatform = 'darwin' | 'linux';

export interface CredentialRef {
  service: string;
  account: string;
}

export interface CommandSpec {
  file: string;
  args: string[];
}

export type CommandRunner = (spec: CommandSpec, input?: Buffer) => Promise<Buffer>;

const SERVICE_RE = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$/;
const ACCOUNT_RE = /^[A-Za-z0-9][A-Za-z0-9.@_+-]{0,199}$/;
const OUTPUT_LIMIT = 1024 * 1024;

export class SecretStoreError extends Error {
  constructor(public readonly code: 'CREDENTIAL_UNAVAILABLE' | 'CREDENTIAL_STORE_FAILED' | 'UNSUPPORTED_PLATFORM') {
    super(code);
    this.name = 'SecretStoreError';
  }
}

export function validateCredentialRef(ref: CredentialRef): CredentialRef {
  if (!SERVICE_RE.test(ref.service)) {
    throw new Error('invalid credential service reference');
  }
  if (!ACCOUNT_RE.test(ref.account) || ref.account.startsWith('-')) {
    throw new Error('invalid credential account reference');
  }
  return { service: ref.service, account: ref.account };
}

function supportedPlatform(platform: NodeJS.Platform): SupportedSecretStorePlatform {
  if (platform === 'darwin' || platform === 'linux') return platform;
  throw new SecretStoreError('UNSUPPORTED_PLATFORM');
}

function loginKeychainPath(home: string): string {
  if (!home.startsWith('/') || /[\u0000-\u001f\u007f]/.test(home)) {
    throw new SecretStoreError('CREDENTIAL_UNAVAILABLE');
  }
  return `${home.replace(/\/+$/, '')}/Library/Keychains/login.keychain-db`;
}

export function buildLookupCommand(
  rawRef: CredentialRef,
  platform: SupportedSecretStorePlatform,
  home: string = homedir(),
): CommandSpec {
  const ref = validateCredentialRef(rawRef);
  if (platform === 'darwin') {
    return {
      file: '/usr/bin/security',
      args: [
        'find-generic-password',
        '-s',
        ref.service,
        '-a',
        ref.account,
        '-w',
        loginKeychainPath(home),
      ],
    };
  }
  return {
    file: '/usr/bin/secret-tool',
    args: [
      'lookup',
      'application',
      'nc-passwords-mcp',
      'service',
      ref.service,
      'account',
      ref.account,
    ],
  };
}

export function buildStoreCommand(
  rawRef: CredentialRef,
  platform: SupportedSecretStorePlatform,
): CommandSpec {
  const ref = validateCredentialRef(rawRef);
  if (platform === 'darwin') {
    return {
      file: '/usr/bin/security',
      // Interactive mode accepts commands over stdin. The secret is supplied
      // as hex in that private stream, never as a process argument.
      args: ['-i'],
    };
  }
  const label = ref.service.split(':').at(-1) ?? ref.service;
  return {
    file: '/usr/bin/secret-tool',
    args: [
      'store',
      `--label=Nextcloud Passwords: ${label}`,
      'application',
      'nc-passwords-mcp',
      'service',
      ref.service,
      'account',
      ref.account,
    ],
  };
}

function securityQuoted(value: string): string {
  if (/[\u0000-\u001f\u007f]/.test(value)) throw new Error('invalid security command value');
  return `"${value.replaceAll('\\', '\\\\').replaceAll('"', '\\"')}"`;
}

function hexBuffer(value: Buffer): Buffer {
  const digits = Buffer.from('0123456789abcdef', 'ascii');
  const encoded = Buffer.alloc(value.length * 2);
  for (let index = 0; index < value.length; index += 1) {
    const byte = value[index]!;
    encoded[index * 2] = digits[byte >>> 4]!;
    encoded[index * 2 + 1] = digits[byte & 0x0f]!;
  }
  digits.fill(0);
  return encoded;
}

function macStoreInput(ref: CredentialRef, secret: Buffer, home: string = homedir()): Buffer {
  const prefix = Buffer.from(
    `add-generic-password -U -a ${securityQuoted(ref.account)} ` +
      `-s ${securityQuoted(ref.service)} -X `,
    'utf8',
  );
  const encoded = hexBuffer(secret);
  const suffix = Buffer.from(` ${securityQuoted(loginKeychainPath(home))}\n`, 'utf8');
  const input = Buffer.concat([prefix, encoded, suffix]);
  encoded.fill(0);
  return input;
}

function childEnvironment(): NodeJS.ProcessEnv {
  const allowed = [
    'HOME',
    'USER',
    'LOGNAME',
    'LANG',
    'LC_ALL',
    'DBUS_SESSION_BUS_ADDRESS',
    'XDG_RUNTIME_DIR',
    'DISPLAY',
    'WAYLAND_DISPLAY',
  ] as const;
  const env: NodeJS.ProcessEnv = {};
  for (const name of allowed) {
    if (process.env[name] !== undefined) env[name] = process.env[name];
  }
  return env;
}

async function runCommand(spec: CommandSpec, input?: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const child = spawn(spec.file, spec.args, {
      env: childEnvironment(),
      shell: false,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    const stdout: Buffer[] = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let settled = false;

    const wipeStdout = (): void => {
      for (const chunk of stdout) chunk.fill(0);
      stdout.length = 0;
    };

    const fail = (): void => {
      if (settled) return;
      settled = true;
      child.kill();
      wipeStdout();
      reject(new Error('credential command failed'));
    };

    child.on('error', fail);
    child.stdout.on('data', (chunk: Buffer) => {
      stdoutBytes += chunk.length;
      if (stdoutBytes > OUTPUT_LIMIT) {
        fail();
        return;
      }
      stdout.push(Buffer.from(chunk));
    });
    child.stderr.on('data', (chunk: Buffer) => {
      stderrBytes += chunk.length;
      if (stderrBytes > OUTPUT_LIMIT) fail();
    });
    child.stdin.on('error', fail);
    child.on('close', (code) => {
      if (settled) return;
      settled = true;
      if (code !== 0) {
        wipeStdout();
        reject(new Error('credential command failed'));
        return;
      }
      const output = Buffer.concat(stdout);
      wipeStdout();
      resolve(output);
    });

    if (input) child.stdin.end(input);
    else child.stdin.end();
  });
}

function stripCommandNewline(value: Buffer): Buffer {
  let end = value.length;
  if (end > 0 && value[end - 1] === 0x0a) end -= 1;
  return Buffer.from(value.subarray(0, end));
}

export async function readSecret(
  ref: CredentialRef,
  platform: NodeJS.Platform = process.platform,
  runner: CommandRunner = runCommand,
): Promise<Buffer> {
  try {
    const output = await runner(buildLookupCommand(ref, supportedPlatform(platform)));
    const secret = stripCommandNewline(output);
    output.fill(0);
    if (secret.length === 0) throw new Error('empty credential');
    return secret;
  } catch (error) {
    if (error instanceof SecretStoreError) throw error;
    throw new SecretStoreError('CREDENTIAL_UNAVAILABLE');
  }
}

export async function writeSecret(
  ref: CredentialRef,
  secret: Buffer,
  platform: NodeJS.Platform = process.platform,
  runner: CommandRunner = runCommand,
): Promise<void> {
  try {
    if (secret.length === 0) {
      throw new Error('invalid credential value');
    }
    const selectedPlatform = supportedPlatform(platform);
    const input = selectedPlatform === 'darwin' ? macStoreInput(ref, secret) : secret;
    try {
      await runner(buildStoreCommand(ref, selectedPlatform), input);
    } finally {
      if (input !== secret) input.fill(0);
    }
    const verification = await readSecret(ref, selectedPlatform, runner);
    try {
      if (verification.length !== secret.length || !timingSafeEqual(verification, secret)) {
        throw new Error('credential verification failed');
      }
    } finally {
      verification.fill(0);
    }
  } catch (error) {
    if (error instanceof SecretStoreError) throw error;
    throw new SecretStoreError('CREDENTIAL_STORE_FAILED');
  }
}
