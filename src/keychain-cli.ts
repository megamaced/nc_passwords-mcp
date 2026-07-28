#!/usr/bin/env node
import { pathToFileURL } from 'node:url';

import { showPassword } from './api.js';
import { loadConfig } from './config.js';
import { PasswordsClient, HttpError } from './http.js';
import {
  defaultInstallManifestPath,
  loadInstallManifest,
  type InstallManifest,
} from './install-manifest.js';
import {
  readSecret,
  SecretStoreError,
  writeSecret,
  type CredentialRef,
} from './secret-store.js';

interface CliArgs {
  profile: string;
}

interface InstallReceipt {
  ok: true;
  operation: 'install';
  profile: string;
  destination: CredentialRef;
}

export function parseCliArgs(argv: string[]): CliArgs {
  if (
    argv.length !== 3 ||
    argv[0] !== 'install' ||
    argv[1] !== '--profile' ||
    !argv[2]
  ) {
    throw new Error('USAGE');
  }
  return { profile: argv[2] };
}

export async function installProfile(
  manifest: InstallManifest,
  profileName: string,
  fetchSecret: (sourceId: string) => Promise<string>,
  store: (destination: CredentialRef, secret: Buffer) => Promise<void>,
): Promise<InstallReceipt> {
  const profile = manifest.profiles[profileName];
  if (!profile) throw new Error('PROFILE_NOT_FOUND');

  let plaintext = await fetchSecret(profile.source_id);
  const secret = Buffer.from(plaintext, 'utf8');
  plaintext = '';
  try {
    await store(profile.destination, secret);
  } finally {
    secret.fill(0);
  }

  return {
    ok: true,
    operation: 'install',
    profile: profileName,
    destination: profile.destination,
  };
}

function safeErrorCode(error: unknown): string {
  if (error instanceof SecretStoreError) return error.code;
  if (error instanceof HttpError) return 'NEXTCLOUD_REQUEST_FAILED';
  if (error instanceof Error && error.message === 'USAGE') return 'USAGE';
  if (error instanceof Error && error.message === 'PROFILE_NOT_FOUND') return 'PROFILE_NOT_FOUND';
  return 'INSTALL_FAILED';
}

async function main(): Promise<void> {
  let client: PasswordsClient | undefined;
  try {
    const args = parseCliArgs(process.argv.slice(2));
    const manifest = await loadInstallManifest(defaultInstallManifestPath());
    const config = loadConfig();
    const appPassword = await readSecret(config.credential);
    client = new PasswordsClient(config, appPassword);
    const receipt = await installProfile(
      manifest,
      args.profile,
      async (sourceId) => {
        const password = await showPassword(client!, sourceId);
        const value = password.password;
        password.password = '';
        password.notes = '';
        password.customFields = '';
        return value;
      },
      (destination, secret) => writeSecret(destination, secret),
    );
    process.stdout.write(`${JSON.stringify(receipt)}\n`);
  } catch (error) {
    process.stdout.write(`${JSON.stringify({ ok: false, code: safeErrorCode(error) })}\n`);
    process.exitCode = 1;
  } finally {
    await client?.close();
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
