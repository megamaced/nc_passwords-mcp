import { constants } from 'node:fs';
import { open } from 'node:fs/promises';
import { userInfo } from 'node:os';
import { dirname } from 'node:path';

import { validateCredentialRef, type CredentialRef } from './secret-store.js';

export interface InstallProfile {
  source_id: string;
  destination: CredentialRef;
}

export interface InstallManifest {
  schema_version: 1;
  profiles: Record<string, InstallProfile>;
}

const PROFILE_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const SOURCE_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const MANIFEST_MAX_BYTES = 1024 * 1024;

function exactKeys(
  value: Record<string, unknown>,
  required: readonly string[],
  label: string,
): void {
  const actual = Object.keys(value).sort();
  const expected = [...required].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(`unsupported ${label} properties`);
  }
}

function objectValue(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

export function parseInstallManifest(input: unknown): InstallManifest {
  const root = objectValue(input, 'manifest');
  exactKeys(root, ['schema_version', 'profiles'], 'manifest');
  if (root.schema_version !== 1) throw new Error('unsupported manifest schema_version');

  const rawProfiles = objectValue(root.profiles, 'profiles');
  if (Object.keys(rawProfiles).length === 0) throw new Error('profiles must not be empty');

  const profiles: Record<string, InstallProfile> = {};
  for (const name of Object.keys(rawProfiles).sort()) {
    if (!PROFILE_RE.test(name)) throw new Error('invalid profile name');
    const rawProfile = objectValue(rawProfiles[name], 'profile');
    exactKeys(rawProfile, ['source_id', 'destination'], 'profile');
    if (typeof rawProfile.source_id !== 'string' || !SOURCE_ID_RE.test(rawProfile.source_id)) {
      throw new Error('invalid source id');
    }

    const rawDestination = objectValue(rawProfile.destination, 'destination');
    exactKeys(rawDestination, ['service', 'account'], 'destination');
    if (typeof rawDestination.service !== 'string' || typeof rawDestination.account !== 'string') {
      throw new Error('destination references must be strings');
    }
    profiles[name] = {
      source_id: rawProfile.source_id,
      destination: validateCredentialRef({
        service: rawDestination.service,
        account: rawDestination.account,
      }),
    };
  }

  return { schema_version: 1, profiles };
}

export function defaultInstallManifestPath(
  platform: NodeJS.Platform = process.platform,
  home: string = userInfo().homedir,
): string {
  if (!home.startsWith('/') || /[\u0000-\u001f\u007f]/.test(home)) {
    throw new Error('effective user home is invalid');
  }
  if (platform === 'darwin') {
    return `${home.replace(/\/+$/, '')}/Library/Application Support/passwords-mcp/install-manifest.json`;
  }
  if (platform === 'linux') {
    return `${home.replace(/\/+$/, '')}/.config/passwords-mcp/install-manifest.json`;
  }
  throw new Error('unsupported platform');
}

function expectedUid(): number {
  if (!process.getuid) throw new Error('manifest ownership checks are unavailable');
  return process.getuid();
}

export async function loadInstallManifest(path: string): Promise<InstallManifest> {
  let directoryHandle;
  let fileHandle;
  try {
    directoryHandle = await open(
      dirname(path),
      constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
    );
    const directoryStat = await directoryHandle.stat();
    if (!directoryStat.isDirectory() || directoryStat.uid !== expectedUid()) {
      throw new Error('manifest directory must be owned by the effective user');
    }
    if ((directoryStat.mode & 0o077) !== 0) {
      throw new Error('manifest directory must use private mode 0700');
    }

    fileHandle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const fileStat = await fileHandle.stat();
    if (!fileStat.isFile() || fileStat.uid !== expectedUid() || fileStat.nlink !== 1) {
      throw new Error('manifest file must be a single regular file owned by the effective user');
    }
    if ((fileStat.mode & 0o077) !== 0) {
      throw new Error('manifest file must use private mode 0600');
    }
    if (fileStat.size <= 0 || fileStat.size > MANIFEST_MAX_BYTES) {
      throw new Error('manifest file size is invalid');
    }

    const text = await fileHandle.readFile({ encoding: 'utf8' });
    return parseInstallManifest(JSON.parse(text) as unknown);
  } catch (error) {
    if (error instanceof Error && error.message.startsWith('manifest ')) throw error;
    throw new Error('manifest unavailable');
  } finally {
    await fileHandle?.close();
    await directoryHandle?.close();
  }
}
