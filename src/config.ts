import { validateCredentialRef, type CredentialRef } from './secret-store.js';

export interface Config {
  /** Nextcloud base URL with no trailing slash, e.g. `https://cloud.example.com`. */
  url: string;
  /** Nextcloud username. */
  user: string;
  /** Reference to the Nextcloud app-password in the OS credential store. */
  credential: CredentialRef;
}

const REQUIRED = [
  'NEXTCLOUD_URL',
  'NEXTCLOUD_USER',
  'NEXTCLOUD_CREDENTIAL_SERVICE',
  'NEXTCLOUD_CREDENTIAL_ACCOUNT',
] as const;

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  if (env.NEXTCLOUD_APP_PASSWORD !== undefined) {
    throw new Error(
      'Plaintext credential environment variables are forbidden; configure a credential-store reference.',
    );
  }
  if (env.ALLOW_INSECURE_HTTP !== undefined) {
    throw new Error('ALLOW_INSECURE_HTTP is unsupported; Nextcloud must use HTTPS');
  }
  const missing = REQUIRED.filter((k) => !env[k]);
  if (missing.length > 0) {
    throw new Error(
      `Missing required environment variable(s): ${missing.join(', ')}. ` +
        'Configure NEXTCLOUD_URL, NEXTCLOUD_USER, NEXTCLOUD_CREDENTIAL_SERVICE, and ' +
        'NEXTCLOUD_CREDENTIAL_ACCOUNT.',
    );
  }

  const rawUrl = env.NEXTCLOUD_URL!.trim();
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new Error('NEXTCLOUD_URL is not a valid URL');
  }

  if (url.protocol !== 'https:') {
    throw new Error('NEXTCLOUD_URL must use HTTPS');
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new Error('NEXTCLOUD_URL must be a credential-free HTTPS origin with an optional path');
  }
  const user = env.NEXTCLOUD_USER!.trim();
  if (!user || user.includes(':') || /[\u0000-\u001f\u007f]/.test(user)) {
    throw new Error('NEXTCLOUD_USER is invalid');
  }

  return {
    url: rawUrl.replace(/\/+$/, ''),
    user,
    credential: validateCredentialRef({
      service: env.NEXTCLOUD_CREDENTIAL_SERVICE!,
      account: env.NEXTCLOUD_CREDENTIAL_ACCOUNT!,
    }),
  };
}
