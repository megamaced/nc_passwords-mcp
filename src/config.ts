export interface Config {
  /** Nextcloud base URL with no trailing slash, e.g. `https://cloud.example.com`. */
  url: string;
  /** Nextcloud username. */
  user: string;
  /** Nextcloud app-password (never the user's real account password). */
  password: string;
  /**
   * Allow plaintext `http://` URLs. Off by default — this server refuses to
   * send credentials over an unencrypted connection unless explicitly opted in
   * for localhost testing.
   */
  allowInsecureHttp: boolean;
  /**
   * Expose only read tools. Off by default (create/update/delete are
   * available). Set `PASSWORDS_READONLY=true` to hide and refuse every write
   * tool for a look-but-don't-touch deployment.
   */
  readOnly: boolean;
}

const REQUIRED = ['NEXTCLOUD_URL', 'NEXTCLOUD_USER', 'NEXTCLOUD_APP_PASSWORD'] as const;

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const missing = REQUIRED.filter((k) => !env[k]);
  if (missing.length > 0) {
    throw new Error(
      `Missing required environment variable(s): ${missing.join(', ')}. ` +
        'Generate an app-password in Nextcloud (Settings → Security → Devices & sessions) ' +
        'and pass NEXTCLOUD_URL, NEXTCLOUD_USER, NEXTCLOUD_APP_PASSWORD to the MCP server.',
    );
  }

  const rawUrl = env.NEXTCLOUD_URL!.trim();
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new Error(`NEXTCLOUD_URL is not a valid URL: ${rawUrl}`);
  }

  const allowInsecureHttp = env.ALLOW_INSECURE_HTTP === 'true';

  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new Error(`NEXTCLOUD_URL must use http or https, got ${url.protocol}`);
  }
  if (url.protocol === 'http:' && !allowInsecureHttp) {
    throw new Error(
      'Refusing to send credentials over plaintext http://. This is a password ' +
        'manager — use an https:// URL. For localhost testing only you may set ' +
        'ALLOW_INSECURE_HTTP=true, but never do this against a remote host.',
    );
  }

  return {
    url: rawUrl.replace(/\/+$/, ''),
    user: env.NEXTCLOUD_USER!.trim(),
    password: env.NEXTCLOUD_APP_PASSWORD!,
    allowInsecureHttp,
    readOnly: env.PASSWORDS_READONLY === 'true',
  };
}
