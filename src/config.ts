export interface Config {
  /** Nextcloud base URL with no trailing slash, e.g. `https://cloud.example.com`. */
  url: string;
  /** Nextcloud username. */
  user: string;
  /** Nextcloud app-password (never the user's real account password). */
  password: string;
  /**
   * Allow plaintext `http://` URLs. Off by default — this server refuses to
   * send credentials over an unencrypted connection unless explicitly opted in,
   * and even then only for a loopback host.
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
  // The opt-in exists for local development against a dev instance. Honouring
  // it for a remote host would put the app-password on the wire in cleartext,
  // so scope it to loopback regardless of what the operator sets.
  if (url.protocol === 'http:' && !isLoopbackHost(url.hostname)) {
    throw new Error(
      `ALLOW_INSECURE_HTTP only permits a loopback host, got ${url.hostname}. ` +
        'Use https:// for any non-local Nextcloud instance.',
    );
  }
  // Credentials belong in NEXTCLOUD_USER / NEXTCLOUD_APP_PASSWORD, not the URL:
  // a userinfo component would be silently ignored while looking like it works,
  // and a query or fragment would be carried onto every API path.
  if (url.username || url.password) {
    throw new Error('NEXTCLOUD_URL must not embed credentials — use NEXTCLOUD_USER instead');
  }
  if (url.search || url.hash) {
    throw new Error('NEXTCLOUD_URL must not include a query string or fragment');
  }

  const user = env.NEXTCLOUD_USER!.trim();
  // A colon would split the HTTP Basic credential pair; control characters
  // would allow header injection.
  if (!user || user.includes(':') || /[\u0000-\u001f\u007f]/.test(user)) {
    throw new Error('NEXTCLOUD_USER must be non-empty and free of colons and control characters');
  }

  return {
    url: rawUrl.replace(/\/+$/, ''),
    user,
    password: env.NEXTCLOUD_APP_PASSWORD!,
    allowInsecureHttp,
    readOnly: env.PASSWORDS_READONLY === 'true',
  };
}

/** True for the hostnames that never leave the machine. */
function isLoopbackHost(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  return host === 'localhost' || host === '::1' || /^127\.\d+\.\d+\.\d+$/.test(host);
}
