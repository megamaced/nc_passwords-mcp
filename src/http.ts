import type { Config } from './config.js';

/**
 * Path prefix for the Nextcloud Passwords API v1.0, appended after the
 * instance base URL.
 */
export const PASSWORDS_API = '/index.php/apps/passwords/api/1.0';

/** Header the Passwords API uses to carry the opaque session token. */
const SESSION_HEADER = 'X-API-SESSION';

/** Per-request network timeout. */
const REQUEST_TIMEOUT_MS = 30_000;

// -----------------------------------------------------------------------------
// Logging
//
// The logger writes to stderr only and is deliberately dumb: callers pass a
// short, already-safe label. Secrets (app-password, session token, and any
// password/notes/customFields field) are NEVER passed to it. Do not change
// call sites to interpolate response bodies or credentials.
// -----------------------------------------------------------------------------

const DEBUG = !!process.env.DEBUG;

function debug(msg: string): void {
  if (DEBUG) process.stderr.write(`[passwords-mcp] ${msg}\n`);
}

// -----------------------------------------------------------------------------
// Retry configuration
// -----------------------------------------------------------------------------

const MAX_RETRIES = 3;
const RETRY_BASE_DELAY_MS = 1000;

function isRetryable(status: number): boolean {
  return status === 429 || (status >= 500 && status <= 599);
}

async function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function parseRetryAfter(res: Response): number | null {
  const header = res.headers.get('Retry-After');
  if (!header) return null;
  const seconds = parseInt(header, 10);
  if (!isNaN(seconds)) return seconds * 1000;
  const date = Date.parse(header);
  if (!isNaN(date)) return Math.max(0, date - Date.now());
  return null;
}

// -----------------------------------------------------------------------------
// Error classes
// -----------------------------------------------------------------------------

const ERROR_BODY_MAX = 200;

/** A failed HTTP response (non-2xx status). */
export class HttpError extends Error {
  public readonly hint: string;

  constructor(
    public readonly status: number,
    public readonly statusText: string,
    body: string,
  ) {
    const snippet = body.length > ERROR_BODY_MAX ? `${body.slice(0, ERROR_BODY_MAX)}…` : body;
    const hint = httpHint(status);
    super(`HTTP ${status} ${statusText}${snippet ? `: ${snippet}` : ''}${hint ? ` [${hint}]` : ''}`);
    this.name = 'HttpError';
    this.hint = hint;
  }
}

function httpHint(status: number): string {
  switch (status) {
    case 401:
      return 'Check NEXTCLOUD_USER / NEXTCLOUD_APP_PASSWORD — the app-password may be expired or revoked.';
    case 403:
      return 'Forbidden — the app-password lacks permission, or a session could not be established.';
    case 404:
      return 'Not found — the Passwords app may not be installed, or the id is wrong.';
    case 429:
      return 'Rate-limited — too many requests. Retry later.';
    default:
      if (status >= 500) return 'Server error — Nextcloud may be overloaded or misconfigured.';
      return '';
  }
}

/** Raised when the account has client-side encryption enabled (unsupported). */
export class CseUnsupportedError extends Error {
  constructor() {
    super(
      'This account has client-side encryption (CSE) enabled — the Passwords ' +
        'server is requesting a master-password challenge. This MCP server only ' +
        'supports accounts with CSE disabled and does not implement the E2E ' +
        'crypto required to decrypt CSE-protected data. Disable CSE in the ' +
        'Passwords app settings, or do not use this server.',
    );
    this.name = 'CseUnsupportedError';
  }
}

// -----------------------------------------------------------------------------
// Client
// -----------------------------------------------------------------------------

/**
 * Minimal read-only client for the Nextcloud Passwords API.
 *
 * Authentication is HTTP Basic with a Nextcloud app-password. The Passwords API
 * additionally requires an opaque per-connection session token, obtained from
 * `session/open` and replayed in the `X-API-SESSION` header. The session is
 * opened lazily and transparently re-opened if the server expires it.
 */
export class PasswordsClient {
  private readonly authHeader: string;
  private session: string | null = null;

  constructor(private readonly config: Config) {
    const token = Buffer.from(`${config.user}:${config.password}`, 'utf8').toString('base64');
    this.authHeader = `Basic ${token}`;
    if (this.config.allowInsecureHttp && config.url.startsWith('http://')) {
      process.stderr.write(
        '[passwords-mcp] WARNING: connecting over plaintext http:// — ' +
          'credentials and secrets are sent unencrypted. Localhost testing only.\n',
      );
    }
  }

  private apiUrl(path: string): string {
    return `${this.config.url}${PASSWORDS_API}${path}`;
  }

  // ---------------------------------------------------------------------------
  // Low-level fetch with timeout + retry on 429 / 5xx
  // ---------------------------------------------------------------------------

  private async fetchWithRetry(
    url: string,
    init: RequestInit,
    label: string,
  ): Promise<Response> {
    let lastError: Error | undefined;
    for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
      if (attempt > 0) {
        const delay = RETRY_BASE_DELAY_MS * Math.pow(2, attempt - 1);
        debug(`retry ${attempt}/${MAX_RETRIES} for ${label} after ${delay}ms`);
        await sleep(delay);
      }

      debug(label);
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
      let res: Response;
      try {
        res = await fetch(url, { ...init, signal: controller.signal });
      } finally {
        clearTimeout(timer);
      }

      if (!res.ok) {
        if (isRetryable(res.status) && attempt < MAX_RETRIES) {
          const retryDelay = parseRetryAfter(res);
          if (retryDelay !== null) await sleep(retryDelay);
          const text = await res.text().catch(() => '');
          lastError = new HttpError(res.status, res.statusText, text);
          continue;
        }
        const text = await res.text().catch(() => '');
        throw new HttpError(res.status, res.statusText, text);
      }
      return res;
    }
    throw lastError ?? new Error('Unexpected retry exhaustion');
  }

  private baseHeaders(): Record<string, string> {
    return {
      Authorization: this.authHeader,
      Accept: 'application/json',
      // Signals a deliberate API request; app-password Basic auth bypasses CSRF.
      'OCS-APIRequest': 'true',
    };
  }

  // ---------------------------------------------------------------------------
  // Session management
  // ---------------------------------------------------------------------------

  /**
   * Ask the server what a session requires. An empty requirement object means
   * no challenge — i.e. client-side encryption is disabled, which is the only
   * configuration this server supports. If the server asks for any challenge
   * we refuse rather than silently returning ciphertext.
   */
  private async assertNoCse(): Promise<void> {
    const res = await this.fetchWithRetry(
      this.apiUrl('/session/request'),
      { method: 'GET', headers: this.baseHeaders() },
      'GET /session/request',
    );
    const body = (await res.json().catch(() => ({}))) as { challenge?: unknown };
    if (body && body.challenge) {
      throw new CseUnsupportedError();
    }
  }

  /** Open a session, capturing the opaque token from the response header. */
  private async openSession(): Promise<string> {
    await this.assertNoCse();
    const res = await this.fetchWithRetry(
      this.apiUrl('/session/open'),
      {
        method: 'POST',
        headers: { ...this.baseHeaders(), 'Content-Type': 'application/json' },
        body: '{}',
      },
      'POST /session/open',
    );
    // Drain the body so the connection can be reused; we only need the header.
    await res.text().catch(() => '');
    const token = res.headers.get(SESSION_HEADER);
    if (!token) {
      throw new Error(
        'Passwords server did not return a session token. The Passwords app may ' +
          'be misconfigured, or the account may require client-side encryption.',
      );
    }
    debug('session opened');
    return token;
  }

  private async ensureSession(): Promise<string> {
    if (!this.session) {
      this.session = await this.openSession();
    }
    return this.session;
  }

  /** Best-effort session close; never throws. */
  async close(): Promise<void> {
    if (!this.session) return;
    const token = this.session;
    this.session = null;
    try {
      await this.fetchWithRetry(
        this.apiUrl('/session/close'),
        { method: 'POST', headers: { ...this.baseHeaders(), [SESSION_HEADER]: token } },
        'POST /session/close',
      );
    } catch {
      // Closing is best-effort — the server expires idle sessions anyway.
    }
  }

  // ---------------------------------------------------------------------------
  // Authenticated API calls
  // ---------------------------------------------------------------------------

  /**
   * Make an authenticated Passwords API request and return the parsed JSON.
   * Transparently (re-)opens the session, retrying once if the server reports
   * the session is missing/expired (401/403).
   */
  async apiJson<T = unknown>(method: string, path: string, body?: unknown): Promise<T> {
    return this.apiJsonInner<T>(method, path, body, true);
  }

  private async apiJsonInner<T>(
    method: string,
    path: string,
    body: unknown,
    retryOnAuth: boolean,
  ): Promise<T> {
    const session = await this.ensureSession();
    const headers: Record<string, string> = { ...this.baseHeaders(), [SESSION_HEADER]: session };
    if (body !== undefined) headers['Content-Type'] = 'application/json';

    try {
      const res = await this.fetchWithRetry(
        this.apiUrl(path),
        { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined },
        `${method} ${path}`,
      );
      const text = await res.text();
      if (!text) return undefined as T;
      try {
        return JSON.parse(text) as T;
      } catch {
        throw new Error(`Passwords API response was not valid JSON (${res.status})`);
      }
    } catch (err) {
      // A stale session shows up as 401/403; drop it and retry once.
      if (retryOnAuth && err instanceof HttpError && (err.status === 401 || err.status === 403)) {
        debug('session rejected — reopening');
        this.session = null;
        return this.apiJsonInner<T>(method, path, body, false);
      }
      throw err;
    }
  }
}
