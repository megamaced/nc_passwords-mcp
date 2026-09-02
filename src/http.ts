import { randomUUID } from 'node:crypto';

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
// password/notes/customFields field) are NEVER passed to it, and neither are
// response bodies — a Passwords API error body can echo the request it failed
// on, so no code path may route one here. Do not change call sites to
// interpolate response bodies or credentials.
// -----------------------------------------------------------------------------

const DEBUG = !!process.env.DEBUG;

function debug(msg: string): void {
  if (DEBUG) process.stderr.write(`[passwords-mcp] ${msg}\n`);
}

/**
 * Read a failed response to completion and throw the content away, so the
 * socket can be reused. The body is never inspected, logged or attached to an
 * error: only the status and a correlation id identify the failure.
 */
async function discardBody(res: Response): Promise<void> {
  try {
    await res.arrayBuffer();
  } catch {
    // A body that cannot be drained is not worth reporting — the status is
    // what the caller acts on.
  }
}

// -----------------------------------------------------------------------------
// Retry configuration
// -----------------------------------------------------------------------------

const MAX_RETRIES = 3;
const RETRY_BASE_DELAY_MS = 1000;

/**
 * Upper bound on any single wait between attempts, including one the server
 * asked for. `Retry-After` is attacker- or misconfiguration-controlled and a
 * value like `86400` would otherwise park a tool call for a day, far past the
 * per-request timeout this server documents.
 */
const RETRY_DELAY_MAX_MS = 30_000;

function isRetryableStatus(status: number): boolean {
  return status === 429 || (status >= 500 && status <= 599);
}

/** Sleep, resolving early (as an abort) when the client is shutting down. */
function sleep(ms: number, signal: AbortSignal): Promise<void> {
  if (signal.aborted) return Promise.reject(new ShutdownError());
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      signal.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    function onAbort(): void {
      clearTimeout(timer);
      reject(new ShutdownError());
    }
    signal.addEventListener('abort', onAbort, { once: true });
  });
}

/** Raised when a pending retry wait is cut short by shutdown. */
export class ShutdownError extends Error {
  constructor() {
    super('Request abandoned: the Passwords client is shutting down.');
    this.name = 'ShutdownError';
  }
}

/**
 * Parse `Retry-After` strictly: RFC 9110 allows only delta-seconds or an
 * HTTP-date. `parseInt` would accept `120junk` as 120 seconds, so digits are
 * matched whole, and every legal HTTP-date form starts with a day name, so
 * `Date.parse` is only consulted for strings that do. The result is clamped —
 * see {@link RETRY_DELAY_MAX_MS}.
 */
export function parseRetryAfter(header: string | null, now: number = Date.now()): number | null {
  if (header === null) return null;
  const raw = header.trim();
  if (raw === '') return null;
  if (/^\d+$/.test(raw)) {
    const seconds = Number(raw);
    if (!Number.isFinite(seconds)) return null;
    return Math.min(seconds * 1000, RETRY_DELAY_MAX_MS);
  }
  if (!/^(Mon|Tue|Wed|Thu|Fri|Sat|Sun)/i.test(raw)) return null;
  const date = Date.parse(raw);
  if (Number.isNaN(date)) return null;
  return Math.min(Math.max(0, date - now), RETRY_DELAY_MAX_MS);
}

/** Exponential backoff with full jitter, capped at {@link RETRY_DELAY_MAX_MS}. */
function backoffDelay(attempt: number): number {
  const ceiling = Math.min(RETRY_BASE_DELAY_MS * Math.pow(2, attempt - 1), RETRY_DELAY_MAX_MS);
  return Math.round(ceiling * (0.5 + Math.random() * 0.5));
}

// -----------------------------------------------------------------------------
// Error classes
// -----------------------------------------------------------------------------

/**
 * A failed HTTP response (non-2xx status).
 *
 * The message carries the status, a static hint and a correlation id only. The
 * response body is deliberately NOT included and is never read: an error body
 * from the Passwords app can echo request content, and this message propagates
 * all the way into the MCP client's context.
 */
export class HttpError extends Error {
  public readonly hint: string;

  constructor(
    public readonly status: number,
    public readonly statusText: string,
    public readonly correlationId?: string,
  ) {
    const hint = httpHint(status);
    super(
      `HTTP ${status} ${statusText}${hint ? ` [${hint}]` : ''}` +
        `${correlationId ? ` (ref ${correlationId})` : ''}`,
    );
    this.name = 'HttpError';
    this.hint = hint;
  }
}

/**
 * Raised when a vault mutation failed in a way that does not prove whether the
 * server applied it — a 5xx, or a network/timeout failure after the request
 * went out. These are never retried automatically: a repeated
 * `password/create` would silently duplicate an entry, and a repeated
 * revision-guarded update would report a conflict for a change that in fact
 * succeeded. The caller must reconcile state before trying again.
 */
export class WriteOutcomeUnknownError extends Error {
  constructor(
    label: string,
    public readonly reason: unknown,
    correlationId: string,
  ) {
    super(
      `The write (${label}) failed without a definite outcome (ref ${correlationId}): ` +
        `${describeCause(reason)}. It may or may not have been applied on the server. ` +
        `This server does not retry writes automatically, because retrying could ` +
        `duplicate an entry or report a false conflict. Re-read the affected item ` +
        `to check its current state before trying again.`,
    );
    this.name = 'WriteOutcomeUnknownError';
  }
}

function describeCause(cause: unknown): string {
  if (cause instanceof HttpError) return `HTTP ${cause.status} ${cause.statusText}`;
  if (cause instanceof Error) return cause.name === 'AbortError' ? 'request timed out' : cause.name;
  return 'network error';
}

function httpHint(status: number): string {
  switch (status) {
    case 401:
      return 'Check NEXTCLOUD_USER / NEXTCLOUD_APP_PASSWORD — the app-password may be expired or revoked.';
    case 403:
      return 'Forbidden — the app-password lacks permission, or a session could not be established.';
    case 404:
      return 'Not found — the Passwords app may not be installed, or the id is wrong.';
    case 412:
      return 'Session expired — the Passwords app requires a fresh authorized session.';
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

/** Statuses the Passwords app uses to report a missing or expired session. */
function isStaleSession(status: number): boolean {
  // 412 is what the current ApiSessionMiddleware returns for an endpoint that
  // requires an authorized session; older builds answered 401/403.
  return status === 401 || status === 403 || status === 412;
}

// -----------------------------------------------------------------------------
// Client
// -----------------------------------------------------------------------------

/** Per-call options for {@link PasswordsClient.apiJson}. */
export interface ApiCallOptions {
  /**
   * Set for vault mutations. Disables automatic retry and converts an
   * ambiguous failure into a {@link WriteOutcomeUnknownError}.
   */
  mutation?: boolean;
}

/**
 * Minimal client for the Nextcloud Passwords API.
 *
 * Authentication is HTTP Basic with a Nextcloud app-password. The Passwords API
 * additionally requires an opaque per-connection session token, obtained from
 * `session/open` and replayed in the `X-API-SESSION` header. Per the Session
 * API contract the server may rotate that token on ANY response, so the most
 * recent value seen is what gets replayed. The session is opened lazily (once,
 * even under concurrent first calls) and transparently re-opened if the server
 * expires it.
 */
export class PasswordsClient {
  private readonly authHeader: string;
  private session: string | null = null;
  /** In-flight handshake, so concurrent first calls open exactly one session. */
  private opening: Promise<string> | null = null;
  /** Aborts pending retry waits when the process is shutting down. */
  private readonly shutdown = new AbortController();

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

  /**
   * Record the session token from any response that carries one. The Session
   * API requires clients to send the most recent header received with every
   * following request; a changed value means the server replaced the session.
   */
  private captureSession(res: Response): void {
    const token = res.headers.get(SESSION_HEADER);
    if (token && token !== this.session) {
      if (this.session) debug('session token rotated by server');
      this.session = token;
    }
  }

  // ---------------------------------------------------------------------------
  // Low-level fetch with timeout, and retry on 429 / 5xx for safe requests only
  // ---------------------------------------------------------------------------

  private async fetchOnce(url: string, init: RequestInit): Promise<Response> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    try {
      // `redirect: 'error'` is a security control, not a convenience: fetch
      // replays the Authorization header on a same-origin redirect and Node
      // would follow a cross-origin one, handing the app-password to whatever
      // host the Location header names. A Passwords API endpoint never
      // legitimately redirects, so treat any 3xx as a hard failure.
      const res = await fetch(url, { ...init, redirect: 'error', signal: controller.signal });
      this.captureSession(res);
      return res;
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Perform a request, retrying 429/5xx responses only when `retry` is set.
   * Callers that mutate the vault pass `retry: false` — see
   * {@link WriteOutcomeUnknownError}.
   */
  private async request(
    url: string,
    init: RequestInit,
    label: string,
    retry: boolean,
    correlationId: string,
  ): Promise<Response> {
    if (!retry) {
      debug(`${label} (ref ${correlationId}, no-retry)`);
      const res = await this.fetchOnce(url, init);
      if (!res.ok) {
        await discardBody(res);
        debug(`${label} -> HTTP ${res.status} (ref ${correlationId})`);
        throw new HttpError(res.status, res.statusText, correlationId);
      }
      return res;
    }

    let lastError: Error | undefined;
    let nextDelayMs = 0;
    for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
      if (attempt > 0) {
        debug(`retry ${attempt}/${MAX_RETRIES} for ${label} after ${nextDelayMs}ms`);
        await sleep(nextDelayMs, this.shutdown.signal);
      }

      debug(`${label} (ref ${correlationId})`);
      const res = await this.fetchOnce(url, init);
      if (res.ok) return res;

      // Drain before any wait so the socket is not held for the whole delay.
      const retryAfter = parseRetryAfter(res.headers.get('Retry-After'));
      await discardBody(res);
      debug(`${label} -> HTTP ${res.status} (ref ${correlationId})`);

      if (isRetryableStatus(res.status) && attempt < MAX_RETRIES) {
        // One delay, not two: a server-supplied Retry-After replaces the
        // backoff rather than being added to it.
        nextDelayMs = retryAfter ?? backoffDelay(attempt + 1);
        lastError = new HttpError(res.status, res.statusText, correlationId);
        continue;
      }
      throw new HttpError(res.status, res.statusText, correlationId);
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

  /** Base headers plus the most recent session token, when one is known. */
  private sessionHeaders(): Record<string, string> {
    const headers = this.baseHeaders();
    if (this.session) headers[SESSION_HEADER] = this.session;
    return headers;
  }

  // ---------------------------------------------------------------------------
  // Session management
  // ---------------------------------------------------------------------------

  /**
   * Ask the server what a session requires. An empty requirement object means
   * no challenge — i.e. client-side encryption is disabled, which is the only
   * configuration this server supports. If the server asks for any challenge
   * we refuse rather than silently returning ciphertext.
   *
   * The response also seeds the session token that `session/open` must carry.
   */
  private async assertNoCse(): Promise<void> {
    const res = await this.request(
      this.apiUrl('/session/request'),
      { method: 'GET', headers: this.sessionHeaders() },
      'GET /session/request',
      true,
      newCorrelationId(),
    );
    const body = (await res.json().catch(() => ({}))) as { challenge?: unknown };
    if (body && body.challenge) {
      throw new CseUnsupportedError();
    }
  }

  /** Open a session, capturing the opaque token from the response header. */
  private async openSession(): Promise<string> {
    await this.assertNoCse();
    const res = await this.request(
      this.apiUrl('/session/open'),
      {
        method: 'POST',
        headers: { ...this.sessionHeaders(), 'Content-Type': 'application/json' },
        body: '{}',
      },
      'POST /session/open',
      true,
      newCorrelationId(),
    );
    // Drain the body so the connection can be reused; we only need the header,
    // which `fetchOnce` has already recorded.
    await discardBody(res);
    if (!this.session) {
      throw new Error(
        'Passwords server did not return a session token. The Passwords app may ' +
          'be misconfigured, or the account may require client-side encryption.',
      );
    }
    debug('session opened');
    return this.session;
  }

  /**
   * Resolve the session token, opening one if needed. The in-flight promise is
   * memoized so that concurrent first calls share a single handshake instead of
   * each opening (and leaking) a server-side session — `session/open` is also
   * rate-limited to 6 requests per minute.
   */
  private async ensureSession(): Promise<string> {
    if (this.session) return this.session;
    if (!this.opening) {
      this.opening = this.openSession().finally(() => {
        this.opening = null;
      });
    }
    return this.opening;
  }

  /**
   * Verify the instance is reachable, the credentials work, the Passwords app
   * is installed and CSE is disabled — without reading any vault data. The
   * handshake plus `session/keepalive` is the least-sensitive proof available.
   */
  async checkConnectivity(): Promise<void> {
    await this.ensureSession();
    const res = await this.request(
      this.apiUrl('/session/keepalive'),
      { method: 'GET', headers: this.sessionHeaders() },
      'GET /session/keepalive',
      true,
      newCorrelationId(),
    );
    await discardBody(res);
  }

  /** Best-effort session close; never throws. */
  async close(): Promise<void> {
    // Cut short any retry wait first, so shutdown is not held up by a backoff.
    this.shutdown.abort();
    if (!this.session) return;
    const headers = this.sessionHeaders();
    this.session = null;
    try {
      // The Passwords route for session/close is GET-only; a POST would 404 and
      // silently leave the session open until it expired.
      const res = await this.request(
        this.apiUrl('/session/close'),
        { method: 'GET', headers },
        'GET /session/close',
        false,
        newCorrelationId(),
      );
      await discardBody(res);
    } catch (err) {
      // Closing is best-effort — the server expires idle sessions anyway — but
      // log it so a protocol regression here stays observable.
      debug(`session close failed: ${err instanceof Error ? err.name : 'unknown error'}`);
    }
  }

  // ---------------------------------------------------------------------------
  // Authenticated API calls
  // ---------------------------------------------------------------------------

  /**
   * Make an authenticated Passwords API request and return the parsed JSON.
   * Transparently (re-)opens the session, retrying once if the server reports
   * the session is missing/expired.
   */
  async apiJson<T = unknown>(
    method: string,
    path: string,
    body?: unknown,
    options: ApiCallOptions = {},
  ): Promise<T> {
    return this.apiJsonInner<T>(method, path, body, options, true);
  }

  private async apiJsonInner<T>(
    method: string,
    path: string,
    body: unknown,
    options: ApiCallOptions,
    retryOnAuth: boolean,
  ): Promise<T> {
    await this.ensureSession();
    const headers = this.sessionHeaders();
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    const correlationId = newCorrelationId();
    const label = `${method} ${path}`;

    try {
      const res = await this.request(
        this.apiUrl(path),
        { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined },
        label,
        !options.mutation,
        correlationId,
      );
      const text = await res.text();
      if (!text) return undefined as T;
      try {
        return JSON.parse(text) as T;
      } catch {
        throw new Error(`Passwords API response was not valid JSON (${res.status})`);
      }
    } catch (err) {
      // A stale session shows up as 401/403/412; drop it and retry once. This
      // is safe even for a mutation: the server rejected the request before
      // acting on it.
      if (retryOnAuth && err instanceof HttpError && isStaleSession(err.status)) {
        debug('session rejected — reopening');
        this.session = null;
        return this.apiJsonInner<T>(method, path, body, options, false);
      }
      if (options.mutation && isAmbiguousWriteFailure(err)) {
        throw new WriteOutcomeUnknownError(label, err, correlationId);
      }
      throw err;
    }
  }
}

/**
 * True when a failed mutation gives no evidence about whether the server
 * applied it. A 429 or a 4xx means the request was rejected outright, so those
 * are reported as-is.
 */
function isAmbiguousWriteFailure(err: unknown): boolean {
  if (err instanceof ShutdownError) return true;
  if (err instanceof HttpError) return err.status >= 500;
  // A network error or timeout may have happened after the server committed.
  return err instanceof Error && err.name !== 'CseUnsupportedError';
}

/** Short opaque id tying a log line to an error message, carrying no content. */
function newCorrelationId(): string {
  return randomUUID().slice(0, 8);
}
