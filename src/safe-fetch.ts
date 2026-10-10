/**
 * Bounded HTTP(S) fetch for untrusted remote documents (JWKS, manifests,
 * extension artifacts).
 *
 * Why this exists: a bare `fetch(url)` followed by `res.json()` lets whoever
 * controls the URL (or a host in the middle) make the verifier read an
 * unbounded body, hang on a slow one, follow redirect chains forever, or be
 * bounced from https to plain http. Every remote document this package reads is
 * small, so every read goes through here with explicit ceilings.
 *
 * Guarantees:
 *  - only `http:` and `https:` URLs (no `file:`, `data:`, `ftp:`, ...);
 *  - ONE total deadline covering connect, redirects and the body stream;
 *  - the response size cap is enforced WHILE streaming (and early on a declared
 *    `Content-Length`), never after buffering the whole body;
 *  - redirects are handled manually, capped, and an https -> http hop is refused;
 *  - failures are a typed {@link SafeFetchError}.
 *
 * This helper does NOT authenticate content: a document it returns is still
 * untrusted and must be verified by the caller before any key in it is used.
 */

export type SafeFetchErrorCode =
  | "invalid_url"
  | "unsupported_scheme"
  | "timeout"
  | "response_too_large"
  | "too_many_redirects"
  | "redirect_downgrade"
  | "bad_redirect"
  | "network_error"
  | "http_error"
  | "invalid_json";

export class SafeFetchError extends Error {
  readonly code: SafeFetchErrorCode;
  readonly status?: number;
  constructor(code: SafeFetchErrorCode, message: string, status?: number) {
    super(message);
    this.name = "SafeFetchError";
    this.code = code;
    if (status !== undefined) this.status = status;
  }
}

export interface SafeFetchOptions {
  /** Total deadline in ms for the whole exchange (all redirects + body). Default 5000. */
  readonly timeoutMs?: number;
  /** Maximum response body size in bytes. Default 1 MiB. */
  readonly maxBytes?: number;
  /** Maximum number of redirects followed. Default 3. */
  readonly maxRedirects?: number;
  /** Extra request headers. */
  readonly headers?: Record<string, string>;
}

export interface SafeFetchResult {
  readonly status: number;
  readonly ok: boolean;
  /** Final URL after redirects. */
  readonly url: string;
  readonly body: Uint8Array;
}

export const SAFE_FETCH_DEFAULT_TIMEOUT_MS = 5_000;
export const SAFE_FETCH_DEFAULT_MAX_BYTES = 1024 * 1024;
export const SAFE_FETCH_DEFAULT_MAX_REDIRECTS = 3;

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

function parseHttpUrl(raw: string): URL {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new SafeFetchError("invalid_url", `not a valid URL: ${raw}`);
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    throw new SafeFetchError(
      "unsupported_scheme",
      `only http: and https: URLs are allowed (got ${u.protocol})`
    );
  }
  return u;
}

async function readBounded(
  res: Response,
  maxBytes: number,
  signal: AbortSignal
): Promise<Uint8Array> {
  const declared = res.headers.get("content-length");
  if (declared !== null) {
    const n = Number(declared);
    if (Number.isFinite(n) && n > maxBytes) {
      await res.body?.cancel().catch(() => undefined);
      throw new SafeFetchError(
        "response_too_large",
        `declared Content-Length ${n} exceeds limit of ${maxBytes} bytes`
      );
    }
  }
  if (!res.body) return new Uint8Array(0);
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      if (signal.aborted) throw new SafeFetchError("timeout", "deadline hit");
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        throw new SafeFetchError(
          "response_too_large",
          `response body exceeds limit of ${maxBytes} bytes`
        );
      }
      chunks.push(value);
    }
  } catch (err) {
    await reader.cancel().catch(() => undefined);
    throw err;
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.byteLength;
  }
  return out;
}

/** Fetches `url` under the limits in `options`. Throws {@link SafeFetchError}. */
export async function safeFetch(
  url: string,
  options: SafeFetchOptions = {}
): Promise<SafeFetchResult> {
  const timeoutMs = options.timeoutMs ?? SAFE_FETCH_DEFAULT_TIMEOUT_MS;
  const maxBytes = options.maxBytes ?? SAFE_FETCH_DEFAULT_MAX_BYTES;
  const maxRedirects =
    options.maxRedirects ?? SAFE_FETCH_DEFAULT_MAX_REDIRECTS;

  let current = parseHttpUrl(url);
  const signal = AbortSignal.timeout(timeoutMs);

  try {
    for (let hop = 0; ; hop++) {
      const res = await fetch(current.toString(), {
        redirect: "manual",
        signal,
        ...(options.headers ? { headers: options.headers } : {}),
      });

      if (REDIRECT_STATUSES.has(res.status)) {
        await res.body?.cancel().catch(() => undefined);
        if (hop >= maxRedirects) {
          throw new SafeFetchError(
            "too_many_redirects",
            `more than ${maxRedirects} redirects`
          );
        }
        const location = res.headers.get("location");
        if (!location) {
          throw new SafeFetchError(
            "bad_redirect",
            `redirect ${res.status} without Location header`
          );
        }
        let next: URL;
        try {
          next = new URL(location, current);
        } catch {
          throw new SafeFetchError("bad_redirect", "invalid Location header");
        }
        if (next.protocol !== "http:" && next.protocol !== "https:") {
          throw new SafeFetchError(
            "unsupported_scheme",
            `redirect to ${next.protocol} refused`
          );
        }
        if (current.protocol === "https:" && next.protocol === "http:") {
          throw new SafeFetchError(
            "redirect_downgrade",
            "redirect from https to http refused"
          );
        }
        current = next;
        continue;
      }

      const body = await readBounded(res, maxBytes, signal);
      return {
        status: res.status,
        ok: res.status >= 200 && res.status < 300,
        url: current.toString(),
        body,
      };
    }
  } catch (err) {
    if (err instanceof SafeFetchError) throw err;
    if (signal.aborted) {
      throw new SafeFetchError("timeout", `timed out after ${timeoutMs} ms`);
    }
    const msg = err instanceof Error ? err.message : String(err);
    throw new SafeFetchError("network_error", msg);
  }
}

/** {@link safeFetch} + UTF-8 decode. Non-2xx throws `http_error`. */
export async function safeFetchText(
  url: string,
  options: SafeFetchOptions = {}
): Promise<string> {
  const res = await safeFetch(url, options);
  if (!res.ok) {
    throw new SafeFetchError("http_error", `HTTP ${res.status}`, res.status);
  }
  return new TextDecoder().decode(res.body);
}

/** {@link safeFetchText} + JSON.parse. */
export async function safeFetchJson(
  url: string,
  options: SafeFetchOptions = {}
): Promise<unknown> {
  const text = await safeFetchText(url, options);
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new SafeFetchError("invalid_json", "response body is not valid JSON");
  }
}
