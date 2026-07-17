/**
 * TrustReceipt verifier.
 *
 * Verifies compact JWS tokens against the TrustReceiptSchema.
 * Supports JWKS URL (remote) and inline public JWK sets.
 * Uses jose for all JWS operations — no custom crypto.
 */

import {
  compactVerify,
  createLocalJWKSet,
  errors,
  importJWK,
  type JWK,
} from "jose";
import { TrustReceiptSchema } from "./schema/trust-receipt.schema.js";
import type { TrustReceipt } from "./schema/trust-receipt.schema.js";
import { TrustReceiptLegacyCompactSchema } from "./schema/trust-receipt-legacy.schema.js";
import type { TrustReceiptLegacyCompact } from "./schema/trust-receipt-legacy.schema.js";
// Reuses the v1.1 envelope verifier's windowed-key-history shape (same
// rotation model) instead of redefining an equivalent type here — see
// `types-1.1.ts` JwksHistoryEntry for the field docs. Already re-exported
// from the package barrel (`index.ts`), so no additional export needed here.
import type { JwksHistoryEntry } from "./types-1.1.js";

// ─── Public types ─────────────────────────────────────────────────────────────

export type PublicJwk = JWK;
export type { JwksHistoryEntry };

export interface VerifyOptions {
  /**
   * Fetch JWKS from a URL (used when neither `jwksHistory` nor `jwks` is
   * provided). Keys MAY carry optional `valid_from`/`valid_to` (unix
   * seconds) custom members; when present they gate `issued_at`/`iat` the
   * same way `jwksHistory` does. Keys without them are treated as always
   * valid (back-compat with plain RFC 7517 JWKS documents).
   */
  jwksUrl?: string;
  /**
   * Inline public JWK set (used when neither `jwksHistory` nor `jwksUrl` is
   * provided). No validity-window enforcement — kept for back-compat with
   * existing callers. Prefer `jwksHistory` for new integrations.
   */
  jwks?: PublicJwk[];
  /**
   * Windowed key history — same rotation model as the v1.1 envelope
   * verifier. When provided, this takes priority over `jwksUrl`/`jwks` for
   * BOTH kid resolution and `issued_at`/`iat` validity-window enforcement,
   * so a retired key can no longer verify a receipt back-dated or forged
   * outside the window it was actually active.
   */
  jwksHistory?: JwksHistoryEntry[];
  /** Clock tolerance in seconds. Default: 30. */
  clockToleranceSeconds?: number;
}

export type VerifyFailureReason =
  | "invalid_jws"
  | "unknown_kid"
  | "tampered_signature"
  | "schema_invalid"
  | "expired"
  | "not_yet_valid"
  | "jwks_fetch_failed"
  | "kid_outside_validity_window";

export interface VerifyResult {
  valid: boolean;
  receipt?: TrustReceipt;
  reason?: VerifyFailureReason;
  errors?: string[];
  /**
   * Which v1.0 shape matched. `"canonical"` = the standard `TrustReceiptSchema`
   * shape (populated in `receipt`). `"legacy_compact"` = the JWT-style compact
   * payload actually emitted by the platform issuer since spec-040 (populated in
   * `legacyReceipt`). Absent when verification failed before schema matching.
   * See `schema/trust-receipt-legacy.schema.ts` (C3 closure).
   */
  variant?: "canonical" | "legacy_compact";
  /**
   * Parsed legacy-compact payload — populated ONLY when
   * `variant === "legacy_compact"`. The cryptographic JWS check is identical to
   * the canonical path; only the post-verify schema shape differs.
   */
  legacyReceipt?: TrustReceiptLegacyCompact;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

interface JwsHeader {
  kid: string;
  alg: string;
}

/**
 * Validates JWS structure and extracts the protected header.
 * Returns null if the token is malformed, has the wrong number of segments,
 * or is missing required header fields.
 */
function parseJwsHeader(jws: string): JwsHeader | null {
  const parts = jws.split(".");
  if (parts.length !== 3) return null;
  const headerSegment = parts[0];
  if (!headerSegment) return null;
  try {
    const headerJson = Buffer.from(headerSegment, "base64url").toString("utf8");
    const header = JSON.parse(headerJson) as Record<string, unknown>;
    if (typeof header.kid !== "string" || !header.kid) return null;
    if (typeof header.alg !== "string" || !header.alg) return null;
    return { kid: header.kid, alg: header.alg };
  } catch {
    return null;
  }
}

function extractPayloadFromJws(jws: string): unknown | null {
  const payloadSegment = jws.split(".")[1];
  if (!payloadSegment) return null;
  try {
    const payloadJson = Buffer.from(payloadSegment, "base64url").toString(
      "utf8"
    );
    return JSON.parse(payloadJson);
  } catch {
    return null;
  }
}

/**
 * Classifies a jose error thrown during compactVerify into a VerifyFailureReason.
 *
 * Separates JWKS fetch/network failures from cryptographic failures so callers
 * can distinguish "key server is down" from "signature was tampered".
 */
function classifyJoseError(err: unknown): VerifyFailureReason {
  if (err instanceof errors.JWKSTimeout) return "jwks_fetch_failed";
  if (err instanceof errors.JWKSInvalid) return "jwks_fetch_failed";
  if (err instanceof errors.JWKSNoMatchingKey) return "unknown_kid";
  if (err instanceof errors.JWKSMultipleMatchingKeys) return "unknown_kid";
  // Network-level fetch errors (ECONNREFUSED, DNS failure, etc.)
  if (err instanceof TypeError) {
    const msg = err.message.toLowerCase();
    if (
      msg.includes("fetch") ||
      msg.includes("network") ||
      msg.includes("econnrefused") ||
      msg.includes("failed to fetch")
    ) {
      return "jwks_fetch_failed";
    }
  }
  return "tampered_signature";
}

/**
 * Finds the history entry for `kid`. Returns null when absent OR when more
 * than one entry claims the same `kid` — an ambiguous match is treated as
 * unresolvable (mirrors jose's `JWKSMultipleMatchingKeys` guard that the
 * previous `createRemoteJWKSet`-based path enforced).
 */
function resolveHistoryEntry(
  history: readonly JwksHistoryEntry[],
  kid: string
): JwksHistoryEntry | null {
  let match: JwksHistoryEntry | null = null;
  for (const entry of history) {
    if (entry.kid !== kid) continue;
    if (match) return null; // ambiguous — more than one match
    match = entry;
  }
  return match;
}

/**
 * `ts` (unix seconds) MUST fall inside `[entry.valid_from, entry.valid_to]`.
 * `valid_to === null` means the key is still active (no upper bound).
 */
function isWithinValidityWindow(entry: JwksHistoryEntry, ts: number): boolean {
  if (ts < entry.valid_from) return false;
  if (entry.valid_to !== null && ts > entry.valid_to) return false;
  return true;
}

/**
 * Maps raw JWKS `keys[]` entries to `JwksHistoryEntry[]`. Keys without a
 * `kid` are dropped (unresolvable). Optional numeric `valid_from`/`valid_to`
 * custom members become the window; absent ⇒ `valid_from: 0, valid_to: null`
 * (always valid — matches pre-windowing behavior for issuers that don't
 * publish rotation windows).
 */
function toHistoryEntries(keys: readonly PublicJwk[]): JwksHistoryEntry[] {
  const entries: JwksHistoryEntry[] = [];
  for (const key of keys) {
    if (typeof key.kid !== "string" || !key.kid) continue;
    const raw = key as Record<string, unknown>;
    const validFrom = typeof raw.valid_from === "number" ? raw.valid_from : 0;
    const validTo = typeof raw.valid_to === "number" ? raw.valid_to : null;
    entries.push({
      kid: key.kid,
      jwk_pub: key as unknown as Record<string, unknown>,
      valid_from: validFrom,
      valid_to: validTo,
    });
  }
  return entries;
}

/** Fetches a plain RFC 7517 JWKS document and maps it to windowed entries. */
async function fetchJwksAsHistory(
  jwksUrl: string
): Promise<{ ok: true; entries: JwksHistoryEntry[] } | { ok: false }> {
  try {
    const res = await fetch(jwksUrl, {
      headers: { accept: "application/json" },
      // Mirrors jose's RemoteJWKSet default timeout (5s) previously used here.
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) return { ok: false };
    const body = (await res.json()) as { keys?: unknown };
    if (!body || !Array.isArray(body.keys)) return { ok: false };
    return { ok: true, entries: toHistoryEntries(body.keys as PublicJwk[]) };
  } catch {
    return { ok: false };
  }
}

// ─── Main verifier ────────────────────────────────────────────────────────────

/**
 * Verify a compact JWS TrustReceipt token.
 *
 * Steps (per SPEC §4):
 * 1. Parse JWS header — 3 segments, alg must be "EdDSA", kid must be present.
 * 2. Resolve key material (jwksHistory > jwksUrl > inline jwks — see
 *    `VerifyOptions`).
 * 3. Verify JWS signature with jose compactVerify.
 * 4. Validate payload against TrustReceiptSchema (Zod) + cross-check kid,
 *    then (4b) enforce the resolved key's `[valid_from, valid_to]` window
 *    when kid resolution came from a windowed source.
 * 5. Check issued_at / expires_at with clock tolerance.
 */
export async function verifyTrustReceipt(
  jws: string,
  options: VerifyOptions
): Promise<VerifyResult> {
  const clockTolerance = options.clockToleranceSeconds ?? 30;

  // 1. Parse and validate JWS protected header
  const jwsHeader = parseJwsHeader(jws);
  if (!jwsHeader) {
    return { valid: false, reason: "invalid_jws" };
  }
  // SPEC §5.1: implementations MUST NOT accept receipts signed with other algorithms.
  if (jwsHeader.alg !== "EdDSA") {
    return { valid: false, reason: "invalid_jws" };
  }
  const { kid } = jwsHeader;

  // 2. Build key resolver. `windowEntry` is set whenever kid resolution came
  // from a windowed source (jwksHistory or jwksUrl) — used in step 5 to
  // enforce that issued_at/iat falls inside the key's active window.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let keyInput: any = null;
  let windowEntry: JwksHistoryEntry | null = null;

  if (options.jwksHistory && options.jwksHistory.length > 0) {
    const entry = resolveHistoryEntry(options.jwksHistory, kid);
    if (!entry) {
      return { valid: false, reason: "unknown_kid" };
    }
    try {
      keyInput = await importJWK(entry.jwk_pub as JWK, jwsHeader.alg);
    } catch {
      return { valid: false, reason: "unknown_kid" };
    }
    windowEntry = entry;
  } else if (options.jwksUrl) {
    const fetched = await fetchJwksAsHistory(options.jwksUrl);
    if (!fetched.ok) {
      return { valid: false, reason: "jwks_fetch_failed" };
    }
    const entry = resolveHistoryEntry(fetched.entries, kid);
    if (!entry) {
      return { valid: false, reason: "unknown_kid" };
    }
    try {
      keyInput = await importJWK(entry.jwk_pub as JWK, jwsHeader.alg);
    } catch {
      return { valid: false, reason: "unknown_kid" };
    }
    windowEntry = entry;
  } else if (options.jwks && options.jwks.length > 0) {
    const matchingKey = options.jwks.find((k) => k.kid === kid);
    if (!matchingKey) {
      return { valid: false, reason: "unknown_kid" };
    }
    try {
      keyInput = createLocalJWKSet({ keys: [matchingKey] });
    } catch {
      return { valid: false, reason: "unknown_kid" };
    }
  } else {
    return {
      valid: false,
      reason: "invalid_jws",
      errors: ["No jwksHistory, jwksUrl, or jwks provided in VerifyOptions"],
    };
  }

  // 3. Verify JWS signature
  let payloadBytes: Uint8Array;
  let verifiedKid: string | undefined;
  try {
    const result = await compactVerify(jws, keyInput);
    payloadBytes = result.payload;
    verifiedKid = (result.protectedHeader as { kid?: string }).kid;
  } catch (err) {
    return { valid: false, reason: classifyJoseError(err) };
  }

  // 4. Parse and validate payload
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(payloadBytes));
  } catch {
    return {
      valid: false,
      reason: "schema_invalid",
      errors: ["Payload is not valid JSON"],
    };
  }

  const schemaResult = TrustReceiptSchema.safeParse(parsed);
  if (!schemaResult.success) {
    // C3 closure: the canonical schema did not match. Before rejecting, try the
    // v1.0-legacy compact shape actually emitted by the platform issuer
    // (spec-040 US2). This branch is entered ONLY when the payload does NOT
    // declare a `schema_version` (so a genuine v1.1 body or a forward-version
    // receipt is never silently down-graded here) AND the crypto signature has
    // ALREADY been verified above. It does not relax the canonical schema.
    const hasSchemaVersion =
      typeof parsed === "object" &&
      parsed !== null &&
      "schema_version" in (parsed as Record<string, unknown>);
    if (!hasSchemaVersion) {
      const legacyResult = TrustReceiptLegacyCompactSchema.safeParse(parsed);
      if (legacyResult.success) {
        return verifyLegacyCompact(legacyResult.data, verifiedKid, {
          clockTolerance,
          windowEntry,
        });
      }
    }
    return {
      valid: false,
      reason: "schema_invalid",
      errors: schemaResult.error.errors.map(
        (e) => `${e.path.join(".")}: ${e.message}`
      ),
    };
  }

  const receipt = schemaResult.data;

  // SPEC §5.2: kid MUST match in both JWS protected header and receipt payload.
  if (receipt.kid !== verifiedKid) {
    return {
      valid: false,
      reason: "schema_invalid",
      errors: [
        `kid mismatch: header=${String(verifiedKid)}, payload=${receipt.kid}`,
      ],
    };
  }

  // 4b. Validity-window check (rotation gap closure) — only enforced when kid
  // resolution came from a windowed source (jwksHistory or jwksUrl). A key
  // retired at time T can no longer verify a receipt whose issued_at falls
  // outside the window it was actually active, closing the gap where a
  // compromised/retired private key could keep forging fresh receipts.
  if (windowEntry && !isWithinValidityWindow(windowEntry, receipt.issued_at)) {
    return { valid: false, receipt, reason: "kid_outside_validity_window" };
  }

  const nowSeconds = Math.floor(Date.now() / 1000);

  // 5a. Check not yet valid (issued_at with tolerance)
  if (receipt.issued_at > nowSeconds + clockTolerance) {
    return { valid: false, receipt, reason: "not_yet_valid" };
  }

  // 5b. Check expired (expires_at with tolerance)
  if (receipt.expires_at < nowSeconds - clockTolerance) {
    return { valid: false, receipt, reason: "expired" };
  }

  return { valid: true, receipt, variant: "canonical" };
}

/**
 * Finalize verification for a v1.0-legacy compact payload (C3 closure).
 *
 * Assumes the JWS signature has ALREADY been cryptographically verified by the
 * caller. Applies the two remaining post-verify checks that are meaningful for
 * the legacy shape:
 *   1. `kid` MUST match between the JWS protected header and the payload
 *      (SPEC §5.2 parity with the canonical path).
 *   2. `iat` not-yet-valid guard (with clock tolerance).
 *
 * Legacy receipts carry NO `expires_at`, so no expiry check is applied — this
 * is intentional and required by FR-018 (v1.0 MUST verify ≥ 7 years).
 */
function verifyLegacyCompact(
  legacy: TrustReceiptLegacyCompact,
  verifiedKid: string | undefined,
  opts: { clockTolerance: number; windowEntry: JwksHistoryEntry | null }
): VerifyResult {
  if (legacy.kid !== verifiedKid) {
    return {
      valid: false,
      reason: "schema_invalid",
      errors: [
        `kid mismatch: header=${String(verifiedKid)}, payload=${legacy.kid}`,
      ],
    };
  }

  // Same rotation-gap closure as the canonical path (see step 4b above).
  if (
    opts.windowEntry &&
    !isWithinValidityWindow(opts.windowEntry, legacy.iat)
  ) {
    return {
      valid: false,
      reason: "kid_outside_validity_window",
      variant: "legacy_compact",
      legacyReceipt: legacy,
    };
  }

  const nowSeconds = Math.floor(Date.now() / 1000);
  if (legacy.iat > nowSeconds + opts.clockTolerance) {
    return {
      valid: false,
      reason: "not_yet_valid",
      variant: "legacy_compact",
      legacyReceipt: legacy,
    };
  }

  return {
    valid: true,
    variant: "legacy_compact",
    legacyReceipt: legacy,
  };
}

// ─── Unsafe inspector ─────────────────────────────────────────────────────────

/**
 * Decode a compact JWS TrustReceipt WITHOUT verifying the signature.
 * For inspection / debugging only — do not trust the returned data.
 * Returns null if the JWS is malformed or the payload is not a valid TrustReceipt.
 */
export async function parseTrustReceiptUnsafe(
  jws: string
): Promise<TrustReceipt | null> {
  const raw = extractPayloadFromJws(jws);
  if (!raw) return null;

  const result = TrustReceiptSchema.safeParse(raw);
  if (!result.success) return null;

  return result.data;
}
