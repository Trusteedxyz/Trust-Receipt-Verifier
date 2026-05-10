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
  createRemoteJWKSet,
  errors,
  type JWK,
} from "jose";
import { TrustReceiptSchema } from "./schema/trust-receipt.schema.js";
import type { TrustReceipt } from "./schema/trust-receipt.schema.js";

// ─── Public types ─────────────────────────────────────────────────────────────

export type PublicJwk = JWK;

export interface VerifyOptions {
  /** Fetch JWKS from a URL (used when jwks not provided inline). */
  jwksUrl?: string;
  /** Inline public JWK set (used when jwksUrl not provided). */
  jwks?: PublicJwk[];
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
  | "jwks_fetch_failed";

export interface VerifyResult {
  valid: boolean;
  receipt?: TrustReceipt;
  reason?: VerifyFailureReason;
  errors?: string[];
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

// ─── Main verifier ────────────────────────────────────────────────────────────

/**
 * Verify a compact JWS TrustReceipt token.
 *
 * Steps (per SPEC §4):
 * 1. Parse JWS header — 3 segments, alg must be "EdDSA", kid must be present.
 * 2. Resolve key material (remote JWKS URL or inline JWK set).
 * 3. Verify JWS signature with jose compactVerify.
 * 4. Validate payload against TrustReceiptSchema (Zod) + cross-check kid.
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

  // 2. Build key resolver
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let keyInput: any = null;

  if (options.jwksUrl) {
    try {
      keyInput = createRemoteJWKSet(new URL(options.jwksUrl));
    } catch {
      // URL constructor threw — malformed jwksUrl
      return { valid: false, reason: "jwks_fetch_failed" };
    }
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
      errors: ["No jwksUrl or jwks provided in VerifyOptions"],
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

  const nowSeconds = Math.floor(Date.now() / 1000);

  // 5a. Check not yet valid (issued_at with tolerance)
  if (receipt.issued_at > nowSeconds + clockTolerance) {
    return { valid: false, receipt, reason: "not_yet_valid" };
  }

  // 5b. Check expired (expires_at with tolerance)
  if (receipt.expires_at < nowSeconds - clockTolerance) {
    return { valid: false, receipt, reason: "expired" };
  }

  return { valid: true, receipt };
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
