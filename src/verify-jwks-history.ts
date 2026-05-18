/**
 * Cryptographic verification of `SignedJwksHistory` against the embedded
 * issuer-root certificate.
 *
 * Prior to this module the verifier accepted any JWKS history payload merely
 * by base64url-decoding the middle JWS segment, which let an attacker bundle a
 * forged history that resolved any `kid` to a key under their control.
 *
 * Flow (JWKS bundle trust anchor):
 *
 * 1. Extract the Ed25519 SubjectPublicKeyInfo from the issuer-root X.509 PEM
 *  via `crypto.createPublicKey({ key: pem, format: "pem" })`.
 * 2. Run `jose.compactVerify(signed.jws_compact, publicKey)` to validate
 *  the signature end-to-end.
 * 3. On success, return the parsed payload to the caller.
 *
 * Production cutover: the embedded issuer-root PEM shipped today is a
 * structural placeholder (see `embedded-issuer-root.ts` → `_STAGING_STUB_ROOT_PEM`).
 * Its body bytes do NOT decode to a verifying-capable Ed25519 key by design —
 * `crypto.createPublicKey` throws `ERR_OSSL_*` on the placeholder. We surface
 * that condition as `embedded_root_not_production` so callers can branch into
 * a structural-fallback path during the staging window. Once's key
 * ceremony lands the production cert, this branch becomes dead-but-safe.
 *
 */

import { compactVerify, decodeProtectedHeader } from "jose";
import { createPublicKey, createHash, type KeyObject } from "node:crypto";
import type { SignedJwksHistory, JwksHistoryEntry } from "./types-1.1.js";
import type { IssuerRootEntry } from "./embedded-issuer-root.js";
import { EMBEDDED_ISSUER_ROOTS } from "./embedded-issuer-root.js";

/**
 * SHA-256s of all currently-shipped staging-stub issuer roots. PEM bytes for
 * these roots are structural placeholders whose body does NOT decode to a
 * verifying-capable Ed25519 key (see `embedded-issuer-root.ts` JSDoc). When
 * `crypto.createPublicKey` rejects a PEM whose SHA-256 is in this set we
 * report `embedded_root_not_production` so callers can branch into the
 * staging-fallback path. Production cutover via replaces these entries
 * and this set is updated to reflect the new constants — at which point the
 * fallback branch is dead-but-safe.
 */
const STAGING_STUB_ROOT_SHA256: ReadonlySet<string> = new Set(
  EMBEDDED_ISSUER_ROOTS.map((entry) => entry.sha256.toLowerCase())
);

function pemSha256(pem: string): string {
  return createHash("sha256").update(Buffer.from(pem, "utf8")).digest("hex");
}

/**
 * Parsed inner payload of a verified `jwks-history.jws`. The runtime type is
 * intentionally loose — this module verifies the SIGNATURE; structural
 * narrowing lives downstream in `verify-1.1.ts` / `verify-export-bundle.ts`.
 */
export interface ParsedJwksHistoryPayload {
  schema_version?: string;
  entries: JwksHistoryEntry[];
  history_chain_sha256?: string;
}

/**
 * Stable machine-readable failure reasons returned by
 * {@link verifyJwksHistorySignature}. Callers MUST switch on these (never on
 * `Error.message` text).
 */
export type JwksHistoryVerifyReason =
  | "malformed_jws"
  | "unsupported_alg"
  | "embedded_root_not_production"
  | "root_pem_invalid"
  | "signature_invalid"
  | "payload_invalid";

export interface JwksHistoryVerifyResult {
  valid: boolean;
  reason?: JwksHistoryVerifyReason;
  payload?: ParsedJwksHistoryPayload;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function isJwsCompactShape(jws: string): boolean {
  const parts = jws.split(".");
  if (parts.length !== 3) return false;
  return parts.every((p) => p.length > 0 && /^[A-Za-z0-9_-]+$/.test(p));
}

/**
 * Extract Ed25519 public key from an X.509 SubjectPublicKeyInfo PEM. Returns
 * the imported KeyObject on success, or a discriminated-failure tuple
 * indicating whether the PEM is a known staging stub vs genuinely malformed.
 *
 * Detection of the staging stub is purely structural: any PEM that fails
 * `createPublicKey` parsing AND whose body contains the documented
 * placeholder marker is treated as the stub. The marker check is defensive —
 * production certs ceremonied via will both parse successfully AND lack
 * the marker, so this path is unreachable in production.
 */
type ImportResult =
  | { ok: true; key: KeyObject }
  | { ok: false; reason: "embedded_root_not_production" | "root_pem_invalid" };

function importIssuerRootPublicKey(pem: string): ImportResult {
  try {
    const key = createPublicKey({ key: pem, format: "pem" });
    return { ok: true, key };
  } catch {
    // Detect staging-stub roots by SHA-256 match against EMBEDDED_ISSUER_ROOTS.
    // The staging stubs have body bytes that fail X.509 parsing by design;
    // production certs ceremonied via will parse successfully and never
    // reach this branch.
    const sha = pemSha256(pem);
    if (STAGING_STUB_ROOT_SHA256.has(sha)) {
      return { ok: false, reason: "embedded_root_not_production" };
    }
    return { ok: false, reason: "root_pem_invalid" };
  }
}

function decodePayload(
  payloadBytes: Uint8Array
): ParsedJwksHistoryPayload | null {
  try {
    const obj = JSON.parse(
      Buffer.from(payloadBytes).toString("utf8")
    ) as unknown;
    if (typeof obj !== "object" || obj === null) return null;
    const entries = (obj as { entries?: unknown }).entries;
    if (!Array.isArray(entries)) return null;
    return obj as ParsedJwksHistoryPayload;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

/**
 * Verify the JWS Compact signature on a `SignedJwksHistory` bundle against
 * the embedded issuer-root certificate.
 *
 * Returns `{ valid: true, payload }` only when the signature verifies AND
 * the payload is structurally sound. All failure paths set `valid: false`
 * AND a stable {@link JwksHistoryVerifyReason}; the `embedded_root_not_production`
 * reason is the SOLE branch under which callers may safely fall back to
 * structural-only parsing (during staging — see file JSDoc).
 */
export async function verifyJwksHistorySignature(
  signed: SignedJwksHistory,
  rootEntry: IssuerRootEntry
): Promise<JwksHistoryVerifyResult> {
  // 1. Structural JWS shape ------------------------------------------------
  if (!isJwsCompactShape(signed.jws_compact)) {
    return { valid: false, reason: "malformed_jws" };
  }

  // 2. Algorithm header check ---------------------------------------------
  let alg: string | undefined;
  try {
    const header = decodeProtectedHeader(signed.jws_compact);
    alg = typeof header.alg === "string" ? header.alg : undefined;
  } catch {
    return { valid: false, reason: "malformed_jws" };
  }
  if (alg !== "EdDSA") {
    return { valid: false, reason: "unsupported_alg" };
  }

  // 3. Import root public key ---------------------------------------------
  const imported = importIssuerRootPublicKey(rootEntry.pem);
  if (!imported.ok) {
    return { valid: false, reason: imported.reason };
  }

  // 4. Cryptographic verification -----------------------------------------
  let payloadBytes: Uint8Array;
  try {
    const verified = await compactVerify(signed.jws_compact, imported.key);
    payloadBytes = verified.payload;
  } catch {
    return { valid: false, reason: "signature_invalid" };
  }

  // 5. Payload parse + minimal structural narrowing ------------------------
  const payload = decodePayload(payloadBytes);
  if (!payload) {
    return { valid: false, reason: "payload_invalid" };
  }

  return { valid: true, payload };
}
