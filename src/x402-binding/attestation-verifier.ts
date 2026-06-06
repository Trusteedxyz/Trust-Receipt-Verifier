/**
 * Spec 054 T121 — Portable PII attestation verifier (FR-013a).
 *
 * Verifies an attestation JWS Compact returned by the merchant's PII
 * challenge endpoint (`PiiAttestationService.attest()` server-side; route
 * surface lands with T118 post Wave 3-B).
 *
 * The attestation is signed by the merchant root key (Ed25519) and carries a
 * JCS-canonicalized payload:
 *
 *   {
 *     "candidate_digest": "hmac-sha256:<hex>",
 *     "key_version": <int>,
 *     "matches": <bool>,
 *     "expected_hmac_hex": "hmac-sha256:<hex>"
 *   }
 *
 * This verifier:
 *   - Looks up the signing `kid` in the merchant's JWKS (`use: "sig"`).
 *   - Verifies the Ed25519 signature over `${headerB64}.${payloadB64}`.
 *   - Surfaces the merchant's `matches` verdict to the auditor.
 *
 * NEVER touches HMAC keys — the auditor's trust derives entirely from the
 * merchant root signature on the attestation envelope.
 *
 * Module is PORTABLE: only `node:crypto`. No filesystem, no env, no Prisma.
 *
 * @see specs/058-trustreceipt-x402-binding/spec.md FR-013a
 */

import { createPublicKey, verify as cryptoVerify } from "node:crypto";

import type { MerchantJwksDocument, JwksKey } from "./delegation-validator.js";

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export type AttestationVerificationReason =
  | "signature_invalid"
  | "kid_not_in_jwks"
  | "key_version_expired"
  | "malformed_attestation";

export interface AttestationVerificationResult {
  /** True iff the signature verifies against a JWKS-listed merchant root. */
  readonly valid: boolean;
  /** Merchant's verdict on the candidate value. Only meaningful when valid. */
  readonly matches: boolean;
  /** Tagged digest the merchant computed under their KMS key. */
  readonly candidateDigest: string;
  /** Key version the merchant used. */
  readonly keyVersion: number;
  /** When `valid` is false, the typed reason; never carries secrets. */
  readonly reason?: AttestationVerificationReason;
}

export interface VerifyPiiAttestationArgs {
  /** JWS Compact string returned by the merchant. */
  readonly attestationJws: string;
  /** JWKS snapshot retrieved out-of-band (e.g., from the issuer JWKS URL). */
  readonly jwks: MerchantJwksDocument;
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

interface AttestationPayload {
  readonly candidate_digest: string;
  readonly key_version: number;
  readonly matches: boolean;
  readonly expected_hmac_hex: string;
}

function malformed(
  reason: AttestationVerificationReason
): AttestationVerificationResult {
  return {
    valid: false,
    matches: false,
    candidateDigest: "",
    keyVersion: 0,
    reason,
  };
}

function decodeJsonSegment<T>(segment: string): T | null {
  try {
    const buf = Buffer.from(segment, "base64url");
    return JSON.parse(buf.toString("utf8")) as T;
  } catch {
    return null;
  }
}

function isAttestationPayload(value: unknown): value is AttestationPayload {
  if (value === null || typeof value !== "object") return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v.candidate_digest === "string" &&
    typeof v.expected_hmac_hex === "string" &&
    typeof v.matches === "boolean" &&
    Number.isInteger(v.key_version)
  );
}

function findSigKey(
  keys: readonly JwksKey[],
  kid: string
): JwksKey | undefined {
  return keys.find((k) => k.kid === kid && k.use === "sig");
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Verify a PII attestation JWS against the merchant JWKS.
 *
 * Never throws on validation failure; always returns a typed result.
 */
export function verifyPiiAttestation(
  args: VerifyPiiAttestationArgs
): AttestationVerificationResult {
  const { attestationJws, jwks } = args;

  if (typeof attestationJws !== "string" || attestationJws.length === 0) {
    return malformed("malformed_attestation");
  }
  const parts = attestationJws.split(".");
  if (parts.length !== 3) {
    return malformed("malformed_attestation");
  }
  const [headerB64, payloadB64, signatureB64] = parts;
  if (!headerB64 || !payloadB64 || !signatureB64) {
    return malformed("malformed_attestation");
  }

  const header = decodeJsonSegment<{ alg?: string; kid?: string }>(headerB64);
  if (!header || header.alg !== "EdDSA" || typeof header.kid !== "string") {
    return malformed("malformed_attestation");
  }

  const payload = decodeJsonSegment<unknown>(payloadB64);
  if (!isAttestationPayload(payload)) {
    return malformed("malformed_attestation");
  }

  if (
    !jwks ||
    typeof jwks !== "object" ||
    !Array.isArray((jwks as { keys?: unknown }).keys)
  ) {
    return malformed("kid_not_in_jwks");
  }
  const sigKey = findSigKey(jwks.keys, header.kid);
  if (!sigKey) {
    return malformed("kid_not_in_jwks");
  }

  let publicKey;
  try {
    publicKey = createPublicKey({
      key: { kty: "OKP", crv: "Ed25519", x: sigKey.x },
      format: "jwk",
    });
  } catch {
    return malformed("kid_not_in_jwks");
  }

  let signatureBytes: Buffer;
  try {
    signatureBytes = Buffer.from(signatureB64, "base64url");
  } catch {
    return malformed("malformed_attestation");
  }

  const signingInput = Buffer.from(`${headerB64}.${payloadB64}`, "utf8");
  let signatureOk = false;
  try {
    signatureOk = cryptoVerify(null, signingInput, publicKey, signatureBytes);
  } catch {
    return malformed("signature_invalid");
  }
  if (!signatureOk) {
    return {
      valid: false,
      matches: false,
      candidateDigest: payload.candidate_digest,
      keyVersion: payload.key_version,
      reason: "signature_invalid",
    };
  }

  return {
    valid: true,
    matches: payload.matches,
    candidateDigest: payload.candidate_digest,
    keyVersion: payload.key_version,
  };
}
