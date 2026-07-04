/**
 * AIVS proof-bundle export (spec-062 US1).
 *
 * Projects a signed TrustReceipt (v1.0 JWS Compact, EdDSA) into an
 * AIVS-compatible proof bundle { manifest_hash, session_sig } per
 * draft-stone-aivs-00, WITHOUT modifying the signed payload.
 *
 * Offline-verifiable: `manifest_hash` is the SHA-256 of the exact signed
 * payload bytes (recoverable from the JWS by any third party), and
 * `session_sig` is the existing EdDSA signature. A consumer needs only the
 * JWS and the issuer JWKS — no Trusteed code — to verify integrity.
 *
 * @see specs/062-vcap-verified-commerce-alignment/data-model.md §T062-01
 */

import { createHash } from "node:crypto";
import { compactVerify, importJWK, type JWK } from "jose";

// ─── Types ──────────────────────────────────────────────────────────────────

/** One hash-chained entry of the AIVS audit log. */
export interface AivsAuditLogEntry {
  /** Position in the projected chain (0 for a single-receipt bundle). */
  seq: number;
  /** This receipt's manifest_hash, tagged `sha256:<hex>`. */
  entry_hash: string;
  /**
   * The previous receipt's hash (`sha256:<hex>`), or null for a genesis
   * receipt. Projected from the receipt's `hash_chain_prev`.
   */
  prev_hash: string | null;
}

/** AIVS-compatible proof bundle projected from a TrustReceipt. */
export interface AivsProofBundle {
  /** SHA-256 of the signed payload bytes, tagged `sha256:<hex>`. */
  manifest_hash: string;
  /** The original JWS Compact (EdDSA) — the AIVS session signature. */
  session_sig: string;
  /** Key ID from the JWS protected header, for offline key resolution. */
  kid: string;
  /** Signature algorithm from the JWS protected header. */
  alg: string;
  /** Hash-chained audit log preserving the receipt's `hash_chain_prev` link. */
  audit_log: AivsAuditLogEntry[];
}

/** A public JWK with a `kid` for offline key resolution. */
export interface AivsPublicJwk extends JWK {
  kid: string;
}

/** Options for {@link verifyAivsProofBundle}. */
export interface VerifyAivsBundleOptions {
  /** Issuer public keys (JWKS) to resolve the signing key by `kid`. */
  jwks: ReadonlyArray<AivsPublicJwk>;
}

/** Reason an AIVS bundle failed offline verification. */
export type AivsVerifyFailureReason =
  | "manifest_hash_mismatch"
  | "unknown_kid"
  | "signature_invalid"
  | "malformed_session_sig";

/** Result of {@link verifyAivsProofBundle}. */
export interface VerifyAivsBundleResult {
  valid: boolean;
  reason?: AivsVerifyFailureReason;
}

// ─── Export ─────────────────────────────────────────────────────────────────

/**
 * Project a signed TrustReceipt JWS into an AIVS proof bundle.
 *
 * The `manifest_hash` is computed over the exact bytes that were signed (the
 * base64url-decoded JWS payload segment), so it is reproducible by any third
 * party directly from the JWS. The signed payload is never re-canonicalized
 * or mutated.
 */
export function exportAivsProofBundle(jws: string): AivsProofBundle {
  const segments = jws.split(".");
  if (segments.length !== 3) {
    throw new Error("aivs_export: input is not a JWS Compact (3 segments)");
  }
  const [headerSegment, payloadSegment] = segments;

  const header = JSON.parse(
    Buffer.from(headerSegment, "base64url").toString("utf-8")
  ) as { alg?: string; kid?: string };

  const signedBytes = Buffer.from(payloadSegment, "base64url");
  const manifestHash =
    "sha256:" + createHash("sha256").update(signedBytes).digest("hex");

  const payload = JSON.parse(signedBytes.toString("utf-8")) as {
    hash_chain_prev?: string | null;
  };
  const prevHash = normalizeChainHash(payload.hash_chain_prev);

  return {
    manifest_hash: manifestHash,
    session_sig: jws,
    kid: header.kid ?? "",
    alg: header.alg ?? "",
    audit_log: [{ seq: 0, entry_hash: manifestHash, prev_hash: prevHash }],
  };
}

/**
 * Normalize a `hash_chain_prev` value (bare SHA-256 hex or already-tagged) to
 * the `sha256:<hex>` form so audit-log `prev_hash` is directly comparable to a
 * previous receipt's `manifest_hash`. Returns null for a genesis receipt.
 */
function normalizeChainHash(value: string | null | undefined): string | null {
  if (!value) return null;
  return value.startsWith("sha256:") ? value : `sha256:${value}`;
}

// ─── Offline verification ─────────────────────────────────────────────────────

/**
 * Verify an AIVS proof bundle offline.
 *
 * Two independent checks, both reproducible by any third party with just the
 * bundle and the issuer JWKS:
 *   1. `manifest_hash` equals the SHA-256 of the signed payload bytes recovered
 *      from `session_sig` (integrity of the projection).
 *   2. The EdDSA signature on `session_sig` validates against the resolved key.
 *
 * No network access and no Trusteed code are required.
 */
export async function verifyAivsProofBundle(
  bundle: AivsProofBundle,
  options: VerifyAivsBundleOptions
): Promise<VerifyAivsBundleResult> {
  const segments = bundle.session_sig.split(".");
  if (segments.length !== 3) {
    return { valid: false, reason: "malformed_session_sig" };
  }

  // Check 1 — manifest_hash binds to the exact signed bytes.
  const signedBytes = Buffer.from(segments[1], "base64url");
  const recomputed =
    "sha256:" + createHash("sha256").update(signedBytes).digest("hex");
  if (recomputed !== bundle.manifest_hash) {
    return { valid: false, reason: "manifest_hash_mismatch" };
  }

  // Check 2 — signature validates against the issuer key resolved by kid.
  const jwk = options.jwks.find((k) => k.kid === bundle.kid);
  if (!jwk) {
    return { valid: false, reason: "unknown_kid" };
  }

  try {
    const key = await importJWK(jwk, bundle.alg);
    await compactVerify(bundle.session_sig, key);
  } catch {
    return { valid: false, reason: "signature_invalid" };
  }

  return { valid: true };
}
