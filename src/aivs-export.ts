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
 * SCOPE LIMIT — no hash chain exists (audit 2026-07-26 §F2).
 * No issuer in this repository writes `hash_chain_prev` onto a TrustReceipt
 * (verified by exhaustive grep: zero write sites). The receipt corpus is a
 * plain table, NOT an append-only hash-linked log; the RFC 8785 prev-hash chain
 * that does exist in the product covers `OAuthAuditLog` and the enforcement
 * event log, not receipts. Consequently the `audit_log` projected here is a
 * SINGLE, UNLINKED entry, and the bundle says so explicitly via
 * {@link AivsProofBundle.chain_status}. This module MUST NOT imply otherwise:
 * the guarantee it provides is per-receipt integrity + signature, never
 * chain-of-custody across receipts.
 *
 * @see specs/062-vcap-verified-commerce-alignment/data-model.md §T062-01
 * @see docs/analisis/trust-receipts-auditoria-arquitectura-2026-07-26.md §F2
 */

import { createHash } from "node:crypto";
import { compactVerify, importJWK, type JWK } from "jose";

// ─── Types ──────────────────────────────────────────────────────────────────

/** One entry of the AIVS audit log projected from a single receipt. */
export interface AivsAuditLogEntry {
  /** Position within THIS bundle (always 0 — a bundle holds one receipt). */
  seq: number;
  /** This receipt's manifest_hash, tagged `sha256:<hex>`. */
  entry_hash: string;
  /**
   * The previous receipt's hash (`sha256:<hex>`), read from the receipt's own
   * `hash_chain_prev` claim. `null` whenever the receipt does not carry that
   * claim — which is the case for every receipt this platform issues today
   * (no issuer writes it). A `null` here means "no predecessor is asserted",
   * NOT "this is the first link of a verified chain".
   */
  prev_hash: string | null;
}

/**
 * Whether the projected audit log links to a predecessor.
 *
 * - `unlinked_single_entry` — the receipt asserts no predecessor. The bundle
 *   proves per-receipt integrity ONLY; no chain-of-custody claim is made.
 * - `linked_single_entry` — the receipt asserts a `hash_chain_prev`. Even then
 *   this bundle contains one entry: a consumer must obtain the predecessor
 *   bundle independently to walk the link.
 */
export type AivsChainStatus = "unlinked_single_entry" | "linked_single_entry";

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
  /**
   * Single-entry audit log projected from this receipt. Length is ALWAYS 1 —
   * the bundle carries one receipt and this module never fabricates links it
   * cannot prove.
   */
  audit_log: AivsAuditLogEntry[];
  /**
   * Honest, machine-readable declaration of what {@link audit_log} does and
   * does not assert. Present so a third-party consumer can branch on the
   * absence of a chain instead of inferring it from a `null` prev_hash.
   */
  chain_status: AivsChainStatus;
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
    chain_status:
      prevHash === null ? "unlinked_single_entry" : "linked_single_entry",
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
