import {
  verifyTimestamp,
  type MerchantTsaPolicy,
  type TimestampEvidenceLike,
  type TimestampVerificationResult,
} from "@agenticmcpstores/trust-receipt-tsa-client";
import type { ReceiptEnvelope, TrustReceiptV11Body } from "./types-1.1.js";

/**
 * Options accepted by {@link verifyTimestampEvidence}.
 *
 * SECURITY (T-CR-002): `tsaRootCertSha256Allowlist` is the operator-controlled
 * pre-approved list of TSA root cert SHA-256 hashes (64-hex, lowercase). The
 * envelope-supplied `evidence.tsa_root_cert_sha256` is attacker-controlled and
 * MUST NOT be used as a trust pin on its own — a malicious bundle could
 * self-pin its own forged TSA chain. We compare the envelope-claimed root
 * against the allowlist BEFORE delegating to {@link verifyTimestamp}, then
 * pass ONLY the allowlist as `rootCertSha256Pins`.
 *
 * Default `[]` ⇒ fail-closed: any TST is rejected with `tsa_root_not_trusted`.
 *
 * `trustAnchorPemSha256` is the issuer trust anchor (R16). It is reused as a
 * fallback pin ONLY when `tsaRootCertSha256Allowlist` is empty AND the trust
 * anchor is supplied — for the rare deployment where the issuer root is also
 * the TSA root. New deployments SHOULD configure the allowlist explicitly.
 */
export interface VerifyTimestampEvidenceOptions {
  readonly envelope: ReceiptEnvelope;
  readonly receipt: TrustReceiptV11Body;
  readonly policyOidAllowlist: readonly string[];
  readonly trustAnchorPemSha256: string;
  readonly tsaRootCertSha256Allowlist?: readonly string[];
  readonly toleranceSeconds?: number;
  /**
   * T-CR-007: per-merchant TSA policy (fail-open default per FR-024,
   * fail-closed override). Plumbed through to the underlying
   * {@link verifyTimestamp}; when absent the TSA client default applies.
   */
  readonly merchantTsaPolicy?: MerchantTsaPolicy;
}

export type VerifyTimestampEvidenceResult =
  | (TimestampVerificationResult & { readonly evidenceType: "RFC3161" })
  | {
      readonly evidenceType: "unavailable";
      readonly valid: false;
      readonly reason: string;
      readonly attemptedAt: number;
      readonly tsa?: string;
    };

/**
 * Stable error code emitted when the envelope-claimed TSA root is not in the
 * operator-supplied allowlist. Surfaced via the `errorCode` field of the
 * returned {@link TimestampVerificationResult}; consumers should map it to
 * their public error taxonomy (e.g. `V11VerifyErrorCode`).
 */
export const TSA_ROOT_NOT_TRUSTED_ERROR_CODE = "tsa_root_not_trusted";

function normalizeHex(value: string): string {
  return value.trim().toLowerCase();
}

export async function verifyTimestampEvidence(
  options: VerifyTimestampEvidenceOptions
): Promise<VerifyTimestampEvidenceResult> {
  const evidence = options.envelope.timestamp_evidence;
  if (evidence.type === "unavailable") {
    return {
      evidenceType: "unavailable",
      valid: false,
      reason: evidence.reason,
      attemptedAt: evidence.attempted_at,
      tsa: evidence.attempted_tsa[0],
    };
  }

  // ── T-CR-002 fix: never trust envelope-supplied root as a pin. ─────────
  // Build the effective pin set from operator-controlled inputs only:
  //   1. `tsaRootCertSha256Allowlist` if non-empty (preferred path).
  //   2. Fallback to `[trustAnchorPemSha256]` ONLY when the allowlist is
  //      empty AND a trust anchor is configured (back-compat for issuer-
  //      doubles-as-TSA deployments).
  //   3. Otherwise empty — fail-closed.
  const allowlist = (options.tsaRootCertSha256Allowlist ?? []).map(
    normalizeHex
  );
  const trustAnchor = normalizeHex(options.trustAnchorPemSha256 ?? "");
  const pins: readonly string[] =
    allowlist.length > 0
      ? allowlist
      : trustAnchor.length > 0
        ? [trustAnchor]
        : [];

  // Gate the envelope-claimed TSA root against the pin set BEFORE crypto.
  // An empty pin set means "no TSA roots trusted" → reject every TST.
  const envelopeRoot = normalizeHex(evidence.tsa_root_cert_sha256);
  if (pins.length === 0 || !pins.includes(envelopeRoot)) {
    // The upstream `TimestampVerificationError` enum does NOT include the new
    // gating code (the gate is verifier-side, not crypto-side). We surface
    // it through the same `errorCode` field so callers can `mapTimestampError`
    // it uniformly; the assertion below preserves the existing public shape.
    return {
      evidenceType: "RFC3161",
      valid: false,
      errorCode:
        TSA_ROOT_NOT_TRUSTED_ERROR_CODE as unknown as TimestampVerificationResult["errorCode"],
      errorDetail:
        pins.length === 0
          ? "no TSA roots configured (fail-closed)"
          : `envelope tsa_root_cert_sha256=${envelopeRoot} not in operator allowlist`,
    };
  }

  const result = await verifyTimestamp({
    receiptPayload: options.envelope.receipt,
    evidence: {
      ...evidence,
      tolerance_seconds: options.toleranceSeconds ?? evidence.tolerance_seconds,
    } satisfies TimestampEvidenceLike,
    rootCertSha256Pins: pins,
    policyOidAllowlist: options.policyOidAllowlist,
    receiptIssuedAt: options.receipt.issued_at,
    ...(options.merchantTsaPolicy !== undefined
      ? { merchantPolicy: options.merchantTsaPolicy }
      : {}),
  });
  return { ...result, evidenceType: "RFC3161" };
}
