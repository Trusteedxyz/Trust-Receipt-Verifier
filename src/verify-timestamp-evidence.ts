import {
  verifyTimestamp,
  type TimestampEvidenceLike,
  type TimestampVerificationResult,
} from "@agenticmcpstores/trust-receipt-tsa-client";
import type { ReceiptEnvelope, TrustReceiptV11Body } from "./types-1.1.js";

/**
 * Error code returned when the TSA root certificate is not in the verifier's
 * trust anchor allowlist.
 */
export const TSA_ROOT_NOT_TRUSTED_ERROR_CODE = "tsa_root_not_trusted" as const;

export interface VerifyTimestampEvidenceOptions {
  readonly envelope: ReceiptEnvelope;
  readonly receipt: TrustReceiptV11Body;
  readonly policyOidAllowlist: readonly string[];
  readonly trustAnchorPemSha256: string;
  readonly toleranceSeconds?: number;
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

  const result = await verifyTimestamp({
    receiptPayload: options.envelope.receipt,
    evidence: {
      ...evidence,
      tolerance_seconds: options.toleranceSeconds ?? evidence.tolerance_seconds,
    } satisfies TimestampEvidenceLike,
    rootCertSha256Pins: [
      options.trustAnchorPemSha256,
      evidence.tsa_root_cert_sha256,
    ],
    policyOidAllowlist: options.policyOidAllowlist,
    receiptIssuedAt: options.receipt.issued_at,
  });
  return { ...result, evidenceType: "RFC3161" };
}
