/**
 * @agenticmcpstores/trust-receipt-verifier
 *
 * TrustReceipt open standard — cross-protocol agentic commerce evidence receipts.
 * Standalone package: no Prisma/DB dependency.
 */

// Schema + types
export {
  TrustReceiptSchema,
  type TrustReceipt,
  type TrustReceiptPayload,
  type ProtocolArtifact,
  type RiskSignal,
  type TrustProviderAssertion,
  type VerificationMethod,
  type Attachment,
} from "./schema/trust-receipt.schema.js";

// Verifier
export {
  verifyTrustReceipt,
  parseTrustReceiptUnsafe,
  type VerifyOptions,
  type VerifyResult,
  type VerifyFailureReason,
  type PublicJwk,
} from "./verifier.js";

// Issuer
export { issueTrustReceipt, type IssueOptions } from "./issuer.js";

// v1.0 verifier (spec-049 T050) — schema-version-routed entry for the T052 dispatcher.
// Pre-existing `verifyTrustReceipt` above remains the canonical v1.0 alias for
// backward compatibility.
export {
  verifyReceiptV10,
  type V10VerifyResult,
  type VerifyV10Options,
  type TrustReceiptV10,
} from "./verify-1.0.js";

// v1.1 envelope verifier (spec-049 T051).
// Re-exported with a v1.1-namespaced `VerifyOptions` alias to avoid colliding
// with the v1.0 `VerifyOptions` already exported above from `./verifier.js`.
export {
  verifyReceiptEnvelope,
  verifyTimestampEvidenceStub,
  type V11VerifyResult,
  type V11VerifyErrorCode,
  type VerifyOptions as VerifyV11Options,
} from "./verify-1.1.js";

export {
  verifyTimestampEvidence,
  type VerifyTimestampEvidenceOptions,
  type VerifyTimestampEvidenceResult,
} from "./verify-timestamp-evidence.js";

// v1.1 types (envelope, body, posture, history) for downstream consumers.
export type {
  ReceiptEnvelope,
  TrustReceiptV11Body,
  LegalPosture,
  ReceiptSubject,
  SignedJwksHistory,
  JwksHistoryEntry,
} from "./types-1.1.js";

// Embedded issuer trust anchors (T422 well-known endpoint consumes this).
export {
  EMBEDDED_ISSUER_ROOTS,
  findIssuerRootBySha256,
  getActiveIssuerRoot,
  type IssuerRootEntry,
} from "./embedded-issuer-root.js";

// ─── T052 dispatcher ──────────────────────────────────────────────────────────
//
// Routes a verification request to the v1.0 or v1.1 verifier.
//
// Cutover semantics (spec-049 FR-018, research.md R8):
//   - v1.0 receipts MUST continue to verify ≥ 7 years post-cutover.
//   - v1.1 envelopes are the new default emission format.
//   - The dispatcher tags v1.0 results with `legacy_pre_eidas_hardening` so
//     callers can surface a soft-deprecation signal without breaking interop.
//
// Wire-format discrimination (post-Codex round 1 D11 + round 2 D29):
//   - v1.0 = bare JWS Compact (3 dot-separated base64url segments).
//   - v1.1 = JSON envelope object with required keys `receipt` (string JWS) and
//     `envelope_metadata` (object). The envelope is the media-typed wrapper;
//     the inner JWS is the signed body.
//
// @see specs/049-trust-receipt-eidas-hardening/spec.md FR-018
// @see specs/049-trust-receipt-eidas-hardening/research.md R8

import { verifyReceiptV10 as _verifyV10 } from "./verify-1.0.js";
import type { V10VerifyResult } from "./verify-1.0.js";
import { verifyReceiptEnvelope as _verifyV11 } from "./verify-1.1.js";
import type {
  V11VerifyResult,
  VerifyOptions as V11VerifyOptions,
} from "./verify-1.1.js";
import type { ReceiptEnvelope } from "./types-1.1.js";

/**
 * Discriminated input for {@link verifyReceiptAuto}.
 */
export type VerifyInput =
  | { kind: "v10_jws"; jws: string; jwks: object }
  | {
      kind: "v11_envelope";
      envelope: ReceiptEnvelope | string;
      verifyOptions: V11VerifyOptions;
    };

/**
 * Dispatcher result. Carries `dispatched_to` so callers can branch without
 * inspecting `schema_version` directly.
 */
export type DispatcherResult =
  | (V10VerifyResult & { dispatched_to: "v1.0" })
  | (V11VerifyResult & { dispatched_to: "v1.1" });

/**
 * Verify a TrustReceipt by explicit `kind` discrimination.
 *
 * - `kind: "v10_jws"` → calls {@link verifyReceiptV10} (T050) and appends the
 *   `legacy_pre_eidas_hardening` warning per FR-018 cutover semantics.
 * - `kind: "v11_envelope"` → calls {@link verifyReceiptEnvelope} (T051).
 *
 * @see specs/049-trust-receipt-eidas-hardening/spec.md FR-018
 */
export async function verifyReceiptAuto(
  input: VerifyInput
): Promise<DispatcherResult> {
  if (input.kind === "v10_jws") {
    const result = await _verifyV10(input.jws, input.jwks);
    return {
      ...result,
      warnings: [...result.warnings, "legacy_pre_eidas_hardening"],
      dispatched_to: "v1.0",
    };
  }
  const result = await _verifyV11(input.envelope, input.verifyOptions);
  return { ...result, dispatched_to: "v1.1" };
}

/**
 * Auto-detect the receipt format from a string blob.
 *
 * Detection rules (post-Codex round 2 D29):
 *  - JSON-parseable object with both `receipt` (string) and `envelope_metadata`
 *    (object) → `"v1.1"`.
 *  - JWS Compact (3 dot-separated base64url segments) → `"v1.0"`.
 *  - Otherwise → `"unknown"`.
 */
export function detectReceiptFormat(blob: string): "v1.0" | "v1.1" | "unknown" {
  // Try JSON first — v1.1 envelope is a JSON object.
  const trimmed = blob.trim();
  if (trimmed.startsWith("{")) {
    try {
      const parsed: unknown = JSON.parse(trimmed);
      if (
        typeof parsed === "object" &&
        parsed !== null &&
        "receipt" in parsed &&
        typeof (parsed as { receipt: unknown }).receipt === "string" &&
        "envelope_metadata" in parsed &&
        typeof (parsed as { envelope_metadata: unknown }).envelope_metadata ===
          "object" &&
        (parsed as { envelope_metadata: unknown }).envelope_metadata !== null
      ) {
        return "v1.1";
      }
    } catch {
      // fall through
    }
  }
  // v1.0 = JWS Compact (3 base64url segments).
  if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(trimmed)) {
    return "v1.0";
  }
  return "unknown";
}

// ─── T557 — AdES claims gate (post-Codex round 2 D27) ─────────────────────────
//
// AdES-conformance claims are only legitimate when the receipt:
//   1. Has `legal_posture === "ades_candidate_timestamped"` AND
//   2. Carries ZERO `legal_posture_warnings`.
//
// Any warning (e.g. `agent_identity_absent`, `tsa_unavailable_fail_open`,
// `consent_evidence_redacted_partial`) downgrades the receipt out of AdES
// candidacy regardless of base posture.
//
// @see specs/049-trust-receipt-eidas-hardening/spec.md FR-019 (legal_posture)
// @see specs/049-trust-receipt-eidas-hardening/CODEX-REMEDIATION-2026-05-04.md D27

/**
 * Returns true iff the receipt body+envelope qualifies for AdES candidacy
 * claims under post-Codex round 2 D27. Callers MUST gate any "AdES-aligned"
 * marketing/legal claim on this helper — never on `legal_posture` alone.
 *
 * Accepts either a `TrustReceiptV11Body` directly or a `ReceiptEnvelope`. The
 * envelope path uses `envelope_metadata.legal_posture` only for the warning
 * count check (verifier-recomputed posture is authoritative for the base
 * posture and lives on the body after a successful verify).
 */
export function isAdesClaimEligible(input: {
  legal_posture: string;
  legal_posture_warnings: ReadonlyArray<unknown> | undefined;
}): boolean {
  return (
    input.legal_posture === "ades_candidate_timestamped" &&
    Array.isArray(input.legal_posture_warnings) &&
    input.legal_posture_warnings.length === 0
  );
}

// ─── T559 — Media types (post-Codex round 2 D29) ──────────────────────────────
//
// v1.1 envelope responses MUST advertise their media type explicitly so
// clients (dashboards, agents, export bundles) can discriminate from v1.0
// bare JWS responses. Mixing both formats in a single response is forbidden.

/**
 * Media type for v1.1 receipt envelope responses (single envelope per
 * response body, JSON-encoded). Includes `receipt` (JWS Compact), required
 * `envelope_metadata`, and optional `protocol_artifact_sidecars` +
 * `timestamp_evidence`.
 */
export const MEDIA_TYPE_RECEIPT_ENVELOPE_V11 =
  "application/vnd.trusteed.receipt-envelope+json";

/**
 * Media type for v1.0 bare JWS Compact responses (string body, single JWS,
 * 3 dot-separated base64url segments). Distinct from v1.1 to ensure clients
 * select the correct verifier path. Per RFC 7515.
 */
export const MEDIA_TYPE_RECEIPT_JWS_V10 = "application/jose";
