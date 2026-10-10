/**
 * Public result/option types for the v1.1 envelope verifier. Split out of
 * verify-1.1.ts (file-size limit); re-exported from there, API unchanged.
 */

import type { MerchantTsaPolicy } from "@agenticmcpstores/trust-receipt-tsa-client";
import type {
  ReceiptEnvelope,
  TrustReceiptV11Body,
  LegalPosture,
  ReceiptSubject,
  SignedJwksHistory,
} from "./types-1.1.js";

// ---------------------------------------------------------------------------
// Public surface
// ---------------------------------------------------------------------------

/**
 * Stable error codes returned in `V11VerifyResult.errorCode` when
 * `outcome === "rejected"`.
 */
export type V11VerifyErrorCode =
  | "envelope_invalid_json"
  | "envelope_schema_invalid"
  | "jws_invalid"
  | "jws_signature_invalid"
  | "schema_invalid"
  | "missing_required_consent_context"
  | "receipt_subject_mismatch"
  | "envelope_metadata_receipt_id_mismatch"
  | "envelope_legal_posture_mismatch"
  | "protocol_artifact_sidecar_hash_mismatch"
  | "protocol_artifact_sidecar_duplicate"
  | "protocol_artifact_sidecar_unverifiable"
  | "unknown_kid"
  | "kid_outside_validity_window"
  | "tsa_invalid"
  | "tsa_status_not_granted"
  | "tsa_nonce_mismatch"
  | "tsa_policy_oid_unauthorized"
  | "tsa_eku_missing"
  | "tsa_chain_invalid"
  | "tsa_cert_revoked"
  | "tsa_revocation_unavailable"
  | "tsa_gen_time_out_of_tolerance"
  | "tsa_imprint_mismatch"
  | "tsa_token_mismatch"
  | "tsa_root_not_trusted"
  | "agent_identity_required_strict"
  | "schema_unsupported"
  | "jwks_history_signature_invalid"
  // M8 — the committed `history_chain_sha256` does not match the recomputed
  // hash chain over the presented entries (tamper-evident integrity check).
  | "jwks_history_chain_mismatch"
  // A6 — the resolved (cryptographically verified) issuer root's
  // [validFrom, validTo] window does not contain the receipt `issued_at`; a
  // retired/compromised root must not keep signing histories indefinitely.
  | "root_outside_validity_window"
  | "receipt_expired"
  | "receipt_not_yet_valid"
  // T-AUD-012 (GAP H4) — strict-mode semantic anchor/jwks verification.
  | "trust_anchor_stub_rejected"
  | "jwks_sha256_stub_rejected"
  | "trust_anchor_mismatch";

/**
 * Result of `verifyReceiptEnvelope`. When `outcome === "accepted"` (or
 * `"accepted_degraded"`) the `receipt`, `envelope`, and
 * `recomputedLegalPosture` fields are populated.
 *
 * `accepted_degraded` (additive 2026-07-27, audit §B1) means: the signature and
 * every structural check passed, but the receipt DECLARES — in its signed body
 * — that its chain of trust is unverifiable (`trust_anchor_staging`). It is a
 * deliberately NEW value so existing consumers that branch on
 * `outcome === "accepted"` keep refusing it; opting in is a conscious act.
 *
 * Scope limit: with no production trust anchor there is no chain of trust.
 * `accepted_degraded` attests internal consistency and issuer intent, NEVER
 * issuer authenticity.
 */
export interface V11VerifyResult {
  outcome: "accepted" | "accepted_degraded" | "rejected";
  schema_version: "1.1";
  errorCode?: V11VerifyErrorCode;
  errorDetail?: string;
  warnings: string[];
  receipt?: TrustReceiptV11Body;
  envelope?: ReceiptEnvelope;
  recomputedLegalPosture?: LegalPosture;
  timestampVerification?: {
    valid: boolean;
    attestedAt?: number;
    tsa?: string;
    reason?: string;
  };
}

/**
 * Options accepted by `verifyReceiptEnvelope`.
 *
 * `jwksHistory` is the issuer's signed JWKS history bundled into the export
 * bundle (or fetched online). `trustAnchorPemSha256` is the SHA-256 (64-hex)
 * of the embedded issuer root cert that the verifier pins against
 * (R16 trust anchor).
 */
export interface VerifyOptions {
  jwksHistory: SignedJwksHistory;
  trustAnchorPemSha256: string;
  policyOidAllowlist: string[];
  /**
   * Operator-controlled allowlist of TSA root cert SHA-256 hashes (64-hex,
   * lowercase). Default `[]` ⇒ fail-closed: any RFC 3161 TST is rejected
   * with `tsa_root_not_trusted`. See {@link verifyTimestampEvidence} for
   * back-compat semantics with `trustAnchorPemSha256`. (T-CR-002)
   */
  tsaRootCertSha256Allowlist?: readonly string[];
  toleranceSeconds?: number;
  /**
   * T-CR-007: per-merchant TSA policy (spec-049 FR-024). Default is
   * `fail_open` (resolved at the TSA client layer). Pass `fail_closed` to
   * reject any receipt whose revocation status could not be obtained.
   */
  merchantTsaPolicy?: MerchantTsaPolicy;
  /**
   * When true (default), an envelope `legal_posture` that disagrees with the
   * verifier-recomputed value yields `envelope_legal_posture_mismatch`. When
   * false, the mismatch is surfaced as a warning only.
   *
   * Verifier recomputation is ALWAYS performed regardless of this flag.
   */
  rejectOnEnvelopePostureMismatch?: boolean;
  /** Optional caller-supplied subject context (R18). */
  expectedSubject?: ReceiptSubject;
  /**
   * Opt-in escape hatch for staging-stub trust anchors (T-CR-001, review
   * round 2). When the bundled `jwksHistory.signed_by_root_sha256` does
   * NOT resolve to an entry in the embedded issuer-root list, OR resolves to
   * an entry whose private-key material has not yet been provisioned (the
   * `embedded_root_not_production` staging stub case), the verifier behaves
   * as follows:
   *
   *  - `false` (default — production fail-closed): the receipt is REJECTED
   *    with `errorCode: "jwks_history_signature_invalid"` and
   *    `errorDetail: "root_not_in_trust_anchor"`. NO structural fallback to
   *    `parseJwksHistoryPayload` is performed, so a bundle CANNOT smuggle a
   *    forged `kid` past verification by pointing at an unknown root.
   *
   *  - `true` (staging / dev / pre-T420 ceremony): the verifier falls back to
   *    structural-only parsing of the JWKS history payload and emits the
   *    non-fatal warning `jwks_history_signature_unverifiable_staging_root`.
   *    This path MUST NOT be enabled in production deployments — the
   *    embedded issuer root must be production-validated before relying on
   *    chain-of-trust assertions.
   */
  allowStagingRoots?: boolean;
  /**
   * Injectable verification clock (UNIX seconds) for the temporal
   * `issued_at` / `expires_at` checks. Defaults to wall-clock
   * `Math.floor(Date.now() / 1000)` when omitted, so production callers need
   * not supply it. Conformance/test harnesses pass a fixed value so the suite
   * is deterministic regardless of the host clock — the temporal check itself
   * is NOT weakened, it merely honors the caller-supplied "now". (GAP H1a)
   */
  currentTimeSeconds?: number;
  /**
   * T-AUD-012 (GAP H4) — semantic trust-anchor / jwks-pin verification mode.
   *
   * The Zod layer validates `verification_methods.trust_anchor_sha256` and
   * `jwks_sha256` only by REGEX FORMAT, so an all-zeros opaque stub anchor
   * passes shape validation. This option adds the SEMANTIC layer:
   *
   *  - `"compat"` (default, canary rollout): a stub (`all-zeros`) anchor / jwks
   *    pin, an anchor that does not match the operator-pinned
   *    `trustAnchorPemSha256`, or a buyer_agent receipt with no agent-identity
   *    binding are surfaced as NON-FATAL warnings — verification still
   *    succeeds. This keeps the rollout non-breaking while observability
   *    accumulates.
   *
   *  - `"strict"`: the same conditions are FATAL rejections
   *    (`trust_anchor_stub_rejected`, `jwks_sha256_stub_rejected`,
   *    `trust_anchor_mismatch`, `agent_identity_required_strict`).
   *
   * Default is `"compat"` so existing callers are unaffected during the canary.
   */
  mode?: "strict" | "compat";
}
