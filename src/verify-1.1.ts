/**
 * TrustReceipt v1.1 envelope verifier (spec-049 — eIDAS hardening).
 *
 * Implements FR-018 (verifier accepts envelope, validates JWS, recomputes
 * envelope-level evidence) plus the post-Codex round 2 invariants:
 *
 * - D22: envelope_metadata fields (receipt_id, legal_posture,
 *   legal_posture_warnings) are NOT signed — verifier MUST recompute against
 *   the JWS-signed body and reject (or warn) on mismatch. The verifier is
 *   AUTHORITATIVE for `legal_posture`: it recomputes from observed evidence
 *   (TST present? agent identity verified? subject?) and surfaces the result
 *   in `recomputedLegalPosture`.
 * - D23: JWKS history validity-window check — both `body.issued_at` AND
 *   `timestamp_evidence.issued_at_attested` MUST fall inside the resolved
 *   `kid`'s `[valid_from, valid_to]` window.
 * - D27: structured legal_posture_warnings reasons.
 *
 * Timestamp (RFC 3161) verification is intentionally STUBBED here — see
 * `verifyTimestampEvidenceStub` below. T430 (resolved 2026-05-05) shipped
 * the full RFC 3161 verification surface in
 * `@agenticmcpstores/trust-receipt-tsa-client` (`verifyTimestamp` orchestrator
 * + `verifyCmsSignerInfo` + `verifyCertPath` + `verifyRevocation`); the
 * remaining work tracked here is to bridge this verifier into that
 * function (passing `merchantPolicy` + `rootCertSha256Pins` from caller
 * config) so that v1.1 conformance tests stop relying on the stub.
 *
 * @see specs/049-trust-receipt-eidas-hardening/spec.md FR-018, FR-019..FR-019g
 * @see specs/049-trust-receipt-eidas-hardening/spec.md FR-020..FR-024, FR-032b
 * @see specs/049-trust-receipt-eidas-hardening/research.md R15, R16, R18
 * @see specs/049-trust-receipt-eidas-hardening/CODEX-REMEDIATION-2026-05-04.md
 */

import { compactVerify, importJWK, decodeProtectedHeader } from "jose";
import type { JWK } from "jose";
import { ReceiptEnvelopeSchema, TrustReceiptV11BodySchema } from "./zod-1.1.js";
import type {
  ReceiptEnvelope,
  TrustReceiptV11Body,
  LegalPosture,
  ReceiptSubject,
  SignedJwksHistory,
  JwksHistoryEntry,
} from "./types-1.1.js";
import { verifyTimestampEvidence } from "./verify-timestamp-evidence.js";
import {
  verifyJwksHistorySignature,
  type ParsedJwksHistoryPayload as VerifiedJwksHistoryPayload,
} from "./verify-jwks-history.js";
import { findIssuerRootBySha256 } from "./embedded-issuer-root.js";

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
  | "unknown_kid"
  | "kid_outside_validity_window"
  | "tsa_invalid"
  | "tsa_status_not_granted"
  | "tsa_nonce_mismatch"
  | "tsa_policy_oid_unauthorized"
  | "tsa_eku_missing"
  | "tsa_chain_invalid"
  | "tsa_cert_revoked"
  | "tsa_gen_time_out_of_tolerance"
  | "tsa_imprint_mismatch"
  | "tsa_token_mismatch"
  | "agent_identity_required_strict"
  | "schema_unsupported"
  | "jwks_history_signature_invalid";

/**
 * Result of `verifyReceiptEnvelope`. When `outcome === "accepted"` the
 * `receipt`, `envelope`, and `recomputedLegalPosture` fields are populated.
 */
export interface V11VerifyResult {
  outcome: "accepted" | "rejected";
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
  toleranceSeconds?: number;
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
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

interface ParsedJwksHistoryPayload {
  schema_version?: string;
  entries: JwksHistoryEntry[];
  history_chain_sha256?: string;
}

/**
 * Parse the inner payload of `jwksHistory.jws_compact` without verifying its
 * signature. The history bundle MUST also be signature-verified upstream when
 * reading from an untrusted source; here we use it only to look up the kid.
 *
 * Returns null on any structural problem.
 */
function parseJwksHistoryPayload(
  signed: SignedJwksHistory
): ParsedJwksHistoryPayload | null {
  const parts = signed.jws_compact.split(".");
  if (parts.length !== 3) return null;
  try {
    const json = Buffer.from(parts[1] ?? "", "base64url").toString("utf8");
    const obj = JSON.parse(json) as ParsedJwksHistoryPayload;
    if (!Array.isArray(obj.entries)) return null;
    return obj;
  } catch {
    return null;
  }
}

/**
 * Resolve a `kid` in the JWKS history. Returns the entry or `null` if the
 * kid is unknown.
 */
function resolveKid(
  history: ParsedJwksHistoryPayload,
  kid: string
): JwksHistoryEntry | null {
  for (const entry of history.entries ?? []) {
    if (entry.kid === kid) return entry;
  }
  return null;
}

/**
 * D23: both `body.issued_at` AND `timestamp_evidence.issued_at_attested` MUST
 * fall inside the resolved kid's `[valid_from, valid_to]` window. A null
 * `valid_to` means "still active".
 */
function isWithinValidityWindow(
  entry: JwksHistoryEntry,
  ...timestamps: number[]
): boolean {
  for (const ts of timestamps) {
    if (ts < entry.valid_from) return false;
    if (entry.valid_to !== null && ts > entry.valid_to) return false;
  }
  return true;
}

/**
 * Compute SHA-256 of arbitrary bytes and return `<64-hex>` (no algo prefix).
 */
async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Recompute the verifier-authoritative legal_posture from observed evidence
 * (post-Codex round 2 D22). The truth table:
 *
 * - merchant_admin subject ⇒ `merchant_admin_action`
 * - buyer_agent + tst-present + agent-identity ⇒ `ades_candidate_timestamped`
 * - buyer_agent + tst-absent + agent-identity ⇒ `ades_candidate_no_tsa`
 * - buyer_agent + tst-present + no agent-identity ⇒ `degraded_no_agent_identity`
 * - buyer_agent + tst-absent + no agent-identity ⇒ `simple_electronic_seal`
 *
 * Agent-identity is considered "verified" when ANY of the following is true:
 *  - `body.trust_provider_assertions` is a non-empty array (spec-045 adapter
 *    output — preferred signal), OR
 *  - `body.authorization_evidence.protocol_authorization_ref` is set (the
 *    receipt cites a signed protocol mandate such as AP2/MCAP/UCP, which
 *    inherently binds an agent identity at the protocol layer).
 *
 * We stay loose because spec-045 adapter shapes vary and not every issuer
 * embeds a `trust_provider_assertions` field at issuance time.
 */
function recomputeLegalPosture(
  body: {
    receipt_subject: ReceiptSubject;
    trust_provider_assertions?: unknown;
    authorization_evidence?: { protocol_authorization_ref?: string };
  },
  envelope: { timestamp_evidence: { type: string } }
): LegalPosture {
  if (body.receipt_subject === "merchant_admin") {
    return "merchant_admin_action";
  }
  const tstPresent = envelope.timestamp_evidence.type === "RFC3161";
  const assertions = body.trust_provider_assertions ?? [];
  const hasAssertions = Array.isArray(assertions) && assertions.length > 0;
  const hasProtocolAuthRef =
    typeof body.authorization_evidence?.protocol_authorization_ref ===
      "string" &&
    body.authorization_evidence.protocol_authorization_ref.length > 0;
  const agentIdentityVerified = hasAssertions || hasProtocolAuthRef;
  if (tstPresent && agentIdentityVerified) return "ades_candidate_timestamped";
  if (!tstPresent && agentIdentityVerified) return "ades_candidate_no_tsa";
  if (tstPresent && !agentIdentityVerified) return "degraded_no_agent_identity";
  return "simple_electronic_seal";
}

/**
 * STUB — full RFC 3161 verification lands in T430 (cert chain to pinned root,
 * policy OID allowlist match, nonce echo, imprint match against JWS Compact
 * bytes, OCSP/CRL freshness at TSA genTime). For now this returns
 * `{ valid: true }` so downstream code paths can be wired and tested.
 *
 * TODO(T430): replace with full RFC 3161 implementation per
 * specs/049-trust-receipt-eidas-hardening/research.md R15.
 */
export function verifyTimestampEvidenceStub(
  envelope: {
    timestamp_evidence:
      | {
          type: "RFC3161";
          issued_at_attested: number;
          tsa_endpoint: string;
        }
      | { type: "unavailable"; reason: string };
  },
  // T430 will use these:
  _options: Pick<
    VerifyOptions,
    "trustAnchorPemSha256" | "policyOidAllowlist" | "toleranceSeconds"
  >
): { valid: boolean; attestedAt?: number; tsa?: string; reason?: string } {
  const ev = envelope.timestamp_evidence;
  if (ev.type === "unavailable") {
    return { valid: false, reason: ev.reason };
  }
  return {
    valid: true,
    attestedAt: ev.issued_at_attested,
    tsa: ev.tsa_endpoint,
  };
}

function reject(
  code: V11VerifyErrorCode,
  detail: string,
  warnings: string[] = []
): V11VerifyResult {
  return {
    outcome: "rejected",
    schema_version: "1.1",
    errorCode: code,
    errorDetail: detail,
    warnings,
  };
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

/**
 * Verify a TrustReceipt v1.1 envelope end-to-end.
 *
 * Flow (FR-018 + post-Codex round 2 D22, D23, D27):
 *  1. Parse envelope (string → JSON if needed) and validate against
 *     `ReceiptEnvelopeSchema`.
 *  2. Decode the JWS Compact protected header to extract `kid`.
 *  3. Resolve `kid` in the bundled `jwksHistory`. Reject `unknown_kid` if
 *     missing.
 *  4. Verify the JWS signature with the resolved JWK (Ed25519).
 *  5. Validate the parsed body against `TrustReceiptV11BodySchema`.
 *  6. D23 validity-window check — `issued_at` AND `issued_at_attested` MUST
 *     fall inside the resolved kid's `[valid_from, valid_to]`.
 *  7. Subject discrimination + missing-context guard.
 *  8. envelope_metadata.receipt_id mirror equality (D22).
 *  9. Recompute every protocol-artifact sidecar SHA-256 and confirm it matches
 *     a `body.protocol_artifacts[].hash` entry.
 * 10. Recompute `legal_posture` from observed evidence (D22). Reject or warn
 *     based on `rejectOnEnvelopePostureMismatch`.
 * 11. Verify timestamp evidence (STUB — see `verifyTimestampEvidenceStub`).
 * 12. Optional `expectedSubject` context check (R18).
 *
 * @see specs/049-trust-receipt-eidas-hardening/spec.md FR-018
 */
export async function verifyReceiptEnvelope(
  envelopeInput: ReceiptEnvelope | string,
  options: VerifyOptions
): Promise<V11VerifyResult> {
  const warnings: string[] = [];

  // 1. Parse envelope -------------------------------------------------------
  let envelopeRaw: unknown;
  if (typeof envelopeInput === "string") {
    try {
      envelopeRaw = JSON.parse(envelopeInput);
    } catch (err) {
      return reject(
        "envelope_invalid_json",
        err instanceof Error ? err.message : "invalid JSON"
      );
    }
  } else {
    envelopeRaw = envelopeInput;
  }

  const envelopeParse = ReceiptEnvelopeSchema.safeParse(envelopeRaw);
  if (!envelopeParse.success) {
    return reject(
      "envelope_schema_invalid",
      envelopeParse.error.issues.map((i) => i.message).join("; ")
    );
  }
  const envelope = envelopeParse.data;

  // 2. Decode JWS protected header -----------------------------------------
  const compact = envelope.receipt;
  const compactParts = compact.split(".");
  if (compactParts.length !== 3) {
    return reject("jws_invalid", "JWS Compact MUST have 3 segments");
  }

  let kid: string | undefined;
  let alg: string | undefined;
  try {
    const header = decodeProtectedHeader(compact);
    kid = typeof header.kid === "string" ? header.kid : undefined;
    alg = typeof header.alg === "string" ? header.alg : undefined;
  } catch (err) {
    return reject(
      "jws_invalid",
      err instanceof Error ? err.message : "could not decode JWS header"
    );
  }
  if (!kid) {
    return reject("jws_invalid", "JWS protected header missing kid");
  }
  if (alg !== "EdDSA") {
    return reject("jws_invalid", `unsupported alg: ${alg ?? "<missing>"}`);
  }

  // 3. JWKS history signature verification + kid resolution -----------------
  // 3a. JWS shape check — must be 3 segments (header.payload.sig)
  const historyJwsParts = options.jwksHistory.jws_compact.split(".");
  if (historyJwsParts.length !== 3) {
    return reject(
      "jwks_history_signature_invalid",
      "JWKS history JWS must have exactly 3 segments",
      warnings
    );
  }

  // 3b. Alg check — only EdDSA is accepted
  let historyAlg: string | undefined;
  try {
    const historyHeader = decodeProtectedHeader(
      options.jwksHistory.jws_compact
    );
    historyAlg =
      typeof historyHeader.alg === "string" ? historyHeader.alg : undefined;
  } catch {
    return reject(
      "jwks_history_signature_invalid",
      "could not decode JWKS history JWS protected header",
      warnings
    );
  }
  if (historyAlg !== "EdDSA") {
    return reject(
      "jwks_history_signature_invalid",
      `JWKS history JWS alg must be EdDSA, got: ${historyAlg ?? "<missing>"}`,
      warnings
    );
  }

  // 3c. Signature verification or staging fallback
  let historyPayload: VerifiedJwksHistoryPayload | null;
  const rootEntry = findIssuerRootBySha256(
    options.jwksHistory.signed_by_root_sha256
  );
  if (!rootEntry) {
    // Unknown root SHA — staging window or unknown issuer; fall back to
    // structural-only parse and emit a non-fatal warning (F1 staging path).
    warnings.push("jwks_history_signature_unverifiable_staging_root");
    historyPayload = parseJwksHistoryPayload(options.jwksHistory);
  } else {
    const sigResult = await verifyJwksHistorySignature(
      options.jwksHistory,
      rootEntry
    );
    if (!sigResult.valid) {
      if (sigResult.reason === "embedded_root_not_production") {
        // Staging stub root — structural fallback is safe per spec
        warnings.push("jwks_history_signature_unverifiable_staging_root");
        historyPayload = parseJwksHistoryPayload(options.jwksHistory);
      } else {
        return reject(
          "jwks_history_signature_invalid",
          `JWKS history signature verification failed: ${sigResult.reason ?? "unknown"}`,
          warnings
        );
      }
    } else {
      historyPayload = sigResult.payload ?? null;
    }
  }

  if (!historyPayload) {
    return reject(
      "unknown_kid",
      "jwksHistory payload could not be parsed; unable to resolve kid",
      warnings
    );
  }
  const entry = resolveKid(historyPayload, kid);
  if (!entry) {
    return reject(
      "unknown_kid",
      `kid not found in jwksHistory: ${kid}`,
      warnings
    );
  }

  // 4. Verify JWS signature ------------------------------------------------
  let publicKey;
  try {
    publicKey = await importJWK(entry.jwk_pub as JWK, "EdDSA");
  } catch (err) {
    return reject(
      "jws_signature_invalid",
      err instanceof Error ? err.message : "could not import JWK"
    );
  }

  let payloadBytes: Uint8Array;
  try {
    const verified = await compactVerify(compact, publicKey);
    payloadBytes = verified.payload;
  } catch (err) {
    return reject(
      "jws_signature_invalid",
      err instanceof Error ? err.message : "JWS signature verification failed"
    );
  }

  // 5. Validate body schema ------------------------------------------------
  let bodyJson: unknown;
  try {
    bodyJson = JSON.parse(Buffer.from(payloadBytes).toString("utf8"));
  } catch (err) {
    return reject(
      "schema_invalid",
      err instanceof Error ? err.message : "JWS payload not JSON"
    );
  }

  // Up-front schema_version check for clearer error code
  if (
    typeof bodyJson === "object" &&
    bodyJson !== null &&
    "schema_version" in bodyJson &&
    (bodyJson as { schema_version: unknown }).schema_version !== "1.1"
  ) {
    return reject(
      "schema_unsupported",
      `unsupported schema_version: ${String((bodyJson as { schema_version: unknown }).schema_version)}`
    );
  }

  const bodyParse = TrustReceiptV11BodySchema.safeParse(bodyJson);
  if (!bodyParse.success) {
    // Map missing-context Zod errors to the more specific error code.
    const missingContext = bodyParse.error.issues.some(
      (i) =>
        i.path[0] === "buyer_agent_consent_context" ||
        i.path[0] === "merchant_admin_authorization_context"
    );
    return reject(
      missingContext ? "missing_required_consent_context" : "schema_invalid",
      bodyParse.error.issues.map((i) => i.message).join("; ")
    );
  }
  const body = bodyParse.data;

  // 6. D23 validity-window check ------------------------------------------
  const attestedAt =
    envelope.timestamp_evidence.type === "RFC3161"
      ? envelope.timestamp_evidence.issued_at_attested
      : envelope.timestamp_evidence.attempted_at;
  if (!isWithinValidityWindow(entry, body.issued_at, attestedAt)) {
    return reject(
      "kid_outside_validity_window",
      `kid ${kid} window=[${entry.valid_from}, ${entry.valid_to ?? "active"}], issued_at=${body.issued_at}, attested=${attestedAt}`
    );
  }

  // 7. Subject context check (caller-supplied) ----------------------------
  if (
    options.expectedSubject !== undefined &&
    body.receipt_subject !== options.expectedSubject
  ) {
    return reject(
      "receipt_subject_mismatch",
      `expected ${options.expectedSubject}, got ${body.receipt_subject}`
    );
  }

  // 8. envelope_metadata.receipt_id mirror (D22) --------------------------
  if (envelope.envelope_metadata.receipt_id !== body.receipt_id) {
    return reject(
      "envelope_metadata_receipt_id_mismatch",
      `envelope.receipt_id=${envelope.envelope_metadata.receipt_id} body.receipt_id=${body.receipt_id}`
    );
  }

  // 9. Protocol artifact sidecar hashes -----------------------------------
  if (envelope.protocol_artifact_sidecars) {
    const knownHashes = new Set(body.protocol_artifacts.map((a) => a.hash));
    for (const sidecar of envelope.protocol_artifact_sidecars) {
      let payload: Uint8Array;
      try {
        payload = Uint8Array.from(Buffer.from(sidecar.payload_b64, "base64"));
      } catch (err) {
        return reject(
          "protocol_artifact_sidecar_hash_mismatch",
          `sidecar ${sidecar.type}: payload_b64 invalid (${err instanceof Error ? err.message : "decode error"})`
        );
      }
      const computedHex = await sha256Hex(payload);
      const computedTagged = `sha256:${computedHex}`;
      if (!knownHashes.has(computedTagged) && !knownHashes.has(sidecar.hash)) {
        return reject(
          "protocol_artifact_sidecar_hash_mismatch",
          `sidecar ${sidecar.type}: computed sha256:${computedHex} does not match any body.protocol_artifacts[].hash`
        );
      }
      // Also confirm the sidecar's own declared hash matches the bytes.
      if (
        sidecar.hash.startsWith("sha256:") &&
        sidecar.hash !== computedTagged
      ) {
        return reject(
          "protocol_artifact_sidecar_hash_mismatch",
          `sidecar ${sidecar.type}: declared ${sidecar.hash} != computed sha256:${computedHex}`
        );
      }
    }
  }

  // 10. Recompute legal_posture (D22 — verifier authoritative) ------------
  const recomputedPosture = recomputeLegalPosture(body, envelope);
  const envelopePosture = envelope.envelope_metadata.legal_posture;
  if (envelopePosture !== recomputedPosture) {
    const rejectOnMismatch = options.rejectOnEnvelopePostureMismatch ?? true;
    if (rejectOnMismatch) {
      return reject(
        "envelope_legal_posture_mismatch",
        `envelope=${envelopePosture} recomputed=${recomputedPosture}`
      );
    }
    warnings.push("envelope_legal_posture_mismatch_recomputed");
  }

  // 11. Timestamp verification -------------------------------------------
  const tsResult = await verifyTimestampEvidence({
    envelope: envelope as unknown as ReceiptEnvelope,
    receipt: body as unknown as TrustReceiptV11Body,
    trustAnchorPemSha256: options.trustAnchorPemSha256,
    policyOidAllowlist: options.policyOidAllowlist,
    toleranceSeconds: options.toleranceSeconds ?? 60,
  });

  if (tsResult.evidenceType === "unavailable") {
    warnings.push(tsResult.reason);
  } else if (!tsResult.valid) {
    return reject(
      mapTimestampError(tsResult.errorCode),
      tsResult.errorDetail ?? "RFC 3161 timestamp verification failed",
      warnings
    );
  }

  // 12. Accepted ---------------------------------------------------------
  // Zod's inferred body type uses plain `string` for tagged digests; the
  // public TS types narrow these to template-literal `<algo>:<hex>` aliases.
  // Both representations carry identical runtime values (Zod has already
  // enforced the regex), so we cast at the public boundary.
  return {
    outcome: "accepted",
    schema_version: "1.1",
    warnings,
    receipt: body as unknown as TrustReceiptV11Body,
    envelope: envelope as unknown as ReceiptEnvelope,
    recomputedLegalPosture: recomputedPosture,
    timestampVerification: tsResult,
  };
}

function mapTimestampError(code: string | undefined): V11VerifyErrorCode {
  switch (code) {
    case "tsa_status_not_granted":
    case "tsa_nonce_mismatch":
    case "tsa_policy_oid_unauthorized":
    case "tsa_eku_missing":
    case "tsa_chain_invalid":
    case "tsa_cert_revoked":
    case "tsa_gen_time_out_of_tolerance":
    case "tsa_imprint_mismatch":
    case "tsa_token_mismatch":
      return code;
    default:
      return "tsa_invalid";
  }
}
