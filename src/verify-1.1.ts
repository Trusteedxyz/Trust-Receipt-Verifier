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
 * Timestamp (RFC 3161) verification is delegated to
 * `verifyTimestampEvidence` (`verify-timestamp-evidence.ts`), which wraps the
 * full RFC 3161 surface from `@agenticmcpstores/trust-receipt-tsa-client`
 * (`verifyTimestamp` orchestrator + `verifyCmsSignerInfo` + `verifyCertPath`
 * + `verifyRevocation`). Caller passes `merchantTsaPolicy` +
 * `tsaRootCertSha256Allowlist` via `VerifyOptions`. T-CR-012 (2026-05-10)
 * removed the legacy `verifyTimestampEvidenceStub` that lived here.
 *
 * @see specs/049-trust-receipt-eidas-hardening/spec.md FR-018, FR-019..FR-019g
 * @see specs/049-trust-receipt-eidas-hardening/spec.md FR-020..FR-024, FR-032b
 * @see specs/049-trust-receipt-eidas-hardening/research.md R15, R16, R18
 * @see specs/049-trust-receipt-eidas-hardening/CODEX-REMEDIATION-2026-05-04.md
 */

import { compactVerify, importJWK, decodeProtectedHeader } from "jose";
import type { JWK } from "jose";
import type { MerchantTsaPolicy } from "@agenticmcpstores/trust-receipt-tsa-client";
import { ReceiptEnvelopeSchema, TrustReceiptV11BodySchema } from "./zod-1.1.js";
import type {
  ReceiptEnvelope,
  TrustReceiptV11Body,
  LegalPosture,
  ReceiptSubject,
  SignedJwksHistory,
  JwksHistoryEntry,
  Rfc9421ProviderAssertion,
  HumanProviderAssertion,
  VisaTapProviderAssertion,
} from "./types-1.1.js";
import { verifyTimestampEvidence } from "./verify-timestamp-evidence.js";
import {
  verifyJwksHistorySignature,
  type ParsedJwksHistoryPayload as VerifiedJwksHistoryPayload,
} from "./verify-jwks-history.js";
import { findIssuerRootBySha256 } from "./embedded-issuer-root.js";
import type { IssuerRootEntry } from "./embedded-issuer-root.js";
import { createHash } from "node:crypto";
import canonicalize from "canonicalize";

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
   * Opt-in escape hatch for staging-stub trust anchors (T-CR-001 / Codex
   * round 2 D2/D3). When the bundled `jwksHistory.signed_by_root_sha256` does
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
   *
   * @see specs/049-trust-receipt-eidas-hardening/CODEX-REMEDIATION-2026-05-04.md D2/D3
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

/**
 * The all-zeros / opaque SHA-256 stub. A `trust_anchor_sha256` or `jwks_sha256`
 * equal to this is structurally well-formed (passes the Zod regex) but carries
 * NO real chain-of-trust binding — it is the placeholder emitted by issuers
 * before a production anchor ceremony. Strict mode rejects it. (T-AUD-012)
 */
const STUB_SHA256 = "0".repeat(64);

/**
 * A SHA-256 hex value is treated as an opaque/synthetic stub when it is the
 * all-zeros placeholder or any single repeated nibble (e.g. all-`f`). These
 * carry no entropy and cannot be a genuine digest.
 */
function isOpaqueStubSha256(value: string): boolean {
  if (value === STUB_SHA256) return true;
  return /^([0-9a-f])\1{63}$/.test(value);
}

// ---------------------------------------------------------------------------
// Trust-provider assertion type predicates (public API)
// ---------------------------------------------------------------------------

export function isRfc9421ProviderAssertion(
  a: unknown
): a is Rfc9421ProviderAssertion {
  return (
    typeof a === "object" &&
    a !== null &&
    (a as Record<string, unknown>)["provider"] === "rfc9421-native"
  );
}

export function isHumanProviderAssertion(
  a: unknown
): a is HumanProviderAssertion {
  return (
    typeof a === "object" &&
    a !== null &&
    (a as Record<string, unknown>)["provider"] === "human"
  );
}

export function isVisaTapProviderAssertion(
  a: unknown
): a is VisaTapProviderAssertion {
  return (
    typeof a === "object" &&
    a !== null &&
    (a as Record<string, unknown>)["provider"] === "visa"
  );
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

/** Synchronous SHA-256 hex of a UTF-8 string. */
function sha256HexStr(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

/**
 * M8 — recompute the append-only JWKS-history hash chain over `entries`.
 *
 * MUST stay byte-identical to the issuer
 * (`apps/api/.../jwks-history.service.ts` → `computeHistoryChainSha256`):
 *
 *   chain_0 = sha256( canonicalize_RFC8785([]) )
 *   chain_i = sha256( chain_{i-1} || canonicalize_RFC8785(entry_i) )
 *
 * The returned value is the final rolling chain after folding every entry.
 * Entries are folded in the order presented (the issuer orders by
 * `valid_from asc`).
 */
function recomputeHistoryChainSha256(
  entries: ReadonlyArray<JwksHistoryEntry>
): string {
  let chain = sha256HexStr(canonicalize([] as unknown[]) ?? "[]");
  for (const entry of entries) {
    const entryCanonical =
      canonicalize(entry as unknown as Record<string, unknown>) ?? "{}";
    chain = sha256HexStr(chain + entryCanonical);
  }
  return chain;
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
 *
 * Staging floor (audit §B1): a body declaring `trust_anchor_staging` has NO
 * verifiable chain of trust behind it. Whatever agent identity or timestamp it
 * carries, the strongest posture it can honestly claim is
 * `simple_electronic_seal` — so the verifier floors it there rather than
 * recomputing a stronger posture and then rejecting the issuer's honest
 * self-downgrade as a mismatch.
 *
 * The floor is evaluated FIRST and DOMINATES the entire truth table above,
 * including `merchant_admin`. `merchant_admin_action` names a subject, not a
 * strength level, so letting it short-circuit would report a receipt with an
 * unverifiable anchor as if the anchor were irrelevant. Mirrors the issuer-side
 * invariant in `apps/api/src/services/trust/legal-posture.resolver.ts`.
 */
function recomputeLegalPosture(
  body: {
    receipt_subject: ReceiptSubject;
    trust_provider_assertions?: unknown;
    authorization_evidence?: { protocol_authorization_ref?: string };
    legal_posture_warnings?: ReadonlyArray<{ reason: string }>;
  },
  envelope: { timestamp_evidence: { type: string } }
): LegalPosture {
  const declaresStagingAnchor = (body.legal_posture_warnings ?? []).some(
    (w) => w.reason === "trust_anchor_staging"
  );
  if (declaresStagingAnchor) {
    return "simple_electronic_seal";
  }
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
 * 11. Verify timestamp evidence — delegated to `verifyTimestampEvidence`.
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

  // 3c. Signature verification or (opt-in) staging fallback ----------------
  //
  // T-CR-001 / Codex round 2 D2/D3: when the bundled root SHA is unknown to
  // the verifier OR resolves to a non-production "(STAGING)" stub, default
  // behavior is FAIL-CLOSED. Without `allowStagingRoots: true` a forged
  // bundle pointing at an unknown root cannot smuggle its own `kid` past us
  // via structural-only parsing.
  //
  // Audit §B1 addendum (2026-07-27): rejecting outright also means the absence
  // of an offline key ceremony invalidates the ENTIRE v1.1 corpus. So instead
  // of deciding here, we DEFER: parse structurally, remember why, and require
  // the receipt's own SIGNED body to declare `trust_anchor_staging` before
  // downgrading to `accepted_degraded` (see `pendingStagingDowngrade` below).
  // A receipt that does not declare it is rejected exactly as before — silence
  // is never read as consent, and the unsigned envelope_metadata mirror alone
  // can never unlock the downgrade.
  const allowStagingRoots = options.allowStagingRoots ?? false;
  /**
   * Set when the chain of trust could NOT be verified and the operator has not
   * opted into staging roots. Holds the rejection that will fire unless the
   * signed body declares its own degradation.
   */
  let pendingStagingDowngrade: { detail: string } | null = null;
  let historyPayload: VerifiedJwksHistoryPayload | null;
  // A6 — the root whose SIGNATURE we cryptographically verified. Remains null on
  // the staging-fallback path (structural-only parse), where a root validity
  // window carries no trust and must NOT gate legitimate staging receipts.
  let verifiedRootEntry: IssuerRootEntry | null = null;
  const rootEntry = findIssuerRootBySha256(
    options.jwksHistory.signed_by_root_sha256
  );
  if (!rootEntry) {
    // Unknown root SHA — staging window or unknown issuer.
    if (!allowStagingRoots) {
      pendingStagingDowngrade = { detail: "root_not_in_trust_anchor" };
    }
    warnings.push("jwks_history_signature_unverifiable_staging_root");
    historyPayload = parseJwksHistoryPayload(options.jwksHistory);
  } else {
    const sigResult = await verifyJwksHistorySignature(
      options.jwksHistory,
      rootEntry
    );
    if (!sigResult.valid) {
      if (sigResult.reason === "embedded_root_not_production") {
        // Staging stub root — gated structural fallback (opt-in only).
        if (!allowStagingRoots) {
          pendingStagingDowngrade = { detail: "root_not_in_trust_anchor" };
        }
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
      verifiedRootEntry = rootEntry;
    }
  }

  if (!historyPayload) {
    return reject(
      "unknown_kid",
      "jwksHistory payload could not be parsed; unable to resolve kid",
      warnings
    );
  }
  // M8 — honor `history_chain_sha256`. Previously the verifier IGNORED this
  // field, so tampering with the presented `entries` (e.g. inserting a forged
  // kid on the structural-fallback path) went undetected. We recompute the
  // append-only hash chain and reject on mismatch. Opaque-stub values
  // (all-zeros / single repeated nibble) are skipped — they are the documented
  // placeholder that pre-chain issuers/fixtures emit and carry no commitment.
  // NOTE: true rollback-to-an-earlier-valid-history is out of scope here (both
  // histories are internally self-consistent); detecting that requires an
  // external anchor (S3 Object-Lock — ops, pending).
  const committedChain = historyPayload.history_chain_sha256;
  if (
    typeof committedChain === "string" &&
    /^[0-9a-f]{64}$/i.test(committedChain) &&
    !isOpaqueStubSha256(committedChain.toLowerCase())
  ) {
    const recomputedChain = recomputeHistoryChainSha256(historyPayload.entries);
    if (recomputedChain !== committedChain.toLowerCase()) {
      return reject(
        "jwks_history_chain_mismatch",
        `history_chain_sha256 mismatch: committed=${committedChain.toLowerCase()} recomputed=${recomputedChain}`,
        warnings
      );
    }
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

  // 5a'. Deferred staging-root decision (audit §B1) ------------------------
  // The chain of trust could not be verified and the operator did not opt into
  // staging roots. The ONLY thing that may keep this receipt alive is the
  // receipt itself declaring — inside the bytes covered by the signature we
  // just verified — that it knows its anchor is unverifiable. Reading the
  // declaration from the SIGNED body (not the unsigned envelope_metadata
  // mirror) is what binds the admission to the issuer's intent.
  const declaresStagingDegradation = body.legal_posture_warnings.some(
    (w) => w.reason === "trust_anchor_staging"
  );
  if (pendingStagingDowngrade !== null && !declaresStagingDegradation) {
    return reject(
      "jwks_history_signature_invalid",
      pendingStagingDowngrade.detail,
      // Drop the structural-fallback warning: fail-closed callers must not see
      // a "we fell back" signal on a path that did NOT fall back.
      warnings.filter(
        (w) => w !== "jwks_history_signature_unverifiable_staging_root"
      )
    );
  }
  // The verdict is degraded because the RECEIPT SAYS SO — not because this
  // verifier happened to have trouble with the anchor.
  //
  // `trust_anchor_staging` is a permanent, signed property of the artifact: at
  // signing time the issuer had no ceremonied root, so nothing anchors the key
  // that produced this signature. Whether the verifier can resolve a root right
  // now is a transient property of the ENVIRONMENT and must never upgrade the
  // verdict. Gating on `pendingStagingDowngrade` conflated the two, with two
  // silent-lie paths: `allowStagingRoots:true`, and — worse — the day after the
  // key ceremony, when export bundles (which assemble `jwksHistory` at EXPORT
  // time, not at issuance) ship the degraded backlog with a verifiable root and
  // the whole backlog would have flipped to `accepted`, backdating trust onto
  // keys that were never anchored.
  //
  // `pendingStagingDowngrade` still governs the REJECTION when there is no
  // declaration — that part was always right, and is unchanged.
  const stagingDegraded = declaresStagingDegradation;
  if (declaresStagingDegradation) {
    warnings.push("trust_anchor_staging");
  }

  // 5b. Temporal checks (issued_at / expires_at) --------------------------
  // Honor the caller-supplied verification clock when provided (deterministic
  // conformance harnesses) and fall back to wall-clock otherwise (production).
  // The expiry/not-yet-valid enforcement itself is unchanged. (GAP H1a)
  const nowSeconds =
    options.currentTimeSeconds ?? Math.floor(Date.now() / 1000);
  const tolerance = options.toleranceSeconds ?? 30;
  if (body.issued_at > nowSeconds + tolerance) {
    return reject(
      "receipt_not_yet_valid",
      `issued_at=${body.issued_at} is ${body.issued_at - nowSeconds}s in the future (tolerance=${tolerance}s)`,
      warnings
    );
  }
  if (body.expires_at < nowSeconds - tolerance) {
    return reject(
      "receipt_expired",
      `expires_at=${body.expires_at} expired ${nowSeconds - body.expires_at}s ago (tolerance=${tolerance}s)`,
      warnings
    );
  }

  // 5b'. A6 — issuer-root validity-window check. `findIssuerRootBySha256`
  // intentionally still RETURNS retired roots (so receipts legitimately signed
  // while a root was active keep verifying for the FR-018 ≥ 7-year window), but
  // the receipt's `issued_at` MUST fall inside that root's [validFrom, validTo].
  // A root retired/compromised at time T must not validate histories for
  // receipts issued after T. Only enforced when the history signature was
  // cryptographically verified against a real root (verifiedRootEntry set);
  // the opt-in staging-fallback path is already warned + gated.
  if (verifiedRootEntry !== null) {
    const rootFrom = verifiedRootEntry.validFrom;
    const rootTo = verifiedRootEntry.validTo;
    if (
      body.issued_at < rootFrom ||
      (rootTo !== null && body.issued_at > rootTo)
    ) {
      return reject(
        "root_outside_validity_window",
        `issuer root window=[${rootFrom}, ${rootTo ?? "active"}] does not contain receipt issued_at=${body.issued_at}`,
        warnings
      );
    }
  }

  // 5c. T-AUD-012 (GAP H4) — semantic trust-anchor / jwks-pin verification ---
  // The Zod layer only enforces the 64-hex REGEX FORMAT, so an all-zeros
  // opaque stub anchor passes shape validation. Here we add the SEMANTIC
  // layer: reject stub pins and verify the body's declared
  // `trust_anchor_sha256` against the operator-pinned anchor.
  const strict = (options.mode ?? "compat") === "strict";
  const vm = body.verification_methods;
  if (isOpaqueStubSha256(vm.trust_anchor_sha256)) {
    if (strict) {
      return reject(
        "trust_anchor_stub_rejected",
        `verification_methods.trust_anchor_sha256 is an opaque stub (${vm.trust_anchor_sha256})`,
        warnings
      );
    }
    warnings.push("trust_anchor_sha256_stub");
  } else if (
    vm.trust_anchor_sha256.toLowerCase() !==
    options.trustAnchorPemSha256.toLowerCase()
  ) {
    // The receipt cites an anchor that is not the one the verifier pins.
    if (strict) {
      return reject(
        "trust_anchor_mismatch",
        `body trust_anchor_sha256=${vm.trust_anchor_sha256} does not match pinned anchor=${options.trustAnchorPemSha256}`,
        warnings
      );
    }
    warnings.push("trust_anchor_sha256_mismatch");
  }
  if (isOpaqueStubSha256(vm.jwks_sha256)) {
    if (strict) {
      return reject(
        "jwks_sha256_stub_rejected",
        `verification_methods.jwks_sha256 is an opaque stub (${vm.jwks_sha256})`,
        warnings
      );
    }
    warnings.push("jwks_sha256_stub");
  }

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
  // Warn when assertions include providers the verifier doesn't recognise.
  const KNOWN_PROVIDERS = new Set(["rfc9421-native", "human", "visa"]);
  const rawAssertions = body.trust_provider_assertions;
  if (Array.isArray(rawAssertions)) {
    for (const a of rawAssertions) {
      if (
        typeof a === "object" &&
        a !== null &&
        typeof (a as Record<string, unknown>)["provider"] === "string" &&
        !KNOWN_PROVIDERS.has(
          (a as Record<string, unknown>)["provider"] as string
        )
      ) {
        warnings.push("unknown_trust_provider_present");
        break;
      }
    }
  }

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

  // 10b. T-AUD-012 (GAP H4) — agent-identity binding gate -----------------
  // A buyer_agent receipt with no verifiable agent-identity binding recomputes
  // to a degraded posture. Strict mode treats that as fatal; compat warns.
  // A receipt floored to `simple_electronic_seal` purely by its declared
  // `trust_anchor_staging` is NOT missing an agent identity — claiming so would
  // be a false finding. Its degradation is already named by `trust_anchor_staging`.
  if (
    body.receipt_subject === "buyer_agent" &&
    !declaresStagingDegradation &&
    (recomputedPosture === "degraded_no_agent_identity" ||
      recomputedPosture === "simple_electronic_seal")
  ) {
    if (strict) {
      return reject(
        "agent_identity_required_strict",
        `buyer_agent receipt has no agent-identity binding (recomputed posture=${recomputedPosture})`,
        warnings
      );
    }
    warnings.push("agent_identity_absent");
  }

  // 11. Timestamp verification -------------------------------------------
  const tsResult = await verifyTimestampEvidence({
    envelope: envelope as unknown as ReceiptEnvelope,
    receipt: body as unknown as TrustReceiptV11Body,
    trustAnchorPemSha256: options.trustAnchorPemSha256,
    tsaRootCertSha256Allowlist: options.tsaRootCertSha256Allowlist,
    policyOidAllowlist: options.policyOidAllowlist,
    toleranceSeconds: options.toleranceSeconds ?? 60,
    ...(options.merchantTsaPolicy !== undefined
      ? { merchantTsaPolicy: options.merchantTsaPolicy }
      : {}),
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
    // `accepted_degraded` whenever the receipt declares `trust_anchor_staging`
    // in its signed body — independent of whether THIS verifier could resolve a
    // root. Never `accepted`: a consumer must opt in to the weaker guarantee.
    outcome: stagingDegraded ? "accepted_degraded" : "accepted",
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
    case "tsa_revocation_unavailable":
    case "tsa_gen_time_out_of_tolerance":
    case "tsa_imprint_mismatch":
    case "tsa_token_mismatch":
    case "tsa_root_not_trusted":
      return code;
    default:
      return "tsa_invalid";
  }
}
