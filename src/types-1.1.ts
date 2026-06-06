/**
 * TrustReceipt v1.1 — canonical TypeScript type definitions.
 *
 * This file is the source of truth for the TrustReceipt v1.1 wire format
 * shipped in the public `trust-receipt-verifier` package. Downstream consumers
 * (api, dashboard, third-party verifiers) MUST import from here:
 *
 *     import type { TrustReceiptV11Body, ReceiptEnvelope } from
 *       "trust-receipt-verifier/types-1.1";
 *
 * Companion file `zod-1.1.ts` (T013) mirrors every interface in this file as a
 * runtime Zod schema. If you add or change a field here, update `zod-1.1.ts`
 * AND the canonical Zod definitions in
 * `specs/049-trust-receipt-eidas-hardening/data-model.md` §3 in the same PR.
 *
 * Source of truth:
 * - `specs/049-trust-receipt-eidas-hardening/data-model.md` §2 (interfaces)
 * - `specs/049-trust-receipt-eidas-hardening/spec.md` (FR-019 family, FR-031,
 *   FR-040, FR-042, FR-051)
 * - `specs/049-trust-receipt-eidas-hardening/CODEX-REMEDIATION-2026-05-04.md`
 *
 * Constraints (per T012 + repo coding standards):
 * - Pure types only — NO runtime code, NO Zod, NO classes.
 * - TypeScript strict mode; NO `any`; NO `@ts-ignore`.
 * - String-literal unions (NOT TS `enum`).
 * - Template-literal types where digest prefix matters.
 *
 * @see spec-049 §2 data-model
 * @see spec-049 FR-019, FR-019d, FR-019e, FR-019f, FR-031, FR-040, FR-051
 */

// ---------------------------------------------------------------------------
// 0. Digest primitives — algorithm-tagged template-literal types.
// ---------------------------------------------------------------------------

/**
 * Algorithm-tagged HMAC-SHA-256 digest. Format: `hmac-sha256:<64-hex>`.
 *
 * Used for fields whose preimage contains PII (e.g. `user_intent_hash`,
 * `consent_hash`, `admin_user_id_hash`). Keying material is held exclusively
 * in AWS KMS HMAC CMKs — see `TrustReceiptHmacKey` (data-model §1.2). The
 * `*_hmac_key_version` companion field selects the active key version.
 *
 * @see spec-049 data-model §1.2
 * @see spec-049 round 2 D32 (user_intent_hash MUST be HMAC-SHA-256)
 */
export type HmacSha256Tagged = `hmac-sha256:${string}`;

/**
 * Algorithm-tagged SHA-256 digest. Format: `sha256:<64-hex>`.
 */
export type Sha256Tagged = `sha256:${string}`;

/**
 * Algorithm-tagged SHA-512 digest. Format: `sha512:<128-hex>`.
 */
export type Sha512Tagged = `sha512:${string}`;

/**
 * Any algorithm-tagged digest accepted by the verifier (sha256, sha512, or
 * hmac-sha256). Use the narrower template-literal aliases above when the
 * algorithm is fixed by the field's role.
 */
export type TaggedDigest = Sha256Tagged | Sha512Tagged | HmacSha256Tagged;

// ---------------------------------------------------------------------------
// 1. Enumerations (string-literal unions).
// ---------------------------------------------------------------------------

/**
 * Receipt-level legal posture per FR-019.
 *
 * Captures which evidentiary regime a receipt qualifies for at issuance.
 * Verifiers MAY surface degradation reasons via `LegalPostureWarning`.
 *
 * @see spec-049 FR-019
 * @see spec-049 round 1 H4, H5
 */
export type LegalPosture =
  | "ades_candidate_timestamped"
  | "ades_candidate_no_tsa"
  | "simple_electronic_seal"
  | "degraded_no_agent_identity"
  | "merchant_admin_action";

/**
 * Structured warning emitted alongside `LegalPosture` when the receipt was
 * issued under a degraded path (e.g. TSA outage). Allows downstream legal /
 * compliance tools to enumerate gaps without parsing free-form text.
 *
 * @see spec-049 round 2 D27
 * @see spec-049 FR-019
 */
export interface LegalPostureWarning {
  reason:
    | "tsa_unavailable"
    | "agent_identity_absent"
    | "consent_evidence_absent"
    | "esign_disclosure_unverified"
    /** Emitted by claims-enforcement when external_counsel_approval_at is null. */
    | "pending_counsel_approval";
  /** Unix seconds — when the degradation began for this receipt. */
  since: number;
  /** Optional pointer to evidence vault entry corroborating the warning. */
  evidence_ref?: string;
}

/**
 * Discriminator: who the receipt attests to. Determines which authorization
 * context block (`buyer_agent_consent_context` vs
 * `merchant_admin_authorization_context`) MUST be present.
 *
 * @see spec-049 round 1 M14
 */
export type ReceiptSubject = "buyer_agent" | "merchant_admin";

/**
 * Privacy-classification tag applied to the receipt body. Verifiers and audit
 * tools use this to apply the correct redaction policy when displaying the
 * receipt.
 */
export type PrivacyClassification =
  | "pii_redacted"
  | "pii_hashed_salted"
  | "pii_absent";

/**
 * Final policy outcome that gated execution. Recorded for forensic analysis.
 */
export type PolicyDecision = "allow" | "deny" | "review" | "challenge";

/**
 * Protocol that produced the underlying transaction the receipt attests to.
 * Cross-protocol coverage is a core TrustReceipt invariant (FR-019).
 */
export type Protocol = "x402" | "AP2" | "ACP" | "MCP" | "UCP" | "MCAP";

/**
 * Rail-aware authorization scheme. Replaces the v1.0 `mandate_hash` /
 * `permit2_authorization_hash` / `mcp_tool_invocation_hash` triplet with a
 * single discriminator + `payment_authorization_hash` pair, so verifiers do
 * not need rail-specific knowledge to locate the canonical authorization
 * artifact.
 *
 * @see spec-049 round 2 D24
 */
export type AuthorizationScheme =
  | "ap2_mandate_jws"
  | "mcap_cart_binding"
  | "ucp_rule_set_plus_agent_token"
  | "acp_session_token"
  | "evm_permit2"
  | "svm_token_authorization"
  | "mcp_tool_invocation"
  // AWS Bedrock AgentCore Payments uses x402 as primary protocol (2026-05-07).
  // Distinguishes the protocol-level claim from rail-specific evm_permit2/svm_token_authorization.
  | "x402_native";

// ---------------------------------------------------------------------------
// 2. Authorization-chain primitives (§2.1a).
// ---------------------------------------------------------------------------

/**
 * One step in the agent authorization chain (user → agent → [delegated agent
 * …]). Every entry carries an algorithm-tagged digest of the canonical
 * evidence record and a Unix-seconds timestamp; entries MUST be ordered
 * non-decreasing in `timestamp`.
 *
 * @see spec-049 data-model §2.1a
 */
export interface AuthorizationChainEntry {
  /** Who acted at this step. */
  actor: "user" | "agent" | "delegated_agent";
  /**
   * Authentication or authorization method. `rfc9421_signature` is wired in
   * from spec-045 (HTTP Message Signatures); `session_token` covers Shopify
   * App Bridge etc. for `merchant_admin` subjects.
   */
  method:
    | "OAuth"
    | "OAuth+MFA"
    | "Passkey"
    | "AP2_mandate"
    | "MCAP_mandate"
    | "UCP_mandate"
    | "rfc9421_signature"
    | "session_token"
    | "other";
  /**
   * Algorithm-tagged digest of the canonical evidence record. Format:
   * `<algo>:<hex>` with `algo ∈ {sha256, hmac-sha256}`. (Stored as the broad
   * `TaggedDigest` union; runtime Zod narrows by field role.)
   */
  hash: TaggedDigest;
  /** Unix seconds. MUST be ≤ next entry's timestamp. */
  timestamp: number;
  /** Optional opaque reference (e.g. AP2 mandate id, MCAP cart hash). */
  ref?: string;
}

/**
 * Tuple type encoding the FR-019d invariant that the agent authorization
 * chain MUST contain at least two entries (user → agent). Zod enforces this
 * at runtime via `.min(2)`; the TS tuple form gives compile-time assurance
 * for callers constructing receipts in code.
 *
 * @see spec-049 FR-019d
 */
export type AgentAuthorizationChain = readonly [
  AuthorizationChainEntry,
  AuthorizationChainEntry,
  ...AuthorizationChainEntry[],
];

// ---------------------------------------------------------------------------
// 3. Subject-discriminated authorization contexts (§2.1a / §2.1b).
// ---------------------------------------------------------------------------

/**
 * Authorization context for `receipt_subject = "buyer_agent"`.
 *
 * All hashes use HMAC-SHA-256 keyed by per-merchant KMS-held HMAC keys; the
 * keying material NEVER leaves AWS KMS, so it cannot be exported or leaked
 * (replaces the deleted v1.0 `TrustReceiptSalt` design — round 1 D4 / R17).
 *
 * @see spec-049 data-model §2.1a
 * @see spec-049 round 1 M14, H6, H8
 * @see spec-049 FR-019d
 */
export interface BuyerAgentConsentContext {
  /** How consent was captured. */
  consent_type:
    | "checkbox"
    | "explicit_action"
    | "voice"
    | "biometric"
    | "oauth_scope_grant";
  /** Unix seconds. MUST be ≤ receipt.issued_at. */
  consent_timestamp: number;
  /** HMAC-SHA-256 of canonical consent record. */
  consent_hash: HmacSha256Tagged;
  /** KMS-held HMAC key version used (links to `TrustReceiptHmacKey`). */
  consent_hmac_key_version: number;
  /** SemVer of merchant disclosure document at consent time (ESIGN). */
  consent_disclosure_version: string;
  /** SHA-256 of withdrawal endpoint URL (FR-019d). */
  consent_withdrawal_uri_hash: Sha256Tagged;
  /**
   * Pointer to evidence vault entry: signed UI screenshot or HTML hash
   * (FR-019d).
   */
  consent_evidence_ref: string;
  /**
   * Ordered chain of authorization entries. MUST contain ≥2 entries:
   * user → agent.
   */
  agent_authorization_chain: AgentAuthorizationChain;
}

/**
 * Authorization context for `receipt_subject = "merchant_admin"` (refunds,
 * voids, configuration changes initiated by a merchant operator rather than a
 * buyer agent).
 *
 * @see spec-049 data-model §2.1b
 * @see spec-049 round 1 M14
 */
export interface MerchantAdminAuthorizationContext {
  /** HMAC-SHA-256 of admin user id, keyed by merchant HMAC key. */
  admin_user_id_hash: HmacSha256Tagged;
  /** e.g. `"refund"` | `"void"` | `"config_change"`. */
  admin_action_type: string;
  admin_authentication_method:
    | "shopify_app_bridge_jwt"
    | "dashboard_jwt+mfa"
    | "sso"
    | "other";
  /** HMAC-SHA-256 of MFA challenge response. */
  mfa_evidence_hash: HmacSha256Tagged;
  /** RBAC role at action time. */
  rbac_role_at_action_time: string;
  /** Unix seconds. */
  acted_at: number;
}

// ---------------------------------------------------------------------------
// 4. Timestamp evidence (§2.2).
// ---------------------------------------------------------------------------

/**
 * RFC 3161 timestamp evidence carried at the **envelope** level (NOT inside
 * the JWS-signed body — round 1 H9 + round 2 D22). Verifiers MUST recompute
 * the imprint over the JWS Compact bytes and validate the TST end-to-end:
 * signature, cert chain to a pinned root, policy OID, nonce echo, and
 * revocation status at TSA `genTime`.
 *
 * @see spec-049 data-model §2.2
 * @see spec-049 round 1 H9
 * @see spec-049 round 2 D25 (added `tsr` — full TimeStampResp envelope)
 */
export interface TimestampEvidence {
  type: "RFC3161";
  /** TSA endpoint URL. */
  tsa_endpoint: string;
  /**
   * Base64 of the **full** RFC 3161 `TimeStampResp` (status + token). Added
   * post-Codex round 2 D25 so verifiers can inspect the TSA status response,
   * not just the embedded token.
   */
  tsr: string;
  /** Base64 of extracted `TimeStampToken` (CMS `SignedData` DER). */
  tst: string;
  /** Unix seconds — TSA-attested time. */
  issued_at_attested: number;
  /** Imprint algorithm used to build the TST request. */
  imprint_algo: "sha-256";
  /** What the imprint covers — for v1.1 always the JWS Compact bytes. */
  imprint_target: "jws_compact_bytes";
  /** 16-byte issuer nonce echoed by the TSA in TSTInfo, hex-encoded (32 chars). */
  nonce: string;
  /** Expected TSA policy OID (dotted form, e.g. freeTSA). */
  policy_oid: string;
  /** Full TSA cert chain to root, PEM array. */
  tsa_cert_chain: string[];
  /** SHA-256 of TSA root CA cert (64-hex); pin-checked at verification time. */
  tsa_root_cert_sha256: string;
  /**
   * Revocation evidence captured at TSA genTime. T-CR-008 discriminated
   * union: `ocsp` / `crl` carry Base64 DER; `unavailable` documents the
   * reason the issuer-side fetcher could not obtain a usable response and
   * gates fail-open vs fail-closed handling at the verifier.
   */
  revocation_evidence:
    | { kind: "ocsp"; data_b64: string }
    | { kind: "crl"; data_b64: string }
    | {
        kind: "unavailable";
        reason:
          | "ocsp_unreachable"
          | "crl_unreachable"
          | "fetch_timeout"
          | "synthetic_fixture";
        attempted_at: number;
      };
  /** Tolerance window applied (seconds). Default 60 s. */
  tolerance_seconds: number;
}

/**
 * Sentinel emitted in place of `TimestampEvidence` when no TSA could be
 * reached and the merchant policy is `fail_open` (Q1). Never appears under
 * `fail_closed` policy — issuance is rejected instead.
 *
 * @see spec-049 data-model §2.2
 */
export interface TimestampUnavailable {
  type: "unavailable";
  reason:
    | "tsa_unavailable"
    | "tsa_error"
    | "tsa_timeout"
    | "all_providers_failed";
  attempted_tsa: string[];
  attempted_at: number;
}

// ---------------------------------------------------------------------------
// 5. Authorization evidence (§2.3).
// ---------------------------------------------------------------------------

/**
 * Hashed evidence of intent → execution alignment.
 *
 * `user_intent_hash` is HMAC-SHA-256 (round 2 D32: PII source). The companion
 * `intent_hmac_key_version` field on the receipt body selects the active KMS
 * HMAC key version; this object only carries the hash itself plus an opaque
 * reference to the protocol-specific authorization artifact.
 *
 * @see spec-049 data-model §2.3
 * @see spec-049 round 2 D32
 */
export interface AuthorizationEvidence {
  /** HMAC-SHA-256 of the user's intent text. */
  user_intent_hash: HmacSha256Tagged;
  /** KMS-held HMAC key version used for `user_intent_hash`. */
  intent_hmac_key_version: number;
  /**
   * Algorithm-tagged digest of the executed action (cart, mandate, payment
   * authorization). `sha256` or `hmac-sha256` depending on whether the
   * preimage contains PII.
   */
  execution_hash: TaggedDigest;
  /** Reference to the protocol-specific authorization (e.g. AP2 mandate id). */
  protocol_authorization_ref?: string;
}

// ---------------------------------------------------------------------------
// 6. Verification methods (§2.4).
// ---------------------------------------------------------------------------

/**
 * How a verifier resolves the issuer's public key.
 *
 * Both `jwks_sha256` and `trust_anchor_sha256` are REQUIRED for v1.1 (round 1
 * M17): they are bound inside the JWS-signed payload so an offline verifier
 * can perform a deterministic pin check against the expected JWKS document
 * and the embedded issuer root cert (R16 trust anchor).
 *
 * @see spec-049 data-model §2.4
 * @see spec-049 round 1 M17
 */
export interface VerificationMethods {
  /** Online resolution mechanism (HTTPS JWKS URI). */
  jwks?: { uri: string; kid: string };
  /** DID-based resolution (alternative to `jwks`). */
  did?: { method: string; identifier: string; key_id: string };
  /** SHA-256 of the JWKS document at issuance time, for offline pin check (64-hex). */
  jwks_sha256: string;
  /** SHA-256 of the embedded issuer root cert (R16 trust anchor) (64-hex). */
  trust_anchor_sha256: string;
}

// ---------------------------------------------------------------------------
// 7. Retention metadata (§2.5).
// ---------------------------------------------------------------------------

/**
 * Retention metadata attached to an export bundle. Resolves the merchant's
 * jurisdiction to the minimum statutory retention window (FR-031). When
 * `jurisdiction = "OTHER"`, the platform default is applied and
 * `manual_review_required` is set so legal can refine.
 *
 * @see spec-049 data-model §2.5
 * @see spec-049 FR-031
 */
export interface RetentionMetadata {
  jurisdiction: "EU" | "US" | "BR" | "MX" | "UK" | "OTHER";
  /** ISO 3166-1 alpha-2 of the resolved jurisdiction. */
  jurisdiction_code: string;
  /** Statute reference (informational). */
  statute_ref?: string;
  /** Minimum years per FR-031. */
  min_retention_years: number;
  /** True when "OTHER" default applied — merchant SHOULD escalate to legal review. */
  manual_review_required: boolean;
  exported_at: number;
}

// ---------------------------------------------------------------------------
// 8. JWKS history + redacted consent record (§2.6).
// ---------------------------------------------------------------------------

/**
 * One entry in the issuer's JWKS history. Replaces the deleted v1.0
 * `SaltSnapshot` (round 1 H8 — salts are no longer exported).
 *
 * @see spec-049 data-model §2.6
 * @see spec-049 round 1 C3, H8
 */
export interface JwksHistoryEntry {
  kid: string;
  /** Public JWK (kty, crv, x for Ed25519). */
  jwk_pub: Record<string, unknown>;
  /** Unix seconds. */
  valid_from: number;
  /** Unix seconds, or null = currently active. */
  valid_to: number | null;
}

/**
 * Signed JWKS history shipped in the export bundle. The JWS payload is
 * `{ schema_version, entries[], history_chain_sha256 }` and is signed by the
 * issuer root key.
 */
export interface SignedJwksHistory {
  jws_compact: string;
  /** SHA-256 of issuer root cert that signed this history (64-hex). */
  signed_by_root_sha256: string;
}

/**
 * Redacted consent record shipped in the export bundle. PII is redacted to
 * placeholders (e.g. via Presidio); the record is signed so an external
 * verifier can confirm the redaction was performed by the issuer.
 *
 * @see spec-049 data-model §2.6
 */
export interface RedactedConsentRecord {
  /** PII redacted to placeholders. */
  consent_text_redacted: string;
  /** e.g. `"presidio-v2"`. */
  redaction_method: string;
  /** Issuer KMS Sign kid. */
  signed_by_kid: string;
  /** JWS Compact over the redacted text + metadata. */
  signature_jws: string;
}

// ---------------------------------------------------------------------------
// 9. Claims-policy version (informational).
// ---------------------------------------------------------------------------

/**
 * Informational metadata pinning the claims-policy document version that was
 * effective when the receipt was issued.
 *
 * @see spec-049 data-model §2.7
 */
export interface ClaimsPolicyVersion {
  /** SemVer of `docs/legal/trust-receipt-claims-policy.md`. */
  version: string;
  /** Unix seconds. */
  effective_at: number;
  /** Canonical URL. */
  source_uri: string;
  /** Owning team/role. */
  owner: string;
}

// ---------------------------------------------------------------------------
// 10. Protocol artifact reference (used inside the signed body).
// ---------------------------------------------------------------------------

/**
 * Reference to a protocol-specific artifact (mandate, cart, payment intent…)
 * that the receipt commits to by hash. Large payloads are NOT embedded —
 * carry them in `ReceiptEnvelope.protocol_artifact_sidecars` and reference
 * them here by hash.
 */
export interface ProtocolArtifactRef {
  type: string;
  hash: TaggedDigest;
  ref?: string;
}

/**
 * Optional risk signals surfaced by the issuer (e.g. agent reputation, fraud
 * model output). Schema is intentionally loose; specific shapes live in
 * adapter-level types.
 */
export type RiskSignals = Record<string, unknown>;

/**
 * Optional trust-provider assertions (e.g. RFC 9421 native, Visa TAP, HUMAN
 * AgenticTrust). Specific shapes live in spec-045 adapter types; we stay
 * deliberately loose here to avoid coupling the receipt schema to provider
 * evolution.
 *
 * Use the narrower `KnownTrustProviderAssertion` union or the type predicates
 * exported from `verify-1.1.ts` when accessing provider-specific fields.
 */
export type TrustProviderAssertion = Record<string, unknown>;

/**
 * RFC 9421 (HTTP Message Signatures) native assertion.
 * @see https://www.rfc-editor.org/rfc/rfc9421
 */
export interface Rfc9421ProviderAssertion {
  provider: "rfc9421-native";
  verification_status: "verified" | "observed" | "spoofed" | "unverified";
  kid?: string;
  signer_url?: string;
  tag?: string;
  evaluated_at?: number;
}

/**
 * HUMAN AgenticTrust assertion.
 * @see https://www.humansecurity.com/agentictrust
 */
export interface HumanProviderAssertion {
  provider: "human";
  human_verification_status: "verified" | "unverified" | "error";
  human_transaction_id?: string;
  human_assurance_level?: string;
  evaluated_at?: number;
}

/**
 * Visa TAP (Trusted Agent Protocol) assertion.
 * Signer domain MUST be `*.visa.com` or `*.visa.net`.
 * @see https://developer.visa.com/
 */
export interface VisaTapProviderAssertion {
  provider: "visa";
  tag: "agent-browser-auth" | "agent-payer-auth";
  verification_status: "verified" | "invalid";
  kid?: string;
  evaluated_at?: number;
}

/** Discriminated union of all known typed trust-provider assertions. */
export type KnownTrustProviderAssertion =
  | Rfc9421ProviderAssertion
  | HumanProviderAssertion
  | VisaTapProviderAssertion;

/**
 * Payment-reference object (rail-specific). Schema deliberately loose; rail
 * adapters narrow at use sites.
 */
export type PaymentReference = Record<string, unknown>;

// ---------------------------------------------------------------------------
// 11. TrustReceipt v1.1 signed body.
// ---------------------------------------------------------------------------

/**
 * The JWS-signed body of a TrustReceipt v1.1.
 *
 * Canonical (JCS) serialization of this object MUST be ≤ 2900 bytes so that
 * the resulting JWS signing input is ≤ 4096 bytes after base64url
 * (round 2 D20). Issuance enforces the cap; Zod does NOT.
 *
 * Subject-discriminated invariants (enforced by Zod `superRefine`, NOT by the
 * TS shape):
 * - `receipt_subject = "buyer_agent"` ⇒ `buyer_agent_consent_context` present,
 *   `merchant_admin_authorization_context` absent, AND
 *   `payment_authorization_hash` + `authorization_scheme` +
 *   `esign_disclosure_version` + `esign_disclosure_hash` +
 *   `consent_evidence_ref` are ALL required (round 2 D24, D28).
 * - `receipt_subject = "merchant_admin"` ⇒ inverse.
 *
 * @see spec-049 data-model §2 + §3
 * @see spec-049 FR-019, FR-019e, FR-019f, FR-040, FR-051
 */
export interface TrustReceiptV11Body {
  // -- identity & versioning --
  /** UUID v4. */
  receipt_id: string;
  schema_version: "1.1";
  /** Unix seconds — issuer-asserted issue time. */
  issued_at: number;
  /** Unix seconds — receipt validity expiry (informational; receipts never expire as evidence). */
  expires_at: number;
  /** Issuer DID or canonical URL. */
  issuer: string;
  merchant_id: string;
  /** Null when `receipt_subject = "merchant_admin"` (no buyer agent involved). */
  agent_id: string | null;
  /** Provider that vouches for the agent identity (HUMAN, Anthropic, OpenAI…). */
  agent_provider: string;

  // -- discriminators --
  receipt_subject: ReceiptSubject;
  privacy_classification: PrivacyClassification;
  legal_posture: LegalPosture;
  /** Structured degradation reasons. Empty array when posture is fully clean. */
  legal_posture_warnings: LegalPostureWarning[];

  // -- subject-discriminated context (exactly one present) --
  buyer_agent_consent_context?: BuyerAgentConsentContext;
  merchant_admin_authorization_context?: MerchantAdminAuthorizationContext;

  // -- intent / cart / order / payment hashes --
  /** HMAC-SHA-256 of the user's intent text (round 2 D32: PII source). */
  user_intent_hash: HmacSha256Tagged;
  /** KMS-held HMAC key version used for `user_intent_hash`. */
  intent_hmac_key_version: number;
  /** SHA-256 of the canonical cart JSON (optional — absent for non-cart receipts). */
  cart_hash?: Sha256Tagged;
  /** SHA-256 of the canonical order JSON. */
  order_hash?: Sha256Tagged;
  /**
   * SHA-256 of the rail-specific payment-authorization artifact. REQUIRED
   * when `receipt_subject = "buyer_agent"` (enforced by Zod superRefine).
   * Replaces the v1.0 `mandate_hash` / `permit2_authorization_hash` /
   * `mcp_tool_invocation_hash` triplet (round 2 D24).
   */
  payment_authorization_hash?: Sha256Tagged;
  /**
   * Discriminator for `payment_authorization_hash`. REQUIRED when
   * `receipt_subject = "buyer_agent"` (enforced by Zod superRefine).
   */
  authorization_scheme?: AuthorizationScheme;

  // -- ESIGN compliance (REQUIRED for buyer_agent — round 2 D28) --
  /** SemVer of disclosure document at issuance. REQUIRED for buyer_agent. */
  esign_disclosure_version?: string;
  /** SHA-256 of the disclosure document content. REQUIRED for buyer_agent. */
  esign_disclosure_hash?: Sha256Tagged;
  /** Pointer to evidence vault entry. REQUIRED for buyer_agent. */
  consent_evidence_ref?: string;

  // -- transaction linkage --
  /** Merchant-side transaction id (opaque). */
  transaction_id?: string;

  // -- protocol provenance --
  protocol: Protocol;
  protocol_artifacts: ProtocolArtifactRef[];

  // -- evidence + verification + decision --
  authorization_evidence: AuthorizationEvidence;
  verification_methods: VerificationMethods;
  policy_decision: PolicyDecision;

  // -- optional sidecars --
  payment_reference?: PaymentReference;
  risk_signals?: RiskSignals;
  trust_provider_assertions?: TrustProviderAssertion[];

  /**
   * Set to `"legacy_pre_eidas_hardening"` on receipts re-signed under the v1.1
   * key but whose underlying transaction predates the v1.1 cutover. Verifiers
   * SHOULD downgrade the legal posture surfaced to operators when present.
   */
  legacy_flag?: "legacy_pre_eidas_hardening";
}

// ---------------------------------------------------------------------------
// 12. Receipt envelope (§2 last interface — wraps the JWS).
// ---------------------------------------------------------------------------

/**
 * Sidecar carrying a large protocol artifact (e.g. AP2 mandate JWS, MCAP
 * cart payload) that the signed body references by hash. Verifiers MUST
 * recompute the digest of `payload_b64` and match it against the
 * corresponding `protocol_artifacts[].hash` inside the JWS.
 */
export interface ProtocolArtifactSidecar {
  type: string;
  hash: TaggedDigest;
  /** Base64-encoded raw payload. */
  payload_b64: string;
}

/**
 * Outer envelope wrapping a JWS-signed v1.1 receipt.
 *
 * Per FR-019e + FR-019f: envelope fields are NOT signed. The verifier MUST
 * recompute every envelope-level value (timestamp imprint, sidecar hashes,
 * `envelope_metadata` mirrors of `receipt_id` / `legal_posture` /
 * `legal_posture_warnings`) and reject any mismatch (round 2 D22).
 *
 * @see spec-049 FR-019e, FR-019f
 * @see spec-049 round 2 D22
 */
export interface ReceiptEnvelope {
  /** JWS Compact Serialization of the signed receipt body. */
  receipt: string;
  /**
   * RFC 3161 timestamp evidence at the envelope level — NOT inside the
   * JWS-signed payload (round 1 H9).
   */
  timestamp_evidence: TimestampEvidence | TimestampUnavailable;
  /**
   * Mirror of selected signed fields, exposed unsigned for fast index/filter.
   * Verifiers MUST recompute and compare against the JWS body (round 2 D22).
   */
  envelope_metadata: {
    receipt_id: string;
    /** Unix seconds — when the envelope was assembled. */
    created_at: number;
    legal_posture: LegalPosture;
    legal_posture_warnings: LegalPostureWarning[];
  };
  /** Optional large protocol blobs referenced by hash inside the JWS. */
  protocol_artifact_sidecars?: ProtocolArtifactSidecar[];
}
