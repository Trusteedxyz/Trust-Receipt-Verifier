/**
 * Zod v3 validators for TrustReceipt v1.1 (spec-049 — eIDAS hardening).
 *
 * Source of truth: specs/049-trust-receipt-eidas-hardening/data-model.md §3
 * and specs/049-trust-receipt-eidas-hardening/spec.md (FR-015..FR-019g, FR-040,
 * FR-024c).
 *
 * Decoupled from `./types-1.1.ts` on purpose — this file defines schemas
 * standalone so callers can use either Zod parsing or pure TypeScript types
 * via `z.infer<typeof XxxSchema>`. Both surfaces stay in sync because the
 * type-level surface is the inferred output here.
 *
 * NOTE: The 2900-byte canonical-bytes cap on the receipt body (FR-019e + FR-040)
 * is **NOT** enforced in Zod — that lives at issuance time per the spec because
 * Zod operates on parsed JSON values, not canonical-encoded bytes.
 */

import { z } from "zod";

// ---------------------------------------------------------------------------
// Tagged digest primitives
// ---------------------------------------------------------------------------

/**
 * Generic algorithm-tagged digest: `<algo>:<hex>`. Accepts `sha256` (64 hex),
 * `sha512` (128 hex), `hmac-sha256` (64 hex). Hex length is validated against
 * the algorithm via `.superRefine`.
 *
 * spec-049 §3 (data-model) — post-Codex round 2.
 */
export const TaggedDigest = z
  .string()
  .regex(/^(sha256|sha512|hmac-sha256):[0-9a-f]+$/)
  .superRefine((v, ctx) => {
    const idx = v.indexOf(":");
    const algo = v.slice(0, idx);
    const hex = v.slice(idx + 1);
    const expected: Record<string, number> = {
      sha256: 64,
      sha512: 128,
      "hmac-sha256": 64,
    };
    const need = expected[algo];
    if (need === undefined || hex.length !== need) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: `${algo} requires ${need ?? "?"} hex chars, got ${hex.length}`,
      });
    }
  });
export type TaggedDigest = z.infer<typeof TaggedDigest>;

/** SHA-256 algorithm-tagged digest (`sha256:<64-hex>`). */
export const Sha256Tagged = z.string().regex(/^sha256:[0-9a-f]{64}$/);
export type Sha256Tagged = z.infer<typeof Sha256Tagged>;

/** SHA-512 algorithm-tagged digest (`sha512:<128-hex>`). */
export const Sha512Tagged = z.string().regex(/^sha512:[0-9a-f]{128}$/);
export type Sha512Tagged = z.infer<typeof Sha512Tagged>;

/**
 * HMAC-SHA-256 algorithm-tagged digest (`hmac-sha256:<64-hex>`). Required for
 * any field that hashes PII (post-Codex round 2 D32).
 */
export const HmacSha256Tagged = z.string().regex(/^hmac-sha256:[0-9a-f]{64}$/);
export type HmacSha256Tagged = z.infer<typeof HmacSha256Tagged>;

// ---------------------------------------------------------------------------
// Authorization chain (FR-019d)
// ---------------------------------------------------------------------------

/** Single hop in the agent authorization chain. spec-049 FR-019d. */
export const AuthorizationChainEntrySchema = z.object({
  actor: z.enum(["user", "agent", "delegated_agent"]),
  method: z.enum([
    "OAuth",
    "OAuth+MFA",
    "Passkey",
    "AP2_mandate",
    "MCAP_mandate",
    "UCP_mandate",
    "rfc9421_signature",
    "session_token",
    "other",
  ]),
  hash: TaggedDigest,
  timestamp: z.number().int().positive(),
  ref: z.string().optional(),
});
export type AuthorizationChainEntry = z.infer<
  typeof AuthorizationChainEntrySchema
>;

// ---------------------------------------------------------------------------
// Subject-discriminated context shapes
// ---------------------------------------------------------------------------

/**
 * Buyer-agent consent context. spec-049 FR-019d (post-Codex round 2 D32:
 * `consent_hash` MUST be HMAC-SHA-256 because consent strings are PII).
 */
export const BuyerAgentConsentContextSchema = z.object({
  consent_type: z.enum([
    "checkbox",
    "explicit_action",
    "voice",
    "biometric",
    "oauth_scope_grant",
  ]),
  consent_timestamp: z.number().int().positive(),
  consent_hash: HmacSha256Tagged,
  consent_hmac_key_version: z.number().int().nonnegative(),
  consent_disclosure_version: z.string().regex(/^\d+\.\d+\.\d+$/),
  consent_withdrawal_uri_hash: Sha256Tagged,
  consent_evidence_ref: z.string().min(1),
  agent_authorization_chain: z.array(AuthorizationChainEntrySchema).min(2),
});
export type BuyerAgentConsentContext = z.infer<
  typeof BuyerAgentConsentContextSchema
>;

/** Merchant-admin authorization context. spec-049 FR-019f. */
export const MerchantAdminAuthorizationContextSchema = z.object({
  admin_user_id_hash: HmacSha256Tagged,
  admin_action_type: z.string().min(1),
  admin_authentication_method: z.enum([
    "shopify_app_bridge_jwt",
    "dashboard_jwt+mfa",
    "sso",
    "other",
  ]),
  mfa_evidence_hash: HmacSha256Tagged,
  rbac_role_at_action_time: z.string().min(1),
  acted_at: z.number().int().positive(),
});
export type MerchantAdminAuthorizationContext = z.infer<
  typeof MerchantAdminAuthorizationContextSchema
>;

// ---------------------------------------------------------------------------
// Legal posture (FR-019)
// ---------------------------------------------------------------------------

/** Receipt-level legal posture. spec-049 FR-019. */
export const LegalPostureSchema = z.enum([
  "ades_candidate_timestamped",
  "ades_candidate_no_tsa",
  "simple_electronic_seal",
  "degraded_no_agent_identity",
  "merchant_admin_action",
]);
export type LegalPosture = z.infer<typeof LegalPostureSchema>;

/** Structured degradation reason (post-Codex round 2 D27). */
export const LegalPostureWarningSchema = z.object({
  reason: z.enum([
    "tsa_unavailable",
    "agent_identity_absent",
    "consent_evidence_absent",
    "esign_disclosure_unverified",
    "pending_counsel_approval",
  ]),
  since: z.number().int().nonnegative(),
  evidence_ref: z.string().optional(),
});
export type LegalPostureWarning = z.infer<typeof LegalPostureWarningSchema>;

// ---------------------------------------------------------------------------
// Authorization scheme (post-Codex round 2 D24 — rail-aware)
// ---------------------------------------------------------------------------

/**
 * Rail-aware payment authorization scheme. spec-049 post-Codex round 2 D24 —
 * replaces v1.0 `mandate_hash` / `permit2_hash` / `mcp_tool_invocation_hash`
 * fields with a single `payment_authorization_hash` discriminated by this
 * scheme.
 */
export const AuthorizationSchemeSchema = z.enum([
  "ap2_mandate_jws",
  "mcap_cart_binding",
  "ucp_rule_set_plus_agent_token",
  "acp_session_token",
  "evm_permit2",
  "svm_token_authorization",
  "mcp_tool_invocation",
  "x402_native",
]);
export type AuthorizationScheme = z.infer<typeof AuthorizationSchemeSchema>;

// ---------------------------------------------------------------------------
// Timestamp evidence (FR-019e — RFC 3161, post-Codex H9)
// ---------------------------------------------------------------------------

/**
 * Envelope-level timestamp evidence (NOT inside the JWS-signed body).
 * Discriminated on `type`. Full RFC 3161 surface for verification.
 */
export const TimestampEvidenceSchema = z.discriminatedUnion("type", [
  z.object({
    type: z.literal("RFC3161"),
    tsa_endpoint: z.string().url(),
    tsr: z.string().min(1),
    tst: z.string().min(1),
    issued_at_attested: z.number().int().positive(),
    imprint_algo: z.literal("sha-256"),
    imprint_target: z.literal("jws_compact_bytes"),
    /** 16-byte nonce as 32 hex chars. */
    nonce: z.string().regex(/^[0-9a-f]{32}$/),
    policy_oid: z.string().regex(/^[0-9.]+$/),
    tsa_cert_chain: z.array(z.string()).min(1),
    tsa_root_cert_sha256: z.string().regex(/^[0-9a-f]{64}$/),
    /**
     * T-CR-008: discriminated union allowing `unavailable` to express
     * "revocation status not obtainable" (issuer fetcher emits this when
     * OCSP/CRL distribution points are absent or unreachable, and the
     * synthetic-fixture path skips revocation entirely). Verifier policy
     * (`merchantTsaPolicy`) gates fail-open vs fail-closed handling.
     */
    revocation_evidence: z.discriminatedUnion("kind", [
      z.object({
        kind: z.literal("ocsp"),
        data_b64: z.string().min(1),
      }),
      z.object({
        kind: z.literal("crl"),
        data_b64: z.string().min(1),
      }),
      z.object({
        kind: z.literal("unavailable"),
        reason: z.enum([
          "ocsp_unreachable",
          "crl_unreachable",
          "fetch_timeout",
          "synthetic_fixture",
        ]),
        attempted_at: z.number().int().positive(),
      }),
    ]),
    tolerance_seconds: z.number().int().positive(),
  }),
  z.object({
    type: z.literal("unavailable"),
    reason: z.enum([
      "tsa_unavailable",
      "tsa_error",
      "tsa_timeout",
      "all_providers_failed",
    ]),
    attempted_tsa: z.array(z.string()).min(1),
    attempted_at: z.number().int().positive(),
  }),
]);
export type TimestampEvidence = z.infer<typeof TimestampEvidenceSchema>;

// ---------------------------------------------------------------------------
// Authorization evidence (intent → execution binding)
// ---------------------------------------------------------------------------

/**
 * spec-049 §2.3 data-model — authorization-evidence binding.
 *
 * post-Codex round 2 D32 (T562): `user_intent_hash` MUST use `hmac-sha256:`
 * prefix only — intent text is reversible PII and the SHA-256 fallback was
 * removed. `execution_hash` remains plain `sha256:` (non-PII canonical
 * payload digest).
 */
export const AuthorizationEvidenceSchema = z.object({
  user_intent_hash: HmacSha256Tagged,
  intent_hmac_key_version: z.number().int().nonnegative(),
  execution_hash: Sha256Tagged,
  protocol_authorization_ref: z.string().optional(),
});
export type AuthorizationEvidence = z.infer<typeof AuthorizationEvidenceSchema>;

// ---------------------------------------------------------------------------
// Verification methods (post-Codex M17 — `jwks_sha256` REQUIRED)
// ---------------------------------------------------------------------------

/**
 * Verifier resolution surface. At least one of `jwks` or `did` MUST be
 * present. `jwks_sha256` and `trust_anchor_sha256` are required pins.
 */
export const VerificationMethodsSchema = z
  .object({
    jwks: z
      .object({
        uri: z.string().url(),
        kid: z.string().min(1),
      })
      .optional(),
    did: z
      .object({
        method: z.string().min(1),
        identifier: z.string().min(1),
        key_id: z.string().min(1),
      })
      .optional(),
    jwks_sha256: z.string().regex(/^[0-9a-f]{64}$/),
    trust_anchor_sha256: z.string().regex(/^[0-9a-f]{64}$/),
  })
  .refine((v) => v.jwks !== undefined || v.did !== undefined, {
    message: "verification_methods MUST carry at least one of jwks or did",
    path: ["jwks"],
  });
export type VerificationMethods = z.infer<typeof VerificationMethodsSchema>;

// ---------------------------------------------------------------------------
// Retention metadata (export bundle, FR-024c)
// ---------------------------------------------------------------------------

/** Retention metadata for export bundles. spec-049 FR-024c. */
export const RetentionMetadataSchema = z.object({
  jurisdiction: z.enum(["EU", "US", "BR", "MX", "UK", "OTHER"]),
  jurisdiction_code: z.string().regex(/^[A-Z]{2}$/),
  statute_ref: z.string().optional(),
  min_retention_years: z.number().int().min(1),
  manual_review_required: z.boolean(),
  exported_at: z.number().int().positive(),
});
export type RetentionMetadata = z.infer<typeof RetentionMetadataSchema>;

// ---------------------------------------------------------------------------
// Common enums
// ---------------------------------------------------------------------------

/** Supported protocols. spec-049 FR-015. */
export const ProtocolSchema = z.enum([
  "x402",
  "AP2",
  "ACP",
  "MCP",
  "UCP",
  "MCAP",
]);
export type Protocol = z.infer<typeof ProtocolSchema>;

/** Receipt subject — buyer-agent flows vs merchant-admin actions. */
export const ReceiptSubjectSchema = z.enum(["buyer_agent", "merchant_admin"]);
export type ReceiptSubject = z.infer<typeof ReceiptSubjectSchema>;

/** Privacy classification (FR-019g). */
export const PrivacyClassificationSchema = z.enum([
  "pii_redacted",
  "pii_hashed_salted",
  "pii_absent",
]);
export type PrivacyClassification = z.infer<typeof PrivacyClassificationSchema>;

/** Final policy decision recorded on the receipt. */
export const PolicyDecisionSchema = z.enum([
  "allow",
  "deny",
  "review",
  "challenge",
]);
export type PolicyDecision = z.infer<typeof PolicyDecisionSchema>;

// ---------------------------------------------------------------------------
// Spec-054 — x402_binding extension (ADR-054-001)
// ---------------------------------------------------------------------------
//
// Optional `x402_binding` field embedded in the TrustReceipt v1.1 body when
// the receipt is bound to an x402 flow per spec-054. When absent, the receipt
// is a standard v1.1. When present, the verifier MUST validate the extension
// shape via the discriminated `output_commitment` union.
//
// IMPORTANT (verifier-portable):
//  - This schema is additive and backward-compatible. v1.1 receipts WITHOUT
//    `x402_binding` continue to verify as before.
//  - `external_attestation` is RESERVED for v1.1 of spec-054 — the schema
//    parser accepts the shape, but Slice-1 acceptance gates (outside the
//    parser) reject `kind === "external_attestation"`.
//  - `posture` MUST be one of `confirmed` | `settlement_failed`.
//    `pending_settlement` is NOT a valid receipt posture (ADR-054-001).
//
// @see specs/058-trustreceipt-x402-binding/contracts/x402-binding-receipt-payload.schema.json
// @see specs/058-trustreceipt-x402-binding/contracts/output-commitment.schema.json

/** spec-054 — agent_authorization_chain attached to an x402 binding. */
export const AgentAuthorizationChainSchema = z.object({
  issuer: z.string().min(1),
  kid: z.string().min(1),
  verification_status: z.enum(["verified", "spoofed", "unverified"]),
  spec045_posture: z.enum(["observe", "enforce"]),
  verified_at: z.string().datetime(),
});
export type AgentAuthorizationChain = z.infer<
  typeof AgentAuthorizationChainSchema
>;

/** spec-054 — static SHA-256 output commitment (immutable artefact digest). */
export const OutputCommitmentStaticSha256Schema = z.object({
  kind: z.literal("static_sha256"),
  algorithm: z.literal("sha256"),
  value: Sha256Tagged,
  content_type: z.string().optional(),
  content_length: z.number().int().nonnegative().optional(),
});
export type OutputCommitmentStaticSha256 = z.infer<
  typeof OutputCommitmentStaticSha256Schema
>;

/** spec-054 — Merkle manifest output commitment (chunked deliverable). */
export const OutputCommitmentMerkleManifestSchema = z.object({
  kind: z.literal("merkle_manifest"),
  algorithm: z.literal("merkle-sha256-v1"),
  root: Sha256Tagged,
  manifest_url: z
    .string()
    .url()
    .regex(/^https:\/\//),
  manifest_hash: Sha256Tagged,
  chunk_size: z.number().int().positive(),
  chunk_count: z.number().int().positive(),
});
export type OutputCommitmentMerkleManifest = z.infer<
  typeof OutputCommitmentMerkleManifestSchema
>;

/**
 * spec-054 — external attestation output commitment (RESERVED for v1.1).
 * Slice-1 acceptance gates (outside this parser) MUST reject this kind.
 */
export const OutputCommitmentExternalAttestationSchema = z.object({
  kind: z.literal("external_attestation"),
  algorithm: z.union([z.literal("sha256"), z.literal("merkle-sha256-v1")]),
  value: Sha256Tagged,
  attestor: z.string().min(1),
  attestation_jws: z.string().min(1),
});
export type OutputCommitmentExternalAttestation = z.infer<
  typeof OutputCommitmentExternalAttestationSchema
>;

/** spec-054 — discriminated union over commitment kinds. */
export const OutputCommitmentSchema = z.discriminatedUnion("kind", [
  OutputCommitmentStaticSha256Schema,
  OutputCommitmentMerkleManifestSchema,
  OutputCommitmentExternalAttestationSchema,
]);
export type OutputCommitment = z.infer<typeof OutputCommitmentSchema>;

/** spec-054 — PII-filtered HMAC hashes carried alongside the x402 binding. */
export const PrivacyFilteredHashesSchema = z.object({
  resource_description_hmac: HmacSha256Tagged.optional(),
  reason_hmac: HmacSha256Tagged.optional(),
  metadata_hmacs: z.record(z.string(), HmacSha256Tagged).optional(),
  buyer_email_hmac: HmacSha256Tagged.optional(),
  buyer_address_hmacs: z.record(z.string(), HmacSha256Tagged).optional(),
});
export type PrivacyFilteredHashes = z.infer<typeof PrivacyFilteredHashesSchema>;

/**
 * spec-054 — top-level `x402_binding` extension carried inside the v1.1 body.
 *
 * Per ADR-054-001:
 *  - `posture` is constrained to `confirmed` | `settlement_failed`.
 *    `pending_settlement` is NEVER a valid receipt posture (receipts are issued
 *    only after the settlement outcome is known).
 *  - `output_commitment` is a discriminated union; `external_attestation` is
 *    RESERVED — acceptance gates outside this schema MUST reject it for Slice 1.
 */
export const X402BindingExtensionSchema = z
  .object({
    binding_profile_version: z.string().regex(/^\d+\.\d+\.\d+$/),
    binding_hash: Sha256Tagged,
    binding_components_manifest_url: z.string().url(),
    /** ULID Crockford base32 (replay key — distinct from receipt_id UUID). */
    binding_id: z.string().regex(/^[0-9A-HJKMNP-TV-Z]{26}$/),
    intent_hash: HmacSha256Tagged,
    pii_hmac_key_version: z.number().int().nonnegative(),
    /** urlbase64 unpadded, 16 bytes → 22 chars. */
    nonce: z.string().regex(/^[A-Za-z0-9_-]{22}$/),
    issued_at: z.string().datetime(),
    expires_at: z.string().datetime(),
    authorization_scheme: AuthorizationSchemeSchema,
    payment_authorization_hash: Sha256Tagged,
    verification_posture: z.enum(["unverified", "observed", "enforced"]),
    agent_authorization_chain: AgentAuthorizationChainSchema.nullable(),
    /** ADR-054-001: `pending_settlement` is NOT valid for issued receipts. */
    posture: z.enum(["confirmed", "settlement_failed"]),
    output_commitment: OutputCommitmentSchema,
    privacy_filtered_hashes: PrivacyFilteredHashesSchema,
    intent_allows_multi_settlement: z.boolean(),
  })
  // M-1 (security review 2026-05-18): reject unknown keys to prevent
  // signed-bytes-vs-parsed-keys drift (auditor view masking attacker-injected
  // semantics like `shadow_signature` / `bypass_flag`).
  .strict();
export type X402BindingExtension = z.infer<typeof X402BindingExtensionSchema>;

/**
 * spec-056 — top-level `mpp_binding` extension carried inside the v1.1 body.
 *
 * MPP (Machine Payment Protocol — draft-ryan-httpauth-payment-01) binding
 * profile. Isomorfico a `x402_binding` (spec-054) pero adaptado al flujo
 * HTTP 402 `WWW-Authenticate: Payment` → 200 OK + `Payment-Receipt` header.
 *
 * Per ADR-056:
 *  - `binding_profile_version` const `"mpp-binding/1.0"` (forward compat draft IETF).
 *  - `posture` 3-state load-bearing:
 *      `confirmed`   = challenge context hit + Payment-Receipt válido.
 *      `unverified`  = challenge context miss (NO evidencia de pago — consumers
 *                      DEBEN respetar este flag, contract test obligatorio).
 *      `recovered`   = status=already_paid (evidencia pago previo, NO insert
 *                      replay cache).
 *  - `request_hash` ata `amount/currency/recipient` del challenge sin replicar
 *    PII en el binding (pattern ADR-019).
 *  - `resource_uri_c14n` canonicalizado per §Canonicalization Rules (RFC 3986
 *    lowercase scheme+host, strip default ports, ordered query, fragment stripped).
 *  - `http_method` aparte del URI previene cross-verb replay.
 *  - `timestamp` + `expires` RFC 3339 strict UTC `Z` (regex enforced).
 *  - Si `posture === "unverified"` → `warnings` REQUIRED con ≥1 entry (cross-field).
 *    `confirmed` (evidencia válida) y `recovered` (evidencia pago previo, ADR-056)
 *    NO fuerzan warnings — pueden ir vacíos/ausentes.
 *  - Schema lock v1: NO `intent` field aquí (siempre "charge" — `session` rechazado
 *    por parser con UnsupportedIntentError, diferido a spec-057).
 *  - `method` restringido a `1*LOWERALPHA` (draft MPP §Method Identifier Format) —
 *    idéntico al ABNF del protocolo real, no solo min/max length.
 *  - `realm` (protection space del `WWW-Authenticate: Payment` real, slot 0 del
 *    binding HMAC del draft) OPCIONAL: presente cuando hubo challenge context
 *    stored (`confirmed`/`recovered`-con-ctx), ausente en `unverified` honesto
 *    (sin ctx no hay realm conocido). Gap encontrado 2026-07-04 vía fetch directo
 *    de `tempoxyz/mpp-specs` — antes de este fix, dos challenges de distinto
 *    realm con el resto de campos iguales colisionaban en el mismo binding_hash.
 *
 * Status: ✅ SSOT activo (2026-06-02). Exportado del barrel del paquete y
 * consumido por `MppReceiptIssuerService` (emisión) y `MppBindingVerifier`
 * (auditoría). Runtime parser + settlement service + 5 rutas cableados
 * (dormant hasta ops gate). Ver `wiki/protocol-notes/spec-056-trustreceipt-mpp-binding.md`.
 */
const Rfc3339StrictUtc = z
  .string()
  .regex(
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?Z$/,
    "must be RFC 3339 strict UTC `Z` (precision 3 dígitos optional)"
  );

const MppWarningCode = z.enum([
  "challenge_context_missing",
  "payment_receipt_absent",
  "timestamp_normalized",
  "digest_absent_for_mutating_method",
]);

export const MppBindingExtensionSchema = z
  .object({
    binding_profile_version: z.literal("mpp-binding/1.0"),
    /** ULID Crockford base32 — identificador unique del receipt. NO es la replay cache key. */
    binding_id: z.string().regex(/^[0-9A-HJKMNP-TV-Z]{26}$/),
    /** Payment method ("stripe" | "tempo" | "lightning" | "solana" | "visa" | "bnpl" | ...). Draft MPP §Method Identifier Format: lowercase ASCII only. */
    method: z.string().regex(/^[a-z]{1,64}$/),
    /** Method-specific tx reference (Stripe charge id, lightning preimage, solana sig, ...). */
    reference: z.string().min(1).max(512),
    /** HMAC-SHA256 challenge id del WWW-Authenticate: Payment original. */
    challenge_id: z.string().min(1).max(256),
    /**
     * Protection space (`realm` del WWW-Authenticate: Payment original) —
     * slot 0 del binding formal MPP; sin esto dos challenges de distinto
     * realm colisionarían en binding_hash. Ausente cuando posture="unverified"
     * SIN challenge context stored (no hay realm conocido que atar).
     */
    realm: z.string().min(1).max(256).optional(),
    /** Resource URI canonicalizado per §Canonicalization Rules. */
    resource_uri_c14n: z.string().url(),
    /** HTTP method del resource (uppercase) — previene cross-verb replay. */
    http_method: z.enum(["GET", "POST", "PUT", "DELETE", "PATCH"]),
    /** Timestamp del Payment-Receipt (RFC 3339 strict UTC `Z`). */
    timestamp: Rfc3339StrictUtc,
    /** sha256(JCS(challenge.request_decoded)) — ata amount/currency/recipient sin replicar PII. */
    request_hash: Sha256Tagged,
    /** RFC 9530 Content-Digest del request body (opcional, recomendado POST/PUT). */
    digest: z.string().optional(),
    /** Expiración del challenge (RFC 3339 strict). */
    expires: Rfc3339StrictUtc.optional(),
    /** sha256:hex de JCS(estructura §Binding Input Formal) — recomputable por verifier independiente. */
    binding_hash: Sha256Tagged,
    posture: z.enum(["confirmed", "unverified", "recovered"]),
    warnings: z.array(MppWarningCode).optional(),
  })
  // Strict: rechaza unknown keys (alinea con X402BindingExtensionSchema M-1).
  .strict()
  .superRefine((binding, ctx) => {
    // ADR-056 §Degradation Matrix — solo `unverified` (NO evidencia de pago)
    // REQUIRES warnings[]. `confirmed` (evidencia válida) y `recovered`
    // (evidencia pago previo válida) NO fuerzan warnings.
    if (binding.posture === "unverified") {
      if (!binding.warnings || binding.warnings.length === 0) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["warnings"],
          message: `posture="unverified" REQUIRES warnings[] with ≥1 entry (ADR-056 §Degradation Matrix — NO payment evidence). Consumers MUST inspect warnings.`,
        });
      }
    }
  });
export type MppBindingExtension = z.infer<typeof MppBindingExtensionSchema>;

// ---------------------------------------------------------------------------
// Receipt body (JWS-signed)
// ---------------------------------------------------------------------------

/**
 * TrustReceipt v1.1 body — payload of the JWS Compact serialization.
 *
 * Cross-field rules enforced via `.superRefine`:
 * - Subject-discriminated context (post-Codex M14 / round 2 D22):
 *   `buyer_agent` → MUST carry `buyer_agent_consent_context` only.
 *   `merchant_admin` → MUST carry `merchant_admin_authorization_context` only.
 * - Buyer-agent extras (post-Codex round 2 D24 + D28):
 *   `payment_authorization_hash` + `authorization_scheme` REQUIRED, and
 *   `esign_disclosure_version` + `esign_disclosure_hash` + `consent_evidence_ref`
 *   REQUIRED.
 *
 * NOTE: The 2900-byte canonical-bytes cap (FR-019e + FR-040) is enforced at
 * issuance time, NOT here — Zod operates on parsed JSON, not canonical bytes.
 */
export const TrustReceiptV11BodySchema = z
  .object({
    receipt_id: z.string().uuid(),
    schema_version: z.literal("1.1"),
    issued_at: z.number().int().positive(),
    expires_at: z.number().int().positive(),
    issuer: z.string().min(1),
    merchant_id: z.string().min(1),
    agent_provider: z.string().min(1),
    agent_id: z.union([z.string(), z.null()]),
    receipt_subject: ReceiptSubjectSchema,
    privacy_classification: PrivacyClassificationSchema,
    legal_posture: LegalPostureSchema,
    legal_posture_warnings: z.array(LegalPostureWarningSchema),
    buyer_agent_consent_context: BuyerAgentConsentContextSchema.optional(),
    merchant_admin_authorization_context:
      MerchantAdminAuthorizationContextSchema.optional(),
    /** post-Codex round 2 D32: PII source — MUST be HMAC. */
    user_intent_hash: HmacSha256Tagged,
    intent_hmac_key_version: z.number().int().nonnegative(),
    cart_hash: Sha256Tagged.optional(),
    order_hash: Sha256Tagged.optional(),
    /** post-Codex round 2 D24. */
    payment_authorization_hash: Sha256Tagged.optional(),
    authorization_scheme: AuthorizationSchemeSchema.optional(),
    /** post-Codex round 2 D28. */
    esign_disclosure_version: z
      .string()
      .regex(/^\d+\.\d+\.\d+$/)
      .optional(),
    esign_disclosure_hash: Sha256Tagged.optional(),
    consent_evidence_ref: z.string().optional(),
    transaction_id: z.string().optional(),
    protocol: ProtocolSchema,
    protocol_artifacts: z.array(
      z.object({
        type: z.string().min(1),
        hash: TaggedDigest,
        ref: z.string().optional(),
      })
    ),
    authorization_evidence: AuthorizationEvidenceSchema,
    verification_methods: VerificationMethodsSchema,
    policy_decision: PolicyDecisionSchema,
    payment_reference: z.string().optional(),
    risk_signals: z.unknown().optional(),
    trust_provider_assertions: z.unknown().optional(),
    legacy_flag: z.boolean().optional(),
    /**
     * spec-054 — optional x402 binding extension (ADR-054-001).
     * Additive + backward-compatible: v1.1 receipts without this field continue
     * to verify. When present, the discriminated `output_commitment` union and
     * `posture` enum are enforced here at parse time.
     */
    x402_binding: X402BindingExtensionSchema.optional(),
    /**
     * spec-056 — optional MPP binding extension (ADR-056).
     * Additive + backward-compatible: v1.1 receipts without this field continue
     * to verify. When present, posture/warnings cross-field rule enforced at
     * parse time. Mutually compatible with x402_binding (distintos perfiles
     * para distintos transports — x402 on-chain settlement vs MPP HTTP 402
     * challenge-bound).
     */
    mpp_binding: MppBindingExtensionSchema.optional(),
    /**
     * Platform bridge carry-over (Shopify/Woo/PS/... order linkage). Emitted
     * by the issuer into the SIGNED body when the receipt is bound to a
     * platform order. Declared here as KNOWN optional fields so the `.strict()`
     * root (A1) accepts them while still rejecting any other unknown key.
     */
    platformOrderId: z.string().optional(),
    platform: z.string().optional(),
  })
  // A1 (security audit 2026-07-03): reject unknown keys at the ROOT body, not
  // just inside the x402_binding/mpp_binding extensions (M-1). Without this a
  // caller could smuggle arbitrary semantic keys (e.g. `shadow_signature`,
  // `bypass_flag`) into the SIGNED bytes; portable verifiers parse-and-discard
  // them, so an auditor's view diverges from what was actually signed. `.strict()`
  // must precede `.superRefine` (which returns a ZodEffects, not a ZodObject).
  .strict()
  .superRefine((receipt, ctx) => {
    const hasBuyer = receipt.buyer_agent_consent_context !== undefined;
    const hasAdmin = receipt.merchant_admin_authorization_context !== undefined;

    if (receipt.receipt_subject === "buyer_agent") {
      if (!hasBuyer || hasAdmin) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["buyer_agent_consent_context"],
          message:
            "buyer_agent receipts MUST carry buyer_agent_consent_context only (post-Codex round 2 D22)",
        });
      }
      if (
        receipt.payment_authorization_hash === undefined ||
        receipt.authorization_scheme === undefined
      ) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["payment_authorization_hash"],
          message:
            "buyer_agent receipts MUST carry payment_authorization_hash AND authorization_scheme (post-Codex round 2 D24)",
        });
      }
      const esignFields = [
        "esign_disclosure_version",
        "esign_disclosure_hash",
        "consent_evidence_ref",
      ] as const;
      for (const f of esignFields) {
        if (receipt[f] === undefined) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: [f],
            message: `${f} is required for buyer_agent receipts (post-Codex round 2 D28)`,
          });
        }
      }
    }

    if (receipt.receipt_subject === "merchant_admin") {
      if (!hasAdmin || hasBuyer) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["merchant_admin_authorization_context"],
          message:
            "merchant_admin receipts MUST carry merchant_admin_authorization_context only (post-Codex round 2 D22)",
        });
      }
    }
  });
export type TrustReceiptV11Body = z.infer<typeof TrustReceiptV11BodySchema>;

// ---------------------------------------------------------------------------
// Envelope (FR-019e)
// ---------------------------------------------------------------------------

/**
 * Receipt envelope — wraps the JWS Compact `receipt` plus envelope-level
 * sidecars. `envelope_metadata` fields are NOT signed; verifiers MUST
 * recompute and reject mismatches (post-Codex round 2 D22).
 */
export const ReceiptEnvelopeSchema = z.object({
  /** JWS Compact serialization of the v1.1 body. */
  receipt: z.string().min(1),
  timestamp_evidence: TimestampEvidenceSchema,
  envelope_metadata: z.object({
    receipt_id: z.string().uuid(),
    created_at: z.number().int().positive(),
    legal_posture: LegalPostureSchema,
    legal_posture_warnings: z.array(LegalPostureWarningSchema),
  }),
  protocol_artifact_sidecars: z
    .array(
      z.object({
        type: z.string().min(1),
        hash: TaggedDigest,
        payload_b64: z.string().min(1),
      })
    )
    .optional(),
});
export type ReceiptEnvelope = z.infer<typeof ReceiptEnvelopeSchema>;
