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
    revocation_evidence: z.object({
      kind: z.enum(["ocsp", "crl"]),
      data_b64: z.string().min(1),
    }),
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
  })
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
