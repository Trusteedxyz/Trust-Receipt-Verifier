/**
 * TrustReceipt v1.0-legacy compact schema (C3 closure — 2026-07-03).
 *
 * The production receipt issuer (`apps/api/.../trust-receipt.service.ts`,
 * `TrustReceiptService.sign` / `.signFromHashes`) has, since spec-040 US2,
 * emitted a JWT-style compact payload that PREDATES the `TrustReceiptSchema`
 * canonical v1.0 shape. That payload carries:
 *
 *   { iss:"merchant:<id>", sub:<callId>, iat, callId, merchantId, agentId,
 *     bucket, tool, inputHash, outputHash, outputHashStatus,
 *     trust_provider_assertions, kid, platformOrderId?, platform?, outcome? }
 *
 * Since 2026-07-27 the issuer additionally stamps `schema_version:"1.0"`,
 * `canon:"jcs"`, `expires_at`, and — conditionally — `protocol`,
 * `policy_decision`, `amount`+`currency` and `checkout_session_id` onto that
 * same shape (T1.3 enrichment). The payload still lacks `receipt_id`,
 * `user_intent_hash` and `verification_methods`, so `TrustReceiptSchema` keeps
 * rejecting it with `schema_invalid` — meaning any third party using the
 * standalone verifier package could not verify a receipt the platform actually
 * issued.
 *
 * These receipts are ALREADY signed and persisted immutably (`trust_receipts`,
 * append-only), so the signed bytes cannot be rewritten. Per FR-018 (v1.0 MUST
 * verify ≥ 7 years) the ONLY backward-compatible closure is to teach the
 * verifier to recognise + verify this actually-emitted format. This schema is
 * that recognizer.
 *
 * SAFETY: this schema is a SEPARATE, additive branch. It does NOT relax the
 * canonical `TrustReceiptSchema` (which still governs conformant v1.0 receipts)
 * and has NOTHING to do with the v1.1 envelope verifier. The JWS signature
 * remains the security boundary — this schema only runs AFTER `compactVerify`
 * has cryptographically validated the payload bytes.
 */

import { z } from "zod";
import { PolicyEvidenceFields } from "./policy-evidence.js";

// ─── Legacy compact schema ───────────────────────────────────────────────────
//
// Field optionality is deliberately permissive on the non-distinctive fields so
// that the OLDEST issued receipts (pre-`outputHashStatus`, pre-
// `trust_provider_assertions`) keep verifying for the full ≥ 7-year window. The
// REQUIRED set is the minimal distinctive fingerprint that only the legacy
// issuer produces, so this branch never accidentally accepts an unrelated JWS.

export const TrustReceiptLegacyCompactSchema = z.object({
  // Distinctive required fingerprint (always emitted by the legacy issuer).
  iss: z.string().min(1),
  iat: z.number().int(),
  callId: z.string().min(1),
  merchantId: z.string().min(1),
  agentId: z.string().min(1),
  tool: z.string().min(1),
  inputHash: z.string().min(1),
  outputHash: z.string().min(1),
  kid: z.string().min(1),

  // Present on all modern legacy receipts; optional to cover the earliest rows.
  sub: z.string().optional(),
  bucket: z.enum(["discovery", "customer", "checkout"]).optional(),
  outputHashStatus: z.enum(["captured", "not_captured"]).optional(),
  trust_provider_assertions: z.array(z.unknown()).optional(),

  // Optional carry-over fields (platform bridges, spec-062 failure outcome).
  platformOrderId: z.string().optional(),
  platform: z.string().optional(),
  outcome: z.enum(["SUCCESS", "FAILURE"]).optional(),

  // ── T1.3 enrichment (2026-07-27) ──────────────────────────────────────────
  //
  // The issuer now stamps these onto the SAME compact payload. They must be
  // DECLARED here even though this is a non-strict `z.object`: non-strict means
  // undeclared keys are accepted, but Zod still STRIPS them from the parsed
  // output. Without these lines the enrichment verified fine yet never reached
  // `VerifyResult.legacyReceipt`, so it was invisible through the public type.
  //
  // All optional: receipts issued before the enrichment must keep verifying for
  // the full >= 7-year window (FR-018).
  /** Always `"1.0"` on this shape. `"1.1"` and `v1.0-FINAL` route elsewhere. */
  schema_version: z.literal("1.0").optional(),
  /** `"jcs"` ⇒ signing input is the RFC 8785 canonical form. */
  canon: z.literal("jcs").optional(),
  /**
   * INFORMATIVE ONLY — deliberately NOT enforced as a validity gate. See
   * `verifyLegacyCompact` in `../verifier.ts`.
   */
  expires_at: z.number().int().optional(),
  protocol: z.string().optional(),
  policy_decision: z.string().optional(),
  /** Emitted together with `currency`, or not at all. */
  amount: z.string().optional(),
  currency: z.string().optional(),
  checkout_session_id: z.string().optional(),

  // ── Evidencia de política (R-02, 2026-07-29) ──────────────────────────────
  // Declarados aquí por el MISMO motivo que el bloque de arriba: no estricto
  // acepta claves no declaradas pero Zod las descarta del objeto parseado, así
  // que sin esto verificarían y no llegarían nunca a `VerifyResult`.
  // Esta es la forma que emite producción hoy, así que es la que tiene que
  // poder transportarlos cuando se cablee el emisor.
  ...PolicyEvidenceFields,
});

export type TrustReceiptLegacyCompact = z.infer<
  typeof TrustReceiptLegacyCompactSchema
>;
