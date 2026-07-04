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
 * It has NONE of `receipt_id` / `schema_version` / `user_intent_hash` /
 * `verification_methods` / `policy_decision`, so `TrustReceiptSchema` rejects
 * it with `schema_invalid` — meaning any third party using the standalone
 * verifier package could not verify a receipt the platform actually issued.
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
});

export type TrustReceiptLegacyCompact = z.infer<
  typeof TrustReceiptLegacyCompactSchema
>;
