/**
 * TrustReceipt schema v1.0
 *
 * Cross-protocol agentic commerce evidence receipt format.
 * ~20 fields covering identity, participants, transaction evidence,
 * protocol artifacts, risk signals, trust provider assertions,
 * compliance/legal context, and audit chain.
 *
 * No Prisma/DB dependency — standalone package.
 */

import { z } from "zod";

// ─── Sub-schemas ─────────────────────────────────────────────────────────────

const ProtocolArtifactSchema = z.object({
  type: z.string(),
  hash: z.string(), // SHA-256 hex
  ref: z.string().optional(),
});

const PaymentReferenceSchema = z.object({
  psp: z.string(),
  ref: z.string(),
});

const RiskSignalSchema = z.object({
  signal_type: z.string(),
  value: z.union([z.string(), z.number(), z.boolean()]),
  source: z.string(),
});

const TrustProviderAssertionSchema = z.object({
  provider: z.string(),
  assertion_type: z.string(), // open string — kyc|fraud_score|agent_trust|payment_trust|identity + provider-specific values
  score: z.number().min(0).max(1).nullable().optional(),
  score_range: z.string().nullable().optional(), // e.g. "0-1000"
  ts: z.number().int(),
  confidence: z.enum(["low", "medium", "high"]),
  evidence_hash: z.string().optional(),
});

const VerificationMethodSchema = z.object({
  type: z.enum(["jwks", "did", "key_id"]),
  value: z.string(),
});

const LiabilityContextSchema = z.object({
  assertor: z.string(),
  scope: z.string(),
});

const ConsentContextSchema = z.object({
  consent_hash: z.string(),
  scope: z.string(),
  ts: z.number().int(),
});

const PrivacyClassificationSchema = z.object({
  contains_pii: z.boolean(),
  retention_days: z.number().int().optional(),
  jurisdiction: z.string().optional(),
});

const AttachmentSchema = z.object({
  name: z.string(),
  content_type: z.string(),
  hash: z.string(),
  uri: z.string().optional(),
});

// ─── Root schema ─────────────────────────────────────────────────────────────

export const TrustReceiptSchema = z.object({
  // Core identity
  receipt_id: z.string().uuid(),
  schema_version: z.literal("1.0"),
  issued_at: z.number().int(),
  expires_at: z.number().int(),
  issuer: z.string(), // e.g. "trusteed.xyz" or merchant domain

  // Participants
  merchant_id: z.string(),
  agent_id: z.string(),
  agent_provider: z.string(), // e.g. "anthropic", "openai", "google"

  // Transaction evidence
  user_intent_hash: z.string().min(1), // SHA-256 hex of user intent text — MUST be non-empty (SPEC §4 Step 4)
  cart_hash: z.string().nullable().optional(),
  order_hash: z.string().nullable().optional(),
  transaction_id: z.string().nullable().optional(),

  // Protocol
  protocol: z.enum(["x402", "AP2", "ACP", "MCP", "UCP", "MCAP"]),
  protocol_artifacts: z.array(ProtocolArtifactSchema),

  // Payment (no raw payment data)
  payment_reference: PaymentReferenceSchema.nullable().optional(),

  // Risk signals (normalized, NOT proprietary blobs)
  risk_signals: z.array(RiskSignalSchema).default([]),

  // Trust provider assertions
  trust_provider_assertions: z.array(TrustProviderAssertionSchema).default([]),

  // Decision
  policy_decision: z.enum(["allow", "deny", "review", "challenge"]),

  // Compliance/legal
  liability_context: LiabilityContextSchema.nullable().optional(),
  consent_context: ConsentContextSchema.nullable().optional(),
  privacy_classification: PrivacyClassificationSchema.nullable().optional(),

  // Verification — SPEC §4 Step 4: MUST be a non-empty array
  verification_methods: z.array(VerificationMethodSchema).min(1),
  kid: z.string(), // Key ID used to sign

  // Audit chain
  hash_chain_prev: z.string().nullable().optional(), // SHA-256 hex of previous receipt

  // Attachments
  attachments: z.array(AttachmentSchema).default([]),

  // Signature (populated when receipt is issued as JWS)
  signature: z.string().optional(),
});

// ─── Types ────────────────────────────────────────────────────────────────────

export type TrustReceipt = z.infer<typeof TrustReceiptSchema>;

/** TrustReceipt without the signature field — used as the JWS payload. */
export type TrustReceiptPayload = Omit<TrustReceipt, "signature">;

// ─── Sub-schema types (exported for use in issuer/verifier) ──────────────────

export type ProtocolArtifact = z.infer<typeof ProtocolArtifactSchema>;
export type RiskSignal = z.infer<typeof RiskSignalSchema>;
export type TrustProviderAssertion = z.infer<
  typeof TrustProviderAssertionSchema
>;
export type VerificationMethod = z.infer<typeof VerificationMethodSchema>;
export type Attachment = z.infer<typeof AttachmentSchema>;
