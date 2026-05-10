/**
 * Receipt body / envelope construction helpers for T065 vectors.
 *
 * Each helper takes deterministic seeded inputs and returns plain TS objects
 * matching `types-1.1.ts`. Hash fields use HMAC-SHA-256 over the canonical
 * preimage with a deterministic per-merchant test key (derived from the
 * master seed). The verifier-side conformance suite knows the test HMAC key
 * and recomputes hashes to validate intent → execution binding.
 */
import { createHash, createHmac, randomUUID } from "node:crypto";

import { CompactSign, type JWK } from "jose";
import { importJWK } from "jose";

import type {
  AgentAuthorizationChain,
  AuthorizationChainEntry,
  AuthorizationEvidence,
  AuthorizationScheme,
  BuyerAgentConsentContext,
  HmacSha256Tagged,
  JwksHistoryEntry,
  LegalPosture,
  LegalPostureWarning,
  MerchantAdminAuthorizationContext,
  PrivacyClassification,
  Protocol,
  ReceiptEnvelope,
  ReceiptSubject,
  Sha256Tagged,
  TimestampEvidence,
  TimestampUnavailable,
  TrustReceiptV11Body,
  VerificationMethods,
} from "../../src/types-1.1.js";

import { canonicalizeJson } from "./canonical.js";
import type { TestKeyPair } from "./keys.js";

const TEST_HMAC_KEY = createHash("sha256")
  .update("T065-spec049-test-hmac-key")
  .digest();

export const TEST_HMAC_KEY_VERSION = 1;

export function hmacTagged(preimage: string): HmacSha256Tagged {
  const h = createHmac("sha256", TEST_HMAC_KEY)
    .update(preimage, "utf8")
    .digest("hex");
  return `hmac-sha256:${h}`;
}

export function sha256Tagged(preimage: string): Sha256Tagged {
  const h = createHash("sha256").update(preimage, "utf8").digest("hex");
  return `sha256:${h}`;
}

export function sha256Hex(preimage: string | Buffer): string {
  const h = createHash("sha256");
  if (typeof preimage === "string") h.update(preimage, "utf8");
  else h.update(preimage);
  return h.digest("hex");
}

// ─── Deterministic UUIDs (NOT secure — vectors only) ─────────────────────────

export function deterministicUuid(seedLabel: string): string {
  const h = createHash("sha256").update(seedLabel).digest();
  // Format as RFC 4122 UUID v4 (set version + variant bits).
  if (h[6] === undefined || h[8] === undefined)
    throw new Error("uuid: hash short");
  h[6] = (h[6] & 0x0f) | 0x40;
  h[8] = (h[8] & 0x3f) | 0x80;
  const hex = h.subarray(0, 16).toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

// Suppress unused-import warning for randomUUID — kept available for future tweaks.
void randomUUID;

// ─── Verification methods (with deterministic JWKS pin) ──────────────────────

export function buildVerificationMethods(opts: {
  jwksUri: string;
  kid: string;
  jwksPub: { keys: Record<string, unknown>[] };
  trustAnchorSha256: string;
}): VerificationMethods {
  const jwksCanonical = canonicalizeJson(opts.jwksPub);
  const jwksSha256 = createHash("sha256")
    .update(jwksCanonical, "utf8")
    .digest("hex");
  return {
    jwks: { uri: opts.jwksUri, kid: opts.kid },
    jwks_sha256: jwksSha256,
    trust_anchor_sha256: opts.trustAnchorSha256,
  };
}

// ─── Buyer-agent consent context ─────────────────────────────────────────────

export interface BuyerCtxOpts {
  consentTimestamp: number;
  disclosureVersion: string;
  withdrawalUrl: string;
  consentText: string;
  evidenceRef: string;
  agentId: string;
}

export function buildBuyerAgentConsentContext(
  opts: BuyerCtxOpts
): BuyerAgentConsentContext {
  const userEntry: AuthorizationChainEntry = {
    actor: "user",
    method: "OAuth+MFA",
    hash: hmacTagged(`user-auth:${opts.evidenceRef}`),
    timestamp: opts.consentTimestamp,
  };
  const agentEntry: AuthorizationChainEntry = {
    actor: "agent",
    method: "rfc9421_signature",
    hash: hmacTagged(`agent-auth:${opts.agentId}`),
    timestamp: opts.consentTimestamp + 1,
    ref: opts.agentId,
  };
  const chain: AgentAuthorizationChain = [userEntry, agentEntry] as const;
  return {
    consent_type: "explicit_action",
    consent_timestamp: opts.consentTimestamp,
    consent_hash: hmacTagged(opts.consentText),
    consent_hmac_key_version: TEST_HMAC_KEY_VERSION,
    consent_disclosure_version: opts.disclosureVersion,
    consent_withdrawal_uri_hash: sha256Tagged(opts.withdrawalUrl),
    consent_evidence_ref: opts.evidenceRef,
    agent_authorization_chain: chain,
  };
}

// ─── Merchant-admin context ──────────────────────────────────────────────────

export function buildMerchantAdminContext(opts: {
  adminUserId: string;
  actionType: string;
  mfaChallenge: string;
  rbacRole: string;
  actedAt: number;
}): MerchantAdminAuthorizationContext {
  return {
    admin_user_id_hash: hmacTagged(opts.adminUserId),
    admin_action_type: opts.actionType,
    admin_authentication_method: "shopify_app_bridge_jwt",
    mfa_evidence_hash: hmacTagged(opts.mfaChallenge),
    rbac_role_at_action_time: opts.rbacRole,
    acted_at: opts.actedAt,
  };
}

// ─── Receipt body assembly ───────────────────────────────────────────────────

export interface ReceiptBuildOpts {
  receiptId: string;
  issuedAt: number;
  expiresAt: number;
  issuer: string;
  merchantId: string;
  agentId: string | null;
  agentProvider: string;
  receiptSubject: ReceiptSubject;
  privacyClassification: PrivacyClassification;
  legalPosture: LegalPosture;
  legalPostureWarnings: LegalPostureWarning[];
  buyerCtx?: BuyerAgentConsentContext;
  adminCtx?: MerchantAdminAuthorizationContext;
  userIntentText: string;
  cartCanonical?: string;
  orderCanonical?: string;
  paymentAuthCanonical?: string;
  authorizationScheme?: AuthorizationScheme;
  esignDisclosureVersion?: string;
  esignDisclosureContent?: string;
  consentEvidenceRef?: string;
  transactionId?: string;
  protocol: Protocol;
  authorizationEvidence: AuthorizationEvidence;
  verificationMethods: VerificationMethods;
  policyDecision: TrustReceiptV11Body["policy_decision"];
  legacyFlag?: "legacy_pre_eidas_hardening";
}

export function buildReceiptBody(opts: ReceiptBuildOpts): TrustReceiptV11Body {
  const body: TrustReceiptV11Body = {
    receipt_id: opts.receiptId,
    schema_version: "1.1",
    issued_at: opts.issuedAt,
    expires_at: opts.expiresAt,
    issuer: opts.issuer,
    merchant_id: opts.merchantId,
    agent_id: opts.agentId,
    agent_provider: opts.agentProvider,
    receipt_subject: opts.receiptSubject,
    privacy_classification: opts.privacyClassification,
    legal_posture: opts.legalPosture,
    legal_posture_warnings: opts.legalPostureWarnings,
    user_intent_hash: hmacTagged(opts.userIntentText),
    intent_hmac_key_version: TEST_HMAC_KEY_VERSION,
    protocol: opts.protocol,
    protocol_artifacts: [],
    authorization_evidence: opts.authorizationEvidence,
    verification_methods: opts.verificationMethods,
    policy_decision: opts.policyDecision,
  };
  if (opts.buyerCtx) body.buyer_agent_consent_context = opts.buyerCtx;
  if (opts.adminCtx) body.merchant_admin_authorization_context = opts.adminCtx;
  if (opts.cartCanonical) body.cart_hash = sha256Tagged(opts.cartCanonical);
  if (opts.orderCanonical) body.order_hash = sha256Tagged(opts.orderCanonical);
  if (opts.paymentAuthCanonical)
    body.payment_authorization_hash = sha256Tagged(opts.paymentAuthCanonical);
  if (opts.authorizationScheme)
    body.authorization_scheme = opts.authorizationScheme;
  if (opts.esignDisclosureVersion)
    body.esign_disclosure_version = opts.esignDisclosureVersion;
  if (opts.esignDisclosureContent)
    body.esign_disclosure_hash = sha256Tagged(opts.esignDisclosureContent);
  if (opts.consentEvidenceRef)
    body.consent_evidence_ref = opts.consentEvidenceRef;
  if (opts.transactionId) body.transaction_id = opts.transactionId;
  if (opts.legacyFlag) body.legacy_flag = opts.legacyFlag;
  return body;
}

// ─── JWS Compact signing (deterministic — Ed25519 is deterministic) ──────────

export async function signReceiptJws(
  body: TrustReceiptV11Body,
  kp: TestKeyPair
): Promise<string> {
  const privateKey = await importJWK(kp.jwkPriv as unknown as JWK, "EdDSA");
  const payload = canonicalizeJson(body);
  const jws = await new CompactSign(new TextEncoder().encode(payload))
    .setProtectedHeader({ alg: "EdDSA", kid: kp.kid, typ: "JWT" })
    .sign(privateKey);
  return jws;
}

// ─── Envelope assembly ───────────────────────────────────────────────────────

export function buildEnvelope(opts: {
  jwsCompact: string;
  body: TrustReceiptV11Body;
  timestampEvidence: TimestampEvidence | TimestampUnavailable;
  envelopeCreatedAt: number;
}): ReceiptEnvelope {
  return {
    receipt: opts.jwsCompact,
    timestamp_evidence: opts.timestampEvidence,
    envelope_metadata: {
      receipt_id: opts.body.receipt_id,
      created_at: opts.envelopeCreatedAt,
      legal_posture: opts.body.legal_posture,
      legal_posture_warnings: opts.body.legal_posture_warnings,
    },
  };
}

// ─── JWKS history (for vector 016 rotated key) ───────────────────────────────

export function buildJwksHistory(
  entries: JwksHistoryEntry[]
): JwksHistoryEntry[] {
  return entries.map((e) => ({ ...e }));
}
