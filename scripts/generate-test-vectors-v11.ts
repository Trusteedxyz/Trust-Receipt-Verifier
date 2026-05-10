/**
 * T065 — Deterministic seeded build script for v1.1 conformance vectors 011-018.
 * SOT: specs/049-trust-receipt-eidas-hardening/research.md R9 + R13;
 * data-model.md §2/§3; CODEX-REMEDIATION-2026-05-04.md (D24/D25/D27/D32).
 * Run: `pnpm --filter trust-receipt-verifier exec tsx scripts/generate-test-vectors-v11.ts [--dry-run]`.
 * Reproducible: same MASTER_SEED → byte-identical output across runs.
 */
import { writeFileSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";

import type {
  AuthorizationEvidence,
  ReceiptEnvelope,
  TimestampEvidence,
  TimestampUnavailable,
  TrustReceiptV11Body,
} from "../src/types-1.1.js";

import { canonicalizeJson, prettyDeterministic } from "./lib/canonical.js";
import { buildTestKeyPair, type TestKeyPair } from "./lib/keys.js";
import { createSeededStream, MASTER_SEED } from "./lib/seeded-rng.js";
import {
  buildSyntheticTimeStampToken,
  buildSyntheticTsaCert,
  type SyntheticTstResult,
} from "./lib/tst.js";
import {
  buildBuyerAgentConsentContext,
  buildEnvelope,
  buildMerchantAdminContext,
  buildReceiptBody,
  buildVerificationMethods,
  deterministicUuid,
  hmacTagged,
  sha256Tagged,
  signReceiptJws,
  TEST_HMAC_KEY_VERSION,
} from "./lib/builders.js";

// ─── Constants ────────────────────────────────────────────────────────────────

const VECTORS_DIR = (() => {
  const here = dirname(fileURLToPath(import.meta.url));
  return join(here, "..", "test-vectors", "v11");
})();

/** Fixed test issuer + merchant + URLs. */
const ISSUER = "https://test.trusteed.xyz";
const MERCHANT_ID = "merchant_T065_test";
const JWKS_URI = "https://test.trusteed.xyz/.well-known/jwks.json";
const KID_V1 = "tr-ed25519-v11-test-2026";
const KID_V2 = "tr-ed25519-v11-test-2026-rotated";

/** Fixed timestamps (deterministic). 2026-05-01 00:00 UTC. */
const ISSUED_AT_V1 = Math.floor(Date.UTC(2026, 4, 1, 0, 0, 0) / 1000);
const ISSUED_AT_LEGACY = Math.floor(Date.UTC(2025, 0, 1, 0, 0, 0) / 1000);
const TST_GEN_TIME = new Date(Date.UTC(2026, 4, 1, 0, 0, 5));
const KID_V2_VALID_FROM = ISSUED_AT_V1 + 7 * 86400;

const TSA_ENDPOINT = "https://test-tsa.trusteed.xyz/tsa";
const TSA_POLICY_OID = "1.2.3.4.5.6.7.8.9";

// ─── Vector contract ─────────────────────────────────────────────────────────

interface VectorFile {
  vector_id: string;
  title: string;
  envelope: ReceiptEnvelope | { receipt: string; legacy_v1_0: true };
  verify_options: Record<string, unknown>;
  expected: {
    outcome: "accepted" | "rejected";
    errorCode: string | null;
    recomputed_legal_posture: string | null;
    warnings: string[];
  };
}

interface VectorResult {
  filename: string;
  content: VectorFile;
}

// ─── Shared seed-derived primitives ──────────────────────────────────────────

const masterStream = createSeededStream(MASTER_SEED, "T065-master");
const issuerKeyV1 = buildTestKeyPair(
  masterStream.derive("issuer-key-v1").bytes(32),
  KID_V1
);
const issuerKeyV2 = buildTestKeyPair(
  masterStream.derive("issuer-key-v2").bytes(32),
  KID_V2
);
const tsaKey = buildTestKeyPair(
  masterStream.derive("tsa-key").bytes(32),
  "tsa-test-cert"
);

const tsaCert = buildSyntheticTsaCert({
  ed25519PubRaw: extractEd25519RawPub(tsaKey),
  cnLabel: "T065 Test TSA",
});

// JWKS objects for hash pinning.
const jwksV1 = {
  keys: [{ ...issuerKeyV1.jwkPub, alg: "EdDSA", use: "sig" }],
};
const jwksV2 = {
  keys: [
    { ...issuerKeyV1.jwkPub, alg: "EdDSA", use: "sig" },
    { ...issuerKeyV2.jwkPub, alg: "EdDSA", use: "sig" },
  ],
};

const TRUST_ANCHOR_SHA256 = createHash("sha256")
  .update("T065-issuer-root-trust-anchor", "utf8")
  .digest("hex");

function extractEd25519RawPub(kp: TestKeyPair): Buffer {
  const x = kp.jwkPub.x;
  const padded = x + "==".slice(0, (4 - (x.length % 4)) % 4);
  return Buffer.from(padded.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

function buildTst(opts: {
  jwsCompact: string;
  nonceLabel: string;
  serial: number;
  genTime?: Date;
}): SyntheticTstResult {
  const imprint = createHash("sha256").update(opts.jwsCompact, "utf8").digest();
  const nonce = createSeededStream(
    MASTER_SEED,
    `tst-nonce/${opts.nonceLabel}`
  ).bytes(16);
  return buildSyntheticTimeStampToken({
    imprint,
    nonce,
    genTime: opts.genTime ?? TST_GEN_TIME,
    policyOid: TSA_POLICY_OID,
    serial: opts.serial,
    tsaCertPem: tsaCert.pem,
    tsaCertDer: tsaCert.derBuffer,
    tsaRootSha256: tsaCert.sha256Hex,
  });
}

function tsEvidenceFromTst(tst: SyntheticTstResult): TimestampEvidence {
  return {
    type: "RFC3161",
    tsa_endpoint: TSA_ENDPOINT,
    tsr: tst.tsr,
    tst: tst.tst,
    issued_at_attested: Math.floor(TST_GEN_TIME.getTime() / 1000),
    imprint_algo: "sha-256",
    imprint_target: "jws_compact_bytes",
    nonce: createSeededStream(MASTER_SEED, `tst-nonce-hex`)
      .bytes(16)
      .toString("hex"),
    policy_oid: TSA_POLICY_OID,
    tsa_cert_chain: tst.tsaCertChain,
    tsa_root_cert_sha256: tst.tsaRootSha256,
    revocation_evidence: tst.revocationEvidence,
    tolerance_seconds: 60,
  };
}

function tsUnavailable(
  reason: TimestampUnavailable["reason"]
): TimestampUnavailable {
  return {
    type: "unavailable",
    reason,
    attempted_tsa: [TSA_ENDPOINT, "https://test-tsa-2.trusteed.xyz/tsa"],
    attempted_at: ISSUED_AT_V1,
  };
}

// ─── Common authorization-evidence + verification-methods (v1) ───────────────

function buyerAuthEvidence(
  intent: string,
  execCanonical: string
): AuthorizationEvidence {
  return {
    user_intent_hash: hmacTagged(intent),
    intent_hmac_key_version: TEST_HMAC_KEY_VERSION,
    execution_hash: sha256Tagged(execCanonical),
    protocol_authorization_ref: "ap2-mandate-test-001",
  };
}

const verifyMethodsV1 = buildVerificationMethods({
  jwksUri: JWKS_URI,
  kid: KID_V1,
  jwksPub: jwksV1,
  trustAnchorSha256: TRUST_ANCHOR_SHA256,
});

// ─── Vector 011 — buyer_agent happy path ─────────────────────────────────────

export async function generateVector011_HappyPath(): Promise<VectorResult> {
  const buyerCtx = buildBuyerAgentConsentContext({
    consentTimestamp: ISSUED_AT_V1 - 60,
    disclosureVersion: "1.0.0",
    withdrawalUrl: "https://merchant.example/withdraw",
    consentText: "I authorize agent X to purchase up to $100",
    evidenceRef: "vault://consent/011",
    agentId: "agent-buyer-test-011",
  });
  const cart = canonicalizeJson({ items: [{ sku: "A", qty: 1, price: 1000 }] });
  const order = canonicalizeJson({ order_id: "o-011", total: 1000 });
  const paymentAuth = canonicalizeJson({
    type: "ap2_mandate",
    mandate_id: "m-011",
  });
  const disclosure = "ESIGN test disclosure v1.0.0";

  const body = buildReceiptBody({
    receiptId: deterministicUuid("vector-011"),
    issuedAt: ISSUED_AT_V1,
    expiresAt: ISSUED_AT_V1 + 86400,
    issuer: ISSUER,
    merchantId: MERCHANT_ID,
    agentId: "agent-buyer-test-011",
    agentProvider: "Anthropic",
    receiptSubject: "buyer_agent",
    privacyClassification: "pii_hashed_salted",
    legalPosture: "ades_candidate_timestamped",
    legalPostureWarnings: [],
    buyerCtx,
    userIntentText: "Buy one A please",
    cartCanonical: cart,
    orderCanonical: order,
    paymentAuthCanonical: paymentAuth,
    authorizationScheme: "ap2_mandate_jws",
    esignDisclosureVersion: "1.0.0",
    esignDisclosureContent: disclosure,
    consentEvidenceRef: "vault://consent/011",
    transactionId: "tx-011",
    protocol: "AP2",
    authorizationEvidence: buyerAuthEvidence("Buy one A please", paymentAuth),
    verificationMethods: verifyMethodsV1,
    policyDecision: "allow",
  });
  const jws = await signReceiptJws(body, issuerKeyV1);
  const tst = buildTst({ jwsCompact: jws, nonceLabel: "011", serial: 11 });
  const envelope = buildEnvelope({
    jwsCompact: jws,
    body,
    timestampEvidence: tsEvidenceFromTst(tst),
    envelopeCreatedAt: ISSUED_AT_V1 + 1,
  });

  return {
    filename: "011-buyer-agent-happy-path.json",
    content: {
      vector_id: "011",
      title: "v1.1 buyer_agent checkout happy path (timestamped, AP2)",
      envelope,
      verify_options: {
        expectedSubject: "buyer_agent",
        jwks: jwksV1,
        currentTime: ISSUED_AT_V1 + 60,
      },
      expected: {
        outcome: "accepted",
        errorCode: null,
        recomputed_legal_posture: "ades_candidate_timestamped",
        warnings: [],
      },
    },
  };
}

// ─── Vector 012 — missing buyer_agent_consent_context ────────────────────────

export async function generateVector012_MissingConsentContext(): Promise<VectorResult> {
  const cart = canonicalizeJson({ items: [{ sku: "B", qty: 1, price: 500 }] });
  const paymentAuth = canonicalizeJson({
    type: "ap2_mandate",
    mandate_id: "m-012",
  });

  // Intentionally OMIT buyerCtx — receipt_subject says buyer_agent but no context.
  const body: TrustReceiptV11Body = {
    receipt_id: deterministicUuid("vector-012"),
    schema_version: "1.1",
    issued_at: ISSUED_AT_V1,
    expires_at: ISSUED_AT_V1 + 86400,
    issuer: ISSUER,
    merchant_id: MERCHANT_ID,
    agent_id: "agent-buyer-test-012",
    agent_provider: "Anthropic",
    receipt_subject: "buyer_agent",
    privacy_classification: "pii_hashed_salted",
    legal_posture: "ades_candidate_timestamped",
    legal_posture_warnings: [],
    user_intent_hash: hmacTagged("Buy one B"),
    intent_hmac_key_version: TEST_HMAC_KEY_VERSION,
    cart_hash: sha256Tagged(cart),
    payment_authorization_hash: sha256Tagged(paymentAuth),
    authorization_scheme: "ap2_mandate_jws",
    esign_disclosure_version: "1.0.0",
    esign_disclosure_hash: sha256Tagged("disclosure"),
    consent_evidence_ref: "vault://consent/012",
    protocol: "AP2",
    protocol_artifacts: [],
    authorization_evidence: buyerAuthEvidence("Buy one B", paymentAuth),
    verification_methods: verifyMethodsV1,
    policy_decision: "allow",
  };
  const jws = await signReceiptJws(body, issuerKeyV1);
  const tst = buildTst({ jwsCompact: jws, nonceLabel: "012", serial: 12 });
  const envelope = buildEnvelope({
    jwsCompact: jws,
    body,
    timestampEvidence: tsEvidenceFromTst(tst),
    envelopeCreatedAt: ISSUED_AT_V1 + 1,
  });

  return {
    filename: "012-missing-consent-context.json",
    content: {
      vector_id: "012",
      title: "v1.1 buyer_agent receipt missing buyer_agent_consent_context",
      envelope,
      verify_options: {
        expectedSubject: "buyer_agent",
        jwks: jwksV1,
        currentTime: ISSUED_AT_V1 + 60,
      },
      expected: {
        outcome: "rejected",
        errorCode: "missing_required_consent_context",
        recomputed_legal_posture: null,
        warnings: [],
      },
    },
  };
}

// ─── Vector 013 — receipt_subject mismatch ───────────────────────────────────

export async function generateVector013_ReceiptSubjectMismatch(): Promise<VectorResult> {
  const adminCtx = buildMerchantAdminContext({
    adminUserId: "admin-013",
    actionType: "refund",
    mfaChallenge: "mfa-challenge-013",
    rbacRole: "merchant_admin",
    actedAt: ISSUED_AT_V1,
  });
  const body = buildReceiptBody({
    receiptId: deterministicUuid("vector-013"),
    issuedAt: ISSUED_AT_V1,
    expiresAt: ISSUED_AT_V1 + 86400,
    issuer: ISSUER,
    merchantId: MERCHANT_ID,
    agentId: null,
    agentProvider: "n/a",
    receiptSubject: "merchant_admin",
    privacyClassification: "pii_hashed_salted",
    legalPosture: "merchant_admin_action",
    legalPostureWarnings: [],
    adminCtx,
    userIntentText: "Refund order o-013",
    transactionId: "tx-013",
    protocol: "MCP",
    authorizationEvidence: {
      user_intent_hash: hmacTagged("Refund order o-013"),
      intent_hmac_key_version: TEST_HMAC_KEY_VERSION,
      execution_hash: sha256Tagged("refund-013-canonical"),
    },
    verificationMethods: verifyMethodsV1,
    policyDecision: "allow",
  });
  const jws = await signReceiptJws(body, issuerKeyV1);
  const tst = buildTst({ jwsCompact: jws, nonceLabel: "013", serial: 13 });
  const envelope = buildEnvelope({
    jwsCompact: jws,
    body,
    timestampEvidence: tsEvidenceFromTst(tst),
    envelopeCreatedAt: ISSUED_AT_V1 + 1,
  });

  return {
    filename: "013-receipt-subject-mismatch.json",
    content: {
      vector_id: "013",
      title:
        "v1.1 merchant_admin receipt verified with expectedSubject=buyer_agent (mismatch)",
      envelope,
      verify_options: {
        expectedSubject: "buyer_agent",
        jwks: jwksV1,
        currentTime: ISSUED_AT_V1 + 60,
      },
      expected: {
        outcome: "rejected",
        errorCode: "receipt_subject_mismatch",
        recomputed_legal_posture: null,
        warnings: [],
      },
    },
  };
}

// ─── Vector 014 — valid timestamp_evidence (full TST per D25) ────────────────

export async function generateVector014_ValidTst(): Promise<VectorResult> {
  // Same shape as 011 but emphasized on TSR + TST + revocation evidence (D25).
  const buyerCtx = buildBuyerAgentConsentContext({
    consentTimestamp: ISSUED_AT_V1 - 30,
    disclosureVersion: "1.0.0",
    withdrawalUrl: "https://merchant.example/withdraw",
    consentText: "I authorize timestamped checkout 014",
    evidenceRef: "vault://consent/014",
    agentId: "agent-buyer-test-014",
  });
  const cart = canonicalizeJson({ items: [{ sku: "C", qty: 2, price: 250 }] });
  const paymentAuth = canonicalizeJson({
    type: "ap2_mandate",
    mandate_id: "m-014",
  });
  const body = buildReceiptBody({
    receiptId: deterministicUuid("vector-014"),
    issuedAt: ISSUED_AT_V1,
    expiresAt: ISSUED_AT_V1 + 86400,
    issuer: ISSUER,
    merchantId: MERCHANT_ID,
    agentId: "agent-buyer-test-014",
    agentProvider: "Anthropic",
    receiptSubject: "buyer_agent",
    privacyClassification: "pii_hashed_salted",
    legalPosture: "ades_candidate_timestamped",
    legalPostureWarnings: [],
    buyerCtx,
    userIntentText: "Timestamped 014",
    cartCanonical: cart,
    paymentAuthCanonical: paymentAuth,
    authorizationScheme: "ap2_mandate_jws",
    esignDisclosureVersion: "1.0.0",
    esignDisclosureContent: "ESIGN disclosure 014",
    consentEvidenceRef: "vault://consent/014",
    protocol: "AP2",
    authorizationEvidence: buyerAuthEvidence("Timestamped 014", paymentAuth),
    verificationMethods: verifyMethodsV1,
    policyDecision: "allow",
  });
  const jws = await signReceiptJws(body, issuerKeyV1);
  const tst = buildTst({ jwsCompact: jws, nonceLabel: "014", serial: 14 });
  const envelope = buildEnvelope({
    jwsCompact: jws,
    body,
    timestampEvidence: tsEvidenceFromTst(tst),
    envelopeCreatedAt: ISSUED_AT_V1 + 1,
  });

  return {
    filename: "014-valid-timestamp-evidence.json",
    content: {
      vector_id: "014",
      title: "v1.1 buyer_agent with full RFC 3161 TimeStampResp + TST (D25)",
      envelope,
      verify_options: {
        expectedSubject: "buyer_agent",
        jwks: jwksV1,
        currentTime: ISSUED_AT_V1 + 60,
        tsa_root_pins: [tsaCert.sha256Hex],
      },
      expected: {
        outcome: "accepted",
        errorCode: null,
        recomputed_legal_posture: "ades_candidate_timestamped",
        warnings: [],
      },
    },
  };
}

// ─── Vector 015 — TSA unavailable (degraded posture + warning) ───────────────

export async function generateVector015_TsaUnavailable(): Promise<VectorResult> {
  const buyerCtx = buildBuyerAgentConsentContext({
    consentTimestamp: ISSUED_AT_V1 - 60,
    disclosureVersion: "1.0.0",
    withdrawalUrl: "https://merchant.example/withdraw",
    consentText: "TSA-down receipt 015",
    evidenceRef: "vault://consent/015",
    agentId: "agent-buyer-test-015",
  });
  const paymentAuth = canonicalizeJson({
    type: "ap2_mandate",
    mandate_id: "m-015",
  });
  const warnings = [
    {
      reason: "tsa_unavailable" as const,
      since: ISSUED_AT_V1,
      evidence_ref: "vault://incident/tsa-down-2026-05-01",
    },
  ];
  const body = buildReceiptBody({
    receiptId: deterministicUuid("vector-015"),
    issuedAt: ISSUED_AT_V1,
    expiresAt: ISSUED_AT_V1 + 86400,
    issuer: ISSUER,
    merchantId: MERCHANT_ID,
    agentId: "agent-buyer-test-015",
    agentProvider: "Anthropic",
    receiptSubject: "buyer_agent",
    privacyClassification: "pii_hashed_salted",
    legalPosture: "ades_candidate_no_tsa",
    legalPostureWarnings: warnings,
    buyerCtx,
    userIntentText: "TSA-down 015",
    paymentAuthCanonical: paymentAuth,
    authorizationScheme: "ap2_mandate_jws",
    esignDisclosureVersion: "1.0.0",
    esignDisclosureContent: "ESIGN disclosure 015",
    consentEvidenceRef: "vault://consent/015",
    protocol: "AP2",
    authorizationEvidence: buyerAuthEvidence("TSA-down 015", paymentAuth),
    verificationMethods: verifyMethodsV1,
    policyDecision: "allow",
  });
  const jws = await signReceiptJws(body, issuerKeyV1);
  const envelope = buildEnvelope({
    jwsCompact: jws,
    body,
    timestampEvidence: tsUnavailable("tsa_unavailable"),
    envelopeCreatedAt: ISSUED_AT_V1 + 1,
  });

  return {
    filename: "015-timestamp-unavailable.json",
    content: {
      vector_id: "015",
      title:
        "v1.1 buyer_agent with timestamp_evidence.unavailable (fail_open path)",
      envelope,
      verify_options: {
        expectedSubject: "buyer_agent",
        jwks: jwksV1,
        currentTime: ISSUED_AT_V1 + 60,
      },
      expected: {
        outcome: "accepted",
        errorCode: null,
        recomputed_legal_posture: "ades_candidate_no_tsa",
        warnings: ["tsa_unavailable"],
      },
    },
  };
}

// ─── Vector 016 — export bundle, JWKS history, rotated key ───────────────────

export async function generateVector016_RotatedKey(): Promise<VectorResult> {
  // Receipt was signed with KID_V1 at ISSUED_AT_V1; KID_V2 activated 7 days later.
  const buyerCtx = buildBuyerAgentConsentContext({
    consentTimestamp: ISSUED_AT_V1 - 30,
    disclosureVersion: "1.0.0",
    withdrawalUrl: "https://merchant.example/withdraw",
    consentText: "Rotated-key bundle 016",
    evidenceRef: "vault://consent/016",
    agentId: "agent-buyer-test-016",
  });
  const paymentAuth = canonicalizeJson({
    type: "ap2_mandate",
    mandate_id: "m-016",
  });
  const body = buildReceiptBody({
    receiptId: deterministicUuid("vector-016"),
    issuedAt: ISSUED_AT_V1,
    expiresAt: ISSUED_AT_V1 + 86400,
    issuer: ISSUER,
    merchantId: MERCHANT_ID,
    agentId: "agent-buyer-test-016",
    agentProvider: "Anthropic",
    receiptSubject: "buyer_agent",
    privacyClassification: "pii_hashed_salted",
    legalPosture: "ades_candidate_timestamped",
    legalPostureWarnings: [],
    buyerCtx,
    userIntentText: "Rotated-key 016",
    paymentAuthCanonical: paymentAuth,
    authorizationScheme: "ap2_mandate_jws",
    esignDisclosureVersion: "1.0.0",
    esignDisclosureContent: "ESIGN disclosure 016",
    consentEvidenceRef: "vault://consent/016",
    protocol: "AP2",
    authorizationEvidence: buyerAuthEvidence("Rotated-key 016", paymentAuth),
    verificationMethods: verifyMethodsV1, // pinned to KID_V1
    policyDecision: "allow",
  });
  const jws = await signReceiptJws(body, issuerKeyV1);
  const tst = buildTst({ jwsCompact: jws, nonceLabel: "016", serial: 16 });
  const envelope = buildEnvelope({
    jwsCompact: jws,
    body,
    timestampEvidence: tsEvidenceFromTst(tst),
    envelopeCreatedAt: ISSUED_AT_V1 + 1,
  });

  // Export-bundle context: JWKS history showing kid_v1 valid_to == kid_v2 valid_from.
  const jwksHistory = [
    {
      kid: KID_V1,
      jwk_pub: { ...issuerKeyV1.jwkPub, alg: "EdDSA", use: "sig" },
      valid_from: ISSUED_AT_V1 - 30 * 86400,
      valid_to: KID_V2_VALID_FROM,
    },
    {
      kid: KID_V2,
      jwk_pub: { ...issuerKeyV2.jwkPub, alg: "EdDSA", use: "sig" },
      valid_from: KID_V2_VALID_FROM,
      valid_to: null,
    },
  ];

  return {
    filename: "016-rotated-key-export-bundle.json",
    content: {
      vector_id: "016",
      title:
        "v1.1 export bundle: receipt signed with kid_v1, JWKS history covers issued_at",
      envelope,
      verify_options: {
        expectedSubject: "buyer_agent",
        jwks: jwksV2,
        jwks_history: jwksHistory,
        currentTime: KID_V2_VALID_FROM + 86400,
        tsa_root_pins: [tsaCert.sha256Hex],
      },
      expected: {
        outcome: "accepted",
        errorCode: null,
        recomputed_legal_posture: "ades_candidate_timestamped",
        warnings: [],
      },
    },
  };
}

// ─── Vector 017 — legacy v1.0 receipt (single JWS, no envelope) ──────────────

export async function generateVector017_LegacyV10(): Promise<VectorResult> {
  // Synthetic v1.0 body — single JWS, NO envelope. Verifier dispatcher routes
  // to the v1.0 verifier and emits `legacy_pre_eidas_hardening` warning.
  const v10Body = {
    receipt_id: deterministicUuid("vector-017"),
    schema_version: "1.0",
    issued_at: ISSUED_AT_LEGACY,
    // 100-year window so the v1.0 verifier (which uses real Date.now())
    // accepts the legacy receipt regardless of when the conformance suite
    // runs. The dispatcher logic, not temporal validity, is what T063
    // exercises.
    expires_at: ISSUED_AT_LEGACY + 100 * 365 * 86400,
    issuer: ISSUER,
    merchant_id: MERCHANT_ID,
    agent_id: "agent-legacy-017",
    agent_provider: "Anthropic",
    protocol: "AP2",
    user_intent_hash:
      "sha256:0000000000000000000000000000000000000000000000000000000000000017",
    cart_hash:
      "sha256:1111111111111111111111111111111111111111111111111111111111111111",
    mandate_hash:
      "sha256:2222222222222222222222222222222222222222222222222222222222222222",
    protocol_artifacts: [],
    risk_signals: [],
    trust_provider_assertions: [],
    policy_decision: "allow",
    verification_methods: [
      {
        type: "jwks",
        value: `${ISSUER}/.well-known/jwks.json`,
      },
    ],
    attachments: [],
    kid: KID_V1,
  };
  const { CompactSign, importJWK } = await import("jose");
  const privKey = await importJWK(issuerKeyV1.jwkPriv as never, "EdDSA");
  const jws = await new CompactSign(
    new TextEncoder().encode(canonicalizeJson(v10Body))
  )
    .setProtectedHeader({ alg: "EdDSA", kid: KID_V1, typ: "JWT" })
    .sign(privKey);

  return {
    filename: "017-legacy-v10-receipt.json",
    content: {
      vector_id: "017",
      title: "v1.0 legacy receipt — dispatcher routes to v1.0 verifier",
      envelope: { receipt: jws, legacy_v1_0: true },
      verify_options: {
        jwks: jwksV1,
        currentTime: ISSUED_AT_LEGACY + 86400,
      },
      expected: {
        outcome: "accepted",
        errorCode: null,
        recomputed_legal_posture: null,
        warnings: ["legacy_pre_eidas_hardening"],
      },
    },
  };
}

// ─── Vector 018 — privacy_classification = pii_absent ────────────────────────

export async function generateVector018_PiiAbsent(): Promise<VectorResult> {
  const buyerCtx = buildBuyerAgentConsentContext({
    consentTimestamp: ISSUED_AT_V1 - 30,
    disclosureVersion: "1.0.0",
    withdrawalUrl: "https://merchant.example/withdraw",
    consentText: "[REDACTED]",
    evidenceRef: "vault://consent/018",
    agentId: "agent-buyer-test-018",
  });
  const paymentAuth = canonicalizeJson({
    type: "ap2_mandate",
    mandate_id: "m-018",
  });
  const body = buildReceiptBody({
    receiptId: deterministicUuid("vector-018"),
    issuedAt: ISSUED_AT_V1,
    expiresAt: ISSUED_AT_V1 + 86400,
    issuer: ISSUER,
    merchantId: MERCHANT_ID,
    agentId: "agent-buyer-test-018",
    agentProvider: "Anthropic",
    receiptSubject: "buyer_agent",
    privacyClassification: "pii_absent",
    legalPosture: "ades_candidate_timestamped",
    legalPostureWarnings: [],
    buyerCtx,
    userIntentText: "[REDACTED]",
    paymentAuthCanonical: paymentAuth,
    authorizationScheme: "ap2_mandate_jws",
    esignDisclosureVersion: "1.0.0",
    esignDisclosureContent: "ESIGN disclosure 018",
    consentEvidenceRef: "vault://consent/018",
    protocol: "AP2",
    authorizationEvidence: buyerAuthEvidence("[REDACTED]", paymentAuth),
    verificationMethods: verifyMethodsV1,
    policyDecision: "allow",
  });
  const jws = await signReceiptJws(body, issuerKeyV1);
  const tst = buildTst({ jwsCompact: jws, nonceLabel: "018", serial: 18 });
  const envelope = buildEnvelope({
    jwsCompact: jws,
    body,
    timestampEvidence: tsEvidenceFromTst(tst),
    envelopeCreatedAt: ISSUED_AT_V1 + 1,
  });

  return {
    filename: "018-pii-absent.json",
    content: {
      vector_id: "018",
      title: "v1.1 buyer_agent with privacy_classification=pii_absent",
      envelope,
      verify_options: {
        expectedSubject: "buyer_agent",
        jwks: jwksV1,
        currentTime: ISSUED_AT_V1 + 60,
        tsa_root_pins: [tsaCert.sha256Hex],
      },
      expected: {
        outcome: "accepted",
        errorCode: null,
        recomputed_legal_posture: "ades_candidate_timestamped",
        warnings: [],
      },
    },
  };
}

// ─── Driver ──────────────────────────────────────────────────────────────────

const VECTOR_GENERATORS: ReadonlyArray<() => Promise<VectorResult>> = [
  generateVector011_HappyPath,
  generateVector012_MissingConsentContext,
  generateVector013_ReceiptSubjectMismatch,
  generateVector014_ValidTst,
  generateVector015_TsaUnavailable,
  generateVector016_RotatedKey,
  generateVector017_LegacyV10,
  generateVector018_PiiAbsent,
];

export default async function main(): Promise<void> {
  const dryRun = process.argv.includes("--dry-run");
  if (!dryRun) mkdirSync(VECTORS_DIR, { recursive: true });

  const summary: Array<{ id: string; file: string; bytes: number }> = [];
  for (const gen of VECTOR_GENERATORS) {
    const result = await gen();
    const json = prettyDeterministic(result.content);
    if (!dryRun) {
      writeFileSync(join(VECTORS_DIR, result.filename), json, "utf8");
    }
    summary.push({
      id: result.content.vector_id,
      file: result.filename,
      bytes: Buffer.byteLength(json, "utf8"),
    });
  }

  // Stable summary output (sorted by id).
  summary.sort((a, b) => a.id.localeCompare(b.id));
  process.stdout.write(
    `T065 v1.1 vectors ${dryRun ? "(dry-run)" : "written"}: ${VECTORS_DIR}\n`
  );
  for (const row of summary) {
    process.stdout.write(`  ${row.id}  ${row.file}  ${row.bytes} bytes\n`);
  }
}

const isMain =
  import.meta.url === `file://${process.argv[1]}` ||
  process.argv[1]?.endsWith("generate-test-vectors-v11.ts") === true;
if (isMain) {
  main().catch((err: unknown) => {
    process.stderr.write(`T065 vector generation FAILED: ${String(err)}\n`);
    process.exit(1);
  });
}
