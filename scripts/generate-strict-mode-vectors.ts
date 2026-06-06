/**
 * T-AUD-012 (GAP H4) — generator for the four strict-mode negative vectors.
 *
 * Each emitted vector is SELF-CONTAINED: it embeds the public JWKS that the
 * conformance runner uses to verify the JWS signature, plus the pinned
 * `trust_anchor_sha256` and the per-mode expectations. The receipts are signed
 * with a deterministically-derived Ed25519 key so re-running this script is
 * byte-stable.
 *
 * Output dir: `test-vectors/v11-strict/`
 *
 * Run:
 *   pnpm --filter trust-receipt-verifier exec tsx scripts/generate-strict-mode-vectors.ts
 *
 * @see specs/049-trust-receipt-eidas-hardening/spec.md T-AUD-012
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
  VerificationMethods,
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
  buildReceiptBody,
  hmacTagged,
  sha256Tagged,
  signReceiptJws,
  TEST_HMAC_KEY_VERSION,
} from "./lib/builders.js";

// ─── Constants ──────────────────────────────────────────────────────────────

const OUT_DIR = (() => {
  const here = dirname(fileURLToPath(import.meta.url));
  return join(here, "..", "test-vectors", "v11-strict");
})();

const ISSUER = "https://test.trusteed.xyz";
const MERCHANT_ID = "merchant_strict_test";
const JWKS_URI = "https://test.trusteed.xyz/.well-known/jwks.json";
const KID = "tr-ed25519-strict-2026";
const STUB_HASH = "0".repeat(64);

const ISSUED_AT = Math.floor(Date.UTC(2026, 4, 1, 0, 0, 0) / 1000);
const EXPIRES_AT = ISSUED_AT + 86_400;
const CURRENT_TIME = ISSUED_AT + 60;
const TST_GEN_TIME = new Date(Date.UTC(2026, 4, 1, 0, 0, 5));
const TSA_ENDPOINT = "https://test-tsa.trusteed.xyz/tsa";
const TSA_POLICY_OID = "1.2.3.4.5.6.7.8.9";

const masterStream = createSeededStream(MASTER_SEED, "strict-master");
const issuerKey = buildTestKeyPair(
  masterStream.derive("issuer-key").bytes(32),
  KID
);
const tsaKey = buildTestKeyPair(
  masterStream.derive("tsa-key").bytes(32),
  "tsa-strict-cert"
);

const jwksPub = { keys: [{ ...issuerKey.jwkPub, alg: "EdDSA", use: "sig" }] };

/** Real (non-stub) trust anchor SHA-256 the verifier pins against. */
const TRUST_ANCHOR_SHA256 = createHash("sha256")
  .update("strict-issuer-root-trust-anchor", "utf8")
  .digest("hex");

function extractEd25519RawPub(kp: TestKeyPair): Buffer {
  const x = kp.jwkPub.x;
  const padded = x + "==".slice(0, (4 - (x.length % 4)) % 4);
  return Buffer.from(padded.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

const tsaCert = buildSyntheticTsaCert({
  ed25519PubRaw: extractEd25519RawPub(tsaKey),
  cnLabel: "Strict Test TSA",
});

/** Single deterministic nonce shared by the TST imprint and the envelope. */
const TST_NONCE = createSeededStream(MASTER_SEED, "strict-tst-nonce").bytes(16);

function buildTst(jwsCompact: string): SyntheticTstResult {
  const imprint = createHash("sha256").update(jwsCompact, "utf8").digest();
  return buildSyntheticTimeStampToken({
    imprint,
    nonce: TST_NONCE,
    genTime: TST_GEN_TIME,
    policyOid: TSA_POLICY_OID,
    serial: 1,
    tsaCertPem: tsaCert.pem,
    tsaCertDer: tsaCert.derBuffer,
    tsaRootSha256: tsaCert.sha256Hex,
  });
}

function tsEvidence(tst: SyntheticTstResult): TimestampEvidence {
  return {
    type: "RFC3161",
    tsa_endpoint: TSA_ENDPOINT,
    tsr: tst.tsr,
    tst: tst.tst,
    issued_at_attested: Math.floor(TST_GEN_TIME.getTime() / 1000),
    imprint_algo: "sha-256",
    imprint_target: "jws_compact_bytes",
    nonce: TST_NONCE.toString("hex"),
    policy_oid: TSA_POLICY_OID,
    tsa_cert_chain: tst.tsaCertChain,
    tsa_root_cert_sha256: tst.tsaRootSha256,
    revocation_evidence: tst.revocationEvidence,
    tolerance_seconds: 60,
  };
}

const tsUnavailable: TimestampUnavailable = {
  type: "unavailable",
  reason: "tsa_unavailable",
  attempted_tsa: [TSA_ENDPOINT],
  attempted_at: ISSUED_AT,
};

function verifMethods(
  overrides: Partial<VerificationMethods>
): VerificationMethods {
  const jwksCanonical = canonicalizeJson(jwksPub);
  const jwksSha256 = createHash("sha256")
    .update(jwksCanonical, "utf8")
    .digest("hex");
  return {
    jwks: { uri: JWKS_URI, kid: KID },
    jwks_sha256: jwksSha256,
    trust_anchor_sha256: TRUST_ANCHOR_SHA256,
    ...overrides,
  };
}

function buyerEvidence(): AuthorizationEvidence {
  return {
    user_intent_hash: hmacTagged("strict-intent"),
    intent_hmac_key_version: TEST_HMAC_KEY_VERSION,
    execution_hash: sha256Tagged("strict-exec"),
    protocol_authorization_ref: "ap2-mandate-strict-001",
  };
}

/** Evidence WITHOUT any agent-identity binding (no protocol_authorization_ref). */
function noIdentityEvidence(): AuthorizationEvidence {
  return {
    user_intent_hash: hmacTagged("strict-intent-noid"),
    intent_hmac_key_version: TEST_HMAC_KEY_VERSION,
    execution_hash: sha256Tagged("strict-exec-noid"),
  };
}

const buyerCtx = buildBuyerAgentConsentContext({
  consentTimestamp: ISSUED_AT - 30,
  disclosureVersion: "1.0.0",
  withdrawalUrl: "https://test.trusteed.xyz/withdraw",
  consentText: "strict consent",
  evidenceRef: "vault://consent/strict",
  agentId: "agent-strict-001",
});

interface StrictVector {
  vector_id: string;
  title: string;
  envelope: ReceiptEnvelope;
  verify_options: {
    currentTime: number;
    expectedSubject: "buyer_agent";
    trust_anchor_sha256: string;
    tsa_root_pins: string[];
    jwks: typeof jwksPub;
  };
  expected_strict: {
    outcome: "accepted" | "rejected";
    errorCode: string | null;
  };
  expected_compat: {
    outcome: "accepted" | "rejected";
    errorCode: string | null;
    warning: string;
  };
}

async function buildVector(opts: {
  vectorId: string;
  title: string;
  verificationMethods: VerificationMethods;
  authorizationEvidence: AuthorizationEvidence;
  legalPosture: TrustReceiptV11Body["legal_posture"];
  useUnavailableTsa: boolean;
  expectedStrict: {
    outcome: "accepted" | "rejected";
    errorCode: string | null;
  };
  expectedCompat: {
    outcome: "accepted" | "rejected";
    errorCode: string | null;
    warning: string;
  };
}): Promise<StrictVector> {
  const receiptId = `00000000-0000-4000-8000-0000000000${opts.vectorId}`;
  const body = buildReceiptBody({
    receiptId,
    issuedAt: ISSUED_AT,
    expiresAt: EXPIRES_AT,
    issuer: ISSUER,
    merchantId: MERCHANT_ID,
    agentId: "agent-strict-001",
    agentProvider: "Anthropic",
    receiptSubject: "buyer_agent",
    privacyClassification: "pii_hashed_salted",
    legalPosture: opts.legalPosture,
    legalPostureWarnings: [],
    buyerCtx,
    userIntentText: "strict-intent",
    cartCanonical: "strict-cart",
    orderCanonical: "strict-order",
    paymentAuthCanonical: "strict-payment",
    authorizationScheme: "ap2_mandate_jws",
    esignDisclosureVersion: "1.0.0",
    esignDisclosureContent: "strict disclosure",
    consentEvidenceRef: "vault://consent/strict",
    transactionId: `tx-${opts.vectorId}`,
    protocol: "AP2",
    authorizationEvidence: opts.authorizationEvidence,
    verificationMethods: opts.verificationMethods,
    policyDecision: "allow",
  });
  const jws = await signReceiptJws(body, issuerKey);
  const evidence = opts.useUnavailableTsa
    ? tsUnavailable
    : tsEvidence(buildTst(jws));
  const envelope = buildEnvelope({
    jwsCompact: jws,
    body,
    timestampEvidence: evidence,
    envelopeCreatedAt: ISSUED_AT + 1,
  });
  return {
    vector_id: opts.vectorId,
    title: opts.title,
    envelope,
    verify_options: {
      currentTime: CURRENT_TIME,
      expectedSubject: "buyer_agent",
      trust_anchor_sha256: TRUST_ANCHOR_SHA256,
      tsa_root_pins: [tsaCert.sha256Hex],
      jwks: jwksPub,
    },
    expected_strict: opts.expectedStrict,
    expected_compat: opts.expectedCompat,
  };
}

async function main(): Promise<void> {
  mkdirSync(OUT_DIR, { recursive: true });

  const vectors: Array<{ filename: string; content: StrictVector }> = [];

  // 1. anchor stub — trust_anchor_sha256 is all-zeros.
  vectors.push({
    filename: "vector-anchor-stub-rejected.json",
    content: await buildVector({
      vectorId: "01",
      title: "trust_anchor_sha256 is the all-zeros opaque stub",
      verificationMethods: verifMethods({ trust_anchor_sha256: STUB_HASH }),
      authorizationEvidence: buyerEvidence(),
      legalPosture: "ades_candidate_timestamped",
      useUnavailableTsa: false,
      expectedStrict: {
        outcome: "rejected",
        errorCode: "trust_anchor_stub_rejected",
      },
      expectedCompat: {
        outcome: "accepted",
        errorCode: null,
        warning: "trust_anchor_sha256_stub",
      },
    }),
  });

  // 2. synthetic user-auth — jwks_sha256 is the all-zeros opaque stub.
  vectors.push({
    filename: "vector-user-auth-synthetic-rejected.json",
    content: await buildVector({
      vectorId: "02",
      title:
        "jwks_sha256 is the all-zeros synthetic stub (unverifiable key pin)",
      verificationMethods: verifMethods({ jwks_sha256: STUB_HASH }),
      authorizationEvidence: buyerEvidence(),
      legalPosture: "ades_candidate_timestamped",
      useUnavailableTsa: false,
      expectedStrict: {
        outcome: "rejected",
        errorCode: "jwks_sha256_stub_rejected",
      },
      expectedCompat: {
        outcome: "accepted",
        errorCode: null,
        warning: "jwks_sha256_stub",
      },
    }),
  });

  // 3. LOTL degraded — TSA unavailable ⇒ WARNING in both modes (accepted).
  vectors.push({
    filename: "vector-lotl-degraded-warning.json",
    content: await buildVector({
      vectorId: "03",
      title:
        "LOTL / TSA degraded — accepted-with-warning in both strict and compat",
      verificationMethods: verifMethods({}),
      authorizationEvidence: buyerEvidence(),
      legalPosture: "ades_candidate_no_tsa",
      useUnavailableTsa: true,
      expectedStrict: { outcome: "accepted", errorCode: null },
      expectedCompat: {
        outcome: "accepted",
        errorCode: null,
        warning: "tsa_unavailable",
      },
    }),
  });

  // 4. agent identity missing — no protocol_authorization_ref, no assertions.
  vectors.push({
    filename: "vector-agent-identity-missing-rejected.json",
    content: await buildVector({
      vectorId: "04",
      title: "buyer_agent receipt with no agent-identity binding",
      verificationMethods: verifMethods({}),
      authorizationEvidence: noIdentityEvidence(),
      legalPosture: "degraded_no_agent_identity",
      useUnavailableTsa: false,
      expectedStrict: {
        outcome: "rejected",
        errorCode: "agent_identity_required_strict",
      },
      expectedCompat: {
        outcome: "accepted",
        errorCode: null,
        warning: "agent_identity_absent",
      },
    }),
  });

  for (const v of vectors) {
    const path = join(OUT_DIR, v.filename);
    writeFileSync(path, prettyDeterministic(v.content), "utf8");
    process.stdout.write(`wrote ${v.filename}\n`);
  }
}

main().catch((err: unknown) => {
  process.stderr.write(
    `[generate-strict-mode-vectors] ${err instanceof Error ? err.stack : String(err)}\n`
  );
  process.exit(1);
});
