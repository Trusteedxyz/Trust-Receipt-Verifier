/**
 * Hardening vectors (sidecars bound to signed artifacts) — generator.
 *
 * NEW vector directory `test-vectors/v11-hardening/`, numbered H001+. Existing
 * vectors (`v11/`, `v11-strict/`, conformance suite) are immutable and untouched.
 * Ed25519 is deterministic and the key is seed-derived, so re-running is
 * byte-stable.
 *
 * Run:
 *   pnpm --filter trust-receipt-verifier exec tsx scripts/generate-hardening-vectors.ts
 */
import { writeFileSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";

import type {
  ReceiptEnvelope,
  TimestampUnavailable,
  TrustReceiptV11Body,
  VerificationMethods,
} from "../src/types-1.1.js";
import { canonicalizeJson, prettyDeterministic } from "./lib/canonical.js";
import { buildTestKeyPair } from "./lib/keys.js";
import { createSeededStream, MASTER_SEED } from "./lib/seeded-rng.js";
import {
  buildBuyerAgentConsentContext,
  buildEnvelope,
  buildReceiptBody,
  hmacTagged,
  sha256Tagged,
  signReceiptJws,
  TEST_HMAC_KEY_VERSION,
} from "./lib/builders.js";

const OUT_DIR = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "test-vectors",
  "v11-hardening"
);
const ISSUER = "https://test.trusteed.xyz";
const MERCHANT_ID = "merchant_hardening_test";
const JWKS_URI = "https://test.trusteed.xyz/.well-known/jwks.json";
const KID = "tr-ed25519-hardening-2026";
const ISSUED_AT = Math.floor(Date.UTC(2026, 4, 1, 0, 0, 0) / 1000);
const CURRENT_TIME = ISSUED_AT + 60;

const issuerKey = buildTestKeyPair(
  createSeededStream(MASTER_SEED, "hardening-master")
    .derive("issuer-key")
    .bytes(32),
  KID
);
const jwksPub = { keys: [{ ...issuerKey.jwkPub, alg: "EdDSA", use: "sig" }] };
const TRUST_ANCHOR_SHA256 = createHash("sha256")
  .update("hardening-issuer-root-trust-anchor", "utf8")
  .digest("hex");

const tsUnavailable: TimestampUnavailable = {
  type: "unavailable",
  reason: "tsa_unavailable",
  attempted_tsa: ["https://test-tsa.trusteed.xyz/tsa"],
  attempted_at: ISSUED_AT,
};

const PAYLOAD_GOOD = Buffer.from("genuine mandate payload", "utf8");
const PAYLOAD_FORGED = Buffer.from("FORGED evidence", "utf8");
const sha256 = (b: Buffer) =>
  `sha256:${createHash("sha256").update(b).digest("hex")}`;
const sha512 = (b: Buffer) =>
  `sha512:${createHash("sha512").update(b).digest("hex")}`;
const b64 = (b: Buffer) => b.toString("base64");
const hmacOf = (s: string) => hmacTagged(s);

type Artifact = { type: string; hash: string };
type Sidecar = { type: string; hash: string; payload_b64: string };

function verificationMethods(): VerificationMethods {
  return {
    jwks: { uri: JWKS_URI, kid: KID },
    jwks_sha256: createHash("sha256")
      .update(canonicalizeJson(jwksPub), "utf8")
      .digest("hex"),
    trust_anchor_sha256: TRUST_ANCHOR_SHA256,
  };
}

async function build(opts: {
  id: string;
  title: string;
  artifacts: Artifact[];
  sidecars: Sidecar[];
  expected: { outcome: "accepted" | "rejected"; errorCode: string | null };
}) {
  const body: TrustReceiptV11Body = buildReceiptBody({
    receiptId: `00000000-0000-4000-8000-00000000${opts.id.replace(/\D/g, "").padStart(4, "0")}`,
    issuedAt: ISSUED_AT,
    expiresAt: ISSUED_AT + 86_400,
    issuer: ISSUER,
    merchantId: MERCHANT_ID,
    agentId: "agent-hardening-001",
    agentProvider: "Anthropic",
    receiptSubject: "buyer_agent",
    privacyClassification: "pii_hashed_salted",
    legalPosture: "ades_candidate_no_tsa",
    legalPostureWarnings: [],
    buyerCtx: buildBuyerAgentConsentContext({
      consentTimestamp: ISSUED_AT - 30,
      disclosureVersion: "1.0.0",
      withdrawalUrl: "https://test.trusteed.xyz/withdraw",
      consentText: "hardening consent",
      evidenceRef: "vault://consent/hardening",
      agentId: "agent-hardening-001",
    }),
    userIntentText: "hardening-intent",
    cartCanonical: "hardening-cart",
    orderCanonical: "hardening-order",
    paymentAuthCanonical: "hardening-payment",
    authorizationScheme: "ap2_mandate_jws",
    esignDisclosureVersion: "1.0.0",
    esignDisclosureContent: "hardening disclosure",
    consentEvidenceRef: "vault://consent/hardening",
    transactionId: `tx-${opts.id}`,
    protocol: "AP2",
    authorizationEvidence: {
      user_intent_hash: hmacTagged("hardening-intent"),
      intent_hmac_key_version: TEST_HMAC_KEY_VERSION,
      execution_hash: sha256Tagged("hardening-exec"),
      protocol_authorization_ref: "ap2-mandate-hardening-001",
    },
    verificationMethods: verificationMethods(),
    policyDecision: "allow",
  });
  body.protocol_artifacts =
    opts.artifacts as unknown as TrustReceiptV11Body["protocol_artifacts"];
  const jws = await signReceiptJws(body, issuerKey);
  const envelope: ReceiptEnvelope = {
    ...buildEnvelope({
      jwsCompact: jws,
      body,
      timestampEvidence: tsUnavailable,
      envelopeCreatedAt: ISSUED_AT + 1,
    }),
    protocol_artifact_sidecars:
      opts.sidecars as unknown as ReceiptEnvelope["protocol_artifact_sidecars"],
  };
  return {
    vector_id: opts.id,
    title: opts.title,
    envelope,
    verify_options: {
      currentTime: CURRENT_TIME,
      expectedSubject: "buyer_agent",
      trust_anchor_sha256: TRUST_ANCHOR_SHA256,
      jwks: jwksPub,
    },
    expected: opts.expected,
  };
}

const rej = (errorCode: string) => ({ outcome: "rejected" as const, errorCode });
const acc = { outcome: "accepted" as const, errorCode: null };

async function main(): Promise<void> {
  mkdirSync(OUT_DIR, { recursive: true });
  const H512 = sha512(PAYLOAD_GOOD);
  const HMAC = hmacOf("sidecar-hmac");
  const H256 = sha256(PAYLOAD_GOOD);
  const vectors: Array<[string, Awaited<ReturnType<typeof build>>]> = [
    [
      "H001-sidecar-sha512-forged-payload-rejected.json",
      await build({
        id: "H001",
        title: "sha512-declared artifact, sidecar carries a different payload",
        artifacts: [{ type: "ap2_mandate", hash: H512 }],
        sidecars: [
          { type: "ap2_mandate", hash: H512, payload_b64: b64(PAYLOAD_FORGED) },
        ],
        expected: rej("protocol_artifact_sidecar_hash_mismatch"),
      }),
    ],
    [
      "H002-sidecar-hmac-forged-payload-rejected.json",
      await build({
        id: "H002",
        title: "hmac-sha256 artifact cannot be verified offline; never pass",
        artifacts: [{ type: "ap2_mandate", hash: HMAC }],
        sidecars: [
          { type: "ap2_mandate", hash: HMAC, payload_b64: b64(PAYLOAD_FORGED) },
        ],
        expected: rej("protocol_artifact_sidecar_unverifiable"),
      }),
    ],
    [
      "H003-sidecar-type-swapped-rejected.json",
      await build({
        id: "H003",
        title: "sidecar type differs from the signed artifact with the same hash",
        artifacts: [{ type: "ap2_mandate", hash: H256 }],
        sidecars: [
          { type: "cart_payload", hash: H256, payload_b64: b64(PAYLOAD_GOOD) },
        ],
        expected: rej("protocol_artifact_sidecar_hash_mismatch"),
      }),
    ],
    [
      "H004-sidecar-duplicate-rejected.json",
      await build({
        id: "H004",
        title: "the same (type, hash) sidecar delivered twice",
        artifacts: [{ type: "ap2_mandate", hash: H256 }],
        sidecars: [
          { type: "ap2_mandate", hash: H256, payload_b64: b64(PAYLOAD_GOOD) },
          { type: "ap2_mandate", hash: H256, payload_b64: b64(PAYLOAD_GOOD) },
        ],
        expected: rej("protocol_artifact_sidecar_duplicate"),
      }),
    ],
    [
      "H005-sidecar-without-signed-artifact-rejected.json",
      await build({
        id: "H005",
        title: "sidecar has no corresponding signed protocol_artifacts entry",
        artifacts: [],
        sidecars: [
          { type: "ap2_mandate", hash: H256, payload_b64: b64(PAYLOAD_GOOD) },
        ],
        expected: rej("protocol_artifact_sidecar_hash_mismatch"),
      }),
    ],
    [
      "H006-sidecar-sha512-valid-accepted.json",
      await build({
        id: "H006",
        title: "sha512 artifact with a matching sidecar is accepted",
        artifacts: [{ type: "ap2_mandate", hash: H512 }],
        sidecars: [
          { type: "ap2_mandate", hash: H512, payload_b64: b64(PAYLOAD_GOOD) },
        ],
        expected: acc,
      }),
    ],
    [
      "H007-sidecar-sha256-valid-accepted.json",
      await build({
        id: "H007",
        title: "sha256 artifact with a matching sidecar is accepted (regression)",
        artifacts: [{ type: "ap2_mandate", hash: H256 }],
        sidecars: [
          { type: "ap2_mandate", hash: H256, payload_b64: b64(PAYLOAD_GOOD) },
        ],
        expected: acc,
      }),
    ],
  ];
  for (const [name, v] of vectors) {
    writeFileSync(join(OUT_DIR, name), prettyDeterministic(v), "utf8");
    process.stdout.write(`wrote ${name}\n`);
  }
}

main().catch((err: unknown) => {
  process.stderr.write(`${err instanceof Error ? err.stack : String(err)}\n`);
  process.exit(1);
});
