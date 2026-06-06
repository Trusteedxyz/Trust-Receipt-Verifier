/**
 * Spec 054 T103 — Integration tests for the audit-command CLI helper.
 *
 * Drives `runCli(argv)` programmatically (no spawn) — covers happy
 * verification, binding mismatch with localization, and input errors.
 *
 * @see specs/058-trustreceipt-x402-binding/tasks.md T103
 */

import {
  generateKeyPairSync,
  sign as edSign,
  type KeyObject,
} from "node:crypto";
import { writeFile, mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import canonicalize from "canonicalize";
import { describe, expect, test } from "vitest";

import { recomputeBindingHash } from "../../x402-binding/binding-hash-recompute.js";
import { runCli } from "../audit-command.js";
import type { TrustReceiptV11Body } from "../../zod-1.1.js";
import type { JwksKey } from "../../x402-binding/delegation-validator.js";

// ---------------------------------------------------------------------------
// Fixture helpers — minimal, mirror the verifier-x402-extension test setup.
// ---------------------------------------------------------------------------

interface Ed25519Material {
  readonly kid: string;
  readonly privateKey: KeyObject;
  readonly publicJwk: { kty: "OKP"; crv: "Ed25519"; x: string };
}

function generateKeyMaterial(kid: string): Ed25519Material {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const jwk = publicKey.export({ format: "jwk" }) as {
    kty: "OKP";
    crv: "Ed25519";
    x: string;
  };
  return { kid, privateKey, publicJwk: jwk };
}

function base64UrlEncode(buf: Buffer): string {
  return buf
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function base64UrlJson(value: unknown): string {
  return base64UrlEncode(Buffer.from(JSON.stringify(value), "utf8"));
}

function evmPermit2Components() {
  return {
    paymentRequirements: {
      scheme: "exact",
      network: "base",
      maxAmountRequired: "1000000",
      resource: "https://merchant.example.com/api/paid-resource",
      payTo: "0x1234567890abcdef1234567890abcdef12345678",
      maxTimeoutSeconds: 300,
      asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    } as Record<string, unknown>,
    paymentPayload: {
      owner: "0xowner",
      spender: "0xspender",
      token: "0xtoken",
      amount: "1000000",
      nonce: "1",
      deadline: "1900000000",
      signature: "0xdeadbeef",
      permit2_authorization: {
        permitted: { token: "0xtoken", amount: "1000000" },
        nonce: "1",
        deadline: "1900000000",
      },
    } as Record<string, unknown>,
    authorizationScheme: "evm_permit2" as const,
    resourceUri: "https://merchant.example.com/api/paid-resource",
    settlementEvidence: {
      txHash: "0xfeedface",
      network: "base",
      amount: "1000000",
      asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
      payTo: "0x1234567890abcdef1234567890abcdef12345678",
      payer: "0xabcdef00",
    },
    outputCommitment: {
      kind: "static_sha256",
      algorithm: "sha256",
      value:
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      content_type: "application/json",
      content_length: 256,
    } as const,
  };
}

function buildBody(bindingHashTagged: string): TrustReceiptV11Body {
  const now = Math.floor(Date.now() / 1000);
  return {
    receipt_id: "00000000-0000-4000-8000-000000000123",
    schema_version: "1.1",
    issued_at: now,
    expires_at: now + 3600,
    issuer: "https://merchant.example.com",
    merchant_id: "merchant_cli",
    agent_provider: "cli_test_agent",
    agent_id: null,
    receipt_subject: "buyer_agent",
    privacy_classification: "pii_absent",
    legal_posture: "ades_candidate_no_tsa",
    legal_posture_warnings: [],
    buyer_agent_consent_context: {
      consent_type: "explicit_action",
      consent_timestamp: now,
      consent_hash:
        "hmac-sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      consent_hmac_key_version: 1,
      consent_disclosure_version: "1.0.0",
      consent_withdrawal_uri_hash:
        "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
      consent_evidence_ref: "ref://e",
      agent_authorization_chain: [
        {
          actor: "user",
          method: "OAuth+MFA",
          hash: "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
          timestamp: now,
        },
        {
          actor: "agent",
          method: "rfc9421_signature",
          hash: "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
          timestamp: now,
        },
      ],
    },
    user_intent_hash:
      "hmac-sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    intent_hmac_key_version: 1,
    payment_authorization_hash:
      "sha256:1111111111111111111111111111111111111111111111111111111111111111",
    authorization_scheme: "evm_permit2",
    esign_disclosure_version: "1.0.0",
    esign_disclosure_hash:
      "sha256:2222222222222222222222222222222222222222222222222222222222222222",
    consent_evidence_ref: "ref://e",
    protocol: "x402",
    protocol_artifacts: [],
    authorization_evidence: {
      user_intent_hash:
        "hmac-sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      intent_hmac_key_version: 1,
      execution_hash:
        "sha256:3333333333333333333333333333333333333333333333333333333333333333",
    },
    verification_methods: {
      jwks: {
        uri: "https://merchant.example.com/.well-known/jwks.json",
        kid: "issuer",
      },
      jwks_sha256:
        "4444444444444444444444444444444444444444444444444444444444444444",
      trust_anchor_sha256:
        "5555555555555555555555555555555555555555555555555555555555555555",
    },
    policy_decision: "allow",
    x402_binding: {
      binding_profile_version: "1.0.0",
      binding_hash: bindingHashTagged,
      binding_components_manifest_url:
        "https://merchant.example.com/api/v1/x402-binding/binding-components-manifest/1.0.0",
      binding_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
      intent_hash:
        "hmac-sha256:7777777777777777777777777777777777777777777777777777777777777777",
      pii_hmac_key_version: 1,
      nonce: "AAAAAAAAAAAAAAAAAAAAAg",
      issued_at: new Date(now * 1000).toISOString(),
      expires_at: new Date((now + 3600) * 1000).toISOString(),
      authorization_scheme: "evm_permit2",
      payment_authorization_hash:
        "sha256:6666666666666666666666666666666666666666666666666666666666666666",
      verification_posture: "unverified",
      agent_authorization_chain: null,
      posture: "confirmed",
      output_commitment: {
        kind: "static_sha256",
        algorithm: "sha256",
        value:
          "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      },
      privacy_filtered_hashes: {},
      intent_allows_multi_settlement: false,
    },
  };
}

async function writeFixturesToTmp(args: {
  readonly envelopeJson: unknown;
  readonly jwksJson: unknown;
  readonly components?: ReturnType<typeof evmPermit2Components>;
  readonly resourceUriOverride?: string;
}): Promise<{
  readonly dir: string;
  readonly paths: Record<string, string>;
  readonly resourceUri: string;
}> {
  const dir = await mkdtemp(join(tmpdir(), "spec054-cli-"));
  const paths: Record<string, string> = {
    envelope: join(dir, "envelope.json"),
    jwks: join(dir, "jwks.json"),
  };
  await writeFile(paths.envelope, JSON.stringify(args.envelopeJson));
  await writeFile(paths.jwks, JSON.stringify(args.jwksJson));
  let resourceUri = "";
  if (args.components) {
    paths.paymentRequirements = join(dir, "payment-requirements.json");
    paths.paymentPayload = join(dir, "payment-payload.json");
    paths.settlementEvidence = join(dir, "settlement-evidence.json");
    paths.outputCommitment = join(dir, "output-commitment.json");
    await writeFile(
      paths.paymentRequirements,
      JSON.stringify(args.components.paymentRequirements)
    );
    await writeFile(
      paths.paymentPayload,
      JSON.stringify(args.components.paymentPayload)
    );
    await writeFile(
      paths.settlementEvidence,
      JSON.stringify(args.components.settlementEvidence)
    );
    await writeFile(
      paths.outputCommitment,
      JSON.stringify(args.components.outputCommitment)
    );
    resourceUri = args.resourceUriOverride ?? args.components.resourceUri;
  }
  return { dir, paths, resourceUri };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("audit-command CLI", () => {
  test("happy verification → exit 0 + VALID", async () => {
    const material = generateKeyMaterial("cli-direct-1");
    const components = evmPermit2Components();
    const { bindingHashTagged } = recomputeBindingHash(components);
    const body = buildBody(bindingHashTagged);
    const headerB64 = base64UrlJson({ alg: "EdDSA", kid: material.kid });
    const payloadB64 = base64UrlJson(body);
    const signingInput = `${headerB64}.${payloadB64}`;
    const sigB64 = base64UrlEncode(
      edSign(null, Buffer.from(signingInput, "utf8"), material.privateKey)
    );
    const envelope = { receipt: `${headerB64}.${payloadB64}.${sigB64}` };
    const jwksKey: JwksKey = {
      kty: "OKP",
      crv: "Ed25519",
      kid: material.kid,
      use: "sig",
      kid_uses: ["receipt-issuance"],
      x: material.publicJwk.x,
    };
    const jwks = { keys: [jwksKey] };

    const { paths, resourceUri } = await writeFixturesToTmp({
      envelopeJson: envelope,
      jwksJson: jwks,
      components,
    });

    const argv = [
      "--envelope",
      paths.envelope!,
      "--jwks-file",
      paths.jwks!,
      "--payment-requirements",
      paths.paymentRequirements!,
      "--payment-payload",
      paths.paymentPayload!,
      "--authorization-scheme",
      "evm_permit2",
      "--resource-uri",
      resourceUri,
      "--settlement-evidence",
      paths.settlementEvidence!,
      "--output-commitment",
      paths.outputCommitment!,
    ];
    const r = await runCli(argv);

    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain("Result: VALID");
    expect(r.stdout).toContain("[OK] JWS signature valid");
  });

  test("binding mismatch with localization → exit 1 + BINDING_MISMATCH (resource_uri)", async () => {
    const material = generateKeyMaterial("cli-mismatch-1");
    const declared = evmPermit2Components();
    const { bindingHashTagged } = recomputeBindingHash(declared);
    const body = buildBody(bindingHashTagged);
    const headerB64 = base64UrlJson({ alg: "EdDSA", kid: material.kid });
    const payloadB64 = base64UrlJson(body);
    const signingInput = `${headerB64}.${payloadB64}`;
    const sigB64 = base64UrlEncode(
      edSign(null, Buffer.from(signingInput, "utf8"), material.privateKey)
    );
    const envelope = { receipt: `${headerB64}.${payloadB64}.${sigB64}` };
    const jwksKey: JwksKey = {
      kty: "OKP",
      crv: "Ed25519",
      kid: material.kid,
      use: "sig",
      kid_uses: ["receipt-issuance"],
      x: material.publicJwk.x,
    };
    const jwks = { keys: [jwksKey] };

    // Verification components: tamper resource_uri.
    const tamperedResourceUri =
      "https://merchant.example.com/api/different-resource";
    const { paths } = await writeFixturesToTmp({
      envelopeJson: envelope,
      jwksJson: jwks,
      components: declared,
      resourceUriOverride: tamperedResourceUri,
    });
    // Also write declared component files (for localization).
    const declaredDir = paths.envelope.replace("envelope.json", "");
    const declaredPaths = {
      paymentRequirements: join(declaredDir, "decl-pr.json"),
      paymentPayload: join(declaredDir, "decl-pp.json"),
      settlementEvidence: join(declaredDir, "decl-se.json"),
      outputCommitment: join(declaredDir, "decl-oc.json"),
    };
    await writeFile(
      declaredPaths.paymentRequirements,
      JSON.stringify(declared.paymentRequirements)
    );
    await writeFile(
      declaredPaths.paymentPayload,
      JSON.stringify(declared.paymentPayload)
    );
    await writeFile(
      declaredPaths.settlementEvidence,
      JSON.stringify(declared.settlementEvidence)
    );
    await writeFile(
      declaredPaths.outputCommitment,
      JSON.stringify(declared.outputCommitment)
    );

    const argv = [
      "--envelope",
      paths.envelope!,
      "--jwks-file",
      paths.jwks!,
      "--payment-requirements",
      paths.paymentRequirements!,
      "--payment-payload",
      paths.paymentPayload!,
      "--authorization-scheme",
      "evm_permit2",
      "--resource-uri",
      tamperedResourceUri,
      "--settlement-evidence",
      paths.settlementEvidence!,
      "--output-commitment",
      paths.outputCommitment!,
      "--declared-payment-requirements",
      declaredPaths.paymentRequirements,
      "--declared-payment-payload",
      declaredPaths.paymentPayload,
      "--declared-resource-uri",
      declared.resourceUri,
      "--declared-settlement-evidence",
      declaredPaths.settlementEvidence,
      "--declared-output-commitment",
      declaredPaths.outputCommitment,
    ];
    const r = await runCli(argv);

    expect(r.exitCode).toBe(1);
    expect(r.stdout).toContain("BINDING_MISMATCH");
    expect(r.stdout).toContain("resource_uri");
  });

  test("missing required arg --envelope → exit 2 + stderr", async () => {
    const r = await runCli(["--jwks-file", "/tmp/does-not-matter.json"]);
    expect(r.exitCode).toBe(2);
    expect(r.stderr).toContain("missing required arg: --envelope");
  });

  test("invalid envelope JSON file → exit 2 + stderr", async () => {
    const dir = await mkdtemp(join(tmpdir(), "spec054-cli-bad-"));
    const envelopePath = join(dir, "envelope.json");
    await writeFile(envelopePath, "{ not valid json");
    const jwksPath = join(dir, "jwks.json");
    await writeFile(jwksPath, JSON.stringify({ keys: [] }));
    const r = await runCli([
      "--envelope",
      envelopePath,
      "--jwks-file",
      jwksPath,
    ]);
    expect(r.exitCode).toBe(2);
    expect(r.stderr).toMatch(/failed to load envelope/);
  });
});
