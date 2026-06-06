/**
 * Spec 054 T101 — Unit tests for VerifierX402Extension.
 *
 * Covers the 12-phase verification pipeline:
 *   - happy-path direct issuer (signature-only)
 *   - happy-path direct issuer + binding hash recompute match
 *   - happy-path delegated issuer
 *   - tampered signature → receipt_signature_invalid
 *   - unknown kid → unknown_kid
 *   - delegation out-of-window → delegation_out_of_window
 *   - malformed JWS shape → schema_invalid
 *   - x402_binding absent → x402_binding_missing
 *   - unsupported authorization_scheme (zk_authorization) → typed reject
 *   - FR-022 inferred identity guard → inferred_identity_not_allowed
 *   - binding hash mismatch (no localization) → binding_mismatch
 *   - binding hash mismatch with declared components → binding_mismatch + mismatched_component
 *   - expected binding_profile_version mismatch → schema_invalid
 *   - metric emit happy + error
 *   - expired receipt → valid: true + warning
 *
 * @see specs/058-trustreceipt-x402-binding/tasks.md T101
 */

import {
  generateKeyPairSync,
  sign as edSign,
  type KeyObject,
} from "node:crypto";

import { describe, expect, test, vi } from "vitest";

import { recomputeBindingHash } from "../binding-hash-recompute.js";
import type {
  AuthorizedDelegate,
  JwksKey,
  MerchantJwksDocument,
} from "../delegation-validator.js";
import {
  VerifierX402Extension,
  type ReceiptEnvelopeInput,
  type VerifierX402ExtensionArgs,
} from "../verifier-x402-extension.js";
import type { TrustReceiptV11Body } from "../../zod-1.1.js";

import canonicalize from "canonicalize";

// ---------------------------------------------------------------------------
// Fixture helpers
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

function buildDirectIssuerJwks(
  material: Ed25519Material
): MerchantJwksDocument {
  const key: JwksKey = {
    kty: "OKP",
    crv: "Ed25519",
    kid: material.kid,
    use: "sig",
    kid_uses: ["receipt-issuance"],
    x: material.publicJwk.x,
  };
  return { keys: [key] };
}

function buildDelegatedJwks(args: {
  readonly root: Ed25519Material;
  readonly delegate: Ed25519Material;
  readonly validFrom: string;
  readonly validUntil: string;
}): MerchantJwksDocument {
  const rootKey: JwksKey = {
    kty: "OKP",
    crv: "Ed25519",
    kid: args.root.kid,
    use: "sig",
    x: args.root.publicJwk.x,
  };
  const delegateKey: JwksKey = {
    kty: "OKP",
    crv: "Ed25519",
    kid: args.delegate.kid,
    use: "sig",
    x: args.delegate.publicJwk.x,
  };
  const payload = {
    kid: args.delegate.kid,
    role: "receipt-issuance",
    valid_from: args.validFrom,
    valid_until: args.validUntil,
    merchant_root_kid: args.root.kid,
  };
  const canonical = canonicalize(payload);
  if (typeof canonical !== "string") {
    throw new Error("canonicalize returned non-string");
  }
  const sig = edSign(
    null,
    Buffer.from(canonical, "utf8"),
    args.root.privateKey
  );
  const delegate: AuthorizedDelegate = {
    kid: args.delegate.kid,
    role: "receipt-issuance",
    valid_from: args.validFrom,
    valid_until: args.validUntil,
    merchant_root_kid: args.root.kid,
    authorization_signature: base64UrlEncode(sig),
  };
  return { keys: [rootKey, delegateKey], authorized_delegates: [delegate] };
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
      permit2_authorization: {
        permitted: { token: "0xtoken", amount: "1000000" },
        nonce: "1",
        deadline: "1900000000",
      },
      owner: "0xowner",
      spender: "0xspender",
      token: "0xtoken",
      amount: "1000000",
      nonce: "1",
      deadline: "1900000000",
      signature: "0xdeadbeef",
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

function buildV11Body(args: {
  readonly bindingHashTagged: string;
  readonly authorizationScheme?:
    | "evm_permit2"
    | "svm_token_authorization"
    | "mcap_cart_binding";
  readonly verificationPosture?: "unverified" | "observed" | "enforced";
  readonly chain?: TrustReceiptV11Body["x402_binding"] extends infer X
    ? X extends { agent_authorization_chain: infer C }
      ? C
      : never
    : never;
  readonly expiresAtSec?: number;
  readonly bindingProfileVersion?: string;
}): TrustReceiptV11Body {
  const now = Math.floor(Date.now() / 1000);
  const body: TrustReceiptV11Body = {
    receipt_id: "00000000-0000-4000-8000-000000000001",
    schema_version: "1.1",
    issued_at: now,
    expires_at: args.expiresAtSec ?? now + 3600,
    issuer: "https://merchant.example.com",
    merchant_id: "merchant_acme",
    agent_provider: "test_agent",
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
      consent_evidence_ref: "ref://evidence/1",
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
    consent_evidence_ref: "ref://evidence/1",
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
      binding_profile_version: args.bindingProfileVersion ?? "1.0.0",
      binding_hash: args.bindingHashTagged,
      binding_components_manifest_url:
        "https://merchant.example.com/api/v1/x402-binding/binding-components-manifest/1.0.0",
      binding_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
      intent_hash:
        "hmac-sha256:7777777777777777777777777777777777777777777777777777777777777777",
      pii_hmac_key_version: 1,
      nonce: "AAAAAAAAAAAAAAAAAAAAAg",
      issued_at: new Date(now * 1000).toISOString(),
      expires_at: new Date((now + 3600) * 1000).toISOString(),
      authorization_scheme: args.authorizationScheme ?? "evm_permit2",
      payment_authorization_hash:
        "sha256:6666666666666666666666666666666666666666666666666666666666666666",
      verification_posture: args.verificationPosture ?? "unverified",
      agent_authorization_chain: args.chain !== undefined ? args.chain : null,
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
  return body;
}

function signEnvelope(args: {
  readonly material: Ed25519Material;
  readonly body: TrustReceiptV11Body;
}): ReceiptEnvelopeInput {
  const headerB64 = base64UrlJson({ alg: "EdDSA", kid: args.material.kid });
  const payloadB64 = base64UrlJson(args.body);
  const signingInput = `${headerB64}.${payloadB64}`;
  const sig = edSign(
    null,
    Buffer.from(signingInput, "utf8"),
    args.material.privateKey
  );
  const sigB64 = base64UrlEncode(sig);
  return { receipt: `${headerB64}.${payloadB64}.${sigB64}` };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("VerifierX402Extension", () => {
  test("happy direct issuer, signature-only (no components)", () => {
    const material = generateKeyMaterial("direct-1");
    const components = evmPermit2Components();
    const { bindingHashTagged } = recomputeBindingHash(components);
    const body = buildV11Body({ bindingHashTagged });
    const envelope = signEnvelope({ material, body });
    const jwks = buildDirectIssuerJwks(material);

    const verifier = new VerifierX402Extension();
    const result = verifier.verify({ envelope, jwks });

    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.delegation_branch).toBe("direct");
      expect(result.binding_hash_match).toBe(false);
      expect(result.warnings).toContain(
        "binding_hash_match_skipped_no_components_provided"
      );
      expect(result.kid).toBe("direct-1");
    }
  });

  test("happy direct issuer with binding hash match", () => {
    const material = generateKeyMaterial("direct-2");
    const components = evmPermit2Components();
    const { bindingHashTagged } = recomputeBindingHash(components);
    const body = buildV11Body({ bindingHashTagged });
    const envelope = signEnvelope({ material, body });
    const jwks = buildDirectIssuerJwks(material);

    const verifier = new VerifierX402Extension();
    const result = verifier.verify({
      envelope,
      jwks,
      componentsForBinding: components,
    });

    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.binding_hash_match).toBe(true);
    }
  });

  test("happy delegated issuer", () => {
    const root = generateKeyMaterial("root-1");
    const delegate = generateKeyMaterial("delegate-1");
    const components = evmPermit2Components();
    const { bindingHashTagged } = recomputeBindingHash(components);
    const body = buildV11Body({ bindingHashTagged });
    const envelope = signEnvelope({ material: delegate, body });
    const jwks = buildDelegatedJwks({
      root,
      delegate,
      validFrom: new Date(Date.now() - 60_000).toISOString(),
      validUntil: new Date(Date.now() + 3_600_000).toISOString(),
    });

    const verifier = new VerifierX402Extension();
    const result = verifier.verify({ envelope, jwks });

    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.delegation_branch).toBe("delegated");
    }
  });

  test("receipt_signature_invalid when signature bytes tampered", () => {
    const material = generateKeyMaterial("tamper-1");
    const components = evmPermit2Components();
    const { bindingHashTagged } = recomputeBindingHash(components);
    const body = buildV11Body({ bindingHashTagged });
    const envelope = signEnvelope({ material, body });
    const parts = envelope.receipt.split(".");
    // Flip the FIRST signature char — guaranteed to alter decoded bytes.
    //
    // Flake fix 2026-05-18: the previous version flipped the LAST char, which
    // for Ed25519 (64-byte sig → 86 base64url chars, last char has 4 padding
    // bits) only carried 2 meaningful bits. When the random keypair produced a
    // sig ending in "A" (00 + 0000), the tamper "A"→"B" (00 + 0001) preserved
    // the leading 2 meaningful bits and the padding-bit difference was
    // discarded by Node's lenient base64url decoder → decoded bytes IDENTICAL
    // → verifier correctly accepted → test failed ~25% of runs. The first
    // char encodes 6 meaningful bits and always flips a real signature byte.
    const firstChar = parts[2]!.charAt(0);
    const tamperedFirst = firstChar === "A" ? "B" : "A";
    const tamperedSig = tamperedFirst + parts[2]!.slice(1);
    const tampered: ReceiptEnvelopeInput = {
      receipt: `${parts[0]}.${parts[1]}.${tamperedSig}`,
    };

    const verifier = new VerifierX402Extension();
    const result = verifier.verify({
      envelope: tampered,
      jwks: buildDirectIssuerJwks(material),
    });

    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.reason).toBe("receipt_signature_invalid");
    }
  });

  test("unknown_kid when JWKS does not contain receipt kid", () => {
    const material = generateKeyMaterial("not-in-jwks");
    const other = generateKeyMaterial("other-1");
    const components = evmPermit2Components();
    const { bindingHashTagged } = recomputeBindingHash(components);
    const body = buildV11Body({ bindingHashTagged });
    const envelope = signEnvelope({ material, body });
    const jwks = buildDirectIssuerJwks(other);

    const verifier = new VerifierX402Extension();
    const result = verifier.verify({ envelope, jwks });

    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reason).toBe("unknown_kid");
  });

  test("delegation_out_of_window when issued_at outside validity", () => {
    const root = generateKeyMaterial("root-oow");
    const delegate = generateKeyMaterial("delegate-oow");
    const components = evmPermit2Components();
    const { bindingHashTagged } = recomputeBindingHash(components);
    const body = buildV11Body({ bindingHashTagged });
    const envelope = signEnvelope({ material: delegate, body });
    // Delegation window in the future, body.x402_binding.issued_at is "now".
    const jwks = buildDelegatedJwks({
      root,
      delegate,
      validFrom: new Date(Date.now() + 3_600_000).toISOString(),
      validUntil: new Date(Date.now() + 7_200_000).toISOString(),
    });

    const verifier = new VerifierX402Extension();
    const result = verifier.verify({ envelope, jwks });

    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.reason).toBe("delegation_out_of_window");
    }
  });

  test("schema_invalid when JWS shape malformed", () => {
    const verifier = new VerifierX402Extension();
    const result = verifier.verify({
      envelope: { receipt: "only.two-parts" },
      jwks: { keys: [] },
    });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reason).toBe("schema_invalid");
  });

  test("x402_binding_missing when receipt is legacy spec-049 (no extension)", () => {
    const material = generateKeyMaterial("legacy-1");
    const components = evmPermit2Components();
    const { bindingHashTagged } = recomputeBindingHash(components);
    const body = buildV11Body({ bindingHashTagged });
    // Strip extension.
    const legacyBody: TrustReceiptV11Body = {
      ...body,
      x402_binding: undefined,
    };
    const envelope = signEnvelope({ material, body: legacyBody });
    const jwks = buildDirectIssuerJwks(material);

    const verifier = new VerifierX402Extension();
    const result = verifier.verify({ envelope, jwks });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reason).toBe("x402_binding_missing");
  });

  test("unsupported_authorization_scheme when scheme reserved for v1.1", () => {
    const material = generateKeyMaterial("unsupported-1");
    const components = evmPermit2Components();
    const { bindingHashTagged } = recomputeBindingHash(components);
    const body = buildV11Body({
      bindingHashTagged,
      // mcap_cart_binding is in the spec-049 AuthorizationScheme enum but NOT
      // in the spec-054 binding v1.0 allowlist (FR-020).
      authorizationScheme: "mcap_cart_binding",
    });
    const envelope = signEnvelope({ material, body });
    const jwks = buildDirectIssuerJwks(material);

    const verifier = new VerifierX402Extension();
    const result = verifier.verify({ envelope, jwks });
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.reason).toBe("unsupported_authorization_scheme");
    }
  });

  test("inferred_identity_not_allowed when posture=unverified + chain present", () => {
    const material = generateKeyMaterial("inferred-1");
    const components = evmPermit2Components();
    const { bindingHashTagged } = recomputeBindingHash(components);
    const body = buildV11Body({
      bindingHashTagged,
      verificationPosture: "unverified",
      chain: {
        issuer: "https://identity.example.com",
        kid: "agent-key-1",
        verification_status: "unverified",
        spec045_posture: "observe",
        verified_at: new Date().toISOString(),
      },
    });
    const envelope = signEnvelope({ material, body });
    const jwks = buildDirectIssuerJwks(material);

    const verifier = new VerifierX402Extension();
    const result = verifier.verify({ envelope, jwks });
    expect(result.valid).toBe(false);
    if (!result.valid)
      expect(result.reason).toBe("inferred_identity_not_allowed");
  });

  test("binding_mismatch when components differ (no localization)", () => {
    const material = generateKeyMaterial("mismatch-1");
    const declared = evmPermit2Components();
    const { bindingHashTagged } = recomputeBindingHash(declared);
    const body = buildV11Body({ bindingHashTagged });
    const envelope = signEnvelope({ material, body });
    const jwks = buildDirectIssuerJwks(material);

    // Tamper resource_uri.
    const tampered = {
      ...declared,
      resourceUri: "https://merchant.example.com/api/different-resource",
    };

    const verifier = new VerifierX402Extension();
    const result = verifier.verify({
      envelope,
      jwks,
      componentsForBinding: tampered,
    });
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.reason).toBe("binding_mismatch");
      expect(result.mismatched_component).toBeUndefined();
    }
  });

  test("binding_mismatch with mismatched_component when declared components supplied", () => {
    const material = generateKeyMaterial("mismatch-2");
    const declared = evmPermit2Components();
    const { bindingHashTagged } = recomputeBindingHash(declared);
    const body = buildV11Body({ bindingHashTagged });
    const envelope = signEnvelope({ material, body });
    const jwks = buildDirectIssuerJwks(material);

    const tampered = {
      ...declared,
      resourceUri: "https://merchant.example.com/api/different-resource",
    };

    const verifier = new VerifierX402Extension();
    const result = verifier.verify({
      envelope,
      jwks,
      componentsForBinding: tampered,
      declaredComponentsForLocalization: declared,
    });
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.reason).toBe("binding_mismatch");
      expect(result.mismatched_component).toBe("resource_uri");
    }
  });

  test("schema_invalid when expectedBindingProfileVersion mismatches", () => {
    const material = generateKeyMaterial("version-1");
    const components = evmPermit2Components();
    const { bindingHashTagged } = recomputeBindingHash(components);
    const body = buildV11Body({ bindingHashTagged });
    const envelope = signEnvelope({ material, body });
    const jwks = buildDirectIssuerJwks(material);

    const verifier = new VerifierX402Extension();
    const result = verifier.verify({
      envelope,
      jwks,
      expectedBindingProfileVersion: "2.0.0",
    });
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.reason).toBe("schema_invalid");
      expect(result.details).toMatchObject({
        binding_profile_version_mismatch: true,
        expected: "2.0.0",
        actual: "1.0.0",
      });
    }
  });

  test("metric emit on valid path", () => {
    const material = generateKeyMaterial("metric-1");
    const components = evmPermit2Components();
    const { bindingHashTagged } = recomputeBindingHash(components);
    const body = buildV11Body({ bindingHashTagged });
    const envelope = signEnvelope({ material, body });
    const jwks = buildDirectIssuerJwks(material);

    const emit = vi.fn();
    const verifier = new VerifierX402Extension({
      emitVerificationMetric: emit,
    });
    const result = verifier.verify({ envelope, jwks });
    expect(result.valid).toBe(true);
    expect(emit).toHaveBeenCalledWith({
      result: "valid",
      posture: "unverified",
    });
  });

  test("metric emit on error path", () => {
    const emit = vi.fn();
    const verifier = new VerifierX402Extension({
      emitVerificationMetric: emit,
    });
    verifier.verify({
      envelope: { receipt: "broken" },
      jwks: { keys: [] },
    });
    expect(emit).toHaveBeenCalledWith({
      result: "schema_invalid",
      posture: "unknown",
    });
  });

  test("expired receipt returns valid: true with warning", () => {
    const material = generateKeyMaterial("expired-1");
    const components = evmPermit2Components();
    const { bindingHashTagged } = recomputeBindingHash(components);
    const past = Math.floor(Date.now() / 1000) - 7200;
    const body = buildV11Body({ bindingHashTagged, expiresAtSec: past });
    const envelope = signEnvelope({ material, body });
    const jwks = buildDirectIssuerJwks(material);

    const verifier = new VerifierX402Extension();
    const result = verifier.verify({ envelope, jwks });
    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.warnings).toContain("receipt_expired_but_signature_valid");
    }
  });
});
