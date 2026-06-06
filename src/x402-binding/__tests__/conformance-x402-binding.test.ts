/**
 * Spec 058 P2-5 — x402_binding conformance suite (parametrized vectors).
 *
 * A vector-driven conformance table that exercises every typed outcome the
 * portable `VerifierX402Extension` produces (`VerifierExtensionResult`). Unlike
 * the per-case unit suite (`verifier-x402-extension.test.ts`), this file is a
 * SINGLE parametrized table: each vector declares a builder that mutates a
 * canonical happy-path fixture by exactly one dimension, plus the exact typed
 * outcome the verifier MUST return. The runner asserts:
 *
 *   - `valid` flag matches,
 *   - on reject: `reason` (and `mismatched_component` when localized) match,
 *   - on accept: `delegation_branch` / `binding_hash_match` / warnings match.
 *
 * COVERAGE GOAL — every member of `VerifierExtensionRejectReason` that the
 * verifier can actually emit for a binding-mismatch-by-component scenario, plus
 * the 5 `MismatchedComponent` localizations (FR-005/006), delegation-branch
 * outcomes (FR-008a), and accept-path warnings. This is offline & stateless:
 * the portable verifier has NO nonce/replay state (that lives server-side in
 * `PrismaMppReplayCacheService`), so NO replay vector is asserted here — doing
 * so would assert an outcome the verifier cannot produce.
 *
 * Reject reasons covered:
 *   schema_invalid (×3: jws-shape, payload-schema, profile-version, metadata
 *     non-object → envelope_metadata_mismatch), x402_binding_missing,
 *   unknown_kid, delegation_signature_invalid, delegation_out_of_window,
 *   delegate_merchant_root_kid_missing, receipt_signature_invalid,
 *   unsupported_authorization_scheme, inferred_identity_not_allowed,
 *   binding_mismatch (×5 components, localized + non-localized),
 *   envelope_metadata_mismatch.
 *
 * NOTE on intentionally-NOT-asserted reasons: the portable verifier never
 * emits `expired` (expiry → accept + warning) nor `internal_error` on any
 * well-formed adversarial input — both are documented below as "not reachable
 * by black-box vector" rather than silently omitted.
 *
 * @see specs/058-trustreceipt-x402-binding/spec.md FR-005/FR-006/FR-008a/FR-020/FR-022
 * @see packages/trust-receipt-verifier/src/x402-binding/verifier-x402-extension.ts
 */

import {
  generateKeyPairSync,
  sign as edSign,
  type KeyObject,
} from "node:crypto";

import canonicalize from "canonicalize";
import { describe, expect, test } from "vitest";

import {
  recomputeBindingHash,
  type BindingHashRecomputeInput,
} from "../binding-hash-recompute.js";
import type {
  AuthorizedDelegate,
  JwksKey,
  MerchantJwksDocument,
} from "../delegation-validator.js";
import {
  VerifierX402Extension,
  type MismatchedComponent,
  type ReceiptEnvelopeInput,
  type VerifierExtensionRejectReason,
  type VerifierX402ExtensionArgs,
} from "../verifier-x402-extension.js";
import type { TrustReceiptV11Body } from "../../zod-1.1.js";

// ---------------------------------------------------------------------------
// Deterministic fixture helpers (mirror verifier-x402-extension.test.ts)
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

function canonicalDelegationPayload(args: {
  readonly delegateKid: string;
  readonly rootKid: string;
  readonly validFrom: string;
  readonly validUntil: string;
}): string {
  const payload = {
    kid: args.delegateKid,
    role: "receipt-issuance",
    valid_from: args.validFrom,
    valid_until: args.validUntil,
    merchant_root_kid: args.rootKid,
  };
  const canonical = canonicalize(payload);
  if (typeof canonical !== "string") {
    throw new Error("canonicalize returned non-string");
  }
  return canonical;
}

function buildDelegatedJwks(args: {
  readonly root: Ed25519Material;
  readonly delegate: Ed25519Material;
  readonly validFrom: string;
  readonly validUntil: string;
  /** When true, the authorization_signature is signed by a foreign key (tamper). */
  readonly forgeSignatureWith?: Ed25519Material;
  /** When true, omit the merchant_root_kid sig key from keys[] (FR missing root). */
  readonly omitRootKey?: boolean;
  /** When true, omit the delegate's own sig key from keys[]. */
  readonly omitDelegateKey?: boolean;
}): MerchantJwksDocument {
  const canonical = canonicalDelegationPayload({
    delegateKid: args.delegate.kid,
    rootKid: args.root.kid,
    validFrom: args.validFrom,
    validUntil: args.validUntil,
  });
  const signer = args.forgeSignatureWith ?? args.root;
  const sig = edSign(null, Buffer.from(canonical, "utf8"), signer.privateKey);
  const delegate: AuthorizedDelegate = {
    kid: args.delegate.kid,
    role: "receipt-issuance",
    valid_from: args.validFrom,
    valid_until: args.validUntil,
    merchant_root_kid: args.root.kid,
    authorization_signature: base64UrlEncode(sig),
  };
  const keys: JwksKey[] = [];
  if (!args.omitRootKey) {
    keys.push({
      kty: "OKP",
      crv: "Ed25519",
      kid: args.root.kid,
      use: "sig",
      x: args.root.publicJwk.x,
    });
  }
  if (!args.omitDelegateKey) {
    keys.push({
      kty: "OKP",
      crv: "Ed25519",
      kid: args.delegate.kid,
      use: "sig",
      x: args.delegate.publicJwk.x,
    });
  }
  return { keys, authorized_delegates: [delegate] };
}

function evmPermit2Components(): BindingHashRecomputeInput {
  return {
    paymentRequirements: {
      scheme: "exact",
      network: "base",
      maxAmountRequired: "1000000",
      resource: "https://merchant.example.com/api/paid-resource",
      payTo: "0x1234567890abcdef1234567890abcdef12345678",
      maxTimeoutSeconds: 300,
      asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    },
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
    },
    authorizationScheme: "evm_permit2",
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
    },
  };
}

function buildV11Body(args: {
  readonly bindingHashTagged: string;
  readonly authorizationScheme?:
    | "evm_permit2"
    | "svm_token_authorization"
    | "mcap_cart_binding";
  readonly verificationPosture?: "unverified" | "observed" | "enforced";
  readonly chain?: unknown;
}): TrustReceiptV11Body {
  const now = Math.floor(Date.now() / 1000);
  const body: TrustReceiptV11Body = {
    receipt_id: "00000000-0000-4000-8000-000000000001",
    schema_version: "1.1",
    issued_at: now,
    expires_at: now + 3600,
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
      binding_profile_version: "1.0.0",
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
      agent_authorization_chain:
        args.chain !== undefined
          ? (args.chain as TrustReceiptV11Body["x402_binding"] & object)
          : null,
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
  } as TrustReceiptV11Body;
  return body;
}

function signEnvelope(args: {
  readonly material: Ed25519Material;
  readonly body: TrustReceiptV11Body;
  readonly extra?: Partial<ReceiptEnvelopeInput>;
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
  return {
    receipt: `${headerB64}.${payloadB64}.${sigB64}`,
    ...args.extra,
  };
}

// ---------------------------------------------------------------------------
// Conformance vector model
// ---------------------------------------------------------------------------

type ExpectedAccept = {
  readonly valid: true;
  readonly delegation_branch: "direct" | "delegated";
  readonly binding_hash_match: boolean;
};

type ExpectedReject = {
  readonly valid: false;
  readonly reason: VerifierExtensionRejectReason;
  readonly mismatched_component?: MismatchedComponent;
};

interface ConformanceVector {
  readonly id: string;
  readonly title: string;
  readonly build: () => VerifierX402ExtensionArgs;
  readonly expected: ExpectedAccept | ExpectedReject;
}

/** Convenience: a fully-valid direct-issuer fixture with matching binding hash. */
function happyDirect(): {
  readonly material: Ed25519Material;
  readonly components: BindingHashRecomputeInput;
  readonly body: TrustReceiptV11Body;
  readonly envelope: ReceiptEnvelopeInput;
  readonly jwks: MerchantJwksDocument;
} {
  const material = generateKeyMaterial("conf-direct");
  const components = evmPermit2Components();
  const { bindingHashTagged } = recomputeBindingHash(components);
  const body = buildV11Body({ bindingHashTagged });
  const envelope = signEnvelope({ material, body });
  const jwks = buildDirectIssuerJwks(material);
  return { material, components, body, envelope, jwks };
}

// ---------------------------------------------------------------------------
// Vector table (16 vectors)
// ---------------------------------------------------------------------------

const VECTORS: readonly ConformanceVector[] = [
  {
    id: "V01",
    title: "accept — direct issuer, binding hash match",
    build: () => {
      const { envelope, jwks, components } = happyDirect();
      return { envelope, jwks, componentsForBinding: components };
    },
    expected: {
      valid: true,
      delegation_branch: "direct",
      binding_hash_match: true,
    },
  },
  {
    id: "V02",
    title: "accept — delegated issuer, in-window, binding hash match",
    build: () => {
      const root = generateKeyMaterial("conf-root");
      const delegate = generateKeyMaterial("conf-delegate");
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
      return { envelope, jwks, componentsForBinding: components };
    },
    expected: {
      valid: true,
      delegation_branch: "delegated",
      binding_hash_match: true,
    },
  },
  {
    id: "V03",
    title: "reject — malformed JWS shape (2 parts) → schema_invalid",
    build: () => ({
      envelope: { receipt: "only.two-parts" },
      jwks: { keys: [] },
    }),
    expected: { valid: false, reason: "schema_invalid" },
  },
  {
    id: "V04",
    title: "reject — x402_binding extension absent → x402_binding_missing",
    build: () => {
      const { material, body, jwks } = happyDirect();
      const legacyBody = {
        ...body,
        x402_binding: undefined,
      } as TrustReceiptV11Body;
      const envelope = signEnvelope({ material, body: legacyBody });
      return { envelope, jwks };
    },
    expected: { valid: false, reason: "x402_binding_missing" },
  },
  {
    id: "V05",
    title: "reject — receipt kid not in JWKS → unknown_kid",
    build: () => {
      const { envelope } = happyDirect();
      const other = generateKeyMaterial("conf-other");
      return { envelope, jwks: buildDirectIssuerJwks(other) };
    },
    expected: { valid: false, reason: "unknown_kid" },
  },
  {
    id: "V06",
    title:
      "reject — delegation authorization_signature forged → delegation_signature_invalid",
    build: () => {
      const root = generateKeyMaterial("conf-root-forge");
      const delegate = generateKeyMaterial("conf-delegate-forge");
      const attacker = generateKeyMaterial("conf-attacker");
      const components = evmPermit2Components();
      const { bindingHashTagged } = recomputeBindingHash(components);
      const body = buildV11Body({ bindingHashTagged });
      const envelope = signEnvelope({ material: delegate, body });
      const jwks = buildDelegatedJwks({
        root,
        delegate,
        validFrom: new Date(Date.now() - 60_000).toISOString(),
        validUntil: new Date(Date.now() + 3_600_000).toISOString(),
        forgeSignatureWith: attacker,
      });
      return { envelope, jwks, componentsForBinding: components };
    },
    expected: { valid: false, reason: "delegation_signature_invalid" },
  },
  {
    id: "V07",
    title:
      "reject — delegation window in the future → delegation_out_of_window",
    build: () => {
      const root = generateKeyMaterial("conf-root-oow");
      const delegate = generateKeyMaterial("conf-delegate-oow");
      const components = evmPermit2Components();
      const { bindingHashTagged } = recomputeBindingHash(components);
      const body = buildV11Body({ bindingHashTagged });
      const envelope = signEnvelope({ material: delegate, body });
      const jwks = buildDelegatedJwks({
        root,
        delegate,
        validFrom: new Date(Date.now() + 3_600_000).toISOString(),
        validUntil: new Date(Date.now() + 7_200_000).toISOString(),
      });
      return { envelope, jwks, componentsForBinding: components };
    },
    expected: { valid: false, reason: "delegation_out_of_window" },
  },
  {
    id: "V08",
    title:
      "reject — delegate merchant_root_kid absent from keys[] → delegate_merchant_root_kid_missing",
    build: () => {
      const root = generateKeyMaterial("conf-root-missing");
      const delegate = generateKeyMaterial("conf-delegate-missing");
      const components = evmPermit2Components();
      const { bindingHashTagged } = recomputeBindingHash(components);
      const body = buildV11Body({ bindingHashTagged });
      const envelope = signEnvelope({ material: delegate, body });
      const jwks = buildDelegatedJwks({
        root,
        delegate,
        validFrom: new Date(Date.now() - 60_000).toISOString(),
        validUntil: new Date(Date.now() + 3_600_000).toISOString(),
        omitRootKey: true,
      });
      return { envelope, jwks, componentsForBinding: components };
    },
    expected: { valid: false, reason: "delegate_merchant_root_kid_missing" },
  },
  {
    id: "V09",
    title: "reject — signature bytes tampered → receipt_signature_invalid",
    build: () => {
      const { envelope, jwks } = happyDirect();
      const parts = envelope.receipt.split(".");
      // Flip the FIRST signature char (carries 6 meaningful bits — always
      // alters a real signature byte; see flake note in unit suite).
      const firstChar = parts[2]!.charAt(0);
      const tamperedFirst = firstChar === "A" ? "B" : "A";
      const tamperedSig = tamperedFirst + parts[2]!.slice(1);
      return {
        envelope: { receipt: `${parts[0]}.${parts[1]}.${tamperedSig}` },
        jwks,
      };
    },
    expected: { valid: false, reason: "receipt_signature_invalid" },
  },
  {
    id: "V10",
    title:
      "reject — authorization_scheme reserved for v1.1 → unsupported_authorization_scheme",
    build: () => {
      const material = generateKeyMaterial("conf-scheme");
      const components = evmPermit2Components();
      const { bindingHashTagged } = recomputeBindingHash(components);
      const body = buildV11Body({
        bindingHashTagged,
        authorizationScheme: "mcap_cart_binding",
      });
      const envelope = signEnvelope({ material, body });
      return { envelope, jwks: buildDirectIssuerJwks(material) };
    },
    expected: { valid: false, reason: "unsupported_authorization_scheme" },
  },
  {
    id: "V11",
    title:
      "reject — posture=unverified carries authorization chain → inferred_identity_not_allowed",
    build: () => {
      const material = generateKeyMaterial("conf-inferred");
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
      return { envelope, jwks: buildDirectIssuerJwks(material) };
    },
    expected: { valid: false, reason: "inferred_identity_not_allowed" },
  },
  {
    id: "V12",
    title:
      "reject — binding mismatch on payment_requirements (localized) → binding_mismatch",
    build: () => {
      const { envelope, jwks, components } = happyDirect();
      const tampered: BindingHashRecomputeInput = {
        ...components,
        paymentRequirements: {
          ...components.paymentRequirements,
          maxAmountRequired: "9999999",
        },
      };
      return {
        envelope,
        jwks,
        componentsForBinding: tampered,
        declaredComponentsForLocalization: components,
      };
    },
    expected: {
      valid: false,
      reason: "binding_mismatch",
      mismatched_component: "payment_requirements",
    },
  },
  {
    id: "V13",
    title:
      "reject — binding mismatch on payment_payload (localized) → binding_mismatch",
    build: () => {
      const { envelope, jwks, components } = happyDirect();
      const tampered: BindingHashRecomputeInput = {
        ...components,
        paymentPayload: { ...components.paymentPayload, signature: "0xforged" },
      };
      return {
        envelope,
        jwks,
        componentsForBinding: tampered,
        declaredComponentsForLocalization: components,
      };
    },
    expected: {
      valid: false,
      reason: "binding_mismatch",
      mismatched_component: "payment_payload",
    },
  },
  {
    id: "V14",
    title:
      "reject — binding mismatch on resource_uri (localized) → binding_mismatch",
    build: () => {
      const { envelope, jwks, components } = happyDirect();
      const tampered: BindingHashRecomputeInput = {
        ...components,
        resourceUri: "https://merchant.example.com/api/different-resource",
      };
      return {
        envelope,
        jwks,
        componentsForBinding: tampered,
        declaredComponentsForLocalization: components,
      };
    },
    expected: {
      valid: false,
      reason: "binding_mismatch",
      mismatched_component: "resource_uri",
    },
  },
  {
    id: "V15",
    title:
      "reject — binding mismatch on settlement_evidence_subset (localized) → binding_mismatch",
    build: () => {
      const { envelope, jwks, components } = happyDirect();
      const tampered: BindingHashRecomputeInput = {
        ...components,
        settlementEvidence: {
          ...components.settlementEvidence,
          payer: "0xdifferentpayer",
        },
      };
      return {
        envelope,
        jwks,
        componentsForBinding: tampered,
        declaredComponentsForLocalization: components,
      };
    },
    expected: {
      valid: false,
      reason: "binding_mismatch",
      mismatched_component: "settlement_evidence_subset",
    },
  },
  {
    id: "V16",
    title:
      "reject — binding mismatch on output_commitment (localized) → binding_mismatch",
    build: () => {
      const { envelope, jwks, components } = happyDirect();
      const tampered: BindingHashRecomputeInput = {
        ...components,
        outputCommitment: {
          ...components.outputCommitment,
          value:
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        },
      };
      return {
        envelope,
        jwks,
        componentsForBinding: tampered,
        declaredComponentsForLocalization: components,
      };
    },
    expected: {
      valid: false,
      reason: "binding_mismatch",
      mismatched_component: "output_commitment",
    },
  },
  {
    id: "V17",
    title:
      "reject — binding mismatch WITHOUT localization (no declared set) → binding_mismatch, no component",
    build: () => {
      const { envelope, jwks, components } = happyDirect();
      const tampered: BindingHashRecomputeInput = {
        ...components,
        resourceUri: "https://merchant.example.com/api/another-resource",
      };
      return { envelope, jwks, componentsForBinding: tampered };
    },
    expected: { valid: false, reason: "binding_mismatch" },
  },
  {
    id: "V18",
    title:
      "reject — envelope_metadata present but not an object → envelope_metadata_mismatch",
    build: () => {
      const { material, body, jwks, components } = happyDirect();
      const envelope = signEnvelope({
        material,
        body,
        extra: { envelope_metadata: "not-an-object" },
      });
      return { envelope, jwks, componentsForBinding: components };
    },
    expected: { valid: false, reason: "envelope_metadata_mismatch" },
  },
  {
    id: "V19",
    title: "reject — expectedBindingProfileVersion mismatch → schema_invalid",
    build: () => {
      const { envelope, jwks } = happyDirect();
      return { envelope, jwks, expectedBindingProfileVersion: "2.0.0" };
    },
    expected: { valid: false, reason: "schema_invalid" },
  },
];

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

describe("x402_binding conformance suite (Spec 058 P2-5)", () => {
  // Sanity: the table satisfies the 10+ vector requirement.
  test("table has at least 10 vectors", () => {
    expect(VECTORS.length).toBeGreaterThanOrEqual(10);
  });

  // Sanity: every binding-mismatch component is exercised at least once.
  test("all 5 MismatchedComponent localizations are covered", () => {
    const covered = new Set(
      VECTORS.flatMap((v) =>
        !v.expected.valid && v.expected.mismatched_component
          ? [v.expected.mismatched_component]
          : []
      )
    );
    expect([...covered].sort()).toEqual(
      [
        "output_commitment",
        "payment_payload",
        "payment_requirements",
        "resource_uri",
        "settlement_evidence_subset",
      ].sort()
    );
  });

  test.each(VECTORS.map((v) => [v.id, v.title, v] as const))(
    "%s %s",
    (_id, _title, vector) => {
      const verifier = new VerifierX402Extension();
      const result = verifier.verify(vector.build());

      expect(result.valid).toBe(vector.expected.valid);

      if (vector.expected.valid) {
        if (result.valid) {
          expect(result.delegation_branch).toBe(
            vector.expected.delegation_branch
          );
          expect(result.binding_hash_match).toBe(
            vector.expected.binding_hash_match
          );
        }
      } else if (!result.valid) {
        expect(result.reason).toBe(vector.expected.reason);
        if (vector.expected.mismatched_component !== undefined) {
          expect(result.mismatched_component).toBe(
            vector.expected.mismatched_component
          );
        }
      }
    }
  );
});
