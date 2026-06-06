/**
 * Spec 054 T012/T013 — Schema-extension tests for `TrustReceiptV11BodySchema`
 * with optional `x402_binding` extension (ADR-054-001).
 *
 * These tests verify the additive, backward-compatible extension:
 *
 *  1. Receipts WITHOUT `x402_binding` still parse cleanly (backward compat).
 *  2. Receipts WITH a well-formed `x402_binding` (kind=static_sha256) parse,
 *     and the field is preserved (not stripped).
 *  3. `x402_binding.posture === "pending_settlement"` is REJECTED per
 *     ADR-054-001 (receipts are only issued after settlement outcome is known).
 *  4. Malformed `output_commitment` (e.g. merkle_manifest missing
 *     `manifest_hash`) is REJECTED at parse time.
 *  5. The cross-field `buyer_agent` super-refinement still passes when
 *     `x402_binding` is present alongside all required buyer-agent fields.
 *
 * @see specs/058-trustreceipt-x402-binding/tasks.md T012 T013
 * @see specs/058-trustreceipt-x402-binding/contracts/x402-binding-receipt-payload.schema.json
 */

import { describe, expect, test } from "vitest";
import {
  TrustReceiptV11BodySchema,
  X402BindingExtensionSchema,
} from "../../zod-1.1.js";

// ---------------------------------------------------------------------------
// Fixture builders
// ---------------------------------------------------------------------------

const HEX64 = "a".repeat(64);
const SHA256_TAGGED = `sha256:${HEX64}` as const;
const HMAC_TAGGED = `hmac-sha256:${HEX64}` as const;

/** Minimal-valid buyer_agent v1.1 receipt body (NO x402_binding). */
function buildMinimalBuyerAgentBody(): Record<string, unknown> {
  return {
    receipt_id: "11111111-2222-4333-8444-555555555555",
    schema_version: "1.1",
    issued_at: 1_700_000_000,
    expires_at: 1_700_086_400,
    issuer: "did:web:trusteed.xyz",
    merchant_id: "merchant_abc",
    agent_provider: "openai",
    agent_id: "agent_123",
    receipt_subject: "buyer_agent",
    privacy_classification: "pii_hashed_salted",
    legal_posture: "ades_candidate_timestamped",
    legal_posture_warnings: [],
    buyer_agent_consent_context: {
      consent_type: "checkbox",
      consent_timestamp: 1_700_000_000,
      consent_hash: HMAC_TAGGED,
      consent_hmac_key_version: 1,
      consent_disclosure_version: "1.0.0",
      consent_withdrawal_uri_hash: SHA256_TAGGED,
      consent_evidence_ref: "evidence://abc",
      agent_authorization_chain: [
        {
          actor: "user",
          method: "OAuth+MFA",
          hash: SHA256_TAGGED,
          timestamp: 1_700_000_000,
        },
        {
          actor: "agent",
          method: "rfc9421_signature",
          hash: SHA256_TAGGED,
          timestamp: 1_700_000_001,
        },
      ],
    },
    user_intent_hash: HMAC_TAGGED,
    intent_hmac_key_version: 1,
    payment_authorization_hash: SHA256_TAGGED,
    authorization_scheme: "evm_permit2",
    esign_disclosure_version: "1.0.0",
    esign_disclosure_hash: SHA256_TAGGED,
    consent_evidence_ref: "evidence://abc",
    protocol: "x402",
    protocol_artifacts: [],
    authorization_evidence: {
      user_intent_hash: HMAC_TAGGED,
      intent_hmac_key_version: 1,
      execution_hash: SHA256_TAGGED,
    },
    verification_methods: {
      jwks: { uri: "https://example.com/jwks.json", kid: "k1" },
      jwks_sha256: HEX64,
      trust_anchor_sha256: HEX64,
    },
    policy_decision: "allow",
  };
}

/** Minimal-valid x402_binding extension (static_sha256 kind). */
function buildValidX402Binding(): Record<string, unknown> {
  return {
    binding_profile_version: "1.0.0",
    binding_hash: SHA256_TAGGED,
    binding_components_manifest_url:
      "https://merchant.example.com/binding-manifest.json",
    binding_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
    intent_hash: HMAC_TAGGED,
    pii_hmac_key_version: 1,
    nonce: "AAAAAAAAAAAAAAAAAAAAAA",
    issued_at: "2026-05-17T10:00:00Z",
    expires_at: "2026-05-18T10:00:00Z",
    authorization_scheme: "evm_permit2",
    payment_authorization_hash: SHA256_TAGGED,
    verification_posture: "enforced",
    agent_authorization_chain: {
      issuer: "did:web:openai.com",
      kid: "key-1",
      verification_status: "verified",
      spec045_posture: "enforce",
      verified_at: "2026-05-17T09:59:00Z",
    },
    posture: "confirmed",
    output_commitment: {
      kind: "static_sha256",
      algorithm: "sha256",
      value: SHA256_TAGGED,
      content_type: "application/json",
      content_length: 1024,
    },
    privacy_filtered_hashes: {
      resource_description_hmac: HMAC_TAGGED,
    },
    intent_allows_multi_settlement: false,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("Spec-054 T012/T013 — TrustReceiptV11BodySchema x402_binding extension", () => {
  describe("backward compatibility", () => {
    test("v1.1 receipt WITHOUT x402_binding still parses (additive extension)", () => {
      const body = buildMinimalBuyerAgentBody();
      const result = TrustReceiptV11BodySchema.safeParse(body);
      if (!result.success) {
        // surface zod errors for diagnosis
        // eslint-disable-next-line no-console
        console.error(JSON.stringify(result.error.issues, null, 2));
      }
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.x402_binding).toBeUndefined();
      }
    });
  });

  describe("happy path with x402_binding", () => {
    test("receipt with well-formed x402_binding (static_sha256) parses and preserves the field", () => {
      const body = buildMinimalBuyerAgentBody();
      body.x402_binding = buildValidX402Binding();
      const result = TrustReceiptV11BodySchema.safeParse(body);
      if (!result.success) {
        // eslint-disable-next-line no-console
        console.error(JSON.stringify(result.error.issues, null, 2));
      }
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.x402_binding).toBeDefined();
        expect(result.data.x402_binding?.posture).toBe("confirmed");
        expect(result.data.x402_binding?.output_commitment.kind).toBe(
          "static_sha256"
        );
      }
    });

    test("buyer_agent super-refinement still passes with x402_binding attached", () => {
      const body = buildMinimalBuyerAgentBody();
      body.x402_binding = buildValidX402Binding();
      const result = TrustReceiptV11BodySchema.safeParse(body);
      expect(result.success).toBe(true);
    });
  });

  describe("strict posture (ADR-054-001)", () => {
    test("REJECTS x402_binding.posture === 'pending_settlement'", () => {
      const binding = buildValidX402Binding() as Record<string, unknown>;
      binding.posture = "pending_settlement";
      const result = X402BindingExtensionSchema.safeParse(binding);
      expect(result.success).toBe(false);
    });

    test("ACCEPTS x402_binding.posture === 'settlement_failed'", () => {
      const binding = buildValidX402Binding() as Record<string, unknown>;
      binding.posture = "settlement_failed";
      const result = X402BindingExtensionSchema.safeParse(binding);
      expect(result.success).toBe(true);
    });
  });

  describe("strict output_commitment", () => {
    test("REJECTS malformed merkle_manifest commitment (missing manifest_hash)", () => {
      const binding = buildValidX402Binding() as Record<string, unknown>;
      binding.output_commitment = {
        kind: "merkle_manifest",
        algorithm: "merkle-sha256-v1",
        root: SHA256_TAGGED,
        manifest_url: "https://merchant.example.com/manifest.json",
        // manifest_hash intentionally omitted
        chunk_size: 65536,
        chunk_count: 4,
      };
      const result = X402BindingExtensionSchema.safeParse(binding);
      expect(result.success).toBe(false);
    });

    test("REJECTS unknown output_commitment.kind", () => {
      const binding = buildValidX402Binding() as Record<string, unknown>;
      binding.output_commitment = {
        kind: "magic_oracle",
        algorithm: "sha256",
        value: SHA256_TAGGED,
      };
      const result = X402BindingExtensionSchema.safeParse(binding);
      expect(result.success).toBe(false);
    });

    test("ACCEPTS well-formed merkle_manifest commitment", () => {
      const binding = buildValidX402Binding() as Record<string, unknown>;
      binding.output_commitment = {
        kind: "merkle_manifest",
        algorithm: "merkle-sha256-v1",
        root: SHA256_TAGGED,
        manifest_url: "https://merchant.example.com/manifest.json",
        manifest_hash: SHA256_TAGGED,
        chunk_size: 65536,
        chunk_count: 4,
      };
      const result = X402BindingExtensionSchema.safeParse(binding);
      expect(result.success).toBe(true);
    });
  });

  describe("nullable agent_authorization_chain", () => {
    test("ACCEPTS null agent_authorization_chain", () => {
      const binding = buildValidX402Binding() as Record<string, unknown>;
      binding.agent_authorization_chain = null;
      const result = X402BindingExtensionSchema.safeParse(binding);
      expect(result.success).toBe(true);
    });
  });
});
