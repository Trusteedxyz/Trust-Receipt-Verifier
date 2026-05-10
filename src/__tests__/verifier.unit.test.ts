/**
 * TrustReceipt verifier unit tests.
 *
 * 10 tests covering: valid receipt, tampered payload, expired receipt,
 * unknown kid, invalid schema, parseTrustReceiptUnsafe, JWKS fetch failure,
 * wrong alg, malformed segments, and kid header/payload mismatch.
 *
 * Uses real Ed25519 keypair generated in beforeAll — no mocks except fetch.
 */

import { describe, it, expect, beforeAll, vi } from "vitest";
import { exportJWK, generateKeyPair, type JWK } from "jose";
import { issueTrustReceipt } from "../issuer.js";
import { verifyTrustReceipt, parseTrustReceiptUnsafe } from "../verifier.js";
import type { PublicJwk } from "../verifier.js";
import type { IssueOptions } from "../issuer.js";

// ─── Fixtures ─────────────────────────────────────────────────────────────────

const KID = "test-key-2026-01";

const MINIMAL_PAYLOAD: IssueOptions["payload"] = {
  issuer: "trusteed.xyz",
  merchant_id: "merchant-001",
  agent_id: "agent-claude-001",
  agent_provider: "anthropic",
  user_intent_hash:
    "a3f5c2d1e8b9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5",
  protocol: "MCP",
  protocol_artifacts: [
    {
      type: "mcp_tool_call",
      hash: "b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2",
    },
  ],
  policy_decision: "allow",
  verification_methods: [
    { type: "jwks", value: "https://trusteed.xyz/.well-known/jwks.json" },
  ],
};

// ─── Test state (populated in beforeAll) ─────────────────────────────────────

let publicJwk: PublicJwk;
let privateJwk: JWK;
let validJws: string;

beforeAll(async () => {
  const { publicKey, privateKey } = await generateKeyPair("EdDSA", {
    extractable: true,
  });

  publicJwk = { ...(await exportJWK(publicKey)), kid: KID, alg: "EdDSA" };
  privateJwk = await exportJWK(privateKey);

  validJws = await issueTrustReceipt({
    payload: MINIMAL_PAYLOAD,
    privateKeyJwk: privateJwk,
    kid: KID,
    validitySeconds: 3600,
  });
});

// ─── Tests ───────────────────────────────────────────────────────────────────

describe("verifyTrustReceipt", () => {
  it("test 1: valid receipt issued with generated key verifies OK", async () => {
    const result = await verifyTrustReceipt(validJws, {
      jwks: [publicJwk],
    });

    expect(result.valid).toBe(true);
    expect(result.receipt).toBeDefined();
    expect(result.receipt?.issuer).toBe("trusteed.xyz");
    expect(result.receipt?.schema_version).toBe("1.0");
    expect(result.receipt?.policy_decision).toBe("allow");
    expect(result.reason).toBeUndefined();
  });

  it("test 2: tampered payload returns tampered_signature", async () => {
    // Split JWS and swap the payload segment with a modified one
    const [header, , sig] = validJws.split(".");
    const tamperedPayload = Buffer.from(
      JSON.stringify({ issuer: "evil.com" })
    ).toString("base64url");
    const tamperedJws = `${header}.${tamperedPayload}.${sig}`;

    const result = await verifyTrustReceipt(tamperedJws, {
      jwks: [publicJwk],
    });

    expect(result.valid).toBe(false);
    expect(result.reason).toBe("tampered_signature");
  });

  it("test 3: expired receipt returns expired", async () => {
    // Issue with -1 validity so expires_at is in the past
    const expiredJws = await issueTrustReceipt({
      payload: MINIMAL_PAYLOAD,
      privateKeyJwk: privateJwk,
      kid: KID,
      validitySeconds: -7200, // already expired 2 hours ago
    });

    const result = await verifyTrustReceipt(expiredJws, {
      jwks: [publicJwk],
      clockToleranceSeconds: 0,
    });

    expect(result.valid).toBe(false);
    expect(result.reason).toBe("expired");
  });

  it("test 4: unknown kid returns unknown_kid", async () => {
    // Provide a JWKS with a different kid
    const wrongKidJwk: PublicJwk = { ...publicJwk, kid: "wrong-kid-9999" };

    const result = await verifyTrustReceipt(validJws, {
      jwks: [wrongKidJwk],
    });

    expect(result.valid).toBe(false);
    expect(result.reason).toBe("unknown_kid");
  });

  it("test 5: invalid schema (missing required field) returns schema_invalid", async () => {
    // Build a JWS with a payload that omits required fields
    const { CompactSign, importJWK } = await import("jose");
    const privKey = await importJWK(privateJwk, "EdDSA");

    const badPayload = {
      // Intentionally missing: receipt_id, schema_version, issued_at, expires_at,
      // issuer, merchant_id, agent_id, agent_provider, user_intent_hash,
      // protocol, protocol_artifacts, policy_decision, verification_methods, kid
      only_field: "this is invalid",
    };

    const badJws = await new CompactSign(
      new TextEncoder().encode(JSON.stringify(badPayload))
    )
      .setProtectedHeader({ alg: "EdDSA", kid: KID, typ: "JWT" })
      .sign(privKey);

    const result = await verifyTrustReceipt(badJws, {
      jwks: [publicJwk],
    });

    expect(result.valid).toBe(false);
    expect(result.reason).toBe("schema_invalid");
    expect(result.errors).toBeDefined();
    expect(result.errors!.length).toBeGreaterThan(0);
  });
});

describe("parseTrustReceiptUnsafe", () => {
  it("test 6: valid JWS returns parsed receipt without verification", async () => {
    const receipt = await parseTrustReceiptUnsafe(validJws);

    expect(receipt).not.toBeNull();
    expect(receipt?.issuer).toBe("trusteed.xyz");
    expect(receipt?.merchant_id).toBe("merchant-001");
    expect(receipt?.agent_provider).toBe("anthropic");
    expect(receipt?.schema_version).toBe("1.0");
  });
});

describe("verifyTrustReceipt — P0 guards", () => {
  it("test 7: remote JWKS fetch failure returns jwks_fetch_failed", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockRejectedValue(new TypeError("Failed to fetch"))
    );

    try {
      const result = await verifyTrustReceipt(validJws, {
        jwksUrl: "https://example.invalid/.well-known/jwks.json",
      });
      expect(result.valid).toBe(false);
      expect(result.reason).toBe("jwks_fetch_failed");
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("test 8: JWS with alg != EdDSA in header returns invalid_jws", async () => {
    const fakeHeader = Buffer.from(
      JSON.stringify({ alg: "RS256", kid: KID })
    ).toString("base64url");
    const [, payload, sig] = validJws.split(".");
    const wrongAlgJws = `${fakeHeader}.${payload ?? ""}.${sig ?? ""}`;

    const result = await verifyTrustReceipt(wrongAlgJws, {
      jwks: [publicJwk],
    });

    expect(result.valid).toBe(false);
    expect(result.reason).toBe("invalid_jws");
  });

  it("test 9: JWS with wrong segment count returns invalid_jws", async () => {
    const result = await verifyTrustReceipt("not.valid", {
      jwks: [publicJwk],
    });

    expect(result.valid).toBe(false);
    expect(result.reason).toBe("invalid_jws");
  });

  it("test 10: header kid != payload kid field returns schema_invalid", async () => {
    const { CompactSign, importJWK } = await import("jose");
    const privKey = await importJWK(privateJwk, "EdDSA");

    // Payload has kid matching the header, but we'll flip it
    const payloadWithMismatchedKid = {
      ...MINIMAL_PAYLOAD,
      receipt_id: "00000000-0000-0000-0000-000000000099",
      schema_version: "1.0" as const,
      issued_at: Math.floor(Date.now() / 1000),
      expires_at: Math.floor(Date.now() / 1000) + 3600,
      kid: "a-different-kid-than-header",
    };

    const mismatchedJws = await new CompactSign(
      new TextEncoder().encode(JSON.stringify(payloadWithMismatchedKid))
    )
      .setProtectedHeader({ alg: "EdDSA", kid: KID }) // header kid = KID
      .sign(privKey);

    const result = await verifyTrustReceipt(mismatchedJws, {
      jwks: [publicJwk],
    });

    expect(result.valid).toBe(false);
    expect(result.reason).toBe("schema_invalid");
    expect(result.errors?.[0]).toMatch(/kid mismatch/);
  });
});
