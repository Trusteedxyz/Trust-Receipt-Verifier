/**
 * TrustReceipt verifier unit tests.
 *
 * Covers: valid receipt, tampered payload, expired receipt, unknown kid,
 * invalid schema, parseTrustReceiptUnsafe, JWKS fetch failure, wrong alg,
 * malformed segments, kid header/payload mismatch, and the windowed
 * jwksHistory/jwksUrl rotation-gap closure (kid_outside_validity_window).
 *
 * Uses real Ed25519 keypair generated in beforeAll — no mocks except fetch.
 */

import { describe, it, expect, beforeAll, vi } from "vitest";
import {
  CompactSign,
  exportJWK,
  generateKeyPair,
  importJWK,
  type JWK,
} from "jose";
import { issueTrustReceipt } from "../issuer.js";
import { verifyTrustReceipt, parseTrustReceiptUnsafe } from "../verifier.js";
import type { PublicJwk, JwksHistoryEntry } from "../verifier.js";
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

  /**
   * CHANGED 2026-07-28 (audit §5 R3). `expires_at` no longer invalidates a v1.0
   * receipt on EITHER branch of this verifier.
   *
   * The legacy-compact branch already exempted it, and documented why: FR-018
   * requires v1.0 receipts to keep verifying for ≥ 7 years, the rows are
   * immutable, and the issuer stamped a 24 h lifetime — so enforcing it here
   * marked essentially the whole corpus `expired`. The canonical branch kept
   * enforcing it, which meant the SAME evidence verified or failed depending on
   * which shape it happened to be in. That is the inconsistency this closes.
   *
   * Freshness is a consumer policy decision, not a signature-validity one, so it
   * is REPORTED (`freshness`) rather than acted on. v1.1 and the Python port are
   * deliberately untouched — their rejection is a published spec-054 conformance
   * requirement (vector `053-temporal-receipt-expired`).
   */
  it("test 3: an expired receipt still VERIFIES, and reports its staleness", async () => {
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

    expect(result.valid).toBe(true);
    expect(result.reason).toBeUndefined();
    expect(result.freshness?.expired).toBe(true);
    expect(result.freshness?.secondsPastExpiry).toBeGreaterThan(0);
  });

  it("test 3b: a receipt inside its window reports expired:false", async () => {
    const freshJws = await issueTrustReceipt({
      payload: MINIMAL_PAYLOAD,
      privateKeyJwk: privateJwk,
      kid: KID,
      validitySeconds: 3600,
    });

    const result = await verifyTrustReceipt(freshJws, {
      jwks: [publicJwk],
      clockToleranceSeconds: 0,
    });

    expect(result.valid).toBe(true);
    expect(result.freshness?.expired).toBe(false);
    expect(result.freshness?.secondsPastExpiry).toBe(0);
  });

  it("test 3c: a not-yet-valid receipt is STILL fatal — that is forgery-shaped", async () => {
    // Signed by hand: `issueTrustReceipt` stamps `issued_at` itself (the field
    // is in its `Omit`), so a future-dated receipt cannot be produced through
    // the public issuer — which is correct, and why this is built directly.
    const nowSec = Math.floor(Date.now() / 1000);
    const body = {
      ...MINIMAL_PAYLOAD,
      receipt_id: "11111111-1111-4111-8111-111111111111",
      schema_version: "1.0",
      issued_at: nowSec + 86_400,
      expires_at: nowSec + 172_800,
      kid: KID,
    };
    const futureJws = await new CompactSign(
      new TextEncoder().encode(JSON.stringify(body))
    )
      .setProtectedHeader({ alg: "EdDSA", kid: KID })
      .sign(await importJWK(privateJwk, "EdDSA"));

    const result = await verifyTrustReceipt(futureJws, {
      jwks: [publicJwk],
      clockToleranceSeconds: 0,
    });

    // Asymmetric on purpose: an old receipt is ordinary, a receipt issued in the
    // future cannot have been issued by an honest clock.
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("not_yet_valid");
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

describe("verifyTrustReceipt — windowed key history (rotation-gap closure)", () => {
  it("test 11: jwksHistory verifies OK when issued_at falls inside the key's window", async () => {
    const history: JwksHistoryEntry[] = [
      { kid: KID, jwk_pub: publicJwk, valid_from: 0, valid_to: null },
    ];

    const result = await verifyTrustReceipt(validJws, { jwksHistory: history });

    expect(result.valid).toBe(true);
  });

  it("test 12: jwksHistory rejects with kid_outside_validity_window when the key was retired before issued_at", async () => {
    const history: JwksHistoryEntry[] = [
      {
        kid: KID,
        jwk_pub: publicJwk,
        valid_from: 0,
        // Key retired well before this receipt's issued_at — a holder of
        // the retired private key must not be able to keep forging fresh
        // receipts after rotation.
        valid_to: Math.floor(Date.now() / 1000) - 100,
      },
    ];

    const result = await verifyTrustReceipt(validJws, { jwksHistory: history });

    expect(result.valid).toBe(false);
    expect(result.reason).toBe("kid_outside_validity_window");
  });

  it("test 13: jwksHistory returns unknown_kid when the kid isn't in the history", async () => {
    const history: JwksHistoryEntry[] = [
      {
        kid: "some-other-kid",
        jwk_pub: { ...publicJwk, kid: "some-other-kid" },
        valid_from: 0,
        valid_to: null,
      },
    ];

    const result = await verifyTrustReceipt(validJws, { jwksHistory: history });

    expect(result.valid).toBe(false);
    expect(result.reason).toBe("unknown_kid");
  });

  it("test 14: jwksUrl honors per-key valid_from/valid_to windows on the fetched JWKS document", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          keys: [
            {
              ...publicJwk,
              // Retired before this receipt's issued_at — same rotation
              // gap as jwksHistory, but sourced from a remote document.
              valid_from: 0,
              valid_to: Math.floor(Date.now() / 1000) - 100,
            },
          ],
        }),
      })
    );

    try {
      const result = await verifyTrustReceipt(validJws, {
        jwksUrl: "https://example.invalid/.well-known/jwks.json",
      });
      expect(result.valid).toBe(false);
      expect(result.reason).toBe("kid_outside_validity_window");
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("test 15: jwksUrl keys without valid_from/valid_to remain unbounded (back-compat)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ keys: [publicJwk] }),
      })
    );

    try {
      const result = await verifyTrustReceipt(validJws, {
        jwksUrl: "https://example.invalid/.well-known/jwks.json",
      });
      expect(result.valid).toBe(true);
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
