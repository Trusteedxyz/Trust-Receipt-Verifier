import { describe, it, expect } from "vitest";
import { CompactSign, exportJWK, generateKeyPair, type JWK } from "jose";
import { verifyTrustReceipt, type PublicJwk } from "../verifier.js";

const KID = "kid-legacy-fields";

async function makeKeys(): Promise<{ pub: PublicJwk; priv: JWK }> {
  const { publicKey, privateKey } = await generateKeyPair("EdDSA", {
    extractable: true,
  });
  return {
    pub: { ...(await exportJWK(publicKey)), kid: KID, alg: "EdDSA" },
    priv: await exportJWK(privateKey),
  };
}

/**
 * Enriched legacy fields must survive Zod. `TrustReceiptLegacyCompactSchema` is a
 * non-strict `z.object`, so undeclared keys are ACCEPTED but STRIPPED — the
 * enriched fields never reached `VerifyResult.legacyReceipt`, making the whole
 * enrichment invisible through the internal verifier's public type.
 */
describe("legacy-compact schema — enriched v1.0 fields survive parsing", () => {
  it("exposes every enriched field on legacyReceipt", async () => {
    const { pub, priv } = await makeKeys();
    const now = Math.floor(Date.now() / 1000);
    const payload = {
      iss: "merchant:m",
      sub: "c1",
      iat: now,
      callId: "c1",
      merchantId: "m",
      agentId: "a",
      bucket: "checkout",
      tool: "complete_checkout",
      inputHash: "a".repeat(64),
      outputHash: "b".repeat(64),
      outputHashStatus: "captured",
      trust_provider_assertions: [],
      kid: KID,
      // Enriched fields:
      schema_version: "1.0",
      canon: "jcs",
      expires_at: now + 86400,
      protocol: "MCP",
      policy_decision: "allow",
      amount: "12.34",
      currency: "EUR",
      checkout_session_id: "cs_1",
      outcome: "SUCCESS",
    };
    const { importJWK } = await import("jose");
    const key = await importJWK(priv, "EdDSA");
    const jws = await new CompactSign(
      new TextEncoder().encode(JSON.stringify(payload))
    )
      .setProtectedHeader({ alg: "EdDSA", kid: KID, typ: "trust-receipt+jwt" })
      .sign(key);

    const res = await verifyTrustReceipt(jws, { jwks: [pub] });

    expect(res.valid).toBe(true);
    const r = res.legacyReceipt as Record<string, unknown> | undefined;
    expect(r?.schema_version).toBe("1.0");
    expect(r?.canon).toBe("jcs");
    expect(r?.expires_at).toBe(now + 86400);
    expect(r?.protocol).toBe("MCP");
    expect(r?.policy_decision).toBe("allow");
    expect(r?.amount).toBe("12.34");
    expect(r?.currency).toBe("EUR");
    expect(r?.checkout_session_id).toBe("cs_1");
    expect(r?.outcome).toBe("SUCCESS");
  });

  // The real issuer signs `amount` as an INTEGER in minor units (`4999`), not
  // as a string. The case above uses `"12.34"`, which nobody emits, so a
  // `z.string()` schema passed the tests while rejecting every real v1.0
  // receipt that carries an amount with `schema_invalid`. Bytes that are
  // already signed cannot be rewritten: the verifier has to accept what was
  // actually issued.
  it("verifies the amount as the issuer really signs it (integer minor units)", async () => {
    const { pub, priv } = await makeKeys();
    const now = Math.floor(Date.now() / 1000);
    const payload = {
      iss: "merchant:m",
      sub: "c1",
      iat: now,
      callId: "c1",
      merchantId: "m",
      agentId: "a",
      bucket: "checkout",
      tool: "complete_checkout",
      inputHash: "a".repeat(64),
      outputHash: "b".repeat(64),
      outputHashStatus: "captured",
      trust_provider_assertions: [],
      kid: KID,
      schema_version: "1.0",
      canon: "jcs",
      expires_at: now + 86400,
      amount: 4999,
      currency: "EUR",
    };
    const { importJWK } = await import("jose");
    const key = await importJWK(priv, "EdDSA");
    const jws = await new CompactSign(
      new TextEncoder().encode(JSON.stringify(payload))
    )
      .setProtectedHeader({ alg: "EdDSA", kid: KID, typ: "trust-receipt+jwt" })
      .sign(key);

    const res = await verifyTrustReceipt(jws, { jwks: [pub] });
    expect(res.valid).toBe(true);
    expect(res.legacyReceipt?.amount).toBe(4999);
  });

  it("still verifies the historic payload that carries none of them", async () => {
    const { pub, priv } = await makeKeys();
    const payload = {
      iss: "merchant:m",
      sub: "c1",
      iat: Math.floor(Date.now() / 1000),
      callId: "c1",
      merchantId: "m",
      agentId: "a",
      bucket: "checkout",
      tool: "t",
      inputHash: "a".repeat(64),
      outputHash: "b".repeat(64),
      kid: KID,
    };
    const { importJWK } = await import("jose");
    const key = await importJWK(priv, "EdDSA");
    const jws = await new CompactSign(
      new TextEncoder().encode(JSON.stringify(payload))
    )
      .setProtectedHeader({ alg: "EdDSA", kid: KID, typ: "trust-receipt+jwt" })
      .sign(key);

    const res = await verifyTrustReceipt(jws, { jwks: [pub] });
    expect(res.valid).toBe(true);
    expect(res.legacyReceipt?.callId).toBe("c1");
  });
});
