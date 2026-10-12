/**
 * `verifyReceiptV10` used to reject EVERY real v1.0 receipt. Issuers emit the
 * compact form (`legacy_compact`), which `verifyTrustReceipt` validates and
 * returns in `legacyReceipt`, not in `receipt`; the wrapper only accepted
 * `receipt` and returned `rejected` with `errors: []`.
 */
import { describe, expect, it } from "vitest";
import { CompactSign, exportJWK, generateKeyPair } from "jose";
import { verifyReceiptV10 } from "../verify-1.0.js";

const KID = "kid-legacy-compact";

async function compactReceipt(payloadExtra: Record<string, unknown> = {}) {
  const { publicKey, privateKey } = await generateKeyPair("EdDSA", {
    extractable: true,
  });
  const pub = { ...(await exportJWK(publicKey)), kid: KID, alg: "EdDSA" };
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
    policy_decision: "allow",
    amount: 4999,
    currency: "EUR",
    outcome: "SUCCESS",
    ...payloadExtra,
  };
  const jws = await new CompactSign(
    new TextEncoder().encode(JSON.stringify(payload))
  )
    .setProtectedHeader({ alg: "EdDSA", kid: KID })
    .sign(privateKey);
  return { jws, jwks: { keys: [pub] } };
}

describe("verifyReceiptV10 with the compact form issuers emit", () => {
  it("accepts it and returns the receipt", async () => {
    const { jws, jwks } = await compactReceipt();
    const r = await verifyReceiptV10(jws, jwks);
    expect(r.outcome).toBe("accepted");
    expect((r.receipt as Record<string, unknown>)["amount"]).toBe(4999);
  });

  it("a rejection never comes back with an empty errors list", async () => {
    const { jws } = await compactReceipt();
    const other = await compactReceipt();
    const r = await verifyReceiptV10(jws, other.jwks);
    expect(r.outcome).toBe("rejected");
    expect((r.errors ?? []).length).toBeGreaterThan(0);
  });
});
