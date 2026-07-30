/**
 * Emitter→verifier contract for the enriched v1.0 payload (A4 coupling).
 *
 * The production issuer is adding `schema_version: "1.0"` and `canon: "jcs"` to
 * the signed compact payload, and is making RFC 8785 canonicalization
 * unconditional. Before this change the legacy-compact branch was gated on the
 * payload NOT declaring a `schema_version` at all, so the very first enriched
 * receipt would have fallen through to `schema_invalid`.
 *
 * That is not a cosmetic failure: `receipt-integrity.service.ts` re-verifies
 * every receipt of the last 90 days and feeds the result into the trust score,
 * so the whole new corpus would have scored as broken.
 *
 * The contract pinned here:
 *   - `schema_version` absent OR exactly "1.0" + compact fingerprint ⇒ legacy branch;
 *   - any OTHER declared version (1.1, v1.0-FINAL, future) ⇒ NEVER downgraded;
 *   - `canon: "jcs"` ⇒ `canonicalization: "jcs"`, absence ⇒ "json-stringify-legacy";
 *   - `expires_at` on a compact receipt is INFORMATIVE — never a validity gate
 *     (FR-018: v1.0 must keep verifying for ≥ 7 years).
 */

import { describe, it, expect } from "vitest";
import { CompactSign, exportJWK, generateKeyPair, type JWK } from "jose";
import { verifyTrustReceipt, type PublicJwk } from "../verifier.js";

const KID = "legacy-kid-a4";

async function makeKeys(): Promise<{ pub: PublicJwk; priv: JWK }> {
  const { publicKey, privateKey } = await generateKeyPair("EdDSA", {
    extractable: true,
  });
  const pub = { ...(await exportJWK(publicKey)), kid: KID, alg: "EdDSA" };
  return { pub, priv: await exportJWK(privateKey) };
}

function compactPayload(
  overrides: Record<string, unknown> = {}
): Record<string, unknown> {
  return {
    iss: "merchant:m-legacy",
    sub: "call-legacy-a4",
    iat: Math.floor(Date.now() / 1000),
    callId: "call-legacy-a4",
    merchantId: "m-legacy",
    agentId: "agent-legacy",
    bucket: "checkout",
    tool: "complete_checkout",
    inputHash: "a".repeat(64),
    outputHash: "b".repeat(64),
    outputHashStatus: "captured",
    trust_provider_assertions: [],
    kid: KID,
    ...overrides,
  };
}

async function sign(priv: JWK, payload: unknown): Promise<string> {
  const { importJWK } = await import("jose");
  const key = await importJWK(priv, "EdDSA");
  return new CompactSign(new TextEncoder().encode(JSON.stringify(payload)))
    .setProtectedHeader({ alg: "EdDSA", kid: KID, typ: "trust-receipt+jwt" })
    .sign(key);
}

describe("legacy-compact branch — schema_version tolerance (A4 contract)", () => {
  it("accepts a compact payload that declares schema_version:'1.0'", async () => {
    const { pub, priv } = await makeKeys();
    const jws = await sign(priv, compactPayload({ schema_version: "1.0" }));

    const res = await verifyTrustReceipt(jws, { jwks: [pub] });

    expect(res.valid).toBe(true);
    expect(res.variant).toBe("legacy_compact");
    expect(res.legacyReceipt?.callId).toBe("call-legacy-a4");
  });

  it("accepts the fully enriched payload (schema_version + canon + expires_at)", async () => {
    const { pub, priv } = await makeKeys();
    const now = Math.floor(Date.now() / 1000);
    const jws = await sign(
      priv,
      compactPayload({
        schema_version: "1.0",
        canon: "jcs",
        expires_at: now + 86_400,
      })
    );

    const res = await verifyTrustReceipt(jws, { jwks: [pub] });

    expect(res.valid).toBe(true);
    expect(res.variant).toBe("legacy_compact");
  });

  it("keeps accepting the pre-A4 payload with no schema_version at all", async () => {
    const { pub, priv } = await makeKeys();
    const jws = await sign(priv, compactPayload());

    const res = await verifyTrustReceipt(jws, { jwks: [pub] });

    expect(res.valid).toBe(true);
    expect(res.variant).toBe("legacy_compact");
  });

  it("NEVER downgrades a payload declaring a different schema_version", async () => {
    const { pub, priv } = await makeKeys();
    // Compact fingerprint but claims to be v1.1 — must not be silently
    // reinterpreted as a v1.0 legacy receipt.
    const jws = await sign(priv, compactPayload({ schema_version: "1.1" }));

    const res = await verifyTrustReceipt(jws, { jwks: [pub] });

    expect(res.valid).toBe(false);
    expect(res.reason).toBe("schema_invalid");
  });

  it("NEVER downgrades a payload declaring schema_version:'v1.0-FINAL'", async () => {
    const { pub, priv } = await makeKeys();
    const jws = await sign(
      priv,
      compactPayload({ schema_version: "v1.0-FINAL" })
    );

    const res = await verifyTrustReceipt(jws, { jwks: [pub] });

    expect(res.valid).toBe(false);
    expect(res.reason).toBe("schema_invalid");
  });
});

describe("legacy-compact branch — canonicalization regime", () => {
  it("reports canonicalization:'jcs' when the payload declares canon:'jcs'", async () => {
    const { pub, priv } = await makeKeys();
    const jws = await sign(
      priv,
      compactPayload({ schema_version: "1.0", canon: "jcs" })
    );

    const res = await verifyTrustReceipt(jws, { jwks: [pub] });

    expect(res.canonicalization).toBe("jcs");
  });

  it("reports the legacy regime when canon is absent", async () => {
    const { pub, priv } = await makeKeys();
    const jws = await sign(priv, compactPayload());

    const res = await verifyTrustReceipt(jws, { jwks: [pub] });

    expect(res.canonicalization).toBe("json-stringify-legacy");
  });
});

describe("legacy-compact branch — expires_at is informative, not a gate", () => {
  it("does NOT expire a compact receipt whose expires_at is long past (FR-018)", async () => {
    const { pub, priv } = await makeKeys();
    const now = Math.floor(Date.now() / 1000);
    const jws = await sign(
      priv,
      compactPayload({
        schema_version: "1.0",
        canon: "jcs",
        // Issued and "expired" a year ago — the ≥7-year verification window
        // means this MUST still verify. Enforcing it would collapse
        // receiptIntegrity to ~0 for everything older than 24h.
        iat: now - 365 * 86_400,
        expires_at: now - 364 * 86_400,
      })
    );

    const res = await verifyTrustReceipt(jws, { jwks: [pub] });

    expect(res.valid).toBe(true);
    expect(res.reason).toBeUndefined();
    expect(res.variant).toBe("legacy_compact");
  });
});
