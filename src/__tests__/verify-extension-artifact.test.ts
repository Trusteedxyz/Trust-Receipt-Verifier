/**
 * Tests for the extension artifact verifier (erasure receipts +
 * extension manifests). Uses real Ed25519 keypairs generated in beforeAll; no
 * network mocks — JWKS is always passed inline.
 */

import { describe, it, expect, beforeAll } from "vitest";
import {
  exportJWK,
  generateKeyPair,
  CompactSign,
  importJWK,
  type JWK,
} from "jose";
import { verifyExtensionArtifact } from "../verify-extension-artifact.js";
import type { PublicJwk } from "../verify-extension-artifact.js";

const KID = "ext-dev-key-2026-05-16";

const ERASURE_PAYLOAD = {
  install_id: "install_01HZK000000000000000000000",
  deleted_at: "2026-05-16T10:00:00Z",
  signed_by: { kid: KID },
  evidence_url: "https://example.com/audit/2026/05/16/install_01HZK.txt",
  record_count_destroyed: 1234,
};

const MANIFEST_PAYLOAD = {
  schema_version: "1.0",
  name: "Acme Slack Notifier",
  vendor: "acme-corp",
  version: "1.2.3",
  description:
    "Sends a Slack message when an agentic checkout completes for the merchant.",
  scopes_requested: ["events:subscribe:checkout", "extension_config:write"],
  endpoints: [
    {
      kind: "webhook_receiver",
      url: "https://hooks.acme.example/trusteed",
      region: "EU",
    },
  ],
  event_subscriptions: ["checkout.completed"],
  pricing_model: { type: "flat_monthly", price_usd_cents: 1900 },
  data_retention_days: 30,
  supported_regions: ["EU", "US"],
  support_url: "https://acme.example/support",
  privacy_policy_url: "https://acme.example/privacy",
  terms_url: "https://acme.example/terms",
  risk_category: "low",
  changelog: "Initial public release. No prior versions.",
};

let publicJwk: PublicJwk;
let privateJwk: JWK;
let wrongPrivateJwk: JWK;

async function signJws(
  payload: unknown,
  key: JWK,
  kid: string
): Promise<string> {
  const privateKey = await importJWK(key, "EdDSA");
  return new CompactSign(new TextEncoder().encode(JSON.stringify(payload)))
    .setProtectedHeader({ alg: "EdDSA", kid })
    .sign(privateKey);
}

beforeAll(async () => {
  const { publicKey, privateKey } = await generateKeyPair("EdDSA", {
    extractable: true,
  });
  publicJwk = { ...(await exportJWK(publicKey)), kid: KID, alg: "EdDSA" };
  privateJwk = await exportJWK(privateKey);

  const { privateKey: wrongPrivate } = await generateKeyPair("EdDSA", {
    extractable: true,
  });
  wrongPrivateJwk = await exportJWK(wrongPrivate);
});

describe("verifyExtensionArtifact — erasure receipts", () => {
  it("verifies a valid erasure receipt", async () => {
    const jws = await signJws(ERASURE_PAYLOAD, privateJwk, KID);
    const result = await verifyExtensionArtifact(jws, {
      kind: "erasure",
      jwks: [publicJwk],
    });

    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.kid).toBe(KID);
      expect(result.payload.install_id).toBe(ERASURE_PAYLOAD.install_id);
    }
  });

  it("rejects erasure signed with a different key", async () => {
    const jws = await signJws(ERASURE_PAYLOAD, wrongPrivateJwk, KID);
    const result = await verifyExtensionArtifact(jws, {
      kind: "erasure",
      jwks: [publicJwk],
    });

    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reason).toBe("signature_invalid");
  });

  it("rejects erasure with kid not present in the JWKS", async () => {
    const jws = await signJws(ERASURE_PAYLOAD, privateJwk, "unknown-kid");
    const result = await verifyExtensionArtifact(jws, {
      kind: "erasure",
      jwks: [publicJwk],
    });

    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reason).toBe("kid_not_found");
  });

  it("rejects erasure missing required deleted_at field", async () => {
    const bad = { ...ERASURE_PAYLOAD };
    delete (bad as Record<string, unknown>).deleted_at;
    const jws = await signJws(bad, privateJwk, KID);
    const result = await verifyExtensionArtifact(jws, {
      kind: "erasure",
      jwks: [publicJwk],
    });

    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.reason).toBe("shape_invalid");
      expect(result.detail).toContain("deleted_at");
    }
  });

  it("rejects erasure with non-string install_id", async () => {
    const bad = { ...ERASURE_PAYLOAD, install_id: 12345 };
    const jws = await signJws(bad, privateJwk, KID);
    const result = await verifyExtensionArtifact(jws, {
      kind: "erasure",
      jwks: [publicJwk],
    });

    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reason).toBe("shape_invalid");
  });

  it("rejects malformed JWS (not three segments)", async () => {
    const result = await verifyExtensionArtifact("not.a.jws.string.too-many", {
      kind: "erasure",
      jwks: [publicJwk],
    });

    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reason).toBe("malformed_jws");
  });
});

describe("verifyExtensionArtifact — extension manifests", () => {
  it("verifies a valid manifest", async () => {
    const jws = await signJws(MANIFEST_PAYLOAD, privateJwk, KID);
    const result = await verifyExtensionArtifact(jws, {
      kind: "manifest",
      jwks: [publicJwk],
    });

    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.kid).toBe(KID);
      expect(result.payload.vendor).toBe("acme-corp");
    }
  });

  it("rejects manifest with missing scopes_requested", async () => {
    const bad: Record<string, unknown> = { ...MANIFEST_PAYLOAD };
    delete bad.scopes_requested;
    const jws = await signJws(bad, privateJwk, KID);
    const result = await verifyExtensionArtifact(jws, {
      kind: "manifest",
      jwks: [publicJwk],
    });

    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.reason).toBe("shape_invalid");
      expect(result.detail).toContain("scopes_requested");
    }
  });

  it("rejects manifest where supported_regions is a string instead of array", async () => {
    const bad = { ...MANIFEST_PAYLOAD, supported_regions: "EU" };
    const jws = await signJws(bad, privateJwk, KID);
    const result = await verifyExtensionArtifact(jws, {
      kind: "manifest",
      jwks: [publicJwk],
    });

    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.reason).toBe("shape_invalid");
      expect(result.detail).toContain("supported_regions");
    }
  });

  it("rejects manifest with non-EdDSA algorithm", async () => {
    // Use jose to forge a JWS with an unsupported alg header
    const { CompactSign: SignAgain } = await import("jose");
    const { generateKeyPair: gen } = await import("jose");
    const { privateKey } = await gen("ES256", { extractable: true });
    const jws = await new SignAgain(
      new TextEncoder().encode(JSON.stringify(MANIFEST_PAYLOAD))
    )
      .setProtectedHeader({ alg: "ES256", kid: KID })
      .sign(privateKey);

    const result = await verifyExtensionArtifact(jws, {
      kind: "manifest",
      jwks: [publicJwk],
    });

    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reason).toBe("unsupported_alg");
  });

  it("rejects manifest with missing kid in JWS header", async () => {
    const privateKey = await importJWK(privateJwk, "EdDSA");
    const jws = await new CompactSign(
      new TextEncoder().encode(JSON.stringify(MANIFEST_PAYLOAD))
    )
      .setProtectedHeader({ alg: "EdDSA" })
      .sign(privateKey);

    const result = await verifyExtensionArtifact(jws, {
      kind: "manifest",
      jwks: [publicJwk],
    });

    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reason).toBe("missing_kid");
  });

  it("reports jwks_unreachable when no JWKS is supplied", async () => {
    const jws = await signJws(MANIFEST_PAYLOAD, privateJwk, KID);
    const result = await verifyExtensionArtifact(jws, { kind: "manifest" });

    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reason).toBe("jwks_unreachable");
  });
});
