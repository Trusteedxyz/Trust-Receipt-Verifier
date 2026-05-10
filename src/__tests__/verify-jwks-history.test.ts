/**
 * Unit tests for `verifyJwksHistorySignature` — closes Codex F1 finding.
 *
 * @see ../verify-jwks-history.ts
 */

import { describe, it, expect } from "vitest";
import { CompactSign, exportJWK } from "jose";
import {
  generateKeyPairSync,
  createPrivateKey,
  type KeyObject,
} from "node:crypto";
import { verifyJwksHistorySignature } from "../verify-jwks-history.js";
import { EMBEDDED_ISSUER_ROOTS } from "../embedded-issuer-root.js";
import type { IssuerRootEntry } from "../embedded-issuer-root.js";
import type { SignedJwksHistory } from "../types-1.1.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

interface TestKey {
  publicPem: string;
  privateKey: KeyObject;
}

function makeEd25519TestKey(): TestKey {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    publicPem: publicKey.export({ type: "spki", format: "pem" }) as string,
    privateKey,
  };
}

function makeRootEntry(pem: string): IssuerRootEntry {
  return {
    pem,
    sha256: "0".repeat(64),
    validFrom: 0,
    validTo: null,
    verifierMinVersion: "test",
  };
}

async function signHistoryPayload(
  privateKey: KeyObject,
  payload: object
): Promise<string> {
  const bytes = new TextEncoder().encode(JSON.stringify(payload));
  return await new CompactSign(bytes)
    .setProtectedHeader({ alg: "EdDSA" })
    .sign(privateKey);
}

const samplePayload = {
  schema_version: "1.0",
  entries: [
    {
      kid: "kid-001",
      jwk_pub: { kty: "OKP", crv: "Ed25519", x: "abc" },
      valid_from: 1_700_000_000,
      valid_to: null,
    },
  ],
  history_chain_sha256: "0".repeat(64),
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("verifyJwksHistorySignature", () => {
  it("accepts a valid Ed25519-signed history with the matching root", async () => {
    const { publicPem, privateKey } = makeEd25519TestKey();
    const jws = await signHistoryPayload(privateKey, samplePayload);
    const signed: SignedJwksHistory = {
      jws_compact: jws,
      signed_by_root_sha256: "0".repeat(64),
    };
    const result = await verifyJwksHistorySignature(
      signed,
      makeRootEntry(publicPem)
    );
    expect(result.valid).toBe(true);
    expect(result.payload?.entries[0]?.kid).toBe("kid-001");
  });

  it("rejects a tampered payload", async () => {
    const { publicPem, privateKey } = makeEd25519TestKey();
    const jws = await signHistoryPayload(privateKey, samplePayload);
    const parts = jws.split(".");
    // Substitute a different valid base64url payload — sig will not match.
    const tamperedPayload = Buffer.from(
      JSON.stringify({ ...samplePayload, history_chain_sha256: "1".repeat(64) })
    ).toString("base64url");
    const tamperedJws = `${parts[0]}.${tamperedPayload}.${parts[2]}`;
    const result = await verifyJwksHistorySignature(
      { jws_compact: tamperedJws, signed_by_root_sha256: "0".repeat(64) },
      makeRootEntry(publicPem)
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("signature_invalid");
  });

  it("rejects a signature made under a different keypair", async () => {
    const attacker = makeEd25519TestKey();
    const victim = makeEd25519TestKey();
    const jws = await signHistoryPayload(attacker.privateKey, samplePayload);
    const result = await verifyJwksHistorySignature(
      { jws_compact: jws, signed_by_root_sha256: "0".repeat(64) },
      makeRootEntry(victim.publicPem)
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("signature_invalid");
  });

  it("rejects a malformed JWS (wrong segment count)", async () => {
    const { publicPem } = makeEd25519TestKey();
    const result = await verifyJwksHistorySignature(
      { jws_compact: "only.two", signed_by_root_sha256: "0".repeat(64) },
      makeRootEntry(publicPem)
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("malformed_jws");
  });

  it("returns embedded_root_not_production for the staging stub root", async () => {
    const { privateKey } = makeEd25519TestKey();
    const jws = await signHistoryPayload(privateKey, samplePayload);
    const stagingRoot = EMBEDDED_ISSUER_ROOTS[0];
    expect(stagingRoot).toBeDefined();
    if (!stagingRoot) throw new Error("missing staging root");
    const result = await verifyJwksHistorySignature(
      { jws_compact: jws, signed_by_root_sha256: stagingRoot.sha256 },
      stagingRoot
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("embedded_root_not_production");
  });

  it("rejects an unsupported alg header", async () => {
    // Hand-roll a JWS with alg: RS256 to trigger the alg gate. Signature
    // bytes are arbitrary — the alg check fires before crypto.
    const header = Buffer.from(JSON.stringify({ alg: "RS256" })).toString(
      "base64url"
    );
    const payload = Buffer.from(JSON.stringify(samplePayload)).toString(
      "base64url"
    );
    const fakeSig = Buffer.from("xx").toString("base64url");
    const { publicPem } = makeEd25519TestKey();
    const result = await verifyJwksHistorySignature(
      {
        jws_compact: `${header}.${payload}.${fakeSig}`,
        signed_by_root_sha256: "0".repeat(64),
      },
      makeRootEntry(publicPem)
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("unsupported_alg");
  });

  it("rejects a payload that is not a JSON object with entries[]", async () => {
    const { publicPem, privateKey } = makeEd25519TestKey();
    const bytes = new TextEncoder().encode(JSON.stringify({ no: "entries" }));
    const jws = await new CompactSign(bytes)
      .setProtectedHeader({ alg: "EdDSA" })
      .sign(privateKey);
    const result = await verifyJwksHistorySignature(
      { jws_compact: jws, signed_by_root_sha256: "0".repeat(64) },
      makeRootEntry(publicPem)
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("payload_invalid");
  });
});

// Silence unused-import on createPrivateKey/exportJWK if tree-shaken.
void createPrivateKey;
void exportJWK;
