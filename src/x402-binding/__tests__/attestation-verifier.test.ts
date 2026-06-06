/**
 * Spec 054 T121 — Unit tests for the portable PII attestation verifier.
 *
 * Covers the decision tree of `verifyPiiAttestation`:
 *   - Happy path: signed by merchant root in JWKS → valid:true, matches passes through.
 *   - Tampered signature → valid:false, reason=signature_invalid.
 *   - kid absent from JWKS → valid:false, reason=kid_not_in_jwks.
 *   - Malformed JWS shape / payload → valid:false, reason=malformed_attestation.
 *   - Non-EdDSA alg header → malformed_attestation.
 */

import { describe, expect, it } from "vitest";
import {
  generateKeyPairSync,
  sign as cryptoSign,
  type KeyObject,
} from "node:crypto";
import canonicalize from "canonicalize";

import {
  verifyPiiAttestation,
  type MerchantJwksDocument,
} from "../../index.js";

// ── Helpers ─────────────────────────────────────────────────────────────────

function generateKey(): {
  publicJwk: { kty: "OKP"; crv: "Ed25519"; x: string };
  privateKey: KeyObject;
} {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const jwk = publicKey.export({ format: "jwk" }) as {
    kty: "OKP";
    crv: "Ed25519";
    x: string;
  };
  return { publicJwk: jwk, privateKey };
}

function base64url(buf: Buffer): string {
  return buf.toString("base64url");
}

function buildAttestation(args: {
  kid: string;
  privateKey: KeyObject;
  payload: {
    candidate_digest: string;
    key_version: number;
    matches: boolean;
    expected_hmac_hex: string;
  };
  alg?: string;
}): string {
  const header = { alg: args.alg ?? "EdDSA", kid: args.kid };
  const headerB64 = base64url(Buffer.from(JSON.stringify(header), "utf8"));
  const canonical = canonicalize(args.payload);
  if (typeof canonical !== "string") {
    throw new Error("JCS canonicalisation failed in test helper");
  }
  const payloadB64 = base64url(Buffer.from(canonical, "utf8"));
  const signingInput = `${headerB64}.${payloadB64}`;
  const sig = cryptoSign(
    null,
    Buffer.from(signingInput, "utf8"),
    args.privateKey
  );
  return `${signingInput}.${base64url(sig)}`;
}

function buildJwks(kid: string, x: string): MerchantJwksDocument {
  return {
    keys: [
      {
        kty: "OKP",
        crv: "Ed25519",
        kid,
        use: "sig",
        x,
      },
    ],
  };
}

// ── Tests ───────────────────────────────────────────────────────────────────

describe("verifyPiiAttestation", () => {
  it("happy path: valid signature → valid:true, exposes matches verdict", () => {
    const { publicJwk, privateKey } = generateKey();
    const kid = "merchant-root-test";
    const attestation = buildAttestation({
      kid,
      privateKey,
      payload: {
        candidate_digest: `hmac-sha256:${"a".repeat(64)}`,
        key_version: 1,
        matches: true,
        expected_hmac_hex: `hmac-sha256:${"a".repeat(64)}`,
      },
    });

    const result = verifyPiiAttestation({
      attestationJws: attestation,
      jwks: buildJwks(kid, publicJwk.x),
    });

    expect(result.valid).toBe(true);
    expect(result.matches).toBe(true);
    expect(result.candidateDigest).toBe(`hmac-sha256:${"a".repeat(64)}`);
    expect(result.keyVersion).toBe(1);
  });

  it("matches:false is preserved through the verifier", () => {
    const { publicJwk, privateKey } = generateKey();
    const kid = "merchant-root-test";
    const attestation = buildAttestation({
      kid,
      privateKey,
      payload: {
        candidate_digest: `hmac-sha256:${"b".repeat(64)}`,
        key_version: 2,
        matches: false,
        expected_hmac_hex: `hmac-sha256:${"c".repeat(64)}`,
      },
    });

    const result = verifyPiiAttestation({
      attestationJws: attestation,
      jwks: buildJwks(kid, publicJwk.x),
    });

    expect(result.valid).toBe(true);
    expect(result.matches).toBe(false);
    expect(result.keyVersion).toBe(2);
  });

  it("tampered signature → valid:false, reason=signature_invalid", () => {
    const { publicJwk, privateKey } = generateKey();
    const kid = "merchant-root-test";
    const att = buildAttestation({
      kid,
      privateKey,
      payload: {
        candidate_digest: `hmac-sha256:${"a".repeat(64)}`,
        key_version: 1,
        matches: true,
        expected_hmac_hex: `hmac-sha256:${"a".repeat(64)}`,
      },
    });
    const [h, p, sig] = att.split(".");
    const sigBuf = Buffer.from(sig, "base64url");
    sigBuf[0] = sigBuf[0] ^ 0xff;
    const tampered = `${h}.${p}.${sigBuf.toString("base64url")}`;

    const result = verifyPiiAttestation({
      attestationJws: tampered,
      jwks: buildJwks(kid, publicJwk.x),
    });

    expect(result.valid).toBe(false);
    expect(result.reason).toBe("signature_invalid");
  });

  it("kid not in JWKS → valid:false, reason=kid_not_in_jwks", () => {
    const { privateKey } = generateKey();
    const otherKey = generateKey();
    const att = buildAttestation({
      kid: "ghost-kid",
      privateKey,
      payload: {
        candidate_digest: `hmac-sha256:${"a".repeat(64)}`,
        key_version: 1,
        matches: true,
        expected_hmac_hex: `hmac-sha256:${"a".repeat(64)}`,
      },
    });

    const result = verifyPiiAttestation({
      attestationJws: att,
      jwks: buildJwks("real-kid", otherKey.publicJwk.x),
    });

    expect(result.valid).toBe(false);
    expect(result.reason).toBe("kid_not_in_jwks");
  });

  it("non-EdDSA alg → malformed_attestation", () => {
    const { publicJwk, privateKey } = generateKey();
    const kid = "merchant-root-test";
    const att = buildAttestation({
      kid,
      privateKey,
      alg: "RS256",
      payload: {
        candidate_digest: `hmac-sha256:${"a".repeat(64)}`,
        key_version: 1,
        matches: true,
        expected_hmac_hex: `hmac-sha256:${"a".repeat(64)}`,
      },
    });

    const result = verifyPiiAttestation({
      attestationJws: att,
      jwks: buildJwks(kid, publicJwk.x),
    });

    expect(result.valid).toBe(false);
    expect(result.reason).toBe("malformed_attestation");
  });

  it("malformed JWS shape (2 segments) → malformed_attestation", () => {
    const { publicJwk } = generateKey();
    const result = verifyPiiAttestation({
      attestationJws: "aa.bb",
      jwks: buildJwks("k", publicJwk.x),
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("malformed_attestation");
  });

  it("empty attestation → malformed_attestation", () => {
    const { publicJwk } = generateKey();
    const result = verifyPiiAttestation({
      attestationJws: "",
      jwks: buildJwks("k", publicJwk.x),
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("malformed_attestation");
  });

  it("payload missing required fields → malformed_attestation", () => {
    const { publicJwk, privateKey } = generateKey();
    const kid = "merchant-root-test";
    // Hand-craft a JWS with incomplete payload.
    const header = { alg: "EdDSA", kid };
    const headerB64 = base64url(Buffer.from(JSON.stringify(header), "utf8"));
    const bogus = base64url(Buffer.from(JSON.stringify({ no: "fields" })));
    const sig = cryptoSign(
      null,
      Buffer.from(`${headerB64}.${bogus}`, "utf8"),
      privateKey
    );
    const att = `${headerB64}.${bogus}.${sig.toString("base64url")}`;

    const result = verifyPiiAttestation({
      attestationJws: att,
      jwks: buildJwks(kid, publicJwk.x),
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("malformed_attestation");
  });
});
