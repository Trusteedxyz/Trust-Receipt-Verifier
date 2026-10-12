/**
 * The verifier accepts v1.1 receipts signed with ES256 and derives the
 * algorithm from the KEY in the signed history, never from the header.
 *
 * The body of vector `011-buyer-agent-happy-path` (valid against the schema)
 * is re-signed with a real P-256 key, the way a KMS would: ECDSA over the
 * SHA-256 of the JWS signing input, encoded as `R||S`.
 */
import { generateKeyPairSync, sign as nodeSign } from "node:crypto";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, it, expect } from "vitest";

import { verifyReceiptEnvelope } from "../verify-1.1.js";
import type { VerifyOptions } from "../verify-1.1.js";
import type { SignedJwksHistory } from "../types-1.1.js";
import { expectedAlgForJwk } from "../verify-1.1-helpers.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const VECTOR = JSON.parse(
  readFileSync(
    join(
      __dirname,
      "..",
      "..",
      "test-vectors",
      "v11",
      "011-buyer-agent-happy-path.json"
    ),
    "utf8"
  )
) as {
  envelope: { receipt: string } & Record<string, unknown>;
  verify_options: { currentTime: number; tsa_root_pins: string[] };
};

const KID = "p256-test-kid";
const p256 = generateKeyPairSync("ec", { namedCurve: "P-256" });
const otherP256 = generateKeyPairSync("ec", { namedCurve: "P-256" });
const ed = generateKeyPairSync("ed25519");

const ecJwk = { ...p256.publicKey.export({ format: "jwk" }), kid: KID };
const okpJwk = { ...ed.publicKey.export({ format: "jwk" }), kid: KID };

const b64 = (b: Buffer | string): string =>
  Buffer.from(b).toString("base64url");

/** The vector's signed body, unchanged. */
const BODY_B64 = VECTOR.envelope.receipt.split(".")[1]!;

/** Signs `header.body` with a P-256 key (ES256, 64-byte R||S). */
function signEs256(
  header: Record<string, unknown>,
  key = p256.privateKey
): string {
  const input = `${b64(JSON.stringify(header))}.${BODY_B64}`;
  const sig = nodeSign("sha256", Buffer.from(input), {
    key,
    dsaEncoding: "ieee-p1363",
  });
  return `${input}.${b64(sig)}`;
}

/** Signs `header.body` with an Ed25519 key (EdDSA). */
function signEdDsa(header: Record<string, unknown>): string {
  const input = `${b64(JSON.stringify(header))}.${BODY_B64}`;
  return `${input}.${b64(nodeSign(null, Buffer.from(input), ed.privateKey))}`;
}

function history(jwk: Record<string, unknown>): SignedJwksHistory {
  const t = VECTOR.verify_options.currentTime;
  const payload = {
    schema_version: "1.0",
    entries: [
      { kid: KID, jwk_pub: jwk, valid_from: t - 86_400 * 365, valid_to: null },
    ],
    history_chain_sha256: "0".repeat(64),
  };
  return {
    jws_compact: `${b64(JSON.stringify({ alg: "EdDSA" }))}.${b64(JSON.stringify(payload))}.AA`,
    signed_by_root_sha256: "0".repeat(64),
  };
}

function options(jwk: Record<string, unknown>): VerifyOptions {
  return {
    jwksHistory: history(jwk),
    trustAnchorPemSha256:
      "dd43bf2cd65023d79e41358226ed1197fcea36bc693f1c0fadde0e318bfd76a1",
    policyOidAllowlist: ["1.2.3.4.5.6.7.8.9"],
    expectedSubject: "buyer_agent",
    allowStagingRoots: true,
    currentTimeSeconds: VECTOR.verify_options.currentTime,
    tsaRootCertSha256Allowlist: VECTOR.verify_options.tsa_root_pins,
  };
}

async function verify(receipt: string, jwk: Record<string, unknown>) {
  return verifyReceiptEnvelope(
    { ...VECTOR.envelope, receipt } as unknown as Parameters<
      typeof verifyReceiptEnvelope
    >[0],
    options(jwk)
  );
}

/**
 * The first check AFTER the signature that a re-signed receipt cannot satisfy:
 * the vector's RFC 3161 timestamp is bound to the original Ed25519 JWS. A
 * verdict that reaches this point proves the signature and its algorithm
 * passed. An end-to-end `accepted` for ES256 needs a vector whose timestamp
 * was issued over the ES256 JWS (pending: ES256 conformance vectors).
 */
const PAST_SIGNATURE = "tsa_imprint_mismatch";

describe("expectedAlgForJwk", () => {
  it("derives alg from the key type and rejects the rest", () => {
    expect(expectedAlgForJwk({ kty: "OKP", crv: "Ed25519" })).toBe("EdDSA");
    expect(expectedAlgForJwk({ kty: "EC", crv: "P-256" })).toBe("ES256");
    expect(expectedAlgForJwk({ kty: "EC", crv: "P-384" })).toBeNull();
    expect(expectedAlgForJwk({ kty: "RSA" })).toBeNull();
    expect(expectedAlgForJwk({ kty: "oct" })).toBeNull();
  });

  it("a JWK declaring an alg that does not match its type is rejected", () => {
    expect(
      expectedAlgForJwk({ kty: "EC", crv: "P-256", alg: "EdDSA" })
    ).toBeNull();
    expect(expectedAlgForJwk({ kty: "EC", crv: "P-256", alg: "ES256" })).toBe(
      "ES256"
    );
  });
});

describe("verifyReceiptEnvelope with ES256", () => {
  it("a receipt signed with ES256 by the history's P-256 key passes the signature check", async () => {
    const result = await verify(
      signEs256({ alg: "ES256", kid: KID, typ: "trust-receipt+jwt" }),
      ecJwk
    );
    expect(result.errorCode).toBe(PAST_SIGNATURE);
  });

  it("ES256 with a different P-256 key -> jws_signature_invalid", async () => {
    const result = await verify(
      signEs256({ alg: "ES256", kid: KID }, otherP256.privateKey),
      ecJwk
    );
    expect(result.outcome).toBe("rejected");
    expect(result.errorCode).toBe("jws_signature_invalid");
  });

  it("EdDSA header against a P-256 key -> jws_invalid (the header cannot choose the alg)", async () => {
    const result = await verify(signEdDsa({ alg: "EdDSA", kid: KID }), ecJwk);
    expect(result.outcome).toBe("rejected");
    expect(result.errorCode).toBe("jws_invalid");
  });

  it("ES256 header against an Ed25519 key -> jws_invalid", async () => {
    const result = await verify(signEs256({ alg: "ES256", kid: KID }), okpJwk);
    expect(result.outcome).toBe("rejected");
    expect(result.errorCode).toBe("jws_invalid");
  });

  it("a P-256 JWK that declares EdDSA -> jws_invalid", async () => {
    const result = await verify(signEs256({ alg: "ES256", kid: KID }), {
      ...ecJwk,
      alg: "EdDSA",
    });
    expect(result.outcome).toBe("rejected");
    expect(result.errorCode).toBe("jws_invalid");
  });

  it.each(["HS256", "ES384", "none"])(
    "header %s -> jws_invalid",
    async (alg) => {
      const result = await verify(signEs256({ alg, kid: KID }), ecJwk);
      expect(result.outcome).toBe("rejected");
      expect(result.errorCode).toBe("jws_invalid");
    }
  );

  it("Ed25519 still passes the signature check as before", async () => {
    const result = await verify(
      signEdDsa({ alg: "EdDSA", kid: KID, typ: "trust-receipt+jwt" }),
      okpJwk
    );
    expect(result.errorCode).toBe(PAST_SIGNATURE);
  });
});
