/**
 * Deterministic Ed25519 keypair derivation for T065 vector generation.
 *
 * Uses Node's `createPrivateKey` with raw 32-byte seed wrapped in the
 * PKCS#8 prefix for OID 1.3.101.112 (Ed25519). Same seed → same key bytes →
 * same JWK `d`/`x` fields → byte-identical signed JWS payload.
 */
import { createPrivateKey, createPublicKey, type KeyObject } from "node:crypto";

/** PKCS#8 prefix for Ed25519 (16 bytes), followed by 32 raw seed bytes. */
const ED25519_PKCS8_PREFIX = Buffer.from(
  "302e020100300506032b657004220420",
  "hex"
);

export interface TestKeyPair {
  jwkPriv: { kty: "OKP"; crv: "Ed25519"; d: string; x: string; kid: string };
  jwkPub: { kty: "OKP"; crv: "Ed25519"; x: string; kid: string };
  privateKey: KeyObject;
  publicKey: KeyObject;
  kid: string;
}

function toBase64Url(buf: Buffer | Uint8Array): string {
  return Buffer.from(buf)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

export function buildTestKeyPair(seed: Uint8Array, kid: string): TestKeyPair {
  if (seed.length !== 32) {
    throw new Error(
      `buildTestKeyPair: Ed25519 seed MUST be 32 bytes, got ${seed.length}`
    );
  }
  const pkcs8 = Buffer.concat([ED25519_PKCS8_PREFIX, Buffer.from(seed)]);
  const privateKey = createPrivateKey({
    key: pkcs8,
    format: "der",
    type: "pkcs8",
  });
  const publicKey = createPublicKey(privateKey);

  const privJwkRaw = privateKey.export({ format: "jwk" }) as Record<
    string,
    string
  >;
  const pubJwkRaw = publicKey.export({ format: "jwk" }) as Record<
    string,
    string
  >;

  const x = pubJwkRaw["x"];
  const d = privJwkRaw["d"];
  if (typeof x !== "string" || typeof d !== "string") {
    throw new Error("buildTestKeyPair: failed to extract Ed25519 JWK fields");
  }

  return {
    jwkPriv: { kty: "OKP", crv: "Ed25519", d, x, kid },
    jwkPub: { kty: "OKP", crv: "Ed25519", x, kid },
    privateKey,
    publicKey,
    kid,
  };
}

/** Compute a deterministic 64-hex SHA-256 over the JWKS document (sorted keys). */
export { toBase64Url };
