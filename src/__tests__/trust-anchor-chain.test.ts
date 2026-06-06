/**
 * Spec-049 T424 — trust-anchor chain validation tests.
 *
 * Companion to `trust-anchor.test.ts` (which exercises EMBEDDED_ISSUER_ROOTS
 * structural invariants). This file covers the chain-validation primitive
 * `validateChain()` and exercises a forged-JWKS rejection path with a
 * synthetic Ed25519 keypair generated per-test (no real T420 ceremony key).
 *
 * Coverage matrix:
 *   (a) receipt valid under bundled history (mock root key fixture).
 *   (b) receipt rejected when bundle includes forged JWKS not signed by
 *       root (the structural check at this layer is `kid_not_in_history`
 *       OR `history_root_kid_mismatch`; cryptographic JWS-signature
 *       rejection lives in `verify-jwks-history.test.ts`).
 *   (c) staging-stub embedded root fail-closes with `root_key_not_provisioned`.
 *
 * @see ../embedded-issuer-root.ts validateChain
 * @see ../verify-jwks-history.ts verifyJwksHistorySignature (signature-level)
 */

import { describe, it, expect } from "vitest";
import { generateKeyPairSync, createHash } from "node:crypto";
import {
  validateChain,
  getActiveIssuerRoot,
  type IssuerRootEntry,
} from "../embedded-issuer-root.js";

/**
 * Build a synthetic non-staging IssuerRootEntry. The PEM content is structural
 * only — `validateChain` only inspects `pem` for the `(STAGING)` marker and
 * `sha256` for cross-comparison; this fixture intentionally OMITS the marker
 * to exercise the post-T420 happy path.
 */
function buildSyntheticRoot(): IssuerRootEntry {
  const { publicKey } = generateKeyPairSync("ed25519");
  const pemBody = publicKey.export({ type: "spki", format: "pem" }).toString();
  // Replace BEGIN PUBLIC KEY with BEGIN CERTIFICATE so the structural check
  // in `embedded-issuer-root.ts` (PEM block markers) holds, and ensure it
  // does NOT contain "(STAGING)" — that's the fail-closed marker.
  const pem = pemBody
    .replace("PUBLIC KEY", "CERTIFICATE")
    .replace("PUBLIC KEY", "CERTIFICATE");
  const sha256 = createHash("sha256").update(pem).digest("hex");
  return {
    pem,
    sha256,
    validFrom: Math.floor(Date.now() / 1000) - 86400,
    validTo: null,
    verifierMinVersion: "0.2.0",
  };
}

describe("validateChain — staging-stub fail-closed", () => {
  it("rejects with root_key_not_provisioned when active root is the staging stub", () => {
    const stub = getActiveIssuerRoot();
    // The "(STAGING)" marker lives inside the X.509 subject CN field — i.e.,
    // in the base64-decoded body, NOT in the raw PEM text.
    const decodedBody = Buffer.from(
      stub.pem
        .replace(/-----BEGIN [^-]+-----/g, "")
        .replace(/-----END [^-]+-----/g, "")
        .replace(/\s+/g, ""),
      "base64"
    ).toString("binary");
    expect(decodedBody).toContain("(STAGING)");
    const history = {
      entries: [{ kid: "any-kid" }],
      signed_by_root_sha256: stub.sha256,
    };
    const result = validateChain("any-kid", history, stub);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("root_key_not_provisioned");
  });
});

describe("validateChain — synthetic non-staging root", () => {
  it("(a) accepts when receipt kid is in history and signed_by_root_sha256 matches", () => {
    const root = buildSyntheticRoot();
    const history = {
      entries: [{ kid: "op-kid-1" }, { kid: "op-kid-2" }],
      signed_by_root_sha256: root.sha256,
    };
    const result = validateChain("op-kid-2", history, root);
    expect(result.valid).toBe(true);
    expect(result.reason).toBeUndefined();
  });

  it("(b1) rejects with kid_not_in_history when receipt kid is absent", () => {
    const root = buildSyntheticRoot();
    const history = {
      entries: [{ kid: "op-kid-1" }],
      signed_by_root_sha256: root.sha256,
    };
    const result = validateChain("forged-kid", history, root);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("kid_not_in_history");
  });

  it("(b2) rejects with history_root_kid_mismatch when forged history claims a different root", () => {
    const root = buildSyntheticRoot();
    const forgedRoot = buildSyntheticRoot();
    expect(forgedRoot.sha256).not.toBe(root.sha256);
    const history = {
      entries: [{ kid: "op-kid-1" }],
      // Attacker bundles a JWKS history claiming to be signed by a DIFFERENT
      // root than the verifier-embedded one.
      signed_by_root_sha256: forgedRoot.sha256,
    };
    const result = validateChain("op-kid-1", history, root);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("history_root_kid_mismatch");
  });

  it("accepts when signed_by_root_sha256 is omitted (cryptographic check defers to verify-jwks-history)", () => {
    const root = buildSyntheticRoot();
    const history = {
      entries: [{ kid: "op-kid-1" }],
      // Field intentionally omitted — structural validateChain does not
      // require it; signature-level verification is the authoritative gate.
    };
    const result = validateChain("op-kid-1", history, root);
    expect(result.valid).toBe(true);
  });

  it("case-insensitive sha256 comparison", () => {
    const root = buildSyntheticRoot();
    const history = {
      entries: [{ kid: "op-kid-1" }],
      signed_by_root_sha256: root.sha256.toUpperCase(),
    };
    const result = validateChain("op-kid-1", history, root);
    expect(result.valid).toBe(true);
  });
});
