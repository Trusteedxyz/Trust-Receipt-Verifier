/**
 * AIVS proof-bundle export tests (spec-062 US1).
 *
 * Projects a signed TrustReceipt (v1.0 JWS Compact) into an AIVS-compatible
 * proof bundle { manifest_hash, session_sig, audit_log } per draft-stone-aivs-00.
 *
 * Core invariant: the projection is verifiable OFFLINE by a third party with no
 * Trusteed code — manifest_hash is the sha256 of the exact signed payload bytes
 * (recoverable from the JWS), and session_sig is the existing EdDSA signature.
 *
 * Uses a real Ed25519 keypair (no mocks).
 */

import { describe, it, expect, beforeAll } from "vitest";
import { createHash } from "node:crypto";
import { exportJWK, generateKeyPair, type JWK } from "jose";
import { issueTrustReceipt } from "../issuer.js";
import type { IssueOptions } from "../issuer.js";
import {
  exportAivsProofBundle,
  verifyAivsProofBundle,
} from "../aivs-export.js";
import type { PublicJwk } from "../verifier.js";

// ─── Fixtures ─────────────────────────────────────────────────────────────────

const KID = "test-key-2026-06";

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

/** Independent third-party recomputation of the AIVS manifest_hash from a JWS. */
function recomputeManifestHashFromJws(jws: string): string {
  const payloadSegment = jws.split(".")[1];
  const signedBytes = Buffer.from(payloadSegment, "base64url");
  return "sha256:" + createHash("sha256").update(signedBytes).digest("hex");
}

let privateJwk: JWK;
let publicJwk: PublicJwk;
let validJws: string;

beforeAll(async () => {
  const { publicKey, privateKey } = await generateKeyPair("EdDSA", {
    extractable: true,
  });
  privateJwk = await exportJWK(privateKey);
  publicJwk = { ...(await exportJWK(publicKey)), kid: KID, alg: "EdDSA" };

  validJws = await issueTrustReceipt({
    payload: MINIMAL_PAYLOAD,
    privateKeyJwk: privateJwk,
    kid: KID,
    validitySeconds: 3600,
  });
});

// ─── Tests ───────────────────────────────────────────────────────────────────

describe("exportAivsProofBundle", () => {
  it("derives manifest_hash as sha256 of the signed payload bytes and keeps the JWS as session_sig", () => {
    const bundle = exportAivsProofBundle(validJws);

    // session_sig IS the existing EdDSA signature — no re-signing.
    expect(bundle.session_sig).toBe(validJws);

    // manifest_hash matches an independent third-party recomputation,
    // proving it derives from the exact signed bytes (offline-verifiable).
    expect(bundle.manifest_hash).toBe(recomputeManifestHashFromJws(validJws));
    expect(bundle.manifest_hash).toMatch(/^sha256:[0-9a-f]{64}$/);

    // Header provenance for offline key resolution.
    expect(bundle.kid).toBe(KID);
    expect(bundle.alg).toBe("EdDSA");
  });

  it("throws when the input is not a JWS Compact (3 segments)", () => {
    expect(() => exportAivsProofBundle("only.two")).toThrow(
      /not a JWS Compact/
    );
  });
});

describe("verifyAivsProofBundle", () => {
  it("verifies a valid bundle offline against the issuer JWKS", async () => {
    const bundle = exportAivsProofBundle(validJws);

    const result = await verifyAivsProofBundle(bundle, { jwks: [publicJwk] });

    expect(result.valid).toBe(true);
    expect(result.reason).toBeUndefined();
  });

  it("rejects a bundle whose signed payload was tampered but manifest_hash left stale", async () => {
    const bundle = exportAivsProofBundle(validJws);
    const [h, , s] = bundle.session_sig.split(".");
    // Swap in a different payload while keeping the old manifest_hash.
    const forgedPayload = Buffer.from(
      JSON.stringify({ tampered: true }),
      "utf-8"
    ).toString("base64url");
    const tampered = {
      ...bundle,
      session_sig: `${h}.${forgedPayload}.${s}`,
    };

    const result = await verifyAivsProofBundle(tampered, { jwks: [publicJwk] });

    expect(result.valid).toBe(false);
    expect(result.reason).toBe("manifest_hash_mismatch");
  });

  it("rejects a bundle where attacker recomputed manifest_hash but cannot forge the signature", async () => {
    const bundle = exportAivsProofBundle(validJws);
    const [h, , s] = bundle.session_sig.split(".");
    const forgedPayload = Buffer.from(
      JSON.stringify({ tampered: true }),
      "utf-8"
    ).toString("base64url");
    const forgedSig = `${h}.${forgedPayload}.${s}`;
    // Attacker honestly recomputes manifest_hash over the forged payload,
    // passing check 1 — but the EdDSA signature no longer matches.
    const honestHash =
      "sha256:" +
      createHash("sha256")
        .update(Buffer.from(forgedPayload, "base64url"))
        .digest("hex");
    const tampered = {
      ...bundle,
      session_sig: forgedSig,
      manifest_hash: honestHash,
    };

    const result = await verifyAivsProofBundle(tampered, { jwks: [publicJwk] });

    expect(result.valid).toBe(false);
    expect(result.reason).toBe("signature_invalid");
  });

  it("rejects a bundle when no JWKS key matches the kid", async () => {
    const bundle = exportAivsProofBundle(validJws);
    const otherKey = { ...publicJwk, kid: "some-other-kid" };

    const result = await verifyAivsProofBundle(bundle, { jwks: [otherKey] });

    expect(result.valid).toBe(false);
    expect(result.reason).toBe("unknown_kid");
  });

  it("rejects a bundle whose session_sig is not a JWS Compact", async () => {
    const bundle = exportAivsProofBundle(validJws);
    const malformed = { ...bundle, session_sig: "not-a-jws" };

    const result = await verifyAivsProofBundle(malformed, {
      jwks: [publicJwk],
    });

    expect(result.valid).toBe(false);
    expect(result.reason).toBe("malformed_session_sig");
  });
});

describe("exportAivsProofBundle — audit_log (hash_chain_prev projection)", () => {
  const PREV_HEX =
    "9f8e7d6c5b4a3928170615243342516079889796a5b4c3d2e1f00112233445566".slice(
      0,
      64
    );

  it("projects hash_chain_prev as the audit_log prev_hash, linking to entry_hash", async () => {
    const chainedJws = await issueTrustReceipt({
      payload: { ...MINIMAL_PAYLOAD, hash_chain_prev: PREV_HEX },
      privateKeyJwk: privateJwk,
      kid: KID,
      validitySeconds: 3600,
    });

    const bundle = exportAivsProofBundle(chainedJws);

    expect(bundle.audit_log).toHaveLength(1);
    expect(bundle.audit_log[0]).toEqual({
      seq: 0,
      entry_hash: bundle.manifest_hash,
      prev_hash: `sha256:${PREV_HEX}`,
    });
  });

  it("records prev_hash null for a genesis receipt (no hash_chain_prev)", () => {
    const bundle = exportAivsProofBundle(validJws);

    expect(bundle.audit_log).toHaveLength(1);
    expect(bundle.audit_log[0]).toEqual({
      seq: 0,
      entry_hash: bundle.manifest_hash,
      prev_hash: null,
    });
  });
});

// ─── Honest chain declaration (audit F2 remediation) ──────────────────────────
//
// No issuer in this repository writes `hash_chain_prev` (verified by exhaustive
// grep: zero write sites). The projected audit_log is therefore an unlinked
// single entry, and the bundle MUST say so in DATA — not only in prose — so a
// third-party consumer never mistakes it for a real append-only chain.

describe("exportAivsProofBundle — chain_status honesty", () => {
  it("declares chain_status 'unlinked_single_entry' when the receipt carries no hash_chain_prev", () => {
    const bundle = exportAivsProofBundle(validJws);

    expect(bundle.chain_status).toBe("unlinked_single_entry");
    expect(bundle.audit_log[0].prev_hash).toBeNull();
  });

  it("declares chain_status 'linked_single_entry' only when the receipt itself carries hash_chain_prev", async () => {
    const chainedJws = await issueTrustReceipt({
      payload: {
        ...MINIMAL_PAYLOAD,
        hash_chain_prev:
          "9f8e7d6c5b4a3928170615243342516079889796a5b4c3d2e1f001122334455",
      },
      privateKeyJwk: privateJwk,
      kid: KID,
      validitySeconds: 3600,
    });

    const bundle = exportAivsProofBundle(chainedJws);

    expect(bundle.chain_status).toBe("linked_single_entry");
  });

  it("never claims a multi-entry chain: audit_log is always length 1 for a single-receipt bundle", () => {
    const bundle = exportAivsProofBundle(validJws);

    expect(bundle.audit_log).toHaveLength(1);
    expect(bundle.audit_log[0].seq).toBe(0);
  });

  it("round-trips chain_status through offline verification without affecting the verdict", async () => {
    const bundle = exportAivsProofBundle(validJws);

    const result = await verifyAivsProofBundle(bundle, { jwks: [publicJwk] });

    expect(result.valid).toBe(true);
    expect(bundle.chain_status).toBe("unlinked_single_entry");
  });
});
