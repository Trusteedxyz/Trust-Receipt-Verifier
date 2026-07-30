/**
 * AIVS reference verifier e2e (spec-062 SC-001).
 *
 * Proves the AIVS thesis end-to-end: a proof bundle produced by the internal
 * export (`exportAivsProofBundle`) is verified OFFLINE by the STANDALONE
 * zero-dependency reference verifier — which imports NO Trusteed code and NO
 * third-party packages (only `node:*`).
 *
 * Coverage:
 *   1. Positive: a real bundle verifies `valid:true`.
 *   2. Negatives: `manifest_hash_mismatch`, `signature_invalid`, `unknown_kid`,
 *      `malformed_session_sig`.
 *   3. Parity: for every input, the standalone verifier returns the SAME verdict
 *      as the internal `verifyAivsProofBundle`.
 *   4. Standalone CLI: `node verify-aivs-bundle.mjs <bundle> <jwks>` runs with
 *      only Node built-ins and prints the verdict.
 *
 * Uses a real Ed25519 keypair (no mocks). `jose` is used ONLY to generate the
 * fixture keypair/receipt on the test side — the verifier under test uses none.
 */

import { describe, it, expect, beforeAll } from "vitest";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { exportJWK, generateKeyPair, type JWK } from "jose";
import { issueTrustReceipt } from "../issuer.js";
import type { IssueOptions } from "../issuer.js";
import {
  exportAivsProofBundle,
  verifyAivsProofBundle,
  type AivsProofBundle,
} from "../aivs-export.js";
import type { PublicJwk } from "../verifier.js";
// The artifact under test — standalone, zero-dependency, pure node:* ESM module.
import { verifyAivsBundle } from "../../reference-verifier/verify-aivs-bundle.mjs";

const VERIFIER_PATH = fileURLToPath(
  new URL("../../reference-verifier/verify-aivs-bundle.mjs", import.meta.url)
);

const KID = "reference-verifier-key-2026";

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

let privateJwk: JWK;
let publicJwk: PublicJwk;
let validJws: string;
let validBundle: AivsProofBundle;

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
  validBundle = exportAivsProofBundle(validJws);
});

/**
 * Assert the standalone verifier agrees with the internal one for a given
 * input, and return the shared verdict for further assertion.
 */
async function verdictWithParity(
  bundle: AivsProofBundle,
  jwks: ReadonlyArray<PublicJwk>
): Promise<{ valid: boolean; reason?: string }> {
  const standalone = verifyAivsBundle(bundle, jwks);
  const internal = await verifyAivsProofBundle(bundle, { jwks });
  expect(standalone).toEqual(internal); // byte-for-byte parity
  return standalone;
}

describe("AIVS reference verifier — standalone zero-dependency (SC-001)", () => {
  it("verifies a real bundle offline as valid, matching the internal verifier", async () => {
    const result = await verdictWithParity(validBundle, [publicJwk]);
    expect(result).toEqual({ valid: true });
  });

  it("rejects a stale manifest_hash (tampered payload) → manifest_hash_mismatch", async () => {
    const [h, , s] = validBundle.session_sig.split(".");
    const forgedPayload = Buffer.from(
      JSON.stringify({ tampered: true }),
      "utf-8"
    ).toString("base64url");
    const tampered: AivsProofBundle = {
      ...validBundle,
      session_sig: `${h}.${forgedPayload}.${s}`,
    };

    const result = await verdictWithParity(tampered, [publicJwk]);
    expect(result).toEqual({ valid: false, reason: "manifest_hash_mismatch" });
  });

  it("rejects a forged payload with honestly recomputed hash → signature_invalid", async () => {
    const [h, , s] = validBundle.session_sig.split(".");
    const forgedPayload = Buffer.from(
      JSON.stringify({ tampered: true }),
      "utf-8"
    ).toString("base64url");
    const honestHash =
      "sha256:" + createHashFor(Buffer.from(forgedPayload, "base64url"));
    const tampered: AivsProofBundle = {
      ...validBundle,
      session_sig: `${h}.${forgedPayload}.${s}`,
      manifest_hash: honestHash,
    };

    const result = await verdictWithParity(tampered, [publicJwk]);
    expect(result).toEqual({ valid: false, reason: "signature_invalid" });
  });

  it("rejects when no JWKS key matches the kid → unknown_kid", async () => {
    const otherKey: PublicJwk = { ...publicJwk, kid: "some-other-kid" };
    const result = await verdictWithParity(validBundle, [otherKey]);
    expect(result).toEqual({ valid: false, reason: "unknown_kid" });
  });

  it("rejects a session_sig that is not a JWS Compact → malformed_session_sig", async () => {
    const malformed: AivsProofBundle = {
      ...validBundle,
      session_sig: "not-a-jws",
    };
    const result = await verdictWithParity(malformed, [publicJwk]);
    expect(result).toEqual({ valid: false, reason: "malformed_session_sig" });
  });

  it("accepts a `{ keys: [...] }` JWKS document, not just a bare array", () => {
    const result = verifyAivsBundle(validBundle, { keys: [publicJwk] });
    expect(result).toEqual({ valid: true });
  });
});

describe("AIVS reference verifier — standalone CLI over `node` only", () => {
  it("runs as `node verify-aivs-bundle.mjs <bundle> <jwks>` and reports valid (exit 0)", () => {
    const dir = mkdtempSync(join(tmpdir(), "aivs-ref-"));
    const bundlePath = join(dir, "bundle.json");
    const jwksPath = join(dir, "jwks.json");
    writeFileSync(bundlePath, JSON.stringify(validBundle), "utf-8");
    writeFileSync(jwksPath, JSON.stringify({ keys: [publicJwk] }), "utf-8");

    const proc = spawnSync(
      process.execPath,
      [VERIFIER_PATH, bundlePath, jwksPath],
      { encoding: "utf-8" }
    );

    expect(proc.status).toBe(0);
    expect(JSON.parse(proc.stdout.trim())).toEqual({ valid: true });
  });

  it("exits 1 and reports the reason on an invalid bundle", () => {
    const dir = mkdtempSync(join(tmpdir(), "aivs-ref-"));
    const bundlePath = join(dir, "bundle.json");
    const jwksPath = join(dir, "jwks.json");
    const invalid: AivsProofBundle = {
      ...validBundle,
      session_sig: "not-a-jws",
    };
    writeFileSync(bundlePath, JSON.stringify(invalid), "utf-8");
    writeFileSync(jwksPath, JSON.stringify([publicJwk]), "utf-8");

    const proc = spawnSync(
      process.execPath,
      [VERIFIER_PATH, bundlePath, jwksPath],
      { encoding: "utf-8" }
    );

    expect(proc.status).toBe(1);
    expect(JSON.parse(proc.stdout.trim())).toEqual({
      valid: false,
      reason: "malformed_session_sig",
    });
  });
});

/** Local sha256 helper (kept out of the import list to avoid name clashes). */
function createHashFor(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}
