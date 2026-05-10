/**
 * Integration tests verifying that `verifyReceiptEnvelope` cryptographically
 * verifies the bundled `SignedJwksHistory` against the embedded issuer root,
 * closing Codex F1 finding.
 *
 * Today's runtime ships the T420 staging-stub root, whose PEM body bytes do
 * not decode to a verifying-capable Ed25519 key. Under that root the
 * verifier falls back to structural-only history parsing AND emits warning
 * `jwks_history_signature_unverifiable_staging_root`. These tests pin that
 * fallback behavior so the conformance vectors continue to pass; once the
 * production cert lands these tests will need a corresponding fixture
 * refresh.
 *
 * @see ../verify-jwks-history.ts
 * @see ../verify-1.1.ts (kid resolution)
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyReceiptEnvelope } from "../verify-1.1.js";
import type { VerifyOptions } from "../verify-1.1.js";
import type { SignedJwksHistory } from "../types-1.1.js";
import type { PublicJwk } from "../verifier.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const VECTORS_DIR = join(__dirname, "..", "..", "test-vectors", "v11");

interface VectorFile {
  envelope: Record<string, unknown> & { legacy_v1_0?: boolean };
  expected: { outcome: "accepted" | "rejected" };
  verify_options: {
    currentTime: number;
    expectedSubject?: "buyer_agent" | "merchant_admin";
    jwks: { keys: PublicJwk[] };
  };
}

function loadHappyVector(): VectorFile {
  const raw = readFileSync(
    join(VECTORS_DIR, "011-buyer-agent-happy-path.json"),
    "utf8"
  );
  return JSON.parse(raw) as VectorFile;
}

function jwksToSignedHistory(
  jwks: { keys: PublicJwk[] },
  currentTime: number
): SignedJwksHistory {
  const payload = {
    schema_version: "1.0",
    entries: jwks.keys.map((k) => ({
      kid: (k as { kid?: string }).kid ?? "",
      jwk_pub: k as unknown as Record<string, unknown>,
      valid_from: currentTime - 86_400,
      valid_to: null,
    })),
    history_chain_sha256: "0".repeat(64),
  };
  const header = Buffer.from(JSON.stringify({ alg: "EdDSA" })).toString(
    "base64url"
  );
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return {
    jws_compact: `${header}.${body}.AA`,
    signed_by_root_sha256: "0".repeat(64),
  };
}

function makeOptions(vector: VectorFile): VerifyOptions {
  return {
    jwksHistory: jwksToSignedHistory(
      vector.verify_options.jwks,
      vector.verify_options.currentTime
    ),
    trustAnchorPemSha256:
      "dd43bf2cd65023d79e41358226ed1197fcea36bc693f1c0fadde0e318bfd76a1",
    policyOidAllowlist: ["1.2.3.4.5.6.7.8.9"],
    expectedSubject: vector.verify_options.expectedSubject,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("verifyReceiptEnvelope — JWKS history signature wiring (Codex F1)", () => {
  it("emits jwks_history_signature_unverifiable_staging_root warning under staging stub", async () => {
    const vector = loadHappyVector();
    const opts = makeOptions(vector);
    const result = await verifyReceiptEnvelope(
      vector.envelope as unknown as Parameters<typeof verifyReceiptEnvelope>[0],
      opts
    );
    expect(result.warnings).toContain(
      "jwks_history_signature_unverifiable_staging_root"
    );
  });

  it("rejects with jwks_history_signature_invalid when JWS shape is malformed", async () => {
    const vector = loadHappyVector();
    const opts: VerifyOptions = {
      ...makeOptions(vector),
      jwksHistory: {
        jws_compact: "only.two",
        signed_by_root_sha256: "0".repeat(64),
      },
    };
    const result = await verifyReceiptEnvelope(
      vector.envelope as unknown as Parameters<typeof verifyReceiptEnvelope>[0],
      opts
    );
    expect(result.outcome).toBe("rejected");
    expect(result.errorCode).toBe("jwks_history_signature_invalid");
  });

  it("rejects with jwks_history_signature_invalid when alg is not EdDSA", async () => {
    const vector = loadHappyVector();
    const header = Buffer.from(JSON.stringify({ alg: "RS256" })).toString(
      "base64url"
    );
    const body = Buffer.from(JSON.stringify({ entries: [] })).toString(
      "base64url"
    );
    const opts: VerifyOptions = {
      ...makeOptions(vector),
      jwksHistory: {
        jws_compact: `${header}.${body}.AA`,
        signed_by_root_sha256: "0".repeat(64),
      },
    };
    const result = await verifyReceiptEnvelope(
      vector.envelope as unknown as Parameters<typeof verifyReceiptEnvelope>[0],
      opts
    );
    expect(result.outcome).toBe("rejected");
    expect(result.errorCode).toBe("jwks_history_signature_invalid");
  });

  it("preserves unknown_kid behavior when staging fallback is hit but kid is foreign", async () => {
    const vector = loadHappyVector();
    // Replace the JWKS with a different kid — staging fallback parses
    // structurally, kid lookup fails, classic unknown_kid path fires.
    const foreignJwks = {
      keys: [
        {
          kty: "OKP",
          crv: "Ed25519",
          x: "AAAA",
          kid: "attacker-kid-not-in-receipt",
        } as unknown as PublicJwk,
      ],
    };
    const opts: VerifyOptions = {
      ...makeOptions(vector),
      jwksHistory: jwksToSignedHistory(
        foreignJwks,
        vector.verify_options.currentTime
      ),
    };
    const result = await verifyReceiptEnvelope(
      vector.envelope as unknown as Parameters<typeof verifyReceiptEnvelope>[0],
      opts
    );
    expect(result.outcome).toBe("rejected");
    expect(result.errorCode).toBe("unknown_kid");
  });
});

// Silence unused-import on readdirSync (kept for parity with conformance test).
void readdirSync;
