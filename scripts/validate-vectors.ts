#!/usr/bin/env tsx
/**
 * TrustReceipt conformance vector validation.
 *
 * Runs full JWS end-to-end verification against all 10 test vectors.
 * For each vector: signs the raw payload with a fresh Ed25519 key,
 * then calls verifyTrustReceipt and asserts the expected outcome.
 *
 * This is the canonical conformance check — it tests the verifier,
 * not just the Zod schema.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { generateKeyPair, exportJWK, CompactSign, importJWK } from "jose";
import { verifyTrustReceipt } from "../src/verifier.js";
import type { VerifyFailureReason } from "../src/verifier.js";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const PKG_DIR = join(__dirname, "..");

type VectorEntry = {
  id: string;
  file: string;
  expected: "valid" | "invalid";
  failure_code?: string;
  description: string;
};

// ─── Setup keypair ────────────────────────────────────────────────────────────

const TEST_KID = "tr-ed25519-2026-04-29-demo";

const { publicKey, privateKey } = await generateKeyPair("EdDSA", {
  extractable: true,
});
const publicJwk = {
  ...(await exportJWK(publicKey)),
  kid: TEST_KID,
  alg: "EdDSA",
};
const privateJwkRaw = await exportJWK(privateKey);

// Separate key pair for TC-008 (wrong-kid — signed with unknown key)
const { privateKey: wrongKey } = await generateKeyPair("EdDSA", {
  extractable: true,
});
const wrongPrivateJwkRaw = await exportJWK(wrongKey);

// ─── Helpers ─────────────────────────────────────────────────────────────────

async function signRawPayload(
  payload: unknown,
  jwkRaw: typeof privateJwkRaw,
  kid: string
): Promise<string> {
  const privKey = await importJWK(jwkRaw, "EdDSA");
  const bytes = new TextEncoder().encode(JSON.stringify(payload));
  return new CompactSign(bytes)
    .setProtectedHeader({ alg: "EdDSA", kid })
    .sign(privKey);
}

function printPass(id: string, note: string): void {
  process.stdout.write(`✓ ${id} — ${note}\n`);
}

function printFail(id: string, note: string): void {
  process.stderr.write(`✗ ${id} — ${note}\n`);
}

// ─── Run vectors ──────────────────────────────────────────────────────────────

const manifest = JSON.parse(
  readFileSync(join(PKG_DIR, "test-vectors/vectors.json"), "utf-8")
) as { vectors: VectorEntry[] };

let passed = 0;
let failed = 0;

for (const v of manifest.vectors) {
  const rawPath = join(PKG_DIR, "test-vectors", v.file);
  const rawPayload: unknown = JSON.parse(readFileSync(rawPath, "utf-8"));

  let jws: string;
  let expectedReason: VerifyFailureReason | undefined;

  if (v.id === "TC-008") {
    // TC-008: signed with a kid absent from the verifier's JWKS → unknown_kid
    jws = await signRawPayload(
      rawPayload,
      wrongPrivateJwkRaw,
      "nonexistent-key-id-abc123"
    );
    expectedReason = "unknown_kid";
  } else {
    // For valid vectors, refresh timestamps so they don't expire between test runs.
    // Invalid vectors (schema/temporal failures) keep their original static timestamps.
    const payloadToSign =
      v.expected === "valid"
        ? {
            ...(rawPayload as Record<string, unknown>),
            issued_at: Math.floor(Date.now() / 1000),
            expires_at: Math.floor(Date.now() / 1000) + 3600,
          }
        : rawPayload;
    jws = await signRawPayload(payloadToSign, privateJwkRaw, TEST_KID);
    expectedReason =
      v.failure_code !== undefined
        ? (v.failure_code as VerifyFailureReason)
        : undefined;
  }

  const result = await verifyTrustReceipt(jws, {
    jwks: [publicJwk],
    // TC-007 contains timestamps far in the past — zero tolerance so it fails
    clockToleranceSeconds: v.id === "TC-007" ? 0 : 30,
  });

  if (v.expected === "valid") {
    if (result.valid) {
      printPass(v.id, "valid — verified OK");
      passed++;
    } else {
      printFail(
        v.id,
        `expected valid but got reason=${result.reason ?? "?"} errors=${JSON.stringify(result.errors)}`
      );
      failed++;
    }
  } else {
    if (!result.valid && result.reason === expectedReason) {
      printPass(v.id, `invalid/${result.reason} — as expected`);
      passed++;
    } else if (!result.valid) {
      printFail(
        v.id,
        `invalid but wrong reason: got=${result.reason} want=${expectedReason}`
      );
      failed++;
    } else {
      printFail(
        v.id,
        `expected failure ${expectedReason ?? "unknown"} but verified as valid`
      );
      failed++;
    }
  }
}

process.stdout.write(`\n${passed}/${passed + failed} vectors passed\n`);
process.exit(failed > 0 ? 1 : 0);
