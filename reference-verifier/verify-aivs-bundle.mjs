/**
 * AIVS proof-bundle reference verifier — ZERO-DEPENDENCY (spec-062 SC-001).
 *
 * A STANDALONE artifact that verifies an AIVS proof bundle OFFLINE using ONLY
 * Node.js built-ins (`node:crypto`, `node:fs`, `node:url`). It imports NO
 * Trusteed code and NO third-party packages (no `jose`, no
 * `@agenticmcpstores/*`). This is the executable proof of the AIVS thesis:
 * "verify it without contacting or trusting Trusteed."
 *
 * It reproduces, byte-for-byte, the verdict of the internal
 * `verifyAivsProofBundle` (packages/trust-receipt-verifier/src/aivs-export.ts):
 *
 *   1. manifest_hash — SHA-256 of the EXACT signed payload bytes recovered from
 *      the JWS (the base64url-decoded payload segment). No JSON canonicalization
 *      is applied: the signed bytes ARE the canonical form, so re-canonicalizing
 *      would be both unnecessary and wrong (it could diverge from what was
 *      signed). Mismatch → `manifest_hash_mismatch`.
 *   2. session_sig — the existing EdDSA (Ed25519) JWS Compact signature,
 *      verified with `crypto.verify(null, signingInput, key, sig)` against the
 *      issuer public key resolved by `kid` from the supplied JWKS.
 *         - not a 3-segment JWS      → `malformed_session_sig`
 *         - no JWKS key matches kid  → `unknown_kid`
 *         - signature does not verify → `signature_invalid`
 *
 * Ed25519 in pure node:crypto:
 *   - `crypto.createPublicKey({ key: jwk, format: "jwk" })` imports an OKP /
 *     Ed25519 public JWK ({ kty:"OKP", crv:"Ed25519", x }) — no `importJWK`.
 *   - `crypto.verify(null, data, key, signature)` verifies a raw 64-byte Ed25519
 *     signature (algorithm is `null` for EdDSA) — no `compactVerify`.
 *   - The JWS signing input is ASCII(`${headerSeg}.${payloadSeg}`), per RFC 7515.
 *
 * CLI:
 *   node verify-aivs-bundle.mjs <bundle.json> <jwks.json>
 * Prints the verdict as JSON to stdout and exits 0 when valid, 1 otherwise.
 *
 * @see specs/062-vcap-verified-commerce-alignment (SC-001)
 * @see packages/trust-receipt-verifier/src/aivs-export.ts (parity reference)
 */

import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

// ─── Pure verification (no I/O) ───────────────────────────────────────────────

/**
 * Verify an AIVS proof bundle offline.
 *
 * @param {{ manifest_hash?: string, session_sig?: string, kid?: string,
 *           alg?: string, audit_log?: unknown }} bundle
 * @param {ReadonlyArray<object> | { keys?: ReadonlyArray<object> }} jwks
 *        Issuer public keys — a JWK array or a `{ keys: [...] }` JWKS document.
 * @returns {{ valid: boolean, reason?: "manifest_hash_mismatch" | "unknown_kid"
 *           | "signature_invalid" | "malformed_session_sig" }}
 */
export function verifyAivsBundle(bundle, jwks) {
  if (!bundle || typeof bundle.session_sig !== "string") {
    return { valid: false, reason: "malformed_session_sig" };
  }

  const segments = bundle.session_sig.split(".");
  if (segments.length !== 3) {
    return { valid: false, reason: "malformed_session_sig" };
  }
  const [headerSeg, payloadSeg, signatureSeg] = segments;

  // Check 1 — manifest_hash binds to the exact signed payload bytes.
  const signedBytes = Buffer.from(payloadSeg, "base64url");
  const recomputed =
    "sha256:" + createHash("sha256").update(signedBytes).digest("hex");
  if (recomputed !== bundle.manifest_hash) {
    return { valid: false, reason: "manifest_hash_mismatch" };
  }

  // Resolve the signing key by kid. Prefer the bundle's top-level kid (parity
  // with the internal verifier, which resolves from bundle.kid); fall back to
  // the JWS protected header only when the bundle omits it.
  const kid =
    typeof bundle.kid === "string" ? bundle.kid : readHeaderKid(headerSeg);
  const keys = normalizeJwks(jwks);
  const jwk = keys.find((k) => k && k.kid === kid);
  if (!jwk) {
    return { valid: false, reason: "unknown_kid" };
  }

  // Check 2 — the EdDSA signature validates against the resolved key.
  try {
    const publicKey = createPublicKey({ key: jwk, format: "jwk" });
    const signingInput = Buffer.from(`${headerSeg}.${payloadSeg}`, "ascii");
    const signature = Buffer.from(signatureSeg, "base64url");
    const ok = cryptoVerify(null, signingInput, publicKey, signature);
    if (!ok) {
      return { valid: false, reason: "signature_invalid" };
    }
  } catch {
    return { valid: false, reason: "signature_invalid" };
  }

  return { valid: true };
}

/** Parse the `kid` from a JWS protected-header segment; "" if unreadable. */
function readHeaderKid(headerSeg) {
  try {
    const header = JSON.parse(
      Buffer.from(headerSeg, "base64url").toString("utf-8")
    );
    return typeof header.kid === "string" ? header.kid : "";
  } catch {
    return "";
  }
}

/** Accept either a bare JWK array or a `{ keys: [...] }` JWKS document. */
function normalizeJwks(jwks) {
  if (Array.isArray(jwks)) return jwks;
  if (jwks && Array.isArray(jwks.keys)) return jwks.keys;
  return [];
}

// ─── CLI ──────────────────────────────────────────────────────────────────────

function runCli(argv) {
  const [bundlePath, jwksPath] = argv;
  if (!bundlePath || !jwksPath) {
    process.stderr.write(
      "usage: node verify-aivs-bundle.mjs <bundle.json> <jwks.json>\n"
    );
    return 2;
  }

  let bundle;
  let jwks;
  try {
    bundle = JSON.parse(readFileSync(bundlePath, "utf-8"));
  } catch (err) {
    process.stderr.write(
      `cannot read bundle "${bundlePath}": ${err instanceof Error ? err.message : String(err)}\n`
    );
    return 2;
  }
  try {
    jwks = JSON.parse(readFileSync(jwksPath, "utf-8"));
  } catch (err) {
    process.stderr.write(
      `cannot read jwks "${jwksPath}": ${err instanceof Error ? err.message : String(err)}\n`
    );
    return 2;
  }

  const result = verifyAivsBundle(bundle, jwks);
  process.stdout.write(JSON.stringify(result) + "\n");
  return result.valid ? 0 : 1;
}

// Run as a CLI only when invoked directly (not when imported by a test).
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  process.exit(runCli(process.argv.slice(2)));
}
