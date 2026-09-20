/**
 * ATEP passport reference verifier — ZERO-DEPENDENCY (spec-062 SC-001).
 *
 * A STANDALONE artifact that verifies an ATEP passport OFFLINE using ONLY
 * Node.js built-ins (`node:crypto`, `node:fs`, `node:url`). It imports NO
 * Trusteed code and NO third-party packages (no `jose`, no
 * monorepo-internal packages). This is the executable proof of the ATEP thesis:
 * "verify a merchant's portable trust attestation without contacting or
 * trusting Trusteed."
 *
 * It reproduces, verdict-for-verdict, the internal `verifyAtepPassport`
 * (Trusteed's issuer-side implementation, not part of this package). The passport carries TWO
 * independent EdDSA anchors, checked in this exact order:
 *
 *   A. issuer_sig — a JWS Compact the issuer computes over the WHOLE canonical
 *      (JCS/RFC 8785) passport body (everything EXCEPT `issuer_sig`). This
 *      attests the issuer-computed aggregates (execution_count / success_rate /
 *      badges) that are NOT present in the snapshot.
 *
 *      SCOPE LIMIT (audit 2026-07-26 §F2): these aggregates are ATTESTED by the
 *      issuer's signature, NOT independently recomputable by a third party. The
 *      underlying TrustReceipt corpus is not hash-chained (no issuer writes
 *      `hash_chain_prev`) and is not externally readable, so a verifier can
 *      confirm the issuer SAID these numbers — never that they are correct.
 *      Failures:
 *         - no issuer_sig / non-3-segment jws → `missing_issuer_sig`
 *         - no JWKS key matches issuer_sig.kid → `unknown_issuer_kid`
 *         - signature does not verify           → `issuer_signature_invalid`
 *         - signed body ≠ canonical(body)       → `issuer_projection_mismatch`
 *   B. provenance.session_sig — the underlying signed StoreScoreSnapshot's own
 *      EdDSA JWS. Failures:
 *         - not a 3-segment JWS      → `malformed_session_sig`
 *         - no JWKS key matches kid  → `unknown_kid`
 *         - signature does not verify → `signature_invalid`
 *   C. faithfulness — the snapshot-attested subset re-projects EXACTLY from the
 *      signed snapshot body, so a tampered tier/score is caught even with a
 *      valid issuer signature. Failure: `projection_mismatch`.
 *
 * Returns `{ valid: true }` iff A, B and C all pass.
 *
 * JCS (RFC 8785) — reimplemented VERBATIM here (see `canonicalizeJSON`).
 *   Unlike the AIVS reference verifier (which hashes the exact base64url-decoded
 *   payload BYTES and never re-canonicalizes), the ATEP `issuer_sig` signs over
 *   the JCS-CANONICALIZED body. So checks A and C must re-canonicalize JSON
 *   byte-for-byte identically to Trusteed's internal `canonicalizeJSON`
 *   (issuer-side, not part of this package), which the internal verifier
 *   uses. Any divergence breaks parity.
 *
 * Ed25519 in pure node:crypto:
 *   - `crypto.createPublicKey({ key: jwk, format: "jwk" })` imports an OKP /
 *     Ed25519 public JWK ({ kty:"OKP", crv:"Ed25519", x }) — no `importJWK`.
 *   - `crypto.verify(null, data, key, signature)` verifies a raw 64-byte Ed25519
 *     signature (algorithm is `null` for EdDSA) — no `compactVerify`.
 *   - The JWS signing input is ASCII(`${headerSeg}.${payloadSeg}`), per RFC 7515.
 *   - The verified payload is the base64url-decoded payload segment (what
 *     jose's `compactVerify(...).payload` returns).
 *
 * CLI:
 *   node verify-atep-passport.mjs <passport.json> <jwks.json>
 * Prints the verdict as JSON to stdout and exits 0 when valid, 1 otherwise.
 *
 * @see specs/062-vcap-verified-commerce-alignment (SC-001)
 * @see Trusteed's issuer-side implementation (parity reference, not part of this package)
 */

import { createPublicKey, verify as cryptoVerify } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

// ─── JCS (RFC 8785) ─────────────────────────────────────────────────────────
// VERBATIM copy of Trusteed's internal canonicalizeJSON (issuer-side, not
// part of this package) — the function the internal
// verifier uses to build the issuer signing input and the faithfulness subsets.
// Do NOT "improve" this: byte-for-byte parity with the internal is the contract.
function canonicalizeJSON(value) {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!isFinite(value)) throw new Error("JCS: non-finite numbers are not allowed");
    return JSON.stringify(value);
  }
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(canonicalizeJSON).join(",") + "]";
  if (typeof value === "object") {
    const obj = value;
    const pairs = Object.keys(obj)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonicalizeJSON(obj[k])}`);
    return "{" + pairs.join(",") + "}";
  }
  throw new Error(`JCS: unsupported value type: ${typeof value}`);
}

// ─── Projection helpers (parity with atep-passport.ts) ────────────────────────

/**
 * Project a SIGNED StoreScoreSnapshot envelope + recomputed aggregates into an
 * ATEP passport BODY (unsigned). Pure and deterministic — mirror of
 * `projectAtepPassport` (atep-passport.ts ~L88). Snapshot-derived fields carry
 * only what the snapshot attests; aggregates come from the caller.
 *
 * @param {any} envelope   ScoreSnapshotEnvelope (verified session_sig payload)
 * @param {any} provenance passport.provenance
 * @param {{ execution_count: number, success_rate: number|null,
 *           badges: readonly string[] }} aggregates
 */
function projectAtepPassport(envelope, provenance, aggregates) {
  return {
    passport_version: "0.2",
    subject: envelope.merchantId,
    trust_tier: envelope.confidenceLevel,
    score: envelope.scoreFinal ?? envelope.score,
    cap_applied: envelope.capApplied,
    components_are_real: envelope.componentsAreReal,
    score_breakdown: envelope.breakdown,
    scoring_version: envelope.scoringVersion,
    execution_count: aggregates.execution_count,
    success_rate: aggregates.success_rate,
    badges: aggregates.badges,
    issued_at: envelope.issuedAt,
    provenance,
  };
}

/**
 * Re-project ONLY the snapshot-attested subset (for the faithfulness check).
 * Mirror of the internal `snapshotSubset` (atep-passport.ts ~L111).
 * @param {any} body
 */
function snapshotSubset(body) {
  return {
    passport_version: body.passport_version,
    subject: body.subject,
    trust_tier: body.trust_tier,
    score: body.score,
    cap_applied: body.cap_applied,
    components_are_real: body.components_are_real,
    score_breakdown: body.score_breakdown,
    scoring_version: body.scoring_version,
    issued_at: body.issued_at,
    provenance: body.provenance,
  };
}

// ─── Pure verification (no I/O) ───────────────────────────────────────────────

/**
 * Verify an ATEP passport offline against the issuer's score JWKS.
 *
 * @param {any} passport A fully-signed ATEP passport (body + `issuer_sig`).
 * @param {ReadonlyArray<object> | { keys?: ReadonlyArray<object> }} jwks
 *        Issuer public keys — a JWK array or a `{ keys: [...] }` JWKS document.
 * @returns {{ valid: boolean, reason?: "missing_issuer_sig" |
 *           "unknown_issuer_kid" | "issuer_signature_invalid" |
 *           "issuer_projection_mismatch" | "malformed_session_sig" |
 *           "unknown_kid" | "signature_invalid" | "projection_mismatch" }}
 */
export function verifyAtepPassport(passport, jwks) {
  const keys = normalizeJwks(jwks);
  const { issuer_sig, ...body } = passport;

  // ── A. Issuer signature over the whole canonical body (attests aggregates) ─
  if (
    !issuer_sig ||
    typeof issuer_sig.jws !== "string" ||
    issuer_sig.jws.split(".").length !== 3
  ) {
    return { valid: false, reason: "missing_issuer_sig" };
  }
  const issuerJwk = keys.find((k) => k && k.kid === issuer_sig.kid);
  if (!issuerJwk) {
    return { valid: false, reason: "unknown_issuer_kid" };
  }
  let issuerPayload;
  try {
    const [hSeg, pSeg, sSeg] = issuer_sig.jws.split(".");
    const publicKey = createPublicKey({ key: issuerJwk, format: "jwk" });
    const signingInput = Buffer.from(`${hSeg}.${pSeg}`, "ascii");
    const signature = Buffer.from(sSeg, "base64url");
    if (!cryptoVerify(null, signingInput, publicKey, signature)) {
      return { valid: false, reason: "issuer_signature_invalid" };
    }
    issuerPayload = Buffer.from(pSeg, "base64url");
  } catch {
    return { valid: false, reason: "issuer_signature_invalid" };
  }
  if (issuerPayload.toString("utf-8") !== canonicalizeJSON(body)) {
    return { valid: false, reason: "issuer_projection_mismatch" };
  }

  // ── B. Underlying snapshot signature authenticity ─────────────────────────
  const segments = passport.provenance.session_sig.split(".");
  if (segments.length !== 3) {
    return { valid: false, reason: "malformed_session_sig" };
  }
  const snapshotJwk = keys.find((k) => k && k.kid === passport.provenance.kid);
  if (!snapshotJwk) {
    return { valid: false, reason: "unknown_kid" };
  }
  let snapshotPayload;
  try {
    const [hSeg, pSeg, sSeg] = segments;
    const publicKey = createPublicKey({ key: snapshotJwk, format: "jwk" });
    const signingInput = Buffer.from(`${hSeg}.${pSeg}`, "ascii");
    const signature = Buffer.from(sSeg, "base64url");
    if (!cryptoVerify(null, signingInput, publicKey, signature)) {
      return { valid: false, reason: "signature_invalid" };
    }
    snapshotPayload = Buffer.from(pSeg, "base64url");
  } catch {
    return { valid: false, reason: "signature_invalid" };
  }

  // ── C. Snapshot-derived subset faithfully re-projects from the signed body ─
  const envelope = JSON.parse(snapshotPayload.toString("utf-8"));
  const expectedSubset = snapshotSubset(
    projectAtepPassport(envelope, passport.provenance, {
      execution_count: body.execution_count,
      success_rate: body.success_rate,
      badges: body.badges,
    })
  );
  if (canonicalizeJSON(expectedSubset) !== canonicalizeJSON(snapshotSubset(body))) {
    return { valid: false, reason: "projection_mismatch" };
  }

  return { valid: true };
}

/** Accept either a bare JWK array or a `{ keys: [...] }` JWKS document. */
function normalizeJwks(jwks) {
  if (Array.isArray(jwks)) return jwks;
  if (jwks && Array.isArray(jwks.keys)) return jwks.keys;
  return [];
}

// ─── CLI ──────────────────────────────────────────────────────────────────────

function runCli(argv) {
  const [passportPath, jwksPath] = argv;
  if (!passportPath || !jwksPath) {
    process.stderr.write(
      "usage: node verify-atep-passport.mjs <passport.json> <jwks.json>\n"
    );
    return 2;
  }

  let passport;
  let jwks;
  try {
    passport = JSON.parse(readFileSync(passportPath, "utf-8"));
  } catch (err) {
    process.stderr.write(
      `cannot read passport "${passportPath}": ${err instanceof Error ? err.message : String(err)}\n`
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

  const result = verifyAtepPassport(passport, jwks);
  process.stdout.write(JSON.stringify(result) + "\n");
  return result.valid ? 0 : 1;
}

// Run as a CLI only when invoked directly (not when imported by a test).
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  process.exit(runCli(process.argv.slice(2)));
}
