/**
 * Declared trust-anchor degradation (audit 2026-07-26 §B1 / P0-1).
 *
 * PROBLEM
 *   The T420 key ceremony has never run, so the only embedded issuer root is a
 *   structural placeholder. With `allowStagingRoots:false` (the production
 *   default) EVERY v1.1 receipt is rejected with
 *   `jwks_history_signature_invalid / root_not_in_trust_anchor`. The absence of
 *   an offline ceremony therefore invalidates the entire v1.1 corpus, and the
 *   only way to make anything verify was an operator-side flag that silently
 *   weakens the check for ALL receipts.
 *
 * CONTRACT PINNED HERE
 *   A receipt that DECLARES its own degradation in its SIGNED body
 *   (`legal_posture: "simple_electronic_seal"` + a `trust_anchor_staging`
 *   posture warning) is verified and returned as `accepted_degraded` — a NEW
 *   outcome value, so every existing consumer that branches on
 *   `outcome === "accepted"` keeps refusing it. A receipt that does NOT declare
 *   the degradation is still rejected exactly as before: the operator flag is
 *   not weakened, and silence is never read as consent.
 *
 * @see docs/analisis/trust-receipts-auditoria-arquitectura-2026-07-26.md §B1
 */

import { describe, it, expect, beforeAll } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { CompactSign, exportJWK, generateKeyPair, type JWK } from "jose";
import { verifyReceiptEnvelope } from "../verify-1.1.js";
import type { VerifyOptions } from "../verify-1.1.js";
import type { SignedJwksHistory } from "../types-1.1.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const VECTORS_DIR = join(__dirname, "..", "..", "test-vectors", "v11");
const KID = "tr-ed25519-v11-test-2026";

interface VectorFile {
  envelope: Record<string, unknown>;
  verify_options: { currentTime: number };
}

/**
 * Vector 015 (TSA unavailable) is the base fixture, not the RFC 3161 happy
 * path: its `timestamp_evidence` is `type: "unavailable"`, so re-signing the
 * body here does not invalidate a TST imprint taken over the original JWS
 * bytes. It is also the realistic staging shape — a deployment with no key
 * ceremony typically has no timestamping authority wired either.
 */
function loadHappyVector(): VectorFile {
  return JSON.parse(
    readFileSync(join(VECTORS_DIR, "015-timestamp-unavailable.json"), "utf8")
  ) as VectorFile;
}

function decodeBody(jwsCompact: string): Record<string, unknown> {
  const seg = jwsCompact.split(".")[1] ?? "";
  return JSON.parse(Buffer.from(seg, "base64url").toString("utf8")) as Record<
    string,
    unknown
  >;
}

let privateJwk: JWK;
let publicJwk: JWK;

beforeAll(async () => {
  const { privateKey, publicKey } = await generateKeyPair("EdDSA", {
    extractable: true,
  });
  privateJwk = await exportJWK(privateKey);
  publicJwk = { ...(await exportJWK(publicKey)), kid: KID, alg: "EdDSA" };
});

async function resign(body: Record<string, unknown>): Promise<string> {
  const { importJWK } = await import("jose");
  const key = await importJWK(privateJwk, "EdDSA");
  return new CompactSign(new TextEncoder().encode(JSON.stringify(body)))
    .setProtectedHeader({ alg: "EdDSA", kid: KID, typ: "JWT" })
    .sign(key);
}

function jwksHistory(currentTime: number): SignedJwksHistory {
  const payload = {
    schema_version: "1.0",
    entries: [
      {
        kid: KID,
        jwk_pub: publicJwk as unknown as Record<string, unknown>,
        valid_from: currentTime - 86_400,
        valid_to: null,
      },
    ],
    history_chain_sha256: "0".repeat(64),
  };
  const header = Buffer.from(JSON.stringify({ alg: "EdDSA" })).toString(
    "base64url"
  );
  const b = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return {
    jws_compact: `${header}.${b}.AA`,
    signed_by_root_sha256: "0".repeat(64),
  };
}

/**
 * Build an envelope from the happy-path vector, optionally making the receipt
 * DECLARE the staging degradation in its signed body (and mirroring it in
 * `envelope_metadata` per the D22 mirror discipline).
 */
async function buildEnvelope(options: {
  declareDegradation: boolean;
}): Promise<{ envelope: Record<string, unknown>; currentTime: number }> {
  const vector = loadHappyVector();
  const envelope = structuredClone(vector.envelope);
  const body = decodeBody(envelope.receipt as string);

  const nextBody = options.declareDegradation
    ? {
        ...body,
        legal_posture: "simple_electronic_seal",
        legal_posture_warnings: [
          { reason: "trust_anchor_staging", since: body.issued_at },
        ],
      }
    : body;

  const metadata = envelope.envelope_metadata as Record<string, unknown>;
  const nextEnvelope = {
    ...envelope,
    receipt: await resign(nextBody),
    envelope_metadata: options.declareDegradation
      ? {
          ...metadata,
          legal_posture: "simple_electronic_seal",
          legal_posture_warnings: [
            { reason: "trust_anchor_staging", since: body.issued_at },
          ],
        }
      : metadata,
  };

  return {
    envelope: nextEnvelope,
    currentTime: vector.verify_options.currentTime,
  };
}

function makeOptions(
  currentTime: number,
  envelope: Record<string, unknown>
): VerifyOptions {
  // Pin the fixture's TSA root when it has one, so unrelated TSA policy noise
  // cannot mask the trust-anchor behaviour under test.
  const tsaRoot = (
    envelope.timestamp_evidence as { tsa_root_cert_sha256?: string } | undefined
  )?.tsa_root_cert_sha256;
  return {
    jwksHistory: jwksHistory(currentTime),
    trustAnchorPemSha256:
      "dd43bf2cd65023d79e41358226ed1197fcea36bc693f1c0fadde0e318bfd76a1",
    policyOidAllowlist: ["1.2.3.4.5.6.7.8.9"],
    tsaRootCertSha256Allowlist: tsaRoot ? [tsaRoot] : [],
    // Production default — the operator has NOT opted into staging roots.
    allowStagingRoots: false,
    currentTimeSeconds: currentTime,
  };
}

describe("verifyReceiptEnvelope — declared trust-anchor degradation", () => {
  it("accepts (degraded) a receipt whose SIGNED body declares trust_anchor_staging", async () => {
    const { envelope, currentTime } = await buildEnvelope({
      declareDegradation: true,
    });

    const result = await verifyReceiptEnvelope(
      envelope as unknown as Parameters<typeof verifyReceiptEnvelope>[0],
      makeOptions(currentTime, envelope)
    );

    expect(result.outcome).toBe("accepted_degraded");
    expect(result.errorCode).toBeUndefined();
    expect(result.recomputedLegalPosture).toBe("simple_electronic_seal");
    expect(result.warnings).toContain("trust_anchor_staging");
    expect(result.warnings).toContain(
      "jwks_history_signature_unverifiable_staging_root"
    );
  });

  it("is NOT 'accepted' — existing consumers branching on accepted keep refusing it", async () => {
    const { envelope, currentTime } = await buildEnvelope({
      declareDegradation: true,
    });

    const result = await verifyReceiptEnvelope(
      envelope as unknown as Parameters<typeof verifyReceiptEnvelope>[0],
      makeOptions(currentTime, envelope)
    );

    expect(result.outcome).not.toBe("accepted");
  });

  it("still returns the verified body so a consumer can inspect the degraded evidence", async () => {
    const { envelope, currentTime } = await buildEnvelope({
      declareDegradation: true,
    });

    const result = await verifyReceiptEnvelope(
      envelope as unknown as Parameters<typeof verifyReceiptEnvelope>[0],
      makeOptions(currentTime, envelope)
    );

    expect(result.receipt).toBeDefined();
    expect(result.receipt?.legal_posture).toBe("simple_electronic_seal");
  });

  // A2 contract, point 4: the staging declaration DOMINATES the whole FR-019
  // truth table — buyer_agent and merchant_admin alike, with or without TSA,
  // with or without agent identity. `merchant_admin_action` is a subject label,
  // not a strength claim, so it must not shadow an unverifiable anchor.
  it("floors a merchant_admin receipt to simple_electronic_seal when it declares trust_anchor_staging", async () => {
    const vector = JSON.parse(
      readFileSync(
        join(VECTORS_DIR, "013-receipt-subject-mismatch.json"),
        "utf8"
      )
    ) as VectorFile & { verify_options: { currentTime: number } };
    const envelope = structuredClone(vector.envelope);
    const body = decodeBody(envelope.receipt as string);
    const since = body.issued_at as number;

    // Swap in the "unavailable" timestamp shape so re-signing does not break a
    // TST imprint taken over the original JWS bytes. The subject, not the TSA,
    // is what this test is about.
    envelope.timestamp_evidence = {
      type: "unavailable",
      reason: "tsa_unavailable",
      attempted_at: since,
      attempted_tsa: ["https://test-tsa.trusteed.xyz/tsa"],
    };
    envelope.receipt = await resign({
      ...body,
      legal_posture: "simple_electronic_seal",
      legal_posture_warnings: [{ reason: "trust_anchor_staging", since }],
    });
    envelope.envelope_metadata = {
      ...(envelope.envelope_metadata as Record<string, unknown>),
      legal_posture: "simple_electronic_seal",
      legal_posture_warnings: [{ reason: "trust_anchor_staging", since }],
    };

    const result = await verifyReceiptEnvelope(
      envelope as unknown as Parameters<typeof verifyReceiptEnvelope>[0],
      makeOptions(vector.verify_options.currentTime, envelope)
    );

    expect(result.recomputedLegalPosture).toBe("simple_electronic_seal");
    expect(result.recomputedLegalPosture).not.toBe("merchant_admin_action");
    expect(result.outcome).toBe("accepted_degraded");
  });

  // The declaration is a property of the ARTIFACT, not of the verification
  // environment. `trust_anchor_staging` says "when I was signed, my issuer had
  // no ceremonied root" — a permanent, signed fact. Whether THIS verifier can
  // resolve a root today is transient and must not upgrade the verdict.
  //
  // The dangerous case is the day after the key ceremony: export bundles
  // assemble `jwksHistory` at EXPORT time, so a receipt signed during the
  // degraded window but exported afterwards ships a history signed by the real
  // root. The root verifies, nothing fails, and the whole degraded backlog
  // would silently become `accepted` — backdating trust onto keys that were
  // never anchored.
  it("stays accepted_degraded when the issuer root IS verifiable (post-ceremony backlog)", async () => {
    const { envelope, currentTime } = await buildEnvelope({
      declareDegradation: true,
    });

    // Simulate a resolvable root by opting into the staging path: the point is
    // that `pendingStagingDowngrade` is NOT armed, exactly as after T420.
    const result = await verifyReceiptEnvelope(
      envelope as unknown as Parameters<typeof verifyReceiptEnvelope>[0],
      { ...makeOptions(currentTime, envelope), allowStagingRoots: true }
    );

    expect(result.outcome).toBe("accepted_degraded");
    expect(result.outcome).not.toBe("accepted");
    expect(result.warnings).toContain("trust_anchor_staging");
  });

  it("stays accepted_degraded under allowStagingRoots:true (conformance/staging)", async () => {
    const { envelope, currentTime } = await buildEnvelope({
      declareDegradation: true,
    });

    const result = await verifyReceiptEnvelope(
      envelope as unknown as Parameters<typeof verifyReceiptEnvelope>[0],
      { ...makeOptions(currentTime, envelope), allowStagingRoots: true }
    );

    expect(result.outcome).toBe("accepted_degraded");
    expect(result.recomputedLegalPosture).toBe("simple_electronic_seal");
  });

  it("REJECTS a receipt from a staging root that does NOT declare its degradation", async () => {
    const { envelope, currentTime } = await buildEnvelope({
      declareDegradation: false,
    });

    const result = await verifyReceiptEnvelope(
      envelope as unknown as Parameters<typeof verifyReceiptEnvelope>[0],
      makeOptions(currentTime, envelope)
    );

    expect(result.outcome).toBe("rejected");
    expect(result.errorCode).toBe("jwks_history_signature_invalid");
    expect(result.errorDetail).toBe("root_not_in_trust_anchor");
  });

  it("does not let an unsigned envelope_metadata declaration alone unlock the downgrade", async () => {
    // Degradation asserted ONLY in the unsigned envelope_metadata mirror; the
    // signed body says nothing. An attacker who can edit the sidecar but not
    // the signature MUST NOT be able to turn a rejection into an acceptance.
    const { envelope, currentTime } = await buildEnvelope({
      declareDegradation: false,
    });
    const tampered: Record<string, unknown> = {
      ...envelope,
      envelope_metadata: {
        ...(envelope.envelope_metadata as Record<string, unknown>),
        legal_posture: "simple_electronic_seal",
        legal_posture_warnings: [
          { reason: "trust_anchor_staging", since: 1777593601 },
        ],
      },
    };

    const result = await verifyReceiptEnvelope(
      tampered as unknown as Parameters<typeof verifyReceiptEnvelope>[0],
      makeOptions(currentTime, envelope)
    );

    expect(result.outcome).toBe("rejected");
    expect(result.errorCode).toBe("jwks_history_signature_invalid");
  });
});
