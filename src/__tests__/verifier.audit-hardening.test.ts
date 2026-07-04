/**
 * Security-audit hardening tests (2026-07-03).
 *
 *  - A1: `TrustReceiptV11BodySchema` is `.strict()` at the ROOT — unknown keys
 *        injected into the signed body are rejected (anti signed-bytes drift).
 *  - M8: `verifyReceiptEnvelope` honors `history_chain_sha256` — a committed
 *        (non-stub) chain that disagrees with the presented entries is rejected
 *        with `jwks_history_chain_mismatch`; a correct chain passes through.
 *  - C3: the standalone `verifyTrustReceipt` accepts the v1.0-legacy compact
 *        payload the platform issuer actually emits (`legacy_compact` variant).
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import canonicalize from "canonicalize";
import {
  CompactSign,
  exportJWK,
  generateKeyPair,
  type JWK,
} from "jose";

import { verifyReceiptEnvelope } from "../verify-1.1.js";
import type { VerifyOptions } from "../verify-1.1.js";
import { TrustReceiptV11BodySchema } from "../zod-1.1.js";
import { verifyTrustReceipt, type PublicJwk } from "../verifier.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const VECTORS_DIR = join(__dirname, "..", "..", "test-vectors", "v11");

// ---------------------------------------------------------------------------
// A1 — strict root body schema
// ---------------------------------------------------------------------------

function loadHappyBody(): Record<string, unknown> {
  const raw = readFileSync(
    join(VECTORS_DIR, "011-buyer-agent-happy-path.json"),
    "utf8"
  );
  const vector = JSON.parse(raw) as {
    envelope: { receipt: string };
  };
  const jws = vector.envelope.receipt;
  const payloadSeg = jws.split(".")[1]!;
  return JSON.parse(Buffer.from(payloadSeg, "base64url").toString("utf8"));
}

describe("A1 — TrustReceiptV11BodySchema strict root", () => {
  it("accepts the canonical happy-path body", () => {
    const body = loadHappyBody();
    expect(TrustReceiptV11BodySchema.safeParse(body).success).toBe(true);
  });

  it("rejects an injected unknown top-level key (signed-bytes drift)", () => {
    const body = { ...loadHappyBody(), shadow_signature: "attacker-controlled" };
    const parsed = TrustReceiptV11BodySchema.safeParse(body);
    expect(parsed.success).toBe(false);
    if (!parsed.success) {
      const codes = parsed.error.issues.map((i) => i.code);
      expect(codes).toContain("unrecognized_keys");
    }
  });

  it("still accepts the known platformOrderId/platform carry-over keys", () => {
    const body = {
      ...loadHappyBody(),
      platformOrderId: "shopify-1234",
      platform: "shopify",
    };
    expect(TrustReceiptV11BodySchema.safeParse(body).success).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// M8 — verifier honors history_chain_sha256
// ---------------------------------------------------------------------------

interface VectorFile {
  envelope: Record<string, unknown>;
  verify_options: { currentTime: number; jwks: { keys: PublicJwk[] } };
}

function loadHappyVector(): VectorFile {
  return JSON.parse(
    readFileSync(join(VECTORS_DIR, "011-buyer-agent-happy-path.json"), "utf8")
  ) as VectorFile;
}

function sha256Hex(s: string): string {
  return createHash("sha256").update(s, "utf8").digest("hex");
}

/** Rolling chain identical to issuer + verifier. */
function rollingChain(entries: ReadonlyArray<Record<string, unknown>>): string {
  let chain = sha256Hex(canonicalize([] as unknown[]) ?? "[]");
  for (const e of entries) {
    chain = sha256Hex(chain + (canonicalize(e) ?? "{}"));
  }
  return chain;
}

function buildHistory(
  jwks: { keys: PublicJwk[] },
  currentTime: number,
  committedChain: string
) {
  const entries = jwks.keys.map((k) => ({
    kid: (k as { kid?: string }).kid ?? "",
    jwk_pub: k as unknown as Record<string, unknown>,
    valid_from: currentTime - 86_400,
    valid_to: null as number | null,
  }));
  const payload = {
    schema_version: "1.0",
    entries,
    history_chain_sha256: committedChain,
  };
  const header = Buffer.from(JSON.stringify({ alg: "EdDSA" })).toString(
    "base64url"
  );
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return {
    signedHistory: {
      jws_compact: `${header}.${body}.AA`,
      signed_by_root_sha256: "0".repeat(64),
    },
    entries,
  };
}

function baseOptions(vector: VectorFile, committedChain: string): VerifyOptions {
  const { signedHistory } = buildHistory(
    vector.verify_options.jwks,
    vector.verify_options.currentTime,
    committedChain
  );
  return {
    jwksHistory: signedHistory,
    trustAnchorPemSha256:
      "dd43bf2cd65023d79e41358226ed1197fcea36bc693f1c0fadde0e318bfd76a1",
    policyOidAllowlist: ["1.2.3.4.5.6.7.8.9"],
    allowStagingRoots: true,
    currentTimeSeconds: vector.verify_options.currentTime,
  };
}

describe("M8 — verifier honors history_chain_sha256", () => {
  it("rejects a non-stub committed chain that disagrees with entries", async () => {
    const vector = loadHappyVector();
    // A valid-looking but WRONG chain (64 hex, non-stub).
    const wrongChain = "a".repeat(63) + "b";
    const result = await verifyReceiptEnvelope(
      vector.envelope as unknown as Parameters<typeof verifyReceiptEnvelope>[0],
      baseOptions(vector, wrongChain)
    );
    expect(result.outcome).toBe("rejected");
    expect(result.errorCode).toBe("jwks_history_chain_mismatch");
  });

  it("does NOT block on the correct recomputed chain", async () => {
    const vector = loadHappyVector();
    const { entries } = buildHistory(
      vector.verify_options.jwks,
      vector.verify_options.currentTime,
      "0".repeat(64)
    );
    const correctChain = rollingChain(entries);
    const result = await verifyReceiptEnvelope(
      vector.envelope as unknown as Parameters<typeof verifyReceiptEnvelope>[0],
      baseOptions(vector, correctChain)
    );
    // Chain check passes → verification proceeds (no chain error surfaced).
    expect(result.errorCode).not.toBe("jwks_history_chain_mismatch");
  });

  it("skips honoring for the opaque all-zeros stub chain (back-compat)", async () => {
    const vector = loadHappyVector();
    const result = await verifyReceiptEnvelope(
      vector.envelope as unknown as Parameters<typeof verifyReceiptEnvelope>[0],
      baseOptions(vector, "0".repeat(64))
    );
    expect(result.errorCode).not.toBe("jwks_history_chain_mismatch");
  });
});

// ---------------------------------------------------------------------------
// C3 — package verifier accepts the legacy compact payload
// ---------------------------------------------------------------------------

describe("C3 — verifyTrustReceipt legacy-compact recognition", () => {
  const KID = "legacy-kid-001";

  async function makeKeys(): Promise<{ pub: PublicJwk; priv: JWK }> {
    const { publicKey, privateKey } = await generateKeyPair("EdDSA", {
      extractable: true,
    });
    const pub = { ...(await exportJWK(publicKey)), kid: KID, alg: "EdDSA" };
    return { pub, priv: await exportJWK(privateKey) };
  }

  async function signLegacy(priv: JWK): Promise<string> {
    const payload = {
      iss: "merchant:m-legacy",
      sub: "call-legacy-1",
      iat: Math.floor(Date.now() / 1000),
      callId: "call-legacy-1",
      merchantId: "m-legacy",
      agentId: "agent-legacy",
      bucket: "checkout",
      tool: "complete_checkout",
      inputHash: "a".repeat(64),
      outputHash: "b".repeat(64),
      outputHashStatus: "captured",
      trust_provider_assertions: [],
      kid: KID,
    };
    const key = await (await import("jose")).importJWK(priv, "EdDSA");
    return new CompactSign(new TextEncoder().encode(JSON.stringify(payload)))
      .setProtectedHeader({ alg: "EdDSA", kid: KID, typ: "trust-receipt+jwt" })
      .sign(key);
  }

  it("accepts a legacy compact receipt and tags variant=legacy_compact", async () => {
    const { pub, priv } = await makeKeys();
    const jws = await signLegacy(priv);
    const res = await verifyTrustReceipt(jws, { jwks: [pub] });
    expect(res.valid).toBe(true);
    expect(res.variant).toBe("legacy_compact");
    expect(res.legacyReceipt?.callId).toBe("call-legacy-1");
  });

  it("still rejects genuinely-invalid payloads (no legacy fingerprint)", async () => {
    const { pub, priv } = await makeKeys();
    const key = await (await import("jose")).importJWK(priv, "EdDSA");
    const jws = await new CompactSign(
      new TextEncoder().encode(JSON.stringify({ hello: "world" }))
    )
      .setProtectedHeader({ alg: "EdDSA", kid: KID })
      .sign(key);
    const res = await verifyTrustReceipt(jws, { jwks: [pub] });
    expect(res.valid).toBe(false);
    expect(res.reason).toBe("schema_invalid");
  });
});
