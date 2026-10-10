/**
 * A status list is authenticated by its JWS, not
 * by a `signed: true` flag the fetched JSON carries about itself.
 */
import { describe, it, expect, beforeAll } from "vitest";
import { CompactSign, exportJWK, generateKeyPair, importJWK } from "jose";
import type { JWK } from "jose";
import { computeManifestHash } from "./helpers/manifest-hash.js";
import {
  checkRevocation,
  hashReceiptId,
  verifyStatusList,
  type TrustReceiptStatusList,
} from "../revocation.js";

const RECEIPT_ID = "11111111-1111-4111-8111-111111111111";
const KID = "manifest-key-1";
const NOW = 1_800_000_000;
const SUBJECT = "catalog:trust-receipt-status-list";

let priv: JWK;
let pub: JWK;
let otherPriv: JWK;

beforeAll(async () => {
  const a = await generateKeyPair("EdDSA", { extractable: true });
  priv = await exportJWK(a.privateKey);
  pub = { ...(await exportJWK(a.publicKey)), kid: KID, alg: "EdDSA" };
  const b = await generateKeyPair("EdDSA", { extractable: true });
  otherPriv = await exportJWK(b.privateKey);
});

interface Overrides {
  readonly revoked?: TrustReceiptStatusList["revoked"];
  readonly merchant?: string;
  readonly issuedAt?: string;
  readonly iss?: string;
  readonly sub?: string;
  readonly iat?: number;
  readonly exp?: number;
  readonly key?: JWK;
  readonly kid?: string;
  readonly hashOverride?: string;
  readonly alg?: string;
}

async function signedList(o: Overrides = {}): Promise<TrustReceiptStatusList> {
  const revoked = o.revoked ?? [];
  const merchant = o.merchant ?? "store_1";
  const body = {
    status_list_version: "trust-receipt-status/v1",
    merchant_id: merchant,
    issued_at: o.issuedAt ?? new Date((NOW - 60) * 1000).toISOString(),
    hash_alg: "sha-256" as const,
    revoked_count: revoked.length,
    revoked,
  };
  const key = await importJWK(o.key ?? priv, "EdDSA");
  const jws = await new CompactSign(
    new TextEncoder().encode(
      JSON.stringify({
        iss: o.iss ?? `merchant:${merchant}`,
        sub: o.sub ?? SUBJECT,
        iat: o.iat ?? NOW - 60,
        exp: o.exp ?? NOW + 3600,
        manifest_hash: o.hashOverride ?? computeManifestHash(body),
        kid: o.kid ?? KID,
        v: 1,
      })
    )
  )
    .setProtectedHeader({ alg: o.alg ?? "EdDSA", kid: o.kid ?? KID, typ: "JWT" })
    .sign(key);
  return { ...body, signed: true, signature: jws };
}

const anchors = () => ({ keys: [pub] });
const ctx = { expectedIssuer: "merchant:store_1", now: NOW };
const hit = (): TrustReceiptStatusList["revoked"] => [
  {
    receipt_id_hash: hashReceiptId(RECEIPT_ID),
    reason: "key_compromise",
    revoked_at: "2026-07-28T11:00:00.000Z",
  },
];

describe("verifyStatusList", () => {
  it("authenticates a correctly signed list and checkRevocation then answers", async () => {
    const res = await verifyStatusList(await signedList({ revoked: hit() }), anchors(), ctx);
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    const r = checkRevocation({ receiptId: RECEIPT_ID, merchantId: "store_1", statusList: res.list });
    expect(r.status).toBe("revoked");
    expect(r.listUnsigned).toBe(false);
  });

  it("repro: { signed: true, signature: 'invalid', revoked: [] } is unknown, NOT not_revoked", () => {
    const r = checkRevocation({
      receiptId: RECEIPT_ID,
      statusList: { signed: true, signature: "invalid", revoked: [] } as TrustReceiptStatusList,
    });
    expect(r.status).toBe("unknown");
    expect(r.unknownReason).toBe("list_not_authenticated");
  });

  it("a hand-built object cannot masquerade as authenticated (no forgeable brand)", async () => {
    const res = await verifyStatusList(await signedList(), anchors(), ctx);
    if (!res.ok) throw new Error("setup");
    const forged = { ...res.list, revoked: [] };
    expect(
      checkRevocation({ receiptId: RECEIPT_ID, statusList: forged as never }).status
    ).toBe("unknown");
  });

  it.each<[string, () => Promise<TrustReceiptStatusList>, string]>([
    ["tampered revoked[] after signing", async () => ({ ...(await signedList({ revoked: hit() })), revoked: [], revoked_count: 0 }), "manifest_hash_mismatch"],
    ["signed by a key not in the anchors", async () => signedList({ key: otherPriv }), "signature_invalid"],
    ["kid unknown to the anchors", async () => signedList({ kid: "nope" }), "unknown_kid"],
    ["wrong issuer", async () => signedList({ iss: "merchant:store_2" }), "issuer_mismatch"],
    ["wrong subject", async () => signedList({ sub: "mcp.json" }), "subject_mismatch"],
    ["expired signature", async () => signedList({ exp: NOW - 1 }), "expired"],
    ["issued_at in the future", async () => signedList({ issuedAt: new Date((NOW + 7200) * 1000).toISOString() }), "issued_at_in_future"],
    ["merchant_id differs from issuer", async () => ({ ...(await signedList()), merchant_id: "store_2" }), "manifest_hash_mismatch"],
  ])("rejects: %s", async (_l, build, reason) => {
    const res = await verifyStatusList(await build(), anchors(), ctx);
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe(reason);
  });

  it("rejects an unsigned list (signature null)", async () => {
    const res = await verifyStatusList({ ...(await signedList()), signed: false, signature: null }, anchors(), ctx);
    expect(res).toEqual({ ok: false, reason: "not_signed" });
  });

  it("a rejected list can never reach checkRevocation as authenticated", async () => {
    const tampered = { ...(await signedList({ revoked: hit() })), revoked: [], revoked_count: 0 };
    const res = await verifyStatusList(tampered, anchors(), ctx);
    expect(res.ok).toBe(false);
    const r = checkRevocation({ receiptId: RECEIPT_ID, statusList: tampered });
    expect(r.status).toBe("unknown");
  });
});
