/**
 * Trust-receipts audit 2026-07-26 §R1 — consumer-side revocation check.
 *
 * The property under test is almost entirely about what must NOT collapse into
 * `not_revoked`. A relying party that treats "I could not check" as "it is fine"
 * accepts receipts signed with a compromised key, which is the exact scenario
 * the registry exists for.
 */

import { describe, it, expect, beforeAll } from "vitest";
import { CompactSign, exportJWK, generateKeyPair, importJWK } from "jose";
import type { JWK } from "jose";
import { computeManifestHash } from "./helpers/manifest-hash.js";

import {
  checkRevocation,
  hashReceiptId,
  verifyStatusList,
  type AuthenticatedStatusList,
  type TrustReceiptStatusList,
} from "../revocation.js";

// Only an AUTHENTICATED list can answer revoked / not_revoked, so the
// positive-path tests sign their lists for real.
const NOW = 1_800_000_000;
let privJwk: JWK;
let pubJwk: JWK;
beforeAll(async () => {
  const kp = await generateKeyPair("EdDSA", { extractable: true });
  privJwk = await exportJWK(kp.privateKey);
  pubJwk = { ...(await exportJWK(kp.publicKey)), kid: "k1", alg: "EdDSA" };
});

/** Signs `overrides` on top of the default list and authenticates it. */
async function authed(
  overrides: Partial<TrustReceiptStatusList> = {}
): Promise<AuthenticatedStatusList> {
  const revoked = overrides.revoked ?? [];
  const body = {
    status_list_version: "trust-receipt-status/v1",
    merchant_id: overrides.merchant_id ?? "store_1",
    issued_at: new Date((NOW - 10) * 1000).toISOString(),
    hash_alg: "sha-256" as const,
    revoked_count: revoked.length,
    revoked,
  };
  const jws = await new CompactSign(
    new TextEncoder().encode(
      JSON.stringify({
        iss: `merchant:${body.merchant_id}`,
        sub: "catalog:trust-receipt-status-list",
        iat: NOW - 10,
        exp: NOW + 3600,
        manifest_hash: computeManifestHash(body),
        kid: "k1",
        v: 1,
      })
    )
  )
    .setProtectedHeader({ alg: "EdDSA", kid: "k1", typ: "JWT" })
    .sign(await importJWK(privJwk, "EdDSA"));
  const res = await verifyStatusList(
    { ...body, signed: true, signature: jws },
    { keys: [pubJwk] },
    { expectedIssuer: `merchant:${body.merchant_id}`, now: NOW }
  );
  if (!res.ok) throw new Error(`fixture failed to authenticate: ${res.reason}`);
  return res.list;
}

const RECEIPT_ID = "11111111-1111-4111-8111-111111111111";

function list(
  overrides: Partial<TrustReceiptStatusList> = {}
): TrustReceiptStatusList {
  return {
    status_list_version: "trust-receipt-status/v1",
    merchant_id: "store_1",
    hash_alg: "sha-256",
    revoked: [],
    signed: true,
    signature: "a.b.c",
    ...overrides,
  };
}

describe("checkRevocation", () => {
  it("reports a listed receipt as revoked, with reason and instant", async () => {
    const result = checkRevocation({
      receiptId: RECEIPT_ID,
      merchantId: "store_1",
      statusList: await authed({
        revoked: [
          {
            receipt_id_hash: hashReceiptId(RECEIPT_ID),
            reason: "key_compromise",
            revoked_at: "2026-07-28T11:00:00.000Z",
          },
        ],
      }),
    });

    expect(result.status).toBe("revoked");
    expect(result.reason).toBe("key_compromise");
    expect(result.revokedAt).toBe("2026-07-28T11:00:00.000Z");
  });

  it("reports an absent receipt as not_revoked against an authenticated list", async () => {
    expect(
      checkRevocation({
        receiptId: RECEIPT_ID,
        merchantId: "store_1",
        statusList: await authed(),
      }).status
    ).toBe("not_revoked");
  });

  it.each([
    ["a missing list", undefined, "no_status_list"],
    ["an explicitly unavailable list", null, "no_status_list"],
  ])("returns unknown, NOT not_revoked, for %s", (_label, value, reason) => {
    const result = checkRevocation({
      receiptId: RECEIPT_ID,
      statusList: value as null | undefined,
    });

    // The whole point: a failed fetch must never read as a clean bill of health.
    expect(result.status).toBe("unknown");
    expect(result.unknownReason).toBe(reason);
  });

  it("returns unknown when the list belongs to a different merchant", () => {
    const result = checkRevocation({
      receiptId: RECEIPT_ID,
      merchantId: "store_1",
      statusList: list({ merchant_id: "store_2" }),
    });

    expect(result.status).toBe("unknown");
    expect(result.unknownReason).toBe("merchant_mismatch");
  });

  it("returns unknown for a hash algorithm it cannot compute", () => {
    const result = checkRevocation({
      receiptId: RECEIPT_ID,
      statusList: list({ hash_alg: "blake3" }),
    });

    expect(result.status).toBe("unknown");
    expect(result.unknownReason).toBe("unsupported_hash_alg");
  });

  it("returns unknown for a future major list version", () => {
    const result = checkRevocation({
      receiptId: RECEIPT_ID,
      statusList: list({ status_list_version: "trust-receipt-status/v2" }),
    });

    // v2 may key entries differently; looking in the wrong place and reporting
    // not_revoked would be worse than admitting we cannot read it.
    expect(result.status).toBe("unknown");
    expect(result.unknownReason).toBe("unsupported_list_version");
  });

  it("returns unknown for a malformed list rather than assuming it is empty", () => {
    const result = checkRevocation({
      receiptId: RECEIPT_ID,
      statusList: { revoked: "nope" } as unknown as TrustReceiptStatusList,
    });

    expect(result.status).toBe("unknown");
    expect(result.unknownReason).toBe("malformed_status_list");
  });

  it("an unauthenticated list naming the receipt is unknown, flagged, never revoked", () => {
    const result = checkRevocation({
      receiptId: RECEIPT_ID,
      merchantId: "store_1",
      statusList: list({
        signed: true,
        signature: "not.a.jws",
        revoked: [
          {
            receipt_id_hash: hashReceiptId(RECEIPT_ID),
            reason: "issued_in_error",
            revoked_at: "2026-07-28T11:00:00.000Z",
          },
        ],
      }),
    });

    // Anyone can write that JSON: neither a revocation nor a clean bill.
    expect(result.status).toBe("unknown");
    expect(result.unknownReason).toBe("list_not_authenticated");
    expect(result.unauthenticatedListNamesReceipt).toBe(true);
    expect(result.listUnsigned).toBe(true);
  });

  it("never reports revoked on a hash collision with another receipt's entry", async () => {
    const result = checkRevocation({
      receiptId: RECEIPT_ID,
      merchantId: "store_1",
      statusList: await authed({
        revoked: [
          {
            receipt_id_hash: hashReceiptId("some-other-receipt"),
            reason: "superseded",
            revoked_at: "2026-07-28T11:00:00.000Z",
          },
        ],
      }),
    });

    expect(result.status).toBe("not_revoked");
  });
});
