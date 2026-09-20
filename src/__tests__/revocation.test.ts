/**
 * Trust-receipts audit 2026-07-26 §R1 — consumer-side revocation check.
 *
 * The property under test is almost entirely about what must NOT collapse into
 * `not_revoked`. A relying party that treats "I could not check" as "it is fine"
 * accepts receipts signed with a compromised key, which is the exact scenario
 * the registry exists for.
 */

import { describe, it, expect } from "vitest";

import {
  checkRevocation,
  hashReceiptId,
  type TrustReceiptStatusList,
} from "../revocation.js";

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
  it("reports a listed receipt as revoked, with reason and instant", () => {
    const result = checkRevocation({
      receiptId: RECEIPT_ID,
      merchantId: "store_1",
      statusList: list({
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

  it("reports an absent receipt as not_revoked against a well-formed list", () => {
    expect(
      checkRevocation({
        receiptId: RECEIPT_ID,
        merchantId: "store_1",
        statusList: list(),
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

  it("flags an unsigned list while still reporting the revocation it names", () => {
    const result = checkRevocation({
      receiptId: RECEIPT_ID,
      merchantId: "store_1",
      statusList: list({
        signed: false,
        signature: null,
        revoked: [
          {
            receipt_id_hash: hashReceiptId(RECEIPT_ID),
            reason: "issued_in_error",
            revoked_at: "2026-07-28T11:00:00.000Z",
          },
        ],
      }),
    });

    // An unsigned list naming your receipt is a reason to investigate, not to
    // ignore — but `listUnsigned` is what stops an unsigned `not_revoked` from
    // being treated as authoritative.
    expect(result.status).toBe("revoked");
    expect(result.listUnsigned).toBe(true);
  });

  it("never reports revoked on a hash collision with another receipt's entry", () => {
    const result = checkRevocation({
      receiptId: RECEIPT_ID,
      merchantId: "store_1",
      statusList: list({
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
