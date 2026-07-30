/**
 * Trust-receipts audit 2026-07-26 §R1 — revocation check for third parties.
 *
 * A revocation registry nobody can query revokes nothing. This is the consumer
 * half of `/.well-known/trust-receipt-status/{merchantId}`: it answers "is THIS
 * receipt revoked?" against a status list the caller has already fetched.
 *
 * ## Deliberately offline and pure
 *
 * No fetch, no cache, no clock. The verifier's whole value is that it can be run
 * against a receipt handed to you on a USB stick in a dispute, and a library
 * that silently reaches the network cannot be run in that setting — nor audited
 * as easily. The caller fetches the list (the receipt's own `issuer` and
 * `merchant_id` say where from) and passes the parsed JSON in.
 *
 * ## Why "no list" is NOT "not revoked"
 *
 * `checkRevocation` returns three states, never two. Collapsing "the list says
 * nothing about this receipt" and "I could not obtain a list" into one boolean
 * is precisely how a relying party ends up accepting receipts signed with a
 * compromised key: the fetch fails, the boolean says false, the receipt passes.
 * The caller has to decide what an `unknown` means for its own risk appetite —
 * this library refuses to decide it silently.
 */

import { createHash } from "node:crypto";

/** Entry as published by the status endpoint. */
export interface StatusListEntry {
  readonly receipt_id_hash: string;
  readonly reason: string;
  readonly revoked_at: string;
}

/** The published document, in the fields this check depends on. */
export interface TrustReceiptStatusList {
  readonly status_list_version?: string;
  readonly merchant_id?: string;
  readonly hash_alg?: string;
  readonly revoked?: readonly StatusListEntry[];
  readonly signed?: boolean;
  readonly signature?: string | null;
}

export type RevocationStatus = "revoked" | "not_revoked" | "unknown";

export interface RevocationResult {
  readonly status: RevocationStatus;
  /** Present only when `status === "revoked"`. */
  readonly reason?: string;
  /** Present only when `status === "revoked"`. ISO-8601. */
  readonly revokedAt?: string;
  /** Why the answer is `unknown`. Never set otherwise. */
  readonly unknownReason?:
    | "no_status_list"
    | "merchant_mismatch"
    | "unsupported_hash_alg"
    | "unsupported_list_version"
    | "malformed_status_list";
  /**
   * `true` when the list carried no cryptographic authorship. The result is
   * still reported — an unsigned list naming your receipt is a reason to
   * investigate, not to ignore — but a caller MUST NOT treat an unsigned
   * `not_revoked` as authoritative.
   */
  readonly listUnsigned: boolean;
}

const SUPPORTED_VERSION_PREFIX = "trust-receipt-status/v1";

/**
 * SHA-256 hex of the receipt id — the published key.
 *
 * Must stay byte-identical to `hashReceiptId` in
 * `apps/api/src/services/trust/receipt-revocation.service.ts`. Unsalted on
 * purpose: the only party that can perform this lookup is one already holding
 * the receipt, so a secret in the derivation would lock out the sole intended
 * user.
 */
export function hashReceiptId(receiptId: string): string {
  return createHash("sha256").update(receiptId, "utf8").digest("hex");
}

export interface CheckRevocationInput {
  /** `receipt_id` from the receipt body. */
  readonly receiptId: string;
  /** `merchant_id` from the receipt body, to catch a list fetched for the wrong issuer. */
  readonly merchantId?: string;
  /** The parsed status list, or `null`/`undefined` when it could not be obtained. */
  readonly statusList?: TrustReceiptStatusList | null;
}

/**
 * Answers whether a receipt appears on a merchant's revocation status list.
 *
 * Every failure mode resolves to `unknown` with a machine-readable
 * `unknownReason`, never to `not_revoked`. A check that cannot be performed is
 * not a clean bill of health.
 */
export function checkRevocation(input: CheckRevocationInput): RevocationResult {
  const list = input.statusList;

  if (list === null || list === undefined) {
    return {
      status: "unknown",
      unknownReason: "no_status_list",
      listUnsigned: true,
    };
  }

  const listUnsigned = list.signed !== true;

  if (
    list.status_list_version !== undefined &&
    !list.status_list_version.startsWith(SUPPORTED_VERSION_PREFIX)
  ) {
    // A future major version may key entries differently. Guessing would risk
    // reporting `not_revoked` because we looked in the wrong place.
    return {
      status: "unknown",
      unknownReason: "unsupported_list_version",
      listUnsigned,
    };
  }

  if (
    input.merchantId !== undefined &&
    list.merchant_id !== undefined &&
    list.merchant_id !== input.merchantId
  ) {
    // Another issuer's list says nothing about this receipt, and treating its
    // silence as `not_revoked` would let a wrong fetch mask a real revocation.
    return {
      status: "unknown",
      unknownReason: "merchant_mismatch",
      listUnsigned,
    };
  }

  if (list.hash_alg !== undefined && list.hash_alg !== "sha-256") {
    return {
      status: "unknown",
      unknownReason: "unsupported_hash_alg",
      listUnsigned,
    };
  }

  if (!Array.isArray(list.revoked)) {
    return {
      status: "unknown",
      unknownReason: "malformed_status_list",
      listUnsigned,
    };
  }

  const target = hashReceiptId(input.receiptId);
  const hit = list.revoked.find((entry) => entry?.receipt_id_hash === target);

  if (hit) {
    return {
      status: "revoked",
      reason: hit.reason,
      revokedAt: hit.revoked_at,
      listUnsigned,
    };
  }

  return { status: "not_revoked", listUnsigned };
}
