/**
 * revocation check for third parties.
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
import { compactVerify, decodeProtectedHeader, importJWK } from "jose";
import type { JWK } from "jose";

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
    | "malformed_status_list"
    | "list_not_authenticated";
  /**
   * Set only with `unknownReason === "list_not_authenticated"`: the
   * UNAUTHENTICATED list names this receipt. Not evidence of revocation (anyone
   * can write that JSON) but a reason to obtain an authenticated list.
   */
  readonly unauthenticatedListNamesReceipt?: boolean;
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
 * the issuing service's `hashReceiptId`. Unsalted on
 * purpose: the only party that can perform this lookup is one already holding
 * the receipt, so a secret in the derivation would lock out the sole intended
 * user.
 */
export function hashReceiptId(receiptId: string): string {
  return createHash("sha256").update(receiptId, "utf8").digest("hex");
}

declare const authenticatedBrand: unique symbol;

/**
 * A status list whose JWS was verified by {@link verifyStatusList}. Membership
 * is tracked in a module-private WeakSet, so the type cannot be produced by a
 * cast, a spread or `JSON.parse`: only `verifyStatusList` mints one.
 */
export type AuthenticatedStatusList = TrustReceiptStatusList & {
  readonly [authenticatedBrand]: true;
};

const AUTHENTICATED = new WeakSet<object>();

export type StatusListRejection =
  | "not_signed"
  | "malformed_jws"
  | "unsupported_alg"
  | "unknown_kid"
  | "bad_anchor_key"
  | "signature_invalid"
  | "payload_invalid"
  | "subject_mismatch"
  | "issuer_mismatch"
  | "kid_mismatch"
  | "expired"
  | "not_yet_valid"
  | "issued_at_invalid"
  | "issued_at_in_future"
  | "manifest_hash_mismatch";

export type VerifyStatusListResult =
  | { readonly ok: true; readonly list: AuthenticatedStatusList }
  | { readonly ok: false; readonly reason: StatusListRejection };

export interface VerifyStatusListContext {
  /** e.g. `merchant:store_1` — the JWS `iss` the caller expects. Required. */
  readonly expectedIssuer: string;
  /** Unix seconds. Injected: this library reads no clock. */
  readonly now: number;
  /** Tolerated clock skew in seconds (default 60). */
  readonly skewSeconds?: number;
}

/** JWS `sub` the platform signs status lists with. */
export const STATUS_LIST_JWS_SUBJECT = "catalog:trust-receipt-status-list";

/**
 * Canonical form of the producer's `manifest_hash` (sorted keys, JSON scalars).
 * Kept local: this package has no dependency on the issuer's code at runtime.
 */
function canonicalStringify(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalStringify).join(",")}]`;
  const o = value as Record<string, unknown>;
  return `{${Object.keys(o)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${canonicalStringify(o[k])}`)
    .join(",")}}`;
}

function statusListManifestHash(list: TrustReceiptStatusList): string {
  const body: Record<string, unknown> = {
    status_list_version: list.status_list_version,
    merchant_id: list.merchant_id,
    issued_at: (list as { issued_at?: unknown }).issued_at,
    hash_alg: list.hash_alg,
    revoked_count: (list as { revoked_count?: unknown }).revoked_count,
    revoked: list.revoked,
  };
  return `sha256:${createHash("sha256").update(canonicalStringify(body)).digest("hex")}`;
}

/**
 * Authenticates a fetched status list against trust anchors (the platform JWKS).
 *
 * Checks, in order: a JWS is present; alg EdDSA; the header `kid` is one of the
 * anchors; the signature; payload `sub`/`iss`/`kid`; `iat`/`exp` against the
 * injected clock; the list's own `issued_at`; and that the JWS `manifest_hash`
 * equals the hash of the list body actually received (the JWS commits only to a
 * hash, so a list edited after signing fails here). `signed: true` on the input
 * means nothing.
 */
export async function verifyStatusList(
  list: TrustReceiptStatusList,
  trustAnchors: { readonly keys: readonly JWK[] },
  ctx: VerifyStatusListContext
): Promise<VerifyStatusListResult> {
  const fail = (reason: StatusListRejection): VerifyStatusListResult => ({
    ok: false,
    reason,
  });
  const jws = list.signature;
  if (typeof jws !== "string" || jws.length === 0) return fail("not_signed");

  let header;
  try {
    header = decodeProtectedHeader(jws);
  } catch {
    return fail("malformed_jws");
  }
  if (header.alg !== "EdDSA") return fail("unsupported_alg");
  const anchor = trustAnchors.keys.find(
    (k) => typeof header.kid === "string" && k.kid === header.kid
  );
  if (!anchor) return fail("unknown_kid");

  let payloadBytes: Uint8Array;
  try {
    const key = await importJWK(anchor, "EdDSA");
    payloadBytes = (await compactVerify(jws, key)).payload;
  } catch (err) {
    const name = err instanceof Error ? err.name : "";
    return fail(name === "JWSSignatureVerificationFailed" ? "signature_invalid" : "bad_anchor_key");
  }

  let p: Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(new TextDecoder().decode(payloadBytes));
    if (typeof parsed !== "object" || parsed === null) return fail("payload_invalid");
    p = parsed as Record<string, unknown>;
  } catch {
    return fail("payload_invalid");
  }
  if (p["sub"] !== STATUS_LIST_JWS_SUBJECT) return fail("subject_mismatch");
  if (p["iss"] !== ctx.expectedIssuer) return fail("issuer_mismatch");
  if (p["kid"] !== header.kid) return fail("kid_mismatch");
  const { iat, exp } = p;
  if (typeof iat !== "number" || typeof exp !== "number") return fail("payload_invalid");
  const skew = ctx.skewSeconds ?? 60;
  if (exp <= ctx.now) return fail("expired");
  if (iat > ctx.now + skew) return fail("not_yet_valid");

  const issuedAtMs = Date.parse(
    String((list as { issued_at?: unknown }).issued_at ?? "")
  );
  if (Number.isNaN(issuedAtMs)) return fail("issued_at_invalid");
  if (issuedAtMs / 1000 > ctx.now + skew) return fail("issued_at_in_future");

  if (p["manifest_hash"] !== statusListManifestHash(list)) {
    return fail("manifest_hash_mismatch");
  }

  const authenticated = { ...list } as AuthenticatedStatusList;
  AUTHENTICATED.add(authenticated);
  return { ok: true, list: authenticated };
}

export interface CheckRevocationInput {
  /** `receipt_id` from the receipt body. */
  readonly receiptId: string;
  /** `merchant_id` from the receipt body, to catch a list fetched for the wrong issuer. */
  readonly merchantId?: string;
  /**
   * The list, or `null`/`undefined` when it could not be obtained. Pass the
   * result of {@link verifyStatusList}. A plain `TrustReceiptStatusList` is
   * accepted for source compatibility only and always yields `unknown`
   * (`list_not_authenticated`): `signed: true` in fetched JSON proves nothing.
   *
   * @deprecated passing an unauthenticated `TrustReceiptStatusList`.
   */
  readonly statusList?:
    | AuthenticatedStatusList
    | TrustReceiptStatusList
    | null;
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

  const authenticated = AUTHENTICATED.has(list);
  const listUnsigned = !authenticated;

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

  if (!authenticated) {
    // The list's own `signed` flag is data an attacker controls. Without a
    // verified JWS neither "revoked" nor "not_revoked" is an answer.
    return {
      status: "unknown",
      unknownReason: "list_not_authenticated",
      unauthenticatedListNamesReceipt: hit !== undefined,
      listUnsigned: true,
    };
  }

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
