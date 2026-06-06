/**
 * Spec 054 T074 — Portable Delegation Validator (FR-008a).
 *
 * Stateless mirror of the server-side `DelegationResolverService`
 * (`apps/api/src/services/trust/x402-binding/delegation-resolver.service.ts`).
 * Receives a JWKS document directly (NO network I/O) and resolves a receipt's
 * signing kid through one of two mutually exclusive branches:
 *
 *   - Branch A (direct issuer):
 *       kid ∈ jwks.keys[], with `use === "sig"` AND
 *       `kid_uses` includes the marker `"receipt-issuance"`.
 *   - Branch B (delegated issuer):
 *       kid ∈ jwks.authorized_delegates[], whose `authorization_signature`
 *       Ed25519-verifies against the merchant_root_kid's public key in
 *       jwks.keys[], with `receiptIssuedAt ∈ [valid_from, valid_until]`
 *       (inclusive on both bounds), and the delegate's own kid must also be
 *       present in jwks.keys[] with `use === "sig"` for downstream receipt
 *       signature verification.
 *
 * Cross-merchant replay defense: the canonical signing input bound to a
 * delegation MUST include `merchant_root_kid`. This prevents an attacker
 * holding a valid `authorization_signature` issued under merchant A's root
 * from reusing it inside merchant B's JWKS to authorize the same delegate
 * kid — tampering with `merchant_root_kid` invalidates the signature.
 *
 * This module is PORTABLE: it relies only on `node:crypto` and the
 * `canonicalize` (JCS, RFC 8785) package. No filesystem, no env, no Prisma.
 *
 * @see specs/058-trustreceipt-x402-binding/spec.md §FR-008a
 * @see specs/058-trustreceipt-x402-binding/tasks.md T074 T075
 */

import { createPublicKey, verify as cryptoVerify } from "node:crypto";
import canonicalize from "canonicalize";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface JwksKey {
  readonly kty: "OKP";
  readonly crv: "Ed25519";
  readonly kid: string;
  readonly use: "sig";
  readonly kid_uses?: readonly string[];
  readonly x: string;
  readonly [key: string]: unknown;
}

export interface AuthorizedDelegate {
  readonly kid: string;
  readonly role: string;
  readonly valid_from: string;
  readonly valid_until: string;
  readonly merchant_root_kid: string;
  readonly authorization_signature: string;
}

export interface MerchantJwksDocument {
  readonly keys: readonly JwksKey[];
  readonly authorized_delegates?: readonly AuthorizedDelegate[];
}

export type DelegationValidationOutcome =
  | "accepted_direct"
  | "accepted_delegated"
  | "unknown_kid"
  | "delegation_signature_invalid"
  | "delegation_out_of_window"
  | "delegate_merchant_root_kid_missing"
  | "jwks_invalid_shape";

export interface DelegationValidationResult {
  readonly outcome: DelegationValidationOutcome;
  readonly branch?: "direct" | "delegated";
  /** When accepted, the public-key JWK used to verify the receipt signature. */
  readonly publicKeyJwk?: JwksKey;
  /** When `accepted_delegated`, the merchant-root kid that authorized the delegation. */
  readonly merchantRootKid?: string;
  /** When `accepted_delegated`, the role the delegate operates under. */
  readonly delegateRole?: string;
  /** Diagnostic reason for non-accepted outcomes; never carries secrets. */
  readonly reason?: string;
}

export interface ValidateDelegationArgs {
  readonly jwks: MerchantJwksDocument;
  readonly receiptKid: string;
  /** RFC 3339 / ISO 8601 timestamp at which the receipt was issued. */
  readonly receiptIssuedAt: string;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const RECEIPT_ISSUANCE_MARKER = "receipt-issuance" as const;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function isJwksKey(value: unknown): value is JwksKey {
  if (typeof value !== "object" || value === null) return false;
  const k = value as Record<string, unknown>;
  return (
    k.kty === "OKP" &&
    k.crv === "Ed25519" &&
    typeof k.kid === "string" &&
    typeof k.x === "string"
  );
}

function decodeBase64Url(input: string): Buffer {
  // Buffer's "base64url" decoding tolerates missing padding.
  return Buffer.from(input, "base64url");
}

function parseIsoTimestamp(value: string): Date | null {
  if (typeof value !== "string" || value.length === 0) return null;
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return null;
  return parsed;
}

function findSigKey(
  keys: readonly JwksKey[],
  kid: string
): JwksKey | undefined {
  return keys.find((k) => k.kid === kid && k.use === "sig");
}

function hasReceiptIssuanceMarker(key: JwksKey): boolean {
  return (
    Array.isArray(key.kid_uses) &&
    key.kid_uses.includes(RECEIPT_ISSUANCE_MARKER)
  );
}

/**
 * Build the JCS canonical payload bound to a delegation authorization.
 * The merchant_root_kid is included so the signature is cryptographically
 * bound to a specific merchant root (cross-merchant replay defense).
 */
function canonicalizeDelegationPayload(entry: AuthorizedDelegate): string {
  const payload = {
    kid: entry.kid,
    role: entry.role,
    valid_from: entry.valid_from,
    valid_until: entry.valid_until,
    merchant_root_kid: entry.merchant_root_kid,
  };
  const canonical = canonicalize(payload);
  if (typeof canonical !== "string") {
    // canonicalize returns undefined for non-JSON values (e.g. functions).
    // Our payload is built from plain strings, so this is unreachable in
    // practice; guard for defensive purposes.
    throw new Error("delegation payload failed JCS canonicalization");
  }
  return canonical;
}

function verifyDelegationSignature(
  entry: AuthorizedDelegate,
  merchantRoot: JwksKey
): boolean {
  let canonical: string;
  try {
    canonical = canonicalizeDelegationPayload(entry);
  } catch {
    return false;
  }
  let signature: Buffer;
  try {
    signature = decodeBase64Url(entry.authorization_signature);
  } catch {
    return false;
  }
  let publicKey;
  try {
    publicKey = createPublicKey({
      key: {
        kty: "OKP",
        crv: "Ed25519",
        x: merchantRoot.x,
      },
      format: "jwk",
    });
  } catch {
    return false;
  }
  try {
    return cryptoVerify(
      null,
      Buffer.from(canonical, "utf8"),
      publicKey,
      signature
    );
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * FR-008a stateless delegation validator. Never throws on validation failure;
 * always returns a typed `DelegationValidationResult`.
 */
export function validateDelegation(
  args: ValidateDelegationArgs
): DelegationValidationResult {
  const { jwks, receiptKid, receiptIssuedAt } = args;

  // ---- Schema sanity --------------------------------------------------------
  if (
    !jwks ||
    typeof jwks !== "object" ||
    !Array.isArray((jwks as { keys?: unknown }).keys)
  ) {
    return {
      outcome: "jwks_invalid_shape",
      reason: "JWKS document is missing a `keys` array.",
    };
  }
  const keys = jwks.keys.filter(isJwksKey);
  // If the caller passed a `keys` array with malformed entries, the survivors
  // are still usable. We do NOT reject the whole document — additional entries
  // (e.g., RSA enc keys) might legitimately be present in extended JWKS.

  const delegates = Array.isArray(jwks.authorized_delegates)
    ? jwks.authorized_delegates
    : [];

  // ---- Branch A: direct issuer ---------------------------------------------
  const directKey = keys.find(
    (k) =>
      k.kid === receiptKid && k.use === "sig" && hasReceiptIssuanceMarker(k)
  );
  if (directKey) {
    return {
      outcome: "accepted_direct",
      branch: "direct",
      publicKeyJwk: directKey,
    };
  }

  // ---- Branch B: delegated issuer ------------------------------------------
  const delegateEntry = delegates.find((d) => d?.kid === receiptKid);
  if (delegateEntry) {
    // (a) Merchant root must exist as a sig key.
    const merchantRoot = findSigKey(keys, delegateEntry.merchant_root_kid);
    if (!merchantRoot) {
      return {
        outcome: "delegate_merchant_root_kid_missing",
        reason: `Merchant root kid '${delegateEntry.merchant_root_kid}' not found in keys[].`,
      };
    }

    // (b)(c)(d)(e) Verify Ed25519 signature over JCS(payload).
    if (!verifyDelegationSignature(delegateEntry, merchantRoot)) {
      return {
        outcome: "delegation_signature_invalid",
        reason: "Authorization signature failed Ed25519 verification.",
      };
    }

    // (f) Parse validity window timestamps.
    const validFrom = parseIsoTimestamp(delegateEntry.valid_from);
    const validUntil = parseIsoTimestamp(delegateEntry.valid_until);
    const issuedAt = parseIsoTimestamp(receiptIssuedAt);
    if (!validFrom || !validUntil || !issuedAt) {
      return {
        outcome: "delegation_signature_invalid",
        reason: "Invalid timestamp in delegation entry or receipt issuedAt.",
      };
    }

    // (g) Inclusive bounds check.
    if (
      issuedAt.getTime() < validFrom.getTime() ||
      issuedAt.getTime() > validUntil.getTime()
    ) {
      return {
        outcome: "delegation_out_of_window",
        reason: `Receipt issued_at ${receiptIssuedAt} outside [${delegateEntry.valid_from}, ${delegateEntry.valid_until}].`,
      };
    }

    // (h) Delegate's own kid must also be in keys[] for downstream verify.
    const delegatePubKey = findSigKey(keys, delegateEntry.kid);
    if (!delegatePubKey) {
      return {
        outcome: "delegate_merchant_root_kid_missing",
        reason: `Delegate kid '${delegateEntry.kid}' not present in keys[].`,
      };
    }

    // (i) Accept.
    return {
      outcome: "accepted_delegated",
      branch: "delegated",
      publicKeyJwk: delegatePubKey,
      merchantRootKid: delegateEntry.merchant_root_kid,
      delegateRole: delegateEntry.role,
    };
  }

  // ---- No branch matched ----------------------------------------------------
  return {
    outcome: "unknown_kid",
    reason: `kid '${receiptKid}' did not match any direct issuer key nor any authorized delegate.`,
  };
}
