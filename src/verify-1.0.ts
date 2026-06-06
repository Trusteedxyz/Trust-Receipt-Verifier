/**
 * TrustReceipt v1.0 verification entry point.
 *
 * Spec-049 — eIDAS hardening (FR-018):
 *   v1.0 receipts MUST continue to verify after the v1.1 cutover. When this
 *   verifier is invoked from the v1.1 dispatcher (T052), the dispatcher will
 *   tag the result with the warning `legacy_pre_eidas_hardening` so callers
 *   can surface a soft-deprecation signal without breaking interop.
 *
 * Codex round 1 — D11 (cutover semantics):
 *   This file is a pure re-export / thin-wrapper of the pre-existing v1.0
 *   verification logic in `./verifier.ts`. The behavior MUST remain byte-for-byte
 *   identical to the v1.0 verifier shipped before spec-049; T052 introduces a
 *   schema-version dispatcher that routes "1.0" payloads here and "1.1"
 *   payloads to the hardened verifier. Do NOT extend v1.0 semantics here.
 *
 * @see specs/049-trust-receipt-eidas-hardening/spec.md FR-018
 */

import {
  verifyTrustReceipt,
  type VerifyOptions,
  type VerifyResult,
  type PublicJwk,
} from "./verifier.js";
import type { TrustReceipt } from "./schema/trust-receipt.schema.js";

// ─── Public types ─────────────────────────────────────────────────────────────

export interface V10VerifyResult {
  outcome: "accepted" | "rejected";
  schema_version: "1.0";
  /**
   * Soft-warning channel. The v1.1 dispatcher (T052) appends
   * `"legacy_pre_eidas_hardening"` here when routing a v1.0 receipt under the
   * v1.1 cutover. The standalone v1.0 verifier itself emits no warnings.
   */
  warnings: string[];
  /** Populated only when outcome === "rejected". */
  errors?: string[];
  /**
   * Parsed receipt body (raw JSON object, untyped at this v1.0 layer).
   * Always present when outcome === "accepted"; may be present on certain
   * "rejected" paths where the schema parsed but a temporal/kid check failed
   * (preserving the legacy `verifyTrustReceipt` behavior).
   */
  receipt?: object;
}

export interface VerifyV10Options {
  /** Inline public JWK set. */
  jwks: PublicJwk[];
  /** Clock tolerance in seconds. Default: 30. */
  clockToleranceSeconds?: number;
}

// ─── Thin wrapper ─────────────────────────────────────────────────────────────

/**
 * Verify a v1.0 TrustReceipt compact JWS.
 *
 * Behavioral contract: identical to {@link verifyTrustReceipt} for v1.0
 * payloads. Returns a normalized `{ outcome, schema_version, warnings, ... }`
 * shape suitable for the T052 dispatcher.
 *
 * Accepts the JWKS as either an array of {@link PublicJwk} or a JWKS object
 * `{ keys: PublicJwk[] }` for ergonomic parity with the dispatcher contract.
 */
export async function verifyReceiptV10(
  jws: string,
  jwks: object
): Promise<V10VerifyResult> {
  const keys = normalizeJwks(jwks);

  if (keys === null) {
    return {
      outcome: "rejected",
      schema_version: "1.0",
      warnings: [],
      errors: ["jwks must be an array of JWKs or { keys: JWK[] }"],
    };
  }

  const opts: VerifyOptions = { jwks: keys };
  const inner: VerifyResult = await verifyTrustReceipt(jws, opts);

  if (inner.valid && inner.receipt) {
    return {
      outcome: "accepted",
      schema_version: "1.0",
      warnings: [],
      receipt: inner.receipt as unknown as object,
    };
  }

  const errors: string[] = [];
  if (inner.reason) errors.push(inner.reason);
  if (inner.errors && inner.errors.length > 0) errors.push(...inner.errors);

  const result: V10VerifyResult = {
    outcome: "rejected",
    schema_version: "1.0",
    warnings: [],
    errors,
  };
  if (inner.receipt) {
    result.receipt = inner.receipt as unknown as object;
  }
  return result;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

interface JwksObject {
  keys: PublicJwk[];
}

function isJwksObject(value: object): value is JwksObject {
  const maybe = value as { keys?: unknown };
  return Array.isArray(maybe.keys);
}

function normalizeJwks(jwks: object): PublicJwk[] | null {
  if (Array.isArray(jwks)) {
    return jwks as PublicJwk[];
  }
  if (jwks && typeof jwks === "object" && isJwksObject(jwks)) {
    return jwks.keys;
  }
  return null;
}

// Re-export the v1.0 receipt type for downstream consumers that want it typed.
export type { TrustReceipt as TrustReceiptV10 };
