/**
 * TrustReceipt issuer helper.
 *
 * Issues compact JWS TrustReceipt tokens signed with Ed25519 (EdDSA).
 * Auto-populates receipt_id, issued_at, expires_at, schema_version.
 * No Prisma/DB dependency — standalone.
 */

import { CompactSign, importJWK, type JWK } from "jose";

// ─── RFC 8785 canonical JSON ──────────────────────────────────────────────────

/**
 * Minimal RFC 8785 (JCS) canonical JSON serializer.
 *
 * Required by the TrustReceipt SPEC §2 for deterministic cross-language
 * interoperability. Key properties: keys sorted alphabetically, no extra
 * whitespace, recursive. Does not handle BigInt or special number values
 * (±Infinity, NaN) — those cannot appear in a TrustReceipt payload.
 */
function canonicalizeJson(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") return JSON.stringify(value);
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return "[" + value.map(canonicalizeJson).join(",") + "]";
  }
  const obj = value as Record<string, unknown>;
  const sorted = Object.keys(obj)
    .sort()
    .map((k) => JSON.stringify(k) + ":" + canonicalizeJson(obj[k]));
  return "{" + sorted.join(",") + "}";
}
import { randomUUID } from "node:crypto";
import type { TrustReceipt } from "./schema/trust-receipt.schema.js";

// ─── Types ────────────────────────────────────────────────────────────────────

type ReceiptCoreFields =
  | "receipt_id"
  | "issued_at"
  | "expires_at"
  | "schema_version"
  | "signature";

export interface IssueOptions {
  /** All TrustReceipt fields except auto-populated core fields and signature. */
  payload: Omit<TrustReceipt, ReceiptCoreFields>;
  /** Ed25519 private key in JWK format. */
  privateKeyJwk: JWK;
  /** Key ID — must match a key in the verifier's JWKS. */
  kid: string;
  /** Token validity duration in seconds. Default: 3600. */
  validitySeconds?: number;
}

// ─── Constants ────────────────────────────────────────────────────────────────

const ALGORITHM = "EdDSA";
const DEFAULT_VALIDITY_SECONDS = 3600;

// ─── Issuer ───────────────────────────────────────────────────────────────────

/**
 * Issue a TrustReceipt as a compact JWS string.
 *
 * Automatically sets:
 * - receipt_id: random UUID v4
 * - schema_version: "1.0"
 * - issued_at: current Unix timestamp
 * - expires_at: issued_at + validitySeconds
 *
 * Algorithm: EdDSA (Ed25519), compact JWS.
 */
export async function issueTrustReceipt(
  options: IssueOptions
): Promise<string> {
  const {
    payload,
    privateKeyJwk,
    kid,
    validitySeconds = DEFAULT_VALIDITY_SECONDS,
  } = options;

  const issuedAt = Math.floor(Date.now() / 1000);
  const expiresAt = issuedAt + validitySeconds;

  const fullPayload: Omit<TrustReceipt, "signature"> = {
    ...payload,
    receipt_id: randomUUID(),
    schema_version: "1.0",
    issued_at: issuedAt,
    expires_at: expiresAt,
    kid,
  };

  const privateKey = await importJWK(privateKeyJwk, ALGORITHM);

  const jws = await new CompactSign(
    new TextEncoder().encode(canonicalizeJson(fullPayload))
  )
    .setProtectedHeader({ alg: ALGORITHM, kid, typ: "JWT" })
    .sign(privateKey);

  return jws;
}
