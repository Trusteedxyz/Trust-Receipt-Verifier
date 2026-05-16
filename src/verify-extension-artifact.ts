/**
 * Generic Ed25519 JWS verifier for Trusteed extension artifacts.
 *
 * Two artifact shapes are validated here:
 *  - `erasure`  — signed by the extension developer's Ed25519 key, asserting
 *    that merchant data has been destroyed after uninstall.
 *  - `manifest` — signed by the developer's Ed25519 key (and, for approved
 *    versions, countersigned by Trusteed). The CLI verifies the developer
 *    signature; full countersignature verification is a server-side concern.
 *
 * Scope and non-goals:
 *  - This module only checks **signature validity** and **payload shape**
 *    (presence + types of the small required field set). It does **not**
 *    enforce manifest-level rules (scope compatibility, PII redaction, region
 *    coverage), which live in the marketplace conformance suite and the
 *    server-side review pipeline.
 *  - JWKS resolution is caller-controlled: pass an inline JWKS array or a URL.
 *  - All failures return a structured `{ valid: false, reason }`; nothing
 *    throws.
 */

import {
  compactVerify,
  decodeProtectedHeader,
  importJWK,
  type JWK,
} from "jose";

// ─── Public types ──────────────────────────────────────────────────────────

export type ExtensionArtifactKind = "erasure" | "manifest";

// Reuses jose's JWK shape so callers can hand us values straight from
// `verifier.ts` / JWKS fetches without re-typing.
export type PublicJwk = JWK;

export interface VerifyExtensionArtifactOptions {
  readonly kind: ExtensionArtifactKind;
  readonly jwks?: readonly PublicJwk[];
  readonly jwksUrl?: string;
}

export type ExtensionArtifactFailureReason =
  | "malformed_jws"
  | "unsupported_alg"
  | "missing_kid"
  | "jwks_unreachable"
  | "kid_not_found"
  | "signature_invalid"
  | "payload_not_json"
  | "shape_invalid";

export type VerifyExtensionArtifactResult =
  | {
      valid: true;
      kind: ExtensionArtifactKind;
      kid: string;
      payload: Record<string, unknown>;
    }
  | {
      valid: false;
      kind: ExtensionArtifactKind;
      reason: ExtensionArtifactFailureReason;
      detail?: string;
    };

// ─── JWS shape helpers ─────────────────────────────────────────────────────

const JWS_COMPACT_RE = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

function isCompactJws(input: string): boolean {
  return JWS_COMPACT_RE.test(input);
}

// ─── JWKS resolver ─────────────────────────────────────────────────────────

async function resolveJwks(
  options: VerifyExtensionArtifactOptions
): Promise<{ ok: true; keys: PublicJwk[] } | { ok: false; detail: string }> {
  if (options.jwks && options.jwks.length > 0) {
    return { ok: true, keys: [...options.jwks] };
  }
  if (!options.jwksUrl) {
    return {
      ok: false,
      detail: "no JWKS source provided (pass jwks or jwksUrl)",
    };
  }
  try {
    const res = await fetch(options.jwksUrl, {
      headers: { accept: "application/json" },
    });
    if (!res.ok) {
      return { ok: false, detail: `JWKS HTTP ${res.status}` };
    }
    const body = (await res.json()) as { keys?: unknown };
    if (!body || !Array.isArray(body.keys)) {
      return { ok: false, detail: "JWKS missing keys[] array" };
    }
    return { ok: true, keys: body.keys as PublicJwk[] };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { ok: false, detail: msg };
  }
}

// ─── Payload shape gates ───────────────────────────────────────────────────

/**
 * Required field probe for erasure receipts.
 *
 * Erasure receipts are deliberately minimal: they assert that a developer has
 * destroyed merchant data on uninstall. The merchant-facing platform reads
 * `install_id`, `deleted_at`, and `signed_by.kid` from this payload to drive
 * the "audit_verified" badge. `evidence_url` is REQUIRED when the merchant
 * exported more than 1 MB of data; for CLI smoke verification we treat it as
 * optional.
 */
function checkErasureShape(
  payload: unknown
): { ok: true } | { ok: false; detail: string } {
  if (!payload || typeof payload !== "object") {
    return { ok: false, detail: "payload is not an object" };
  }
  const p = payload as Record<string, unknown>;
  if (typeof p.install_id !== "string" || p.install_id.length === 0) {
    return { ok: false, detail: "install_id (string) required" };
  }
  if (typeof p.deleted_at !== "string" || isNaN(Date.parse(p.deleted_at))) {
    return { ok: false, detail: "deleted_at (RFC 3339 string) required" };
  }
  const signedBy = p.signed_by;
  if (
    !signedBy ||
    typeof signedBy !== "object" ||
    typeof (signedBy as Record<string, unknown>).kid !== "string"
  ) {
    return { ok: false, detail: "signed_by.kid (string) required" };
  }
  // evidence_url, record_count_destroyed → optional. Type-check if present.
  if (
    "evidence_url" in p &&
    p.evidence_url !== undefined &&
    typeof p.evidence_url !== "string"
  ) {
    return { ok: false, detail: "evidence_url, if present, must be a string" };
  }
  if (
    "record_count_destroyed" in p &&
    p.record_count_destroyed !== undefined &&
    typeof p.record_count_destroyed !== "number"
  ) {
    return {
      ok: false,
      detail: "record_count_destroyed, if present, must be a number",
    };
  }
  return { ok: true };
}

/**
 * Required field probe for Trusteed extension manifests.
 *
 * This is intentionally a subset of the canonical JSON Schema — we check the
 * top-level required keys exist and have the right type. The conformance
 * suite + server review run the full validation.
 */
function checkManifestShape(
  payload: unknown
): { ok: true } | { ok: false; detail: string } {
  if (!payload || typeof payload !== "object") {
    return { ok: false, detail: "payload is not an object" };
  }
  const p = payload as Record<string, unknown>;
  const required: Array<[string, "string" | "array" | "object" | "number"]> = [
    ["schema_version", "string"],
    ["name", "string"],
    ["vendor", "string"],
    ["version", "string"],
    ["description", "string"],
    ["scopes_requested", "array"],
    ["endpoints", "array"],
    ["event_subscriptions", "array"],
    ["pricing_model", "object"],
    ["data_retention_days", "number"],
    ["supported_regions", "array"],
    ["support_url", "string"],
    ["privacy_policy_url", "string"],
    ["terms_url", "string"],
    ["risk_category", "string"],
    ["changelog", "string"],
  ];
  for (const [field, expected] of required) {
    const value = p[field];
    if (value === undefined) {
      return { ok: false, detail: `missing required field "${field}"` };
    }
    if (expected === "array" && !Array.isArray(value)) {
      return { ok: false, detail: `field "${field}" must be an array` };
    }
    if (
      expected === "object" &&
      (Array.isArray(value) || typeof value !== "object")
    ) {
      return { ok: false, detail: `field "${field}" must be an object` };
    }
    if (
      (expected === "string" || expected === "number") &&
      typeof value !== expected
    ) {
      return { ok: false, detail: `field "${field}" must be a ${expected}` };
    }
  }
  return { ok: true };
}

// ─── Main entry point ──────────────────────────────────────────────────────

/**
 * Verify a Trusteed extension artifact (erasure receipt or manifest).
 *
 * Steps:
 *  1. Parse JWS Compact shape.
 *  2. Decode protected header — require `alg=EdDSA` and a `kid`.
 *  3. Resolve JWKS (inline or URL).
 *  4. Locate the key by `kid` and import as Ed25519.
 *  5. Verify the JWS signature with `jose.compactVerify`.
 *  6. JSON-parse the payload bytes.
 *  7. Apply the kind-specific shape gate.
 */
export async function verifyExtensionArtifact(
  jws: string,
  options: VerifyExtensionArtifactOptions
): Promise<VerifyExtensionArtifactResult> {
  const { kind } = options;

  if (typeof jws !== "string" || !isCompactJws(jws.trim())) {
    return { valid: false, kind, reason: "malformed_jws" };
  }
  const compact = jws.trim();

  // Header → alg + kid
  let alg: string | undefined;
  let kid: string | undefined;
  try {
    const header = decodeProtectedHeader(compact);
    alg = typeof header.alg === "string" ? header.alg : undefined;
    kid = typeof header.kid === "string" ? header.kid : undefined;
  } catch {
    return { valid: false, kind, reason: "malformed_jws" };
  }
  if (alg !== "EdDSA") {
    return {
      valid: false,
      kind,
      reason: "unsupported_alg",
      detail: alg ?? "missing",
    };
  }
  if (!kid) {
    return { valid: false, kind, reason: "missing_kid" };
  }

  // Resolve JWKS
  const jwksResult = await resolveJwks(options);
  if (!jwksResult.ok) {
    return {
      valid: false,
      kind,
      reason: "jwks_unreachable",
      detail: jwksResult.detail,
    };
  }
  const match = jwksResult.keys.find((k) => k.kid === kid);
  if (!match) {
    return { valid: false, kind, reason: "kid_not_found", detail: kid };
  }

  // Import + verify
  let publicKey;
  try {
    publicKey = await importJWK({ ...match, alg: "EdDSA" }, "EdDSA");
  } catch (err) {
    return {
      valid: false,
      kind,
      reason: "signature_invalid",
      detail: err instanceof Error ? err.message : "key import failed",
    };
  }

  let payloadBytes: Uint8Array;
  try {
    const verified = await compactVerify(compact, publicKey);
    payloadBytes = verified.payload;
  } catch (err) {
    return {
      valid: false,
      kind,
      reason: "signature_invalid",
      detail: err instanceof Error ? err.message : "compactVerify failed",
    };
  }

  // Parse payload JSON
  let payload: unknown;
  try {
    payload = JSON.parse(new TextDecoder().decode(payloadBytes));
  } catch {
    return { valid: false, kind, reason: "payload_not_json" };
  }

  // Shape gate
  const shapeCheck =
    kind === "erasure"
      ? checkErasureShape(payload)
      : checkManifestShape(payload);
  if (!shapeCheck.ok) {
    return {
      valid: false,
      kind,
      reason: "shape_invalid",
      detail: shapeCheck.detail,
    };
  }

  return {
    valid: true,
    kind,
    kid,
    payload: payload as Record<string, unknown>,
  };
}
