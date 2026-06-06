/**
 * spec-056 — `MppBindingExtensionSchema` parse tests.
 *
 * Cubre:
 *  - Positive parse (confirmed posture, todos los fields).
 *  - Optional fields (digest, expires, warnings).
 *  - Field validation (ULID, http_method enum, RFC 3339 strict timestamp,
 *    Sha256Tagged formato, URL formato).
 *  - Cross-field rule ADR-056 §Degradation Matrix:
 *      SOLO posture == "unverified" REQUIRES warnings[] con ≥1 entry
 *      (NO evidencia de pago). `confirmed` y `recovered` (evidencia pago
 *      previo válida) NO fuerzan warnings.
 *  - Schema lock: .strict() rechaza unknown keys.
 *  - Schema lock v1: NO field `intent` (siempre "charge" — parser rechaza
 *    "session" upstream, no aquí).
 *  - Integración con TrustReceiptV11BodySchema (additivo backward-compat —
 *    body sin mpp_binding sigue verificando).
 */
import { describe, expect, it } from "vitest";
import {
  MppBindingExtensionSchema,
  TrustReceiptV11BodySchema,
} from "../zod-1.1.js";

const VALID_ULID = "01HXXXXXXXXXXXXXXXXXXXXXXX";
const VALID_BINDING_HASH = `sha256:${"a".repeat(64)}`;
const VALID_REQUEST_HASH = `sha256:${"b".repeat(64)}`;

const baseConfirmed = {
  binding_profile_version: "mpp-binding/1.0" as const,
  binding_id: VALID_ULID,
  method: "stripe",
  reference: "ch_abc123xyz",
  challenge_id: "chal_hmac_sha256_a1b2c3",
  resource_uri_c14n: "https://api.example.com/premium/resource",
  http_method: "GET" as const,
  timestamp: "2026-05-20T12:04:30Z",
  request_hash: VALID_REQUEST_HASH,
  binding_hash: VALID_BINDING_HASH,
  posture: "confirmed" as const,
};

describe("MppBindingExtensionSchema — positive parse", () => {
  it("accepts minimal confirmed posture", () => {
    const parsed = MppBindingExtensionSchema.safeParse(baseConfirmed);
    expect(parsed.success).toBe(true);
  });

  it("accepts all optional fields (digest, expires) with confirmed", () => {
    const parsed = MppBindingExtensionSchema.safeParse({
      ...baseConfirmed,
      digest: "sha-256=:abc123=:",
      expires: "2026-05-20T12:10:00Z",
    });
    expect(parsed.success).toBe(true);
  });

  it("accepts timestamp with milliseconds precision 3", () => {
    const parsed = MppBindingExtensionSchema.safeParse({
      ...baseConfirmed,
      timestamp: "2026-05-20T12:04:30.123Z",
    });
    expect(parsed.success).toBe(true);
  });

  it("accepts all 5 HTTP methods", () => {
    for (const method of ["GET", "POST", "PUT", "DELETE", "PATCH"] as const) {
      const parsed = MppBindingExtensionSchema.safeParse({
        ...baseConfirmed,
        http_method: method,
      });
      expect(parsed.success).toBe(true);
    }
  });

  it("accepts posture=recovered with warnings", () => {
    const parsed = MppBindingExtensionSchema.safeParse({
      ...baseConfirmed,
      posture: "recovered",
      warnings: ["payment_receipt_absent"],
    });
    expect(parsed.success).toBe(true);
  });

  it("accepts posture=unverified with challenge_context_missing warning", () => {
    const parsed = MppBindingExtensionSchema.safeParse({
      ...baseConfirmed,
      posture: "unverified",
      warnings: ["challenge_context_missing"],
    });
    expect(parsed.success).toBe(true);
  });
});

describe("MppBindingExtensionSchema — ADR-056 §Degradation Matrix cross-field", () => {
  it("REJECTS posture=unverified without warnings[]", () => {
    const parsed = MppBindingExtensionSchema.safeParse({
      ...baseConfirmed,
      posture: "unverified",
    });
    expect(parsed.success).toBe(false);
    if (!parsed.success) {
      expect(parsed.error.issues[0]?.path).toEqual(["warnings"]);
      expect(parsed.error.issues[0]?.message).toMatch(
        /warnings\[\] with ≥1 entry/
      );
    }
  });

  it("REJECTS posture=unverified with empty warnings[]", () => {
    const parsed = MppBindingExtensionSchema.safeParse({
      ...baseConfirmed,
      posture: "unverified",
      warnings: [],
    });
    expect(parsed.success).toBe(false);
  });

  it("ACCEPTS posture=recovered without warnings[] (valid prior-payment evidence, ADR-056)", () => {
    const parsed = MppBindingExtensionSchema.safeParse({
      ...baseConfirmed,
      posture: "recovered",
    });
    expect(parsed.success).toBe(true);
  });

  it("ACCEPTS posture=recovered with empty warnings[] (warnings not forced)", () => {
    const parsed = MppBindingExtensionSchema.safeParse({
      ...baseConfirmed,
      posture: "recovered",
      warnings: [],
    });
    expect(parsed.success).toBe(true);
  });

  it("ACCEPTS posture=confirmed without warnings[]", () => {
    const parsed = MppBindingExtensionSchema.safeParse(baseConfirmed);
    expect(parsed.success).toBe(true);
  });
});

describe("MppBindingExtensionSchema — field validation", () => {
  it("rejects invalid ULID (lowercase)", () => {
    const parsed = MppBindingExtensionSchema.safeParse({
      ...baseConfirmed,
      binding_id: "01hxxxxxxxxxxxxxxxxxxxxxxx",
    });
    expect(parsed.success).toBe(false);
  });

  it("rejects ULID with I/L/O/U (excluded chars Crockford)", () => {
    const parsed = MppBindingExtensionSchema.safeParse({
      ...baseConfirmed,
      binding_id: "01ILOUXXXXXXXXXXXXXXXXXXXX",
    });
    expect(parsed.success).toBe(false);
  });

  it("rejects binding_profile_version distinto a mpp-binding/1.0", () => {
    const parsed = MppBindingExtensionSchema.safeParse({
      ...baseConfirmed,
      binding_profile_version: "mpp-binding/2.0",
    });
    expect(parsed.success).toBe(false);
  });

  it("rejects http_method lowercase", () => {
    const parsed = MppBindingExtensionSchema.safeParse({
      ...baseConfirmed,
      http_method: "get",
    });
    expect(parsed.success).toBe(false);
  });

  it("rejects http_method OPTIONS / HEAD (out of enum)", () => {
    for (const method of ["OPTIONS", "HEAD"]) {
      const parsed = MppBindingExtensionSchema.safeParse({
        ...baseConfirmed,
        http_method: method,
      });
      expect(parsed.success).toBe(false);
    }
  });

  it("rejects binding_hash sin prefix sha256:", () => {
    const parsed = MppBindingExtensionSchema.safeParse({
      ...baseConfirmed,
      binding_hash: "a".repeat(64),
    });
    expect(parsed.success).toBe(false);
  });

  it("rejects request_hash con sha512 prefix", () => {
    const parsed = MppBindingExtensionSchema.safeParse({
      ...baseConfirmed,
      request_hash: `sha512:${"a".repeat(128)}`,
    });
    expect(parsed.success).toBe(false);
  });

  it("rejects resource_uri_c14n no-URL", () => {
    const parsed = MppBindingExtensionSchema.safeParse({
      ...baseConfirmed,
      resource_uri_c14n: "not-a-url",
    });
    expect(parsed.success).toBe(false);
  });

  it("rejects posture=pending (no en enum)", () => {
    const parsed = MppBindingExtensionSchema.safeParse({
      ...baseConfirmed,
      posture: "pending",
    });
    expect(parsed.success).toBe(false);
  });
});

describe("MppBindingExtensionSchema — RFC 3339 strict timestamp", () => {
  const negatives = [
    ["timezone offset", "2026-05-20T12:04:30+00:00"],
    ["missing Z", "2026-05-20T12:04:30"],
    ["space en lugar de T", "2026-05-20 12:04:30Z"],
    ["precisión 1 dígito ms", "2026-05-20T12:04:30.1Z"],
    ["precisión 6 dígitos ms", "2026-05-20T12:04:30.123456Z"],
    ["fecha sin T", "2026-05-20"],
  ] as const;

  for (const [name, ts] of negatives) {
    it(`rejects timestamp invalido — ${name}: ${ts}`, () => {
      const parsed = MppBindingExtensionSchema.safeParse({
        ...baseConfirmed,
        timestamp: ts,
      });
      expect(parsed.success).toBe(false);
    });
  }

  const positives = [
    ["sin ms", "2026-05-20T12:04:30Z"],
    ["ms 3 dígitos", "2026-05-20T12:04:30.123Z"],
    ["año cualquiera", "1999-12-31T23:59:59Z"],
  ] as const;

  for (const [name, ts] of positives) {
    it(`accepts timestamp valido — ${name}: ${ts}`, () => {
      const parsed = MppBindingExtensionSchema.safeParse({
        ...baseConfirmed,
        timestamp: ts,
      });
      expect(parsed.success).toBe(true);
    });
  }

  it("aplica misma validacion a expires field", () => {
    const parsed = MppBindingExtensionSchema.safeParse({
      ...baseConfirmed,
      expires: "2026-05-20T12:10:00+00:00",
    });
    expect(parsed.success).toBe(false);
  });
});

describe("MppBindingExtensionSchema — schema lock", () => {
  it(".strict() rejects unknown top-level keys", () => {
    const parsed = MppBindingExtensionSchema.safeParse({
      ...baseConfirmed,
      shadow_signature: "attacker_injected",
    });
    expect(parsed.success).toBe(false);
  });

  it("rejects field `intent` (no existe en schema v1 — siempre charge upstream)", () => {
    const parsed = MppBindingExtensionSchema.safeParse({
      ...baseConfirmed,
      intent: "session",
    });
    expect(parsed.success).toBe(false);
  });

  it("rejects warnings con valor fuera de enum", () => {
    const parsed = MppBindingExtensionSchema.safeParse({
      ...baseConfirmed,
      posture: "unverified",
      warnings: ["unknown_warning_code"],
    });
    expect(parsed.success).toBe(false);
  });
});

describe("TrustReceiptV11BodySchema — mpp_binding wiring (additive + backward-compat)", () => {
  // Note: full body integration tests live downstream (apps/api).
  // Aquí solo verificamos que el extension field está cableado y que un body
  // payload con mpp_binding bien-formado NO produce error path sobre `mpp_binding`
  // (otros required del body v1.1 pueden faltar — ese es scope de tests v1.1 base).

  function getMppBindingErrors(input: unknown) {
    const parsed = TrustReceiptV11BodySchema.safeParse(input);
    if (parsed.success) return [];
    return parsed.error.issues.filter((issue) =>
      issue.path.includes("mpp_binding")
    );
  }

  it("body with valid mpp_binding does NOT emit errors under mpp_binding path", () => {
    const errors = getMppBindingErrors({ mpp_binding: baseConfirmed });
    expect(errors).toEqual([]);
  });

  it("body with malformed mpp_binding (posture=unverified sin warnings) DOES emit error under mpp_binding path", () => {
    const errors = getMppBindingErrors({
      mpp_binding: {
        ...baseConfirmed,
        posture: "unverified",
      },
    });
    expect(errors.length).toBeGreaterThan(0);
    expect(errors[0]?.path).toContain("mpp_binding");
  });

  it("body without mpp_binding does NOT emit errors under mpp_binding path (optional field)", () => {
    const errors = getMppBindingErrors({});
    expect(errors).toEqual([]);
  });
});
