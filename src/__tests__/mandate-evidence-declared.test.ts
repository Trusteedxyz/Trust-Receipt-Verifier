/**
 * La evidencia de mandato y aprobación debe estar declarada en los TRES
 * esquemas, por el mismo motivo que el enlace de operación: un `z.object` no
 * estricto ACEPTA una clave no declarada y la DESCARTA del objeto parseado, así
 * que declararla en uno solo verifica bien y no llega nunca al tipo público.
 *
 * El vector del hash está calculado A MANO (`python3 -c hashlib.sha256(...)`)
 * sobre la cadena canónica escrita literal en el test. No lo genera el propio
 * código: si lo generara, el test no podría fallar por un cambio de material.
 */
import { describe, expect, it } from "vitest";
import {
  APPROVAL_EVIDENCE_KEYS,
  ApprovalEvidenceFields,
  computeMandateClaimsHash,
  MANDATE_EVIDENCE_KEYS,
  MandateEvidenceFields,
  MandateVerificationSchema,
  serializeMandateClaimsForHash,
} from "../schema/mandate-evidence.js";

describe("MandateEvidenceFields", () => {
  it("declara los ocho campos del mandato", () => {
    expect([...MANDATE_EVIDENCE_KEYS].sort()).toEqual(
      [
        "mandate_id",
        "mandate_claims_hash",
        "mandate_max_amount_cents",
        "mandate_currency",
        "mandate_subject",
        "mandate_audience",
        "mandate_expires_at",
        "mandate_verification",
      ].sort()
    );
    expect(Object.keys(MandateEvidenceFields).sort()).toEqual(
      [...MANDATE_EVIDENCE_KEYS].sort()
    );
  });

  it("declara los tres campos de la aprobación", () => {
    expect([...APPROVAL_EVIDENCE_KEYS].sort()).toEqual(
      ["approval_ref", "approval_channel", "approval_at"].sort()
    );
    expect(Object.keys(ApprovalEvidenceFields).sort()).toEqual(
      [...APPROVAL_EVIDENCE_KEYS].sort()
    );
  });

  it("todos son opcionales: no invalidan ningún recibo ya emitido", () => {
    for (const key of MANDATE_EVIDENCE_KEYS) {
      expect(
        MandateEvidenceFields[key].safeParse(undefined).success,
        `${key} debería aceptar ausencia`
      ).toBe(true);
    }
    for (const key of APPROVAL_EVIDENCE_KEYS) {
      expect(
        ApprovalEvidenceFields[key].safeParse(undefined).success,
        `${key} debería aceptar ausencia`
      ).toBe(true);
    }
  });

  it("`mandate_verification` no admite un valor que no podamos sostener", () => {
    expect(MandateVerificationSchema.safeParse("structure_only").success).toBe(
      true
    );
    expect(
      MandateVerificationSchema.safeParse("signature_verified").success
    ).toBe(true);
    expect(MandateVerificationSchema.safeParse("trusted").success).toBe(false);
  });

  it("`mandate_claims_hash` exige SHA-256 hex en minúscula", () => {
    expect(
      MandateEvidenceFields.mandate_claims_hash.safeParse("a".repeat(64))
        .success
    ).toBe(true);
    expect(
      MandateEvidenceFields.mandate_claims_hash.safeParse("A".repeat(64))
        .success
    ).toBe(false);
    expect(
      MandateEvidenceFields.mandate_claims_hash.safeParse("abc").success
    ).toBe(false);
  });

  it("la moneda del mandato es ISO 4217 en mayúsculas", () => {
    expect(
      MandateEvidenceFields.mandate_currency.safeParse("USD").success
    ).toBe(true);
    expect(
      MandateEvidenceFields.mandate_currency.safeParse("usd").success
    ).toBe(false);
  });

  it("un cap negativo no es un cap", () => {
    expect(
      MandateEvidenceFields.mandate_max_amount_cents.safeParse(-1).success
    ).toBe(false);
    expect(
      MandateEvidenceFields.mandate_max_amount_cents.safeParse(13599).success
    ).toBe(true);
  });
});

describe("computeMandateClaimsHash", () => {
  const claims = {
    mandate_id: "mnd_demo_001",
    max_amount_cents: 20000,
    currency: "USD",
    exp: 1757548800,
    sub: "agent:playground",
    aud: "demo-store",
  } as const;

  it("serializa exactamente las seis claims en forma RFC 8785", () => {
    expect(serializeMandateClaimsForHash(claims)).toBe(
      '{"aud":"demo-store","currency":"USD","exp":1757548800,"mandate_id":"mnd_demo_001","max_amount_cents":20000,"sub":"agent:playground"}'
    );
  });

  it("vector fijo calculado a mano", () => {
    expect(computeMandateClaimsHash(claims)).toBe(
      "86e0602b901b3f20200ddca649b80508335c2d534a4b87df0135e3e003f365f0"
    );
  });

  it("el orden de las claves de entrada no cambia el hash", () => {
    const reordered = {
      aud: "demo-store",
      sub: "agent:playground",
      exp: 1757548800,
      currency: "USD",
      max_amount_cents: 20000,
      mandate_id: "mnd_demo_001",
    } as const;
    expect(computeMandateClaimsHash(reordered)).toBe(
      computeMandateClaimsHash(claims)
    );
  });

  it("cambiar el cap cambia el hash", () => {
    expect(
      computeMandateClaimsHash({ ...claims, max_amount_cents: 20001 })
    ).not.toBe(computeMandateClaimsHash(claims));
  });
});

describe("declarado en los tres esquemas", () => {
  it("canónico, legacy y v1.1 declaran las once claves", async () => {
    const [canonical, legacy, v11] = await Promise.all([
      import("../schema/trust-receipt.schema.js"),
      import("../schema/trust-receipt-legacy.schema.js"),
      import("../zod-1.1.js"),
    ]);

    const shapeOf = (schema: unknown): Record<string, unknown> => {
      let node = schema as {
        shape?: Record<string, unknown>;
        _def?: { schema?: unknown; innerType?: unknown };
      };
      for (let i = 0; i < 8 && !node?.shape; i++) {
        const next = node?._def?.schema ?? node?._def?.innerType;
        if (!next) break;
        node = next as typeof node;
      }
      return node?.shape ?? {};
    };

    const targets: ReadonlyArray<readonly [string, unknown]> = [
      ["canónico", canonical.TrustReceiptSchema],
      ["legacy", legacy.TrustReceiptLegacyCompactSchema],
      ["v1.1", v11.TrustReceiptV11BodySchema],
    ];

    for (const [name, schema] of targets) {
      expect(schema, `${name}: no se resolvió el esquema`).toBeDefined();
      const shape = shapeOf(schema);
      for (const key of [...MANDATE_EVIDENCE_KEYS, ...APPROVAL_EVIDENCE_KEYS]) {
        expect(shape, `${name} debería declarar ${key}`).toHaveProperty(key);
      }
    }
  });
});

describe("no pisa el `mandate_hash` legacy", () => {
  it("ninguna clave nueva se llama `mandate_hash`", () => {
    // `mandate_hash` es una claim del v1.0 histórico con formato `sha256:<hex>`
    // y sigue viva en el corpus (`test-vectors/v11/017-legacy-v10-receipt.json`).
    // Declararla aquí con formato hex a secas convirtió ese vector en
    // `rejected`: un recibo legacy válido dejaba de verificar.
    expect([...MANDATE_EVIDENCE_KEYS, ...APPROVAL_EVIDENCE_KEYS]).not.toContain(
      "mandate_hash"
    );
  });

  it("el esquema canónico sigue SIN declarar `mandate_hash`", async () => {
    const canonical = await import("../schema/trust-receipt.schema.js");
    expect(Object.keys(canonical.TrustReceiptSchema.shape)).not.toContain(
      "mandate_hash"
    );
  });
});
