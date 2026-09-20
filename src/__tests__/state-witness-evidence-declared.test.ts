/**
 * La evidencia de State Witness debe estar declarada en los TRES esquemas.
 * Mismo motivo que `operation-link-declared.test.ts`: un `z.object` no estricto
 * descarta la clave no declarada, y el v1.1 estricto rechaza el recibo entero.
 */
import { describe, expect, it } from "vitest";
import {
  StateWitnessEvidenceFields,
  STATE_WITNESS_EVIDENCE_KEYS,
  StateWitnessResolutionSchema,
} from "../schema/state-witness-evidence.js";

describe("StateWitnessEvidenceFields", () => {
  it("declara los tres campos", () => {
    expect([...STATE_WITNESS_EVIDENCE_KEYS].sort()).toEqual(
      [
        "state_witness_authoritative_hash",
        "state_witness_reasons",
        "state_witness_resolution",
      ].sort()
    );
  });

  it("todos son opcionales", () => {
    for (const key of STATE_WITNESS_EVIDENCE_KEYS) {
      expect(StateWitnessEvidenceFields[key].safeParse(undefined).success).toBe(
        true
      );
    }
  });

  it("BLOCK no es una resolución publicable en un recibo", () => {
    expect(StateWitnessResolutionSchema.safeParse("BLOCK").success).toBe(false);
    expect(
      StateWitnessResolutionSchema.safeParse("EXECUTE_WITHIN_TOLERANCE").success
    ).toBe(true);
  });

  it("el hash exige sha256 hex minúscula", () => {
    const f = StateWitnessEvidenceFields.state_witness_authoritative_hash;
    expect(f.safeParse("a".repeat(64)).success).toBe(true);
    expect(f.safeParse("A".repeat(64)).success).toBe(false);
  });

  it("los motivos son un vocabulario cerrado", () => {
    const f = StateWitnessEvidenceFields.state_witness_reasons;
    expect(f.safeParse(["price_within_tolerance"]).success).toBe(true);
    expect(f.safeParse(["porque_si"]).success).toBe(false);
  });
});

describe("declarado en los tres esquemas", () => {
  it("canónico, legacy y v1.1 declaran las tres claves", async () => {
    const [canonical, legacy, v11] = await Promise.all([
      import("../schema/trust-receipt.schema.js"),
      import("../schema/trust-receipt-legacy.schema.js"),
      import("../zod-1.1.js"),
    ]);

    /**
     * `.shape` del objeto base. El root de v1.1 es `.strict()` envuelto en
     * refinamientos, así que se accede al `innerType` cuando lo hay: buscarlo
     * por heurística daría un falso verde el día que el nombre cambie.
     */
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
      [
        "canónico",
        (canonical as Record<string, unknown>)["TrustReceiptSchema"] ??
          (canonical as Record<string, unknown>)["TrustReceiptCanonicalSchema"],
      ],
      ["legacy", legacy.TrustReceiptLegacyCompactSchema],
      ["v1.1", v11.TrustReceiptV11BodySchema],
    ];

    for (const [name, schema] of targets) {
      expect(schema, `${name}: no se resolvió el esquema`).toBeDefined();
      const shape = shapeOf(schema);
      for (const key of STATE_WITNESS_EVIDENCE_KEYS) {
        expect(shape, `${name} debería declarar ${key}`).toHaveProperty(key);
      }
    }
  });
});
