/**
 * El enlace de operación debe estar declarado en los TRES esquemas.
 *
 * Los `z.object` no estrictos aceptan una clave no declarada y la DESCARTAN del
 * objeto parseado: declararlo en uno solo verifica bien y no llega nunca al
 * tipo público. Ese fallo ya mordió dos veces aquí (enriquecimiento T1.3 y el
 * propio `hash_chain_prev`), y este test es lo que impide la tercera.
 */
import { describe, expect, it } from "vitest";
import {
  OperationLinkFields,
  OPERATION_LINK_KEYS,
  SupersededReasonSchema,
} from "../schema/operation-link.js";

describe("OperationLinkFields", () => {
  it("declara los cuatro campos", () => {
    expect([...OPERATION_LINK_KEYS].sort()).toEqual(
      [
        "operation_id",
        "supersedes_receipt_hash",
        "superseded_reason",
        "reconfirmed_state_hash",
      ].sort()
    );
    expect(Object.keys(OperationLinkFields).sort()).toEqual(
      [...OPERATION_LINK_KEYS].sort()
    );
  });

  it("todos son opcionales: no invalidan ningún recibo ya emitido", () => {
    for (const key of OPERATION_LINK_KEYS) {
      expect(
        OperationLinkFields[key].safeParse(undefined).success,
        `${key} debería aceptar ausencia`
      ).toBe(true);
    }
  });

  it("rechaza un motivo fuera del enum", () => {
    expect(SupersededReasonSchema.safeParse("porque_si").success).toBe(false);
    expect(SupersededReasonSchema.safeParse("state_reconfirmed").success).toBe(
      true
    );
    expect(SupersededReasonSchema.safeParse("mandate_corrected").success).toBe(
      true
    );
  });

  it("los hashes exigen SHA-256 hex en minúscula", () => {
    const ok = "a".repeat(64);
    expect(
      OperationLinkFields.supersedes_receipt_hash.safeParse(ok).success
    ).toBe(true);
    expect(
      OperationLinkFields.supersedes_receipt_hash.safeParse("A".repeat(64))
        .success
    ).toBe(false);
    expect(
      OperationLinkFields.reconfirmed_state_hash.safeParse("abc").success
    ).toBe(false);
  });
});

describe("declarado en los tres esquemas", () => {
  it("canónico, legacy y v1.1 declaran las cuatro claves", async () => {
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
      for (const key of OPERATION_LINK_KEYS) {
        expect(shape, `${name} debería declarar ${key}`).toHaveProperty(key);
      }
    }
  });
});
