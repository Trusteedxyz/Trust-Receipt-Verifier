/**
 * La evidencia de liquidación debe estar declarada en los TRES esquemas.
 *
 * Mismo motivo que `operation-link-declared.test.ts`: los `z.object` no
 * estrictos aceptan una clave no declarada y la DESCARTAN del objeto parseado,
 * así que declararla en uno solo verifica bien y no llega nunca al tipo
 * público. Aquí duele más que en ningún otro campo: el recibo firmaría la
 * referencia del rail y el lector la perdería, que es exactamente el defecto
 * que esta evidencia existe para cerrar.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  SettlementEvidenceFields,
  SETTLEMENT_EVIDENCE_KEYS,
  SETTLEMENT_CART_HASH_ALG,
  SettlementEvidenceSchema,
} from "../schema/settlement-evidence.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

describe("SettlementEvidenceFields", () => {
  it("declara los seis campos", () => {
    expect([...SETTLEMENT_EVIDENCE_KEYS].sort()).toEqual(
      [
        "settlement_psp",
        "settlement_ref",
        "settlement_network",
        "funding_source",
        "settlement_cart_hash",
        "settlement_cart_hash_alg",
      ].sort()
    );
    expect(Object.keys(SettlementEvidenceFields).sort()).toEqual(
      [...SETTLEMENT_EVIDENCE_KEYS].sort()
    );
  });

  it("todos son opcionales: no invalidan ningún recibo ya emitido", () => {
    for (const key of SETTLEMENT_EVIDENCE_KEYS) {
      expect(
        SettlementEvidenceFields[key].safeParse(undefined).success,
        `${key} debería aceptar ausencia`
      ).toBe(true);
    }
    expect(SettlementEvidenceSchema.safeParse({}).success).toBe(true);
  });

  it("el nombre del algoritmo del hash NO lleva el salto de línea final", () => {
    expect(SETTLEMENT_CART_HASH_ALG).toBe("trusteed:payment-mandate:cart:v1");
    expect(SETTLEMENT_CART_HASH_ALG.endsWith("\n")).toBe(false);
    expect(
      SettlementEvidenceFields.settlement_cart_hash_alg.safeParse(
        `${SETTLEMENT_CART_HASH_ALG}\n`
      ).success
    ).toBe(false);
  });

  it("la referencia del rail exige `<stripe|x402>:<tipo>:<id>`", () => {
    const ref = SettlementEvidenceFields.settlement_ref;
    expect(ref.safeParse("stripe:txn:pi_3Q").success).toBe(true);
    expect(ref.safeParse("x402:tx:0xabc").success).toBe(true);
    // Un rail que no publicamos aquí, un espacio o un identificador vacío.
    expect(ref.safeParse("paypal:capture:1").success).toBe(false);
    expect(ref.safeParse("stripe:txn:pi 3Q").success).toBe(false);
    expect(ref.safeParse("stripe:txn:").success).toBe(false);
  });

  it("el hash del carrito es base64url de 43 caracteres", () => {
    expect(
      SettlementEvidenceFields.settlement_cart_hash.safeParse("A".repeat(43))
        .success
    ).toBe(true);
    expect(
      SettlementEvidenceFields.settlement_cart_hash.safeParse("A".repeat(42))
        .success
    ).toBe(false);
    expect(
      SettlementEvidenceFields.settlement_cart_hash.safeParse(
        `${"A".repeat(42)}+`
      ).success
    ).toBe(false);
  });

  it("los enums son cerrados", () => {
    expect(
      SettlementEvidenceFields.settlement_psp.safeParse("paypal").success
    ).toBe(false);
    expect(
      SettlementEvidenceFields.funding_source.safeParse("robado").success
    ).toBe(false);
    expect(
      SettlementEvidenceFields.funding_source.safeParse("buyer_wallet").success
    ).toBe(true);
  });
});

describe("declarado en los tres esquemas", () => {
  it("NO pisa ninguna clave que los esquemas declaren EN LÍNEA", () => {
    /**
     * Por qué existe este test: la primera versión declaraba `cart_hash` a
     * secas, que YA existe en los tres esquemas con otro formato
     * (`sha256:<hex>` en el cuerpo v1.1). El spread lo sobrescribía y tumbaba
     * 42 tests, vectores de conformidad incluidos.
     *
     * Y por qué se mira el FUENTE y no el `shape` resuelto: la colisión que
     * ocurrió era con una clave declarada **en línea** dentro del `z.object`, no
     * con un módulo hermano. En el `shape` final es invisible —el spread ya
     * sobrescribió, así que sólo queda un valor y es el nuestro—, y restar las
     * claves hermanas tampoco la revela, porque `cart_hash` no está en ninguno
     * de los siete hermanos. Un conjunto de nombres escrito a mano habría
     * dejado pasar `outcome`, `amount`, `tool` o `bucket`, que también son
     * inline (comprobado: los cuatro están en el esquema legacy).
     *
     * La extracción es deliberadamente generosa —cualquier `clave:` a cualquier
     * nivel de anidamiento cuenta— porque de más sólo puede hacer el gate más
     * estricto, y de menos lo haría inútil.
     */
    const DECLARACION = /^\s+([a-z_][a-z0-9_]*)\s*:/gm;
    const ficheros = [
      "schema/trust-receipt.schema.ts",
      "schema/trust-receipt-legacy.schema.ts",
      "zod-1.1.ts",
    ] as const;

    for (const rel of ficheros) {
      const fuente = readFileSync(join(__dirname, "..", rel), "utf8");
      const enLinea = new Set(
        [...fuente.matchAll(DECLARACION)].map((m) => m[1] as string)
      );
      // El propio módulo de evidencia no entra por aquí: llega por `...Fields`,
      // que esta regex no ve. Si una de nuestras claves aparece, es AJENA.
      for (const key of SETTLEMENT_EVIDENCE_KEYS) {
        expect(
          enLinea.has(key),
          `${rel} ya declara ${key} en línea: el spread lo sobrescribiría`
        ).toBe(false);
      }
      // Guardia contra un gate ciego: la extracción tiene que estar viendo algo.
      expect(
        enLinea.size,
        `${rel}: no se extrajo ninguna declaración`
      ).toBeGreaterThan(10);
    }
  });

  it("canónico, legacy y v1.1 declaran las seis claves", async () => {
    const [canonical, legacy, v11] = await Promise.all([
      import("../schema/trust-receipt.schema.js"),
      import("../schema/trust-receipt-legacy.schema.js"),
      import("../zod-1.1.js"),
    ]);

    /** Mismo desenvolvedor que el gate hermano del enlace de operación. */
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
      for (const key of SETTLEMENT_EVIDENCE_KEYS) {
        expect(shape, `${name} debería declarar ${key}`).toHaveProperty(key);
      }
    }
  });
});
