/**
 * `evaluation_id` tiene que estar DECLARADO en los tres esquemas, y por dos
 * motivos distintos según el esquema.
 *
 * ## Por qué existe el campo
 *
 * Desde el fix del 2026-08-06, el `evaluationId` que devuelve el evaluador ES
 * el `id` de la fila decisiva de `EnforcementEvent`. Eso hace que la unión
 * decisión ↔ prueba deje de necesitar la heurística «el último evento de este
 * merchant hace milisegundos» — pero sólo dentro de nuestra base. Sin el campo
 * en el cuerpo firmado, el artefacto portable sigue sin poder señalar la
 * evaluación que lo produjo, que es justo lo que un tercero necesita para pedir
 * el expediente.
 *
 * ## Por qué se prueban los tres
 *
 * - **Legacy compacto**: es el que valida el 100% del corpus productivo
 *   (`verifier.ts`). Es un `z.object` NO estricto, así que una clave no
 *   declarada se ACEPTA y se DESCARTA del objeto parseado: el emisor firmaría,
 *   el verificador diría «válido», y el campo no existiría para nadie. Cuarta
 *   aparición de esta familia — ver `hash-chain-prev-declared.test.ts`.
 * - **Canónico**: mismo riesgo de descarte silencioso.
 * - **v1.1 estricto**: el riesgo es el opuesto. Al ser `.strict()`, una clave no
 *   declarada **rechaza el recibo entero**. Sin declararla, emitirla rompería
 *   la verificación en vez de perderse.
 *
 * Los tres comparten `PolicyEvidenceFields` como SSOT, así que este test fija
 * que la comparten de verdad: si alguien copiase el campo a mano en uno solo,
 * los otros dos caerían aquí.
 */

import { describe, expect, it } from "vitest";

import { TrustReceiptLegacyCompactSchema } from "../schema/trust-receipt-legacy.schema.js";
import { TrustReceiptSchema } from "../schema/trust-receipt.schema.js";
import { PolicyEvidenceFields } from "../schema/policy-evidence.js";

const EVALUATION_ID = "3f2b1c44-9d1e-4a55-8b77-0e6a2c9d1234";

/** Cuerpo compacto mínimo que el emisor v1.0 productivo firma. */
const LEGACY_BODY = {
  iss: "merchant:store-1",
  sub: "call-1",
  iat: 1_760_000_000,
  callId: "call-1",
  merchantId: "store-1",
  agentId: "did:web:claude.ai",
  bucket: "checkout",
  tool: "complete_checkout",
  inputHash: "b".repeat(64),
  outputHash: "c".repeat(64),
  outputHashStatus: "captured",
  trust_provider_assertions: [],
  kid: "kid-1",
  schema_version: "1.0",
  canon: "jcs",
  expires_at: 1_760_000_000 + 3600,
  outcome: "SUCCESS",
};

describe("evaluation_id — declarado en los esquemas que se usan", () => {
  it("sobrevive al parseo del esquema LEGACY compacto (el del corpus real)", () => {
    const parsed = TrustReceiptLegacyCompactSchema.parse({
      ...LEGACY_BODY,
      evaluation_id: EVALUATION_ID,
    });

    expect(parsed.evaluation_id).toBe(EVALUATION_ID);
  });

  it("sobrevive al parseo del esquema canónico", () => {
    const shape = TrustReceiptSchema.shape as Record<string, unknown>;

    expect(shape["evaluation_id"]).toBeDefined();
  });

  it("está en el SSOT que comparten las tres formas, incluida la v1.1 estricta", () => {
    // v1.1 esparce el MISMO objeto (`zod-1.1.ts`). Comprobar el SSOT cubre las
    // tres sin importar cuál importe cada una, y es lo que impide que alguien
    // «arregle» una forma copiando el campo a mano en ella.
    expect(PolicyEvidenceFields).toHaveProperty("evaluation_id");
  });

  it("ausente ⇒ ausente: no se inventa un valor por defecto", () => {
    // El contrato publicado de la evidencia de política es «presente ⇒
    // autoritativo, ausente ⇒ el receipt no lo declara». Un default lo
    // convertiría en una afirmación firmada que nadie hizo.
    const parsed = TrustReceiptLegacyCompactSchema.parse({ ...LEGACY_BODY });

    expect(parsed.evaluation_id).toBeUndefined();
    expect("evaluation_id" in parsed).toBe(false);
  });

  it("acepta un identificador opaco que no sea UUID", () => {
    // Deliberado: el emisor de otra implementación puede no usar UUID, y
    // rechazar el recibo ENTERO por la forma de un id opaco convierte un
    // artefacto válido en inválido. Mismo criterio que `evaluated_rules`.
    const parsed = TrustReceiptLegacyCompactSchema.parse({
      ...LEGACY_BODY,
      evaluation_id: "eval_2026-08-06_00417",
    });

    expect(parsed.evaluation_id).toBe("eval_2026-08-06_00417");
  });

  it("rechaza la cadena vacía y la desmesurada", () => {
    // Vacía no es «ausente»: es una afirmación de identidad que no identifica.
    expect(() =>
      TrustReceiptLegacyCompactSchema.parse({
        ...LEGACY_BODY,
        evaluation_id: "",
      })
    ).toThrow();
    expect(() =>
      TrustReceiptLegacyCompactSchema.parse({
        ...LEGACY_BODY,
        evaluation_id: "x".repeat(129),
      })
    ).toThrow();
  });
});
