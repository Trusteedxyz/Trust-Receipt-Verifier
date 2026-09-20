/**
 * Ola 5 — `hash_chain_prev` tiene que estar DECLARADO en el esquema que valida
 * el corpus real, no sólo en el canónico.
 *
 * ## El fallo que esto impide
 *
 * El 100% de los recibos productivos son v1.0 en forma compacta y los valida
 * `TrustReceiptLegacyCompactSchema` (`verifier.ts:410`), no el canónico. Los dos
 * son `z.object` NO estrictos, y eso en Zod significa: una clave no declarada se
 * ACEPTA y se DESCARTA del objeto parseado.
 *
 * O sea que sin esta declaración el emisor firmaría `hash_chain_prev`, el
 * verificador diría "válido"… y el campo no existiría en el tipo público. La
 * cadena quedaría firmada y sería invisible para todo consumidor —incluido
 * `aivs-export.ts`, que lee justo ese campo para decidir entre
 * `unlinked_single_entry` y `linked_single_entry`.
 *
 * Es el mismo patrón que ya mordió con el enriquecimiento T1.3
 * (`trust-receipt-legacy.schema.ts:68-77`), con la evidencia de política
 * (`policy-evidence.ts §Por qué se declaran…`) y tres veces con
 * `schema.response` de Fastify.
 */

import { describe, expect, it } from "vitest";

import { TrustReceiptLegacyCompactSchema } from "../schema/trust-receipt-legacy.schema.js";
import { TrustReceiptSchema } from "../schema/trust-receipt.schema.js";

const PREV = "a".repeat(64);

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

describe("hash_chain_prev — declarado en los esquemas que se usan", () => {
  it("sobrevive al parseo del esquema LEGACY compacto (el del corpus real)", () => {
    const parsed = TrustReceiptLegacyCompactSchema.parse({
      ...LEGACY_BODY,
      hash_chain_prev: PREV,
    });

    expect(parsed.hash_chain_prev).toBe(PREV);
  });

  it("distingue `null` de ausente en el esquema legacy", () => {
    // `null` = "declaro que NO tengo predecesor" (el génesis de un comerciante).
    // Ausente = "este recibo no lo declara" (cadena apagada, o pre-génesis).
    // Colapsarlas convertiría el génesis en un recibo mudo.
    const withNull = TrustReceiptLegacyCompactSchema.parse({
      ...LEGACY_BODY,
      hash_chain_prev: null,
    });
    const without = TrustReceiptLegacyCompactSchema.parse({ ...LEGACY_BODY });

    expect(withNull.hash_chain_prev).toBeNull();
    expect("hash_chain_prev" in withNull).toBe(true);
    expect(without.hash_chain_prev).toBeUndefined();
  });

  it("sigue sobreviviendo al parseo del esquema canónico", () => {
    // Ya estaba declarado ahí; se fija para que nadie lo retire al tocar el otro.
    const shape = TrustReceiptSchema.shape as Record<string, unknown>;

    expect(shape["hash_chain_prev"]).toBeDefined();
  });
});
