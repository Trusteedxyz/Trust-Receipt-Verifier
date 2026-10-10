/**
 * Evidencia de LIQUIDACIÓN — qué rail movió el dinero, de dónde salió y sobre
 * qué carrito.
 *
 * ## Qué afirma
 *
 * Hasta ahora el recibo publicaba el desenlace de la llamada (`outcome`) y no
 * guardaba NINGUNA referencia al rail que cobró. Un tercero que quisiera
 * comprobar por su cuenta que hubo un cobro no tenía por dónde empezar: tenía
 * que creerse el `SUCCESS`. Estos campos publican el identificador que ese
 * tercero puede resolver en el propio rail —un `PaymentIntent` de Stripe, una
 * transacción on-chain de x402— más la fuente de los fondos y el hash del
 * carrito que se cobró.
 *
 * ## Contrato publicado
 *
 * **Presentes ⇒ el emisor vio al rail capturar un cobro, y esto es su
 * referencia.** El bloque NO publica ningún importe: el importe cobrado vive en
 * el rail al que apunta `settlement_ref`, y es allí donde un tercero lo lee.
 * Se firman sólo los estados en los que el dinero se movió (`captured` y
 * `captured_unfinalized`); un intento que no cobró no los lleva.
 *
 * **Ausentes ⇒ este recibo NO afirma liquidación.** Nunca significa «no se
 * pagó»: significa que este recibo no lo declara. Un rail sin señal, una señal
 * mal formada o un PSP fuera de `stripe`/`x402` dan ausencia, no negación.
 *
 * ## Por qué opcionales y sin subir `schema_version`
 *
 * El mismo razonamiento —y las mismas dos razones mecánicas— que
 * `operation-link.ts` y `mandate-evidence.ts`: `verifier.ts` verifica la firma
 * sobre los **bytes crudos** antes de parsear, así que añadir campos no
 * invalida ninguna firma ya emitida; y el dispatcher falla ruidosamente ante
 * versiones futuras, así que estrenar un `schema_version` haría que TODO
 * verificador desplegado —TypeScript y Python— rechazase estos recibos hasta
 * actualizarse.
 *
 * El esquema congelado `trust-receipt-v1.0-final.schema.json` **no** declara
 * `additionalProperties` en el nivel superior: campos nuevos no lo invalidan, y
 * por eso este cambio no toca el artefacto congelado, ni el pin
 * `EMBEDDED_SCHEMA_SHA256`, ni el port Python, ni los vectores de conformidad.
 *
 * ## Por qué se declaran en los TRES esquemas
 *
 * No estricto significa que Zod ACEPTA una clave no declarada y la DESCARTA del
 * objeto parseado. Declararlo en un solo esquema verificaría bien y no llegaría
 * nunca al tipo público — el fallo que ya mordió dos veces aquí (el
 * enriquecimiento T1.3 y el propio `hash_chain_prev`).
 */
import { z } from "zod";

/**
 * Dominio del hash del carrito. Es el dominio del hash
 * del carrito del mandato de plataforma **sin** el `\n` final que lleva como
 * separador del material a hashear: aquí es el NOMBRE del algoritmo, no el
 * prefijo de los bytes.
 *
 * Es una constante propia porque este paquete se publica solo y no depende de
 * ningún otro. El emisor fija el mismo valor con una prueba de su lado.
 */
export const SETTLEMENT_CART_HASH_ALG =
  "trusteed:payment-mandate:cart:v1" as const;

/** Rails cuyo identificador un tercero puede resolver por su cuenta. */
export const SettlementPspSchema = z.enum(["stripe", "x402"]);
export type SettlementPsp = z.infer<typeof SettlementPspSchema>;

/**
 * De dónde salieron los fondos. `platform_*` son los medios de prueba que la
 * plataforma pone en la tienda de demostración; `buyer_wallet` es la cartera
 * del propio pagador (x402).
 */
export const SettlementFundingSourceSchema = z.enum([
  "platform_test_card",
  "platform_test_wallet",
  "buyer_wallet",
]);
export type SettlementFundingSource = z.infer<
  typeof SettlementFundingSourceSchema
>;

/** Listo para esparcir dentro de un `z.object`, igual que los hermanos. */
export const SettlementEvidenceFields = {
  settlement_psp: SettlementPspSchema.optional(),
  /**
   * `<rail>:<tipo>:<id>` — p. ej. `stripe:txn:pi_3Q…` o `x402:tx:0x…`. ASCII
   * imprimible sin espacios: el valor acaba en una columna y en un log, y nunca
   * debe ser un token crudo.
   */
  settlement_ref: z
    .string()
    .regex(/^(stripe|x402):[a-z_]+:[\x21-\x7e]{1,200}$/)
    .optional(),
  /** Red del rail cuando la tiene (x402), p. ej. `base-sepolia`. */
  settlement_network: z
    .string()
    .regex(/^[a-z0-9:-]{1,40}$/)
    .optional(),
  funding_source: SettlementFundingSourceSchema.optional(),
  /**
   * Hash del carrito cobrado, calculado por el emisor (base64url, 43).
   *
   * El prefijo `settlement_` NO es decorativo: `cart_hash` a secas YA EXISTE en
   * los tres esquemas y significa otra cosa —el digest del carrito en formato
   * `sha256:<hex>` del cuerpo v1.1—, así que declararlo con ese nombre lo
   * habría SOBRESCRITO con otro formato. Se detectó con el gate de declaración
   * puesto ya en verde y 42 tests del verificador en rojo, incluidos los
   * vectores de conformidad. Es el mismo criterio con el que la evidencia de
   * mandato llama al suyo `mandate_cart_hash`: cada dominio de hash, su nombre.
   */
  settlement_cart_hash: z
    .string()
    .regex(/^[A-Za-z0-9_-]{43}$/)
    .optional(),
  settlement_cart_hash_alg: z.literal(SETTLEMENT_CART_HASH_ALG).optional(),
} as const;

/** Las claves de la evidencia de liquidación, para gates y vectores. */
export const SETTLEMENT_EVIDENCE_KEYS = Object.keys(
  SettlementEvidenceFields
) as ReadonlyArray<keyof typeof SettlementEvidenceFields>;

/** La misma forma como objeto, para quien valide el bloque por separado. */
export const SettlementEvidenceSchema = z.object(SettlementEvidenceFields);
export type SettlementEvidence = z.infer<typeof SettlementEvidenceSchema>;
