/**
 * El enlace de cadena del TrustReceipt — SSOT de `hash_chain_prev`.
 *
 * ## Por qué es un módulo y no una línea suelta
 *
 * El campo llevaba declarado sólo en el esquema CANÓNICO
 * (`trust-receipt.schema.ts`), pero el 100% del corpus productivo lo valida el
 * esquema LEGACY compacto (`verifier.ts` cae a él cuando el canónico no casa).
 * Los dos son `z.object` NO estrictos, y eso en Zod significa que una clave no
 * declarada se ACEPTA y se DESCARTA del objeto parseado. Resultado: firmar el
 * enlace y que el verificador no lo viera nunca.
 *
 * Declarado UNA vez y esparcido en los dos esquemas, esa deriva deja de ser
 * posible. Mismo patrón que `PolicyEvidenceFields` y `SignerFields`, y por el
 * mismo motivo.
 *
 * ## Qué significa el valor, y por qué `null` no es "ausente"
 *
 * SHA-256 hex del `hash_chain_self` del recibo ANTERIOR del mismo comerciante,
 * en la secuencia `merchant_seq`. Tres estados, tres significados distintos:
 *
 *   - `"<64 hex>"` — este recibo declara a su predecesor.
 *   - `null`       — este recibo declara que NO tiene predecesor: es el génesis
 *                    de la cadena de ese comerciante.
 *   - AUSENTE      — este recibo no dice nada sobre cadena alguna. Es el estado
 *                    de todo el corpus anterior a la ola 5 y el de cualquier
 *                    recibo emitido con la cadena apagada.
 *
 * Colapsar `null` y ausente convertiría el génesis —una afirmación fuerte, "aquí
 * empieza la cadena y lo firmo"— en un recibo mudo indistinguible de los
 * históricos.
 *
 * ## Lo que este campo NO es
 *
 * No es un enlace de ciclo de vida. `hash_chain_prev` ordena los recibos de UN
 * comerciante por tiempo de emisión; no dice que este recibo continúe la
 * operación del anterior. Autorización → pago → envío → entrega → devolución es
 * otra relación, necesita su propio campo y, sobre todo, necesita recibos de
 * envío y entrega que hoy no se emiten.
 */

import { z } from "zod";

/** SHA-256 en hexadecimal minúsculo, la forma que emite `computeReceiptChainHash`. */
const Sha256Hex = z
  .string()
  .regex(/^[0-9a-f]{64}$/, "must be lowercase SHA-256 hex");

/**
 * Listo para esparcir dentro de un `z.object`, igual que `PolicyEvidenceFields`.
 *
 * `.nullable().optional()` no es redundancia: `nullable` habilita el génesis y
 * `optional` habilita la ausencia, y arriba está escrito por qué son cosas
 * distintas.
 */
export const ChainLinkFields = {
  hash_chain_prev: Sha256Hex.nullable().optional(),
} as const;

/** Las claves del enlace de cadena, para gates y vectores. */
export const CHAIN_LINK_KEYS = Object.keys(
  ChainLinkFields
) as readonly (keyof typeof ChainLinkFields)[];
