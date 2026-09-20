/**
 * Relación de OPERACIÓN entre recibos — lo que `hash_chain_prev` no es.
 *
 * ## Por qué no se reutiliza el enlace de cadena
 *
 * `chain-link.ts` lo dice de su propio campo, y conviene citarlo entero porque
 * es exactamente el motivo de que este módulo exista: *«No es un enlace de
 * ciclo de vida. `hash_chain_prev` ordena los recibos de UN comerciante por
 * tiempo de emisión; no dice que este recibo continúe la operación del
 * anterior. […] otra relación, necesita su propio campo»*.
 *
 * Éste es ese campo. Reutilizar `hash_chain_prev` habría sido barato y
 * visualmente convincente, y habría hecho que cualquier verificador leyera
 * «ocurrió después» donde queremos decir «sustituye a».
 *
 * ## Qué relación afirma
 *
 * Dos recorridos reales producen dos recibos que hay que poder atar:
 *
 *   - un checkout denegado por la frontera del mandato y su reintento
 *     corregido (`mandate_corrected`);
 *   - un checkout que exigió reconfirmación porque el estado del comerciante se
 *     movió, y su ejecución posterior (`state_reconfirmed`).
 *
 * En los dos casos el segundo recibo declara al primero. Sin eso, un tercero
 * ve dos recibos sueltos del mismo comerciante y tiene que adivinar que el
 * segundo continúa al primero.
 *
 * ## Por qué opcionales y sin subir `schema_version`
 *
 * El mismo razonamiento que `policy-evidence.ts`, y por las mismas dos razones
 * mecánicas: `verifier.ts` verifica la firma sobre los **bytes crudos** antes
 * de parsear, así que añadir campos no invalida ninguna firma ya emitida; y el
 * dispatcher falla ruidosamente ante versiones futuras, así que estrenar un
 * `schema_version` haría que TODO verificador desplegado —TypeScript y Python—
 * rechazase estos recibos hasta actualizarse.
 *
 * Se comprobó además que el esquema congelado
 * `trust-receipt-v1.0-final.schema.json` **no** declara `additionalProperties`
 * en el nivel superior: campos nuevos no lo invalidan, y por eso este cambio no
 * toca el artefacto congelado ni los pines `EMBEDDED_SCHEMA_SHA256` ni el port
 * Python.
 *
 * ## Por qué se declaran incluso en los `z.object` no estrictos
 *
 * No estricto significa que Zod ACEPTA una clave no declarada y la DESCARTA del
 * objeto parseado. Declararlo en un solo esquema verificaría bien y no llegaría
 * nunca al tipo público — el fallo que ya mordió dos veces aquí: el
 * enriquecimiento T1.3 y el propio `hash_chain_prev`.
 *
 * ## Contrato publicado
 *
 * **Presentes ⇒ autoritativos; ausentes ⇒ el recibo no afirma continuidad.**
 * Ausente NO significa «no hubo»: significa que este recibo no lo declara.
 */
import { z } from "zod";

/** SHA-256 en hexadecimal minúsculo, la forma que emiten nuestros digests. */
const Sha256Hex = z
  .string()
  .regex(/^[0-9a-f]{64}$/, "must be lowercase SHA-256 hex");

export const SupersededReasonSchema = z.enum([
  /** El estado del comerciante cambió y el comprador lo reconfirmó. */
  "state_reconfirmed",
  /** El carrito excedía la frontera del mandato y el agente lo corrigió. */
  "mandate_corrected",
]);

export type SupersededReason = z.infer<typeof SupersededReasonSchema>;

/** Listo para esparcir dentro de un `z.object`, igual que los hermanos. */
export const OperationLinkFields = {
  /**
   * Operación a la que pertenece este recibo. Clave canónica de correlación:
   * el `checkoutSessionId`, la MISMA que ya usan el emisor de enforcement, el
   * de receipts y el State Witness, para que las evidencias converjan.
   */
  operation_id: z.string().min(1).max(128).optional(),
  /** `hash_chain_self` del recibo al que este SUCEDE dentro de la operación. */
  supersedes_receipt_hash: Sha256Hex.optional(),
  superseded_reason: SupersededReasonSchema.optional(),
  /**
   * Estado autoritativo que el agente reconfirmó explícitamente, cuando lo
   * hubo. Presente sólo con `superseded_reason: "state_reconfirmed"`.
   */
  reconfirmed_state_hash: Sha256Hex.optional(),
} as const;

/** Las claves del enlace de operación, para gates y vectores. */
export const OPERATION_LINK_KEYS = Object.keys(
  OperationLinkFields
) as ReadonlyArray<keyof typeof OperationLinkFields>;
