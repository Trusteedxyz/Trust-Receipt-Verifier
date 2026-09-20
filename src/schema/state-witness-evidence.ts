/**
 * Evidencia de STATE WITNESS — qué resolvió el comparador de spec-063 antes de
 * mover dinero, y contra qué estado autoritativo.
 *
 * Cierra un hueco concreto: el recibo sólo decía algo del estado cuando hubo
 * reconfirmación (`reconfirmed_state_hash`). Un checkout que se ejecutó porque
 * el estado NO se había movido no dejaba constancia firmada. Es la mitad que
 * complementa a una autorización del consumidor (p. ej. Verifiable Intent):
 * aquélla prueba qué se autorizó; ésta, que lo autorizado seguía siendo verdad
 * al cobrar.
 *
 * Opcionales y sin `schema_version` nueva, por las mismas razones que
 * `operation-link.ts` y `mandate-evidence.ts`: la firma cubre los bytes crudos
 * y el esquema congelado no declara `additionalProperties` arriba.
 *
 * Contrato: presentes ⇒ autoritativos; ausentes ⇒ el recibo no declara que
 * State Witness corriera. Ausente NO significa «el estado cambió».
 */
import { z } from "zod";

const Sha256Hex = z
  .string()
  .regex(/^[0-9a-f]{64}$/, "must be lowercase SHA-256 hex");

/** Sin BLOCK: un checkout bloqueado no se ejecuta, y su recibo no puede decir lo contrario. */
export const StateWitnessResolutionSchema = z.enum([
  "EXECUTE",
  "EXECUTE_WITHIN_TOLERANCE",
  "RECONFIRM",
]);

/** Espejo de `ExecutionDivergenceReason` (apps/api state-witness). Lo fija un test de forma en el emisor. */
export const StateWitnessReasonSchema = z.enum([
  "price_within_tolerance",
  "price_diverged",
  "price_diverged_severely",
  "stock_insufficient",
  "policy_version_changed",
  "authoritative_state_unavailable",
]);

export const StateWitnessEvidenceFields = {
  state_witness_resolution: StateWitnessResolutionSchema.optional(),
  /** SHA-256 RFC 8785 del estado autoritativo en el instante de ejecutar. */
  state_witness_authoritative_hash: Sha256Hex.optional(),
  state_witness_reasons: z.array(StateWitnessReasonSchema).max(6).optional(),
} as const;

export const STATE_WITNESS_EVIDENCE_KEYS = Object.keys(
  StateWitnessEvidenceFields
) as ReadonlyArray<keyof typeof StateWitnessEvidenceFields>;
