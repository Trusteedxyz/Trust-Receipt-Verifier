/**
 * Evidencia del MANDATO EMITIDO POR LA PLATAFORMA (`platform_mandate`).
 *
 * Cinco campos hermanos, todos opcionales, que acompanan a `mandate_verification`
 * cuando ese valor es `signature_verified`. Dicen QUIEN firmo el mandato, con
 * que clave, de que clase fue la aprobacion y sobre que carrito. No tocan el
 * esquema congelado v1.0-FINAL: no declara `additionalProperties` arriba, y por
 * eso no cambia el artefacto, ni `EMBEDDED_SCHEMA_SHA256`, ni ningun vector
 * existente (mismo razonamiento que `mandate-evidence.ts` y `operation-link.ts`).
 *
 * ## Que prueba y que no
 *
 * Un recibo con estos campos prueba: "Trusteed afirma que hubo una aprobacion de
 * clase X sobre este carrito, para este agente, con este tope". NO prueba
 * consentimiento del usuario ni que una persona viera el importe. La clase esta
 * en un enum cerrado, y `mandate_human_presence_verified` solo puede ser `true`
 * con `passkey` (unica clase con presencia humana): un recibo que diga otra cosa
 * lo rechaza el verificador.
 *
 * ## Contrato
 *
 * Presentes => autoritativos; ausentes => el recibo no declara mandato de
 * plataforma. `mandate_verification: "signature_verified"` sin `mandate_issuer`,
 * `mandate_kid` y `mandate_approval_method` es un recibo que afirma una
 * verificacion sin decir de quien: se rechaza.
 */
import { z } from "zod";

/** Enum CERRADO. `magic_link` y `passkey` estan declarados y hoy no tienen emisor. */
export const MandateApprovalMethodSchema = z.enum([
  "agent_bound",
  "magic_link",
  "passkey",
]);

export const PlatformMandateEvidenceFields = {
  /** Origen (`iss`) del despliegue que firmo el mandato. */
  mandate_issuer: z.string().url().max(256).optional(),
  /** `kid` de la clave publicada en el JWKS que firmo el mandato. */
  mandate_kid: z.string().min(1).max(128).optional(),
  /** Clase de la aprobacion. Ver {@link MandateApprovalMethodSchema}. */
  mandate_approval_method: MandateApprovalMethodSchema.optional(),
  /** `true` solo con `passkey`. Ver {@link platformMandateEvidenceIssues}. */
  mandate_human_presence_verified: z.boolean().optional(),
  /** `cart_hash` del preview aprobado (base64url, dominio propio). */
  mandate_cart_hash: z.string().min(1).max(128).optional(),
} as const;

export const PLATFORM_MANDATE_EVIDENCE_KEYS = Object.keys(
  PlatformMandateEvidenceFields
) as ReadonlyArray<keyof typeof PlatformMandateEvidenceFields>;

export interface PlatformMandateEvidenceView {
  readonly mandate_verification?: string | undefined;
  readonly mandate_issuer?: string | undefined;
  readonly mandate_kid?: string | undefined;
  readonly mandate_approval_method?: string | undefined;
  readonly mandate_human_presence_verified?: boolean | undefined;
}

/**
 * Invariantes entre campos que un `z.object` no puede expresar. Devuelve los
 * mensajes (vacio = coherente). Lo aplican los tres verificadores (canonico,
 * legacy compacto y v1.1) tras parsear, y no dentro de los `z.object`: envolver
 * el esquema en un `ZodEffects` rompe a quien lee `.shape`.
 */
export function platformMandateEvidenceIssues(
  receipt: PlatformMandateEvidenceView
): readonly string[] {
  const issues: string[] = [];
  if (
    receipt.mandate_human_presence_verified === true &&
    receipt.mandate_approval_method !== "passkey"
  ) {
    issues.push(
      "mandate_human_presence_verified can only be true when mandate_approval_method is passkey"
    );
  }
  if (receipt.mandate_verification === "signature_verified") {
    for (const field of [
      "mandate_issuer",
      "mandate_kid",
      "mandate_approval_method",
    ] as const) {
      if (receipt[field] === undefined) {
        issues.push(
          `mandate_verification signature_verified requires ${field}`
        );
      }
    }
  }
  return issues;
}
