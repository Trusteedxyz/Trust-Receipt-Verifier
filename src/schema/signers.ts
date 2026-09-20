/**
 * Declaración de firmantes del TrustReceipt — SSOT de los campos R-03.
 *
 * ## Qué problema resuelve
 *
 * El rc.2 del A-Comm Evidence Protocol introdujo **clases de verificación
 * relativas al destinatario** (§2.8, §5, §4.3): un paquete de evidencia sin
 * anclaje externo y verificado sólo por quien lo exporta obtiene la clase más
 * baja, `Asserted`. Ése es nuestro modelo hoy: firmamos lo que observamos, con
 * una clave nuestra, y el verificador que publicamos es nuestro.
 *
 * Un tercero no puede clasificar la evidencia si el artefacto no le dice quién
 * firmó ni bajo qué custodia. Este bloque se lo dice. **No mejora la clase: la
 * hace legible.** Es la diferencia entre que un adjudicador tenga que
 * preguntarnos y que pueda deducirlo del propio recibo.
 *
 * ## Por qué va DENTRO del cuerpo firmado
 *
 * La distinción importa y es fácil de confundir:
 *
 * - Una **co-firma** es una firma sobre el `payload_hash`. No puede vivir dentro
 *   del cuerpo que firma — sería circular — y por eso el plan la situaba fuera.
 * - Esto **no es una firma, es una afirmación**: "quién firmó y quién tenía la
 *   clave". Si viajara fuera del cuerpo firmado, cualquiera podría editar
 *   `platform_held` → `party_held` y **subirse la clase de verificación**
 *   falsificando justo el dato que existe para impedirlo.
 *
 * Degradar sin firma es inocuo; ascender sin firma es el ataque. Va dentro.
 *
 * ## Estado hoy
 *
 * El corpus vivo tiene EXACTAMENTE un firmante: nosotros, con la clave en
 * nuestra custodia. Declararlo no es una concesión, es el dato. El camino que
 * cambiaría la clase (claves en poder del comerciante) está descrito en
 * `docs/analisis/informe-estrategico-v3-contraplan-2026-07-29.md` §R-03.
 */

import { z } from "zod";

/**
 * Quién es el firmante respecto de la operación.
 *
 * `issuer` es el único valor que el emisor produce hoy. Los demás existen para
 * que el schema no tenga que cambiar cuando aparezca una firma que no sea
 * nuestra — no para insinuar que ya existen.
 */
export const SignerPartySchema = z.enum([
  /** Quien emite y firma el recibo (hoy: la plataforma). */
  "issuer",
  /** El comercio cuya política se aplicó. */
  "merchant",
  /** El agente que ejecutó la operación. */
  "agent",
  /** El proveedor de pago que la liquidó. */
  "psp",
]);

/**
 * Quién tiene la clave privada. Es EL dato que decide la clase de verificación.
 *
 * Una firma hecha con una clave que custodia el emisor es indistinguible de una
 * firma del emisor, por mucho que la clave esté etiquetada con otro nombre.
 */
export const SignerCustodySchema = z.enum([
  /** La privada la genera, cifra y usa la plataforma. */
  "platform_held",
  /** La privada la posee la parte que firma; la plataforma sólo ve la pública. */
  "party_held",
]);

/**
 * Relación del firmante con el sujeto de la operación.
 *
 * `processor` usa el sentido del RGPD a propósito: la plataforma trata datos por
 * cuenta del comercio, que es el responsable. Un adjudicador que lea
 * `party: issuer` + `relation_to_subject: processor` sabe que la evidencia
 * viene de un procesador, no de una parte independiente.
 */
export const SignerRelationSchema = z.enum([
  /** Trata la operación por cuenta del sujeto (plataforma ↔ comercio). */
  "processor",
  /** El firmante ES el sujeto. */
  "self",
  /** Tercero sin interés en el resultado. */
  "independent",
]);

export const SignerSchema = z.object({
  party: SignerPartySchema,
  /** `kid` de la clave usada. Debe resolver contra el JWKS del firmante. */
  kid: z.string().min(1).max(256),
  custody: SignerCustodySchema,
  relation_to_subject: SignerRelationSchema,
});

/**
 * Listo para esparcir dentro de un `z.object`, igual que `PolicyEvidenceFields`.
 *
 * Opcional: los recibos emitidos antes de 2026-07-30 no lo llevan y tienen que
 * seguir verificando durante toda la ventana de retención (FR-018). Ausente NO
 * significa "sin firmantes" — significa que ese recibo no lo declara.
 */
export const SignerFields = {
  signers: z.array(SignerSchema).min(1).max(8).optional(),
} as const;

export type Signer = z.infer<typeof SignerSchema>;
export type SignerCustody = z.infer<typeof SignerCustodySchema>;

/**
 * Clase de verificación deducible del propio recibo.
 *
 * Deliberadamente conservadora: basta UN firmante en custodia de la plataforma
 * para que el conjunto no pueda considerarse verificado de forma independiente.
 * Y sin declaración no se asume nada mejor — `undefined` significa "el recibo no
 * da información suficiente", que no es lo mismo que "es independiente".
 */
export function classifySignerCustody(
  signers: readonly Signer[] | undefined
): "self_asserted" | "party_attested" | undefined {
  if (signers === undefined || signers.length === 0) return undefined;
  return signers.every((s) => s.custody === "party_held")
    ? "party_attested"
    : "self_asserted";
}
