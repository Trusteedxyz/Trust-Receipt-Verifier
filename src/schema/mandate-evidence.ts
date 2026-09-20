/**
 * Evidencia del MANDATO y de la APROBACIÓN — lo que hace demostrable ante un
 * tercero que el total cobrado cabía dentro de lo autorizado.
 *
 * ## Qué problema cierra
 *
 * Hasta hoy el recibo firmaba `amount`/`currency` y, cuando el mandato del
 * agente denegaba la compra, el recibo de la denegación y el del reintento
 * quedaban atados por `operation_id`. Lo que NO viajaba en el cuerpo firmado
 * era el mandato mismo: su identidad, su tope y a quién se le concedió. Un
 * auditor externo veía «135,99 USD, permitido» y tenía que creerse que alguien
 * había comprobado un límite que el artefacto no menciona.
 *
 * Con estos campos, un tercero que tenga el mandato original puede recomputar
 * {@link computeMandateClaimsHash} y comprobar que es EL MISMO que se aplicó, y
 * luego comparar `amount` con `mandate_max_amount_cents` sin fiarse de nadie.
 *
 * ## Qué NO afirma: la firma del mandato
 *
 * `mandate_verification` existe justamente para no mentir aquí. Hoy el mandato
 * se PARSEA, no se verifica: la verificación criptográfica está diferida a los
 * specs de binding AP2/MPP (044/056/058) — ver `payment-mandate-claims.ts`, que
 * lo dice en su primera línea. Por eso el único valor que hoy puede emitirse es
 * `structure_only`, y `signature_verified` está declarado para el día que
 * exista, no para usarlo antes. Un recibo con `structure_only` prueba «el
 * agente se ató a este límite y lo respetamos», NO «alguien le concedió ese
 * límite».
 *
 * ## Por qué opcionales y sin `schema_version` nueva
 *
 * El mismo razonamiento —y las mismas dos razones mecánicas— que
 * `operation-link.ts` y `policy-evidence.ts`: `verifier.ts` verifica la firma
 * sobre los BYTES CRUDOS antes de parsear, así que añadir campos no invalida
 * ninguna firma ya emitida; y el dispatcher falla ruidosamente ante versiones
 * futuras, así que estrenar un `schema_version` haría que TODO verificador
 * desplegado —TypeScript y Python— rechazase estos recibos hasta actualizarse.
 *
 * Se comprobó, además, que el esquema congelado
 * `trust-receipt-v1.0-final.schema.json` **no** declara `additionalProperties`
 * en el nivel superior: campos nuevos no lo invalidan, y por eso esto no toca
 * el artefacto congelado, ni `EMBEDDED_SCHEMA_SHA256`, ni el port Python.
 *
 * ## Por qué `mandate_claims_hash` y no `mandate_hash`
 *
 * `mandate_hash` **ya existe** y significa otra cosa: es una claim del v1.0
 * histórico (el triplete `mandate_hash` / `permit2_authorization_hash` /
 * `mcp_tool_invocation_hash` que la D24 sustituyó por `authorization_scheme` +
 * `payment_authorization_hash`), viaja como *tagged digest* `sha256:<hex>` y
 * sigue vivo en el corpus — el vector de conformidad
 * `test-vectors/v11/017-legacy-v10-receipt.json` lo lleva.
 *
 * Declararlo aquí con formato hex a secas **rechazaba ese vector**: un recibo
 * legacy perfectamente válido pasaba a `rejected`. Lo cazó la suite, no el
 * compilador. Nombre distinto, además, porque el material también lo es: aquél
 * hashea el artefacto del mandato, éste las claims que se aplicaron.
 *
 * ## Privacidad
 *
 * Ni un dato del comprador. `mandate_subject` es el AGENTE (`sub` del mandato)
 * y `mandate_audience` la TIENDA (`aud`); `approval_ref` es una referencia
 * opaca de nuestra propia superficie, no un identificador de persona. El hash
 * se calcula sobre esas mismas seis claims, así que tampoco puede filtrar por
 * la puerta de atrás.
 *
 * ## Contrato publicado
 *
 * **Presentes ⇒ autoritativos; ausentes ⇒ el recibo no declara mandato ni
 * aprobación.** Ausente NO significa «no lo hubo».
 */
import { createHash } from "node:crypto";
import canonicalize from "canonicalize";
import { z } from "zod";

/** SHA-256 en hexadecimal minúsculo, la forma que emiten nuestros digests. */
const Sha256Hex = z
  .string()
  .regex(/^[0-9a-f]{64}$/, "must be lowercase SHA-256 hex");

/**
 * Qué se comprobó del mandato antes de aplicarlo.
 *
 * Union CERRADA a propósito: es el campo del que depende el valor probatorio
 * entero, y abrirlo a `string` permitiría que un emisor escribiera una clase de
 * verificación que no existe.
 */
export const MandateVerificationSchema = z.enum([
  /** Se leyeron las claims y se aplicó el tope. NO se verificó ninguna firma. */
  "structure_only",
  /** Firma del mandato verificada criptográficamente. Hoy nadie lo emite. */
  "signature_verified",
]);

export type MandateVerification = z.infer<typeof MandateVerificationSchema>;

/**
 * Las seis claims del mandato que entran en el material hasheado.
 *
 * Es EXACTAMENTE el `PaymentMandateClaims` de `packages/shared`. Se redeclara
 * aquí —en vez de importarlo— porque este paquete es el que consume un
 * verificador de tercero y no puede depender del monorepo; la equivalencia la
 * fija un test de forma en el emisor.
 */
export interface MandateClaimsForHash {
  readonly mandate_id: string;
  readonly max_amount_cents: number;
  readonly currency: string;
  readonly exp: number;
  readonly sub: string;
  readonly aud: string;
}

/**
 * El material EXACTO sobre el que se calcula `mandate_claims_hash`.
 *
 * ```
 * mandate_claims_hash = sha256( RFC8785({aud, currency, exp, mandate_id,
 *                                 max_amount_cents, sub}) )
 * ```
 *
 * Se hashea la forma canónica de las SEIS claims, y no la cadena presentada en
 * la cabecera, por dos motivos:
 *
 *   1. La cadena presentada trae codificación, cabecera y —cuando la haya—
 *      firma. Dos presentaciones equivalentes darían hashes distintos, y el
 *      recibo dejaría de poder atarse a «el mandato que se aplicó».
 *   2. Lo que se aplicó fueron las claims. Hashear otra cosa haría que el hash
 *      probase un artefacto distinto del que gobernó la decisión.
 *
 * ⚠️ Este material es ESTABLE por contrato. Ampliarlo cambia todos los hashes
 * ya emitidos y rompe la comparación de cualquier tercero que los guardara —
 * ver `wiki/gotchas/ampliar-un-material-hasheado-2026-09-08.md`. Una claim
 * nueva exige campo nuevo, no una séptima clave aquí.
 *
 * Se exporta aparte del hash para que un tercero pueda inspeccionar la cadena
 * y no sólo aceptar un digest opaco.
 */
export function serializeMandateClaimsForHash(
  claims: MandateClaimsForHash
): string {
  const material = {
    aud: claims.aud,
    currency: claims.currency,
    exp: claims.exp,
    mandate_id: claims.mandate_id,
    max_amount_cents: claims.max_amount_cents,
    sub: claims.sub,
  };
  // `canonicalize` ordena las claves por sí mismo (RFC 8785); el orden literal
  // de arriba es para que se lea igual que el material documentado, no una
  // dependencia del resultado. Hay un test que lo fija reordenando la entrada.
  return canonicalize(material) ?? JSON.stringify(material);
}

/** SHA-256 hex minúscula de {@link serializeMandateClaimsForHash}. */
export function computeMandateClaimsHash(claims: MandateClaimsForHash): string {
  return createHash("sha256")
    .update(serializeMandateClaimsForHash(claims), "utf8")
    .digest("hex");
}

/**
 * Los ocho campos del mandato, listos para esparcir dentro de un `z.object`.
 *
 * Objeto plano y no `z.object` por la misma razón que sus hermanos: se inyecta
 * tal cual en los tres esquemas (v1.0 canónico, v1.0 legacy compacto y v1.1
 * estricto) sin que ninguno herede la estrictez de otro.
 */
export const MandateEvidenceFields = {
  /** Identidad del mandato aplicado. Opaca: no se le impone forma. */
  mandate_id: z.string().min(1).max(128).optional(),
  /** Ver {@link computeMandateClaimsHash} para el material exacto. */
  mandate_claims_hash: Sha256Hex.optional(),
  /**
   * El tope, en unidades mínimas. Es el número contra el que un tercero compara
   * `amount` — sin él, el resto de la evidencia no demuestra nada.
   */
  mandate_max_amount_cents: z.number().int().nonnegative().optional(),
  /**
   * Moneda DEL MANDATO. Puede diferir de la del carrito: cuando difieren, la
   * frontera deniega por `mandate_currency_mismatch`, y publicar sólo la del
   * carrito borraría justamente la causa.
   */
  mandate_currency: z
    .string()
    .regex(/^[A-Z]{3}$/, "must be an uppercase ISO 4217 code")
    .optional(),
  /** `sub`: el AGENTE al que se concedió. Nunca el comprador. */
  mandate_subject: z.string().min(1).max(256).optional(),
  /** `aud`: la TIENDA para la que vale. */
  mandate_audience: z.string().min(1).max(256).optional(),
  /** `exp` en unix seconds. Con `issued_at` a la vista, la caducidad es comprobable. */
  mandate_expires_at: z.number().int().positive().optional(),
  /** Qué se comprobó. Ver {@link MandateVerificationSchema}. */
  mandate_verification: MandateVerificationSchema.optional(),
} as const;

/** Las claves de la evidencia de mandato, para gates y vectores. */
export const MANDATE_EVIDENCE_KEYS = Object.keys(
  MandateEvidenceFields
) as ReadonlyArray<keyof typeof MandateEvidenceFields>;

/**
 * La aprobación fuera de banda, cuando la hubo.
 *
 * Va aparte del mandato porque responde a otra pregunta: el mandato dice
 * «cuánto podía gastar el agente», la aprobación dice «una persona dijo que sí
 * a ESTA compra». Colapsarlas haría que el recibo no pudiera distinguir un
 * checkout dentro de mandato SIN aprobación humana de uno con las dos cosas.
 *
 * El origen del dato es la sesión (server-authoritative), NUNCA los argumentos
 * de la tool: si el agente pudiera declarar «un humano aprobó esto», el recibo
 * firmaría una afirmación que el propio firmante no puede sostener.
 */
export const ApprovalEvidenceFields = {
  /** Referencia opaca de la aprobación registrada en nuestra superficie. */
  approval_ref: z.string().min(1).max(256).optional(),
  /**
   * Por dónde llegó (p. ej. `demo_playground_confirmation`). Cadena laxa y no
   * enum: los canales los añade el producto, y rechazar el recibo ENTERO por un
   * canal que este verificador no conoce convertiría un artefacto válido en
   * inválido.
   */
  approval_channel: z.string().min(1).max(64).optional(),
  /** Unix seconds del momento aprobado. Comparable con `issued_at`. */
  approval_at: z.number().int().positive().optional(),
} as const;

/** Las claves de la evidencia de aprobación, para gates y vectores. */
export const APPROVAL_EVIDENCE_KEYS = Object.keys(
  ApprovalEvidenceFields
) as ReadonlyArray<keyof typeof ApprovalEvidenceFields>;
