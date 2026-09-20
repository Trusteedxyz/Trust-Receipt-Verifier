/**
 * §3 y §4 de `draft-hood-agtp-merchant-identity-02` — validación del Agent
 * Identity Document como contraparte de un PURCHASE.
 *
 * Función pura: sirva quien sirva el documento (una resolución AGTP, una caché,
 * un vector de conformidad), las reglas de rol, ciclo de vida, nivel de
 * confianza y huella son las mismas. Separarla del transporte es lo que permite
 * implementar la parte verificable del draft sin implementar AGTP entero.
 */

import { createHash } from "node:crypto";
import {
  AGENT_ID_PATTERN,
  AGTP_MERCHANT_FIELDS,
  AGTP_MERCHANT_ROLE,
  AGTP_VERIFICATION_PATHS,
  NON_RETRYABLE_REASONS,
  TIER2_REQUIRED_TRUST_WARNING,
  normalizeLifecycleState,
  type AgtpAgentIdentityDocument,
  type AgtpMerchantFailureReason,
  type AgtpMerchantFields,
  type AgtpMerchantVerificationResult,
  type AgtpTrustTier,
  type AgtpVerificationPath,
} from "./types.js";

/**
 * §8.2 — la retriabilidad depende del motivo **y, en el ciclo de vida, del
 * estado concreto**: `Suspended` se puede reintentar cuando el comerciante
 * vuelva a Activo; `Revoked`/`Deprecated` no se reintentan sin remediación. Un
 * único `lifecycle_not_active` "reintentable" mandaría a un cliente a repetir
 * eternamente contra un comerciante revocado.
 */
function fail(
  reason: AgtpMerchantFailureReason,
  detail?: string,
  retryableOverride?: boolean
): AgtpMerchantVerificationResult {
  const retryable = retryableOverride ?? !NON_RETRYABLE_REASONS.has(reason);
  return detail === undefined
    ? { valid: false, reason, retryable }
    : { valid: false, reason, retryable, detail };
}

/**
 * §4.1 paso 6 — «Computing the manifest fingerprint (SHA-256 hash of the
 * canonical Agent Identity Document bytes)».
 *
 * La canonicalización se recibe del llamante. El draft dice «canonical … bytes»
 * y **no dice cuál** es la forma canónica del Identity Document; elegir una en
 * silencio produciría huellas que no casan con las del servidor receptor, y ese
 * desajuste es justo lo que devuelve un 458. Igual que con Cart-Digest: el hueco
 * es del draft, y se hace visible en la firma de la función en vez de taparse.
 */
export function computeManifestFingerprint(
  document: unknown,
  canonicalize: (value: unknown) => string
): string {
  const bytes = Buffer.from(canonicalize(document), "utf8");
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

export interface VerifyMerchantIdentityOptions {
  /** §4.2 — el `Merchant-ID` que viajaba en la petición PURCHASE. */
  readonly expectedMerchantId: string;
  /** §4.2 — la huella que el agente dice haber verificado. */
  readonly presentedFingerprint?: string | null;
  readonly canonicalize: (value: unknown) => string;
  /**
   * §4.1 paso 5 — umbral de la política del agente para el importe en curso.
   * Sin umbral no se aplica: el draft lo deja a la política del llamante.
   */
  readonly minimumTrustTier?: AgtpTrustTier;
}

function readTrustTier(raw: unknown): AgtpTrustTier | null {
  return raw === 1 || raw === 2 || raw === 3 ? raw : null;
}

function readVerificationPath(raw: unknown): AgtpVerificationPath | null {
  return typeof raw === "string" &&
    (AGTP_VERIFICATION_PATHS as readonly string[]).includes(raw)
    ? (raw as AgtpVerificationPath)
    : null;
}

function extractMerchantFields(
  doc: AgtpAgentIdentityDocument
): AgtpMerchantFields {
  const out: Record<string, unknown> = {};
  for (const field of AGTP_MERCHANT_FIELDS) {
    if (doc[field] !== undefined) out[field] = doc[field];
  }
  return out as AgtpMerchantFields;
}

function hasAnyMerchantField(doc: Record<string, unknown>): boolean {
  return AGTP_MERCHANT_FIELDS.some((f) => doc[f] !== undefined);
}

/**
 * Verifica un Agent Identity Document como contraparte de PURCHASE.
 *
 * Orden deliberado: forma → rol → identificador → ciclo de vida → confianza →
 * huella. Cada paso puede devolver un motivo distinto porque §8.2 hace depender
 * la retriabilidad del motivo concreto: un `Suspended` se puede reintentar
 * cuando vuelva a Activo; un «este agente no es comerciante» no se reintenta
 * nunca.
 */
export function verifyMerchantIdentityDocument(
  document: unknown,
  options: VerifyMerchantIdentityOptions
): AgtpMerchantVerificationResult {
  if (typeof document !== "object" || document === null || Array.isArray(document)) {
    return fail("document_shape_invalid", "not a JSON object");
  }
  const doc = document as AgtpAgentIdentityDocument;

  // §3.2 — los campos de comerciante sin el rol NO invalidan el documento: el
  // draft dice «MUST ignore the merchant fields and log the inconsistency».
  // Pero un documento SIN rol tampoco es direccionable por PURCHASE (§4.1
  // paso 2), así que el rechazo llega igual — por el rol, no por los campos.
  const declaresMerchantRole = doc.role === AGTP_MERCHANT_ROLE;
  if (!declaresMerchantRole) {
    return fail(
      hasAnyMerchantField(doc as Record<string, unknown>)
        ? "merchant_fields_without_role"
        : "not_a_merchant",
      "Agent Identity Document does not declare role: \"merchant\""
    );
  }

  if (
    typeof doc.agent_id !== "string" ||
    !AGENT_ID_PATTERN.test(doc.agent_id)
  ) {
    return fail(
      "merchant_id_malformed",
      "agent_id must be 64 lowercase hexadecimal characters (§2)"
    );
  }

  // §4.2 — «the Merchant-ID does not match the addressed agent's canonical
  // Agent-ID» es una de las condiciones explícitas de 458.
  if (doc.agent_id !== options.expectedMerchantId) {
    return fail("merchant_id_mismatch");
  }

  const lifecycle = normalizeLifecycleState(doc.status);
  if (lifecycle === null) return fail("lifecycle_unknown", String(doc.status));
  // §3.4 — cualquier estado distinto de Activo: 458.
  if (lifecycle !== "active") {
    return fail("lifecycle_not_active", lifecycle, lifecycle === "suspended");
  }

  const trustTier = readTrustTier(doc.trust_tier);
  // §3.3 — Tier 3 NO puede aparecer en flujos PURCHASE de producción.
  if (trustTier === 3) return fail("trust_tier_experimental");
  // §3.3 — Tier 2 DEBE llevar el aviso, con ese valor exacto.
  if (trustTier === 2 && doc.trust_warning !== TIER2_REQUIRED_TRUST_WARNING) {
    return fail(
      "tier2_trust_warning_absent",
      `Tier 2 must carry trust_warning: "${TIER2_REQUIRED_TRUST_WARNING}"`
    );
  }
  if (
    options.minimumTrustTier !== undefined &&
    (trustTier === null || trustTier > options.minimumTrustTier)
  ) {
    return fail(
      "trust_tier_below_policy",
      `resolved tier ${trustTier ?? "unknown"} does not meet policy minimum ${options.minimumTrustTier}`
    );
  }

  // §4.1 paso 6 + §4.2 — la huella ata el documento que el agente verificó al
  // que el servidor presenta. Es la defensa contra la sustitución de manifiesto
  // (§9.2) y no se puede saltar sin comprometer la clave de la plataforma.
  const fingerprint = computeManifestFingerprint(doc, options.canonicalize);
  if (options.presentedFingerprint !== undefined) {
    if (
      options.presentedFingerprint === null ||
      options.presentedFingerprint.length === 0
    ) {
      return fail("fingerprint_absent");
    }
    if (options.presentedFingerprint !== fingerprint) {
      return fail("fingerprint_mismatch");
    }
  }

  return {
    valid: true,
    merchantId: doc.agent_id,
    lifecycle,
    trustTier,
    verificationPath: readVerificationPath(doc.verification_path),
    manifestFingerprint: fingerprint,
    merchantFields: extractMerchantFields(doc),
  };
}
