/**
 * M-01, segundo draft (plan de evolución 2026-08-21, §3) — identidad de
 * comerciante en AGTP: `draft-hood-agtp-merchant-identity-02` (C. Hood,
 * Nomotic; Informational; expira 27-nov-2026), sobre la base
 * `draft-hood-independent-agtp-09`.
 *
 * ## Qué se implementa, y qué NO
 *
 * **No hay cliente AGTP aquí, a propósito.** El plan asumía que «el coste
 * marginal del segundo draft es bajo». No lo es: MIA es un JSON firmado que se
 * descarga por HTTPS de un well-known, mientras que AGTP es un protocolo de
 * aplicación completo —puerto 4480, línea `AGTP/1.0 METHOD PATH`, TLS 1.3
 * obligatorio, framing por `Content-Length`, dieciocho métodos de suelo,
 * identidad por Agent Genesis, registro de plataforma de gobernanza—. La
 * verificación de contraparte de §4.1 empieza por **resolver una URI AGTP**.
 * Implementar eso es implementar un transporte nuevo, no un verificador.
 *
 * Lo que sí se implementa es exactamente lo que el draft declara verificable
 * **sin hablar AGTP**, que además es nuestra posición real en el flujo:
 *
 * - **Intent Assertion** (§5). §5.3 lo dice sin rodeos: el JWT está
 *   estructurado «precisely so that it can be forwarded» a una red de pago que
 *   lo verifica con la clave pública de la plataforma de gobernanza. Nosotros
 *   somos un receptor de ese reenvío.
 * - **Validación del Agent Identity Document con rol de comerciante** (§3, §4)
 *   como función pura: sirva quien sirva el documento, las reglas de rol,
 *   estado de ciclo de vida, nivel de confianza y huella son las mismas.
 * - **Cart-Digest** (§6, §9.4).
 *
 * Reglas y secciones en `docs/referencias/drafts-mia/NORMATIVE-EXTRACT-agtp-merchant-02.md`,
 * junto con siete defectos del draft encontrados al implementarlo.
 */

/** §3.1 — un comerciante es un agente cuyo Identity Document declara este rol. */
export const AGTP_MERCHANT_ROLE = "merchant";

/**
 * Estados de ciclo de vida.
 *
 * **Los dos drafts no coinciden**: merchant §3.4 (tabla 2) usa
 * `Active/Suspended/Revoked/Deprecated` en mayúscula inicial; la base v09 §7.3.3
 * usa minúsculas y **renombra `Revoked` a `retired`**. Un verificador estricto
 * con uno rechazaría documentos del otro, así que se aceptan ambas formas y se
 * normaliza — con la equivalencia declarada, no supuesta.
 */
export const AGTP_LIFECYCLE_STATES = [
  "active",
  "suspended",
  "retired",
  "deprecated",
] as const;
export type AgtpLifecycleState = (typeof AGTP_LIFECYCLE_STATES)[number];

/** `Revoked` (merchant v02) y `retired` (base v09) son el mismo estado. */
export function normalizeLifecycleState(raw: unknown): AgtpLifecycleState | null {
  if (typeof raw !== "string") return null;
  const lower = raw.toLowerCase();
  if (lower === "revoked") return "retired";
  return (AGTP_LIFECYCLE_STATES as readonly string[]).includes(lower)
    ? (lower as AgtpLifecycleState)
    : null;
}

/** §3.3 — niveles alineados con AGTP-TRUST. */
export type AgtpTrustTier = 1 | 2 | 3;

/** §3.3 / base §7.1.9. `org-asserted` es el valor de Tier 2. */
export const AGTP_VERIFICATION_PATHS = [
  "dns-anchored",
  "log-anchored",
  "hybrid",
  "org-asserted",
] as const;
export type AgtpVerificationPath = (typeof AGTP_VERIFICATION_PATHS)[number];

/** §3.3 — el aviso exacto que un Tier 2 DEBE llevar. */
export const TIER2_REQUIRED_TRUST_WARNING = "legal-entity-unverified";

/** §3.2 — campos que sólo pueden aparecer con `role: "merchant"`. */
export const AGTP_MERCHANT_FIELDS = [
  "legal_entity_name",
  "merchant_category_code",
  "registered_jurisdiction",
  "accepted_payment_networks",
  "dispute_policy_uri",
  "refund_policy_uri",
] as const;

/** §5.2 — `exp` NO puede exceder `iat` + 300 s. */
export const INTENT_ASSERTION_MAX_LIFETIME_SECONDS = 300;

/**
 * §14.1 — tolerancia de reloj: recomendada ≤60 s; **NUNCA** superior a 300 s,
 * porque eso extendería la ventana de repetición más allá de la vida del token.
 */
export const INTENT_ASSERTION_RECOMMENDED_SKEW_SECONDS = 60;
export const INTENT_ASSERTION_MAX_SKEW_SECONDS = 300;

/** §2 — Merchant-ID = Agent-ID canónico: 64 hex minúsculas. */
export const AGENT_ID_PATTERN = /^[0-9a-f]{64}$/;

export interface AgtpMerchantFields {
  readonly legal_entity_name?: string;
  readonly merchant_category_code?: string;
  readonly registered_jurisdiction?: string;
  readonly accepted_payment_networks?: readonly string[];
  readonly dispute_policy_uri?: string;
  readonly refund_policy_uri?: string;
}

export interface AgtpAgentIdentityDocument extends AgtpMerchantFields {
  readonly agent_id: string;
  readonly role?: string;
  readonly status: string;
  readonly trust_tier?: number;
  readonly verification_path?: string;
  readonly trust_warning?: string;
  readonly [key: string]: unknown;
}

/**
 * Motivos de rechazo, ligados a la condición del draft que los exige. §8.1
 * enumera las condiciones de 458; §8.2 separa las reintentables de las que no.
 */
export type AgtpMerchantFailureReason =
  // §4.1 paso 2 / §8.1
  | "not_a_merchant"
  // §2
  | "merchant_id_malformed"
  // §4.2 / §8.1
  | "merchant_id_mismatch"
  | "fingerprint_absent"
  | "fingerprint_mismatch"
  // §3.4 / §8.1
  | "lifecycle_not_active"
  | "lifecycle_unknown"
  // §3.3
  | "trust_tier_experimental"
  | "tier2_trust_warning_absent"
  | "trust_tier_below_policy"
  // §3.2
  | "merchant_fields_without_role"
  // forma
  | "document_shape_invalid";

/**
 * §8.2 — la retriabilidad es parte del contrato, no una decisión del que
 * verifica: el cuerpo del 458 **DEBE** declarar `retryable`.
 */
export const NON_RETRYABLE_REASONS: ReadonlySet<AgtpMerchantFailureReason> =
  new Set([
    "not_a_merchant",
    "merchant_id_mismatch",
    "merchant_id_malformed",
    "merchant_fields_without_role",
    "trust_tier_experimental",
    "lifecycle_unknown",
    "document_shape_invalid",
  ]);

export interface AgtpMerchantVerificationSuccess {
  readonly valid: true;
  readonly merchantId: string;
  readonly lifecycle: AgtpLifecycleState;
  readonly trustTier: AgtpTrustTier | null;
  readonly verificationPath: AgtpVerificationPath | null;
  /** §4.1 paso 6 — SHA-256 de los bytes canónicos del documento. */
  readonly manifestFingerprint: string;
  readonly merchantFields: AgtpMerchantFields;
}

export interface AgtpMerchantVerificationFailure {
  readonly valid: false;
  readonly reason: AgtpMerchantFailureReason;
  /** §8.2 — declarado, no inferido por el llamante. */
  readonly retryable: boolean;
  readonly detail?: string;
}

export type AgtpMerchantVerificationResult =
  | AgtpMerchantVerificationSuccess
  | AgtpMerchantVerificationFailure;

// ─── Intent Assertion (§5) ─────────────────────────────────────────────────

/** §5.2 tabla 3 — claims de la Intent Assertion. */
export interface AgtpIntentAssertionClaims {
  readonly iss: string;
  readonly sub: string;
  readonly aud: string;
  readonly agent_id: string;
  readonly item_digest: string;
  readonly amount_ceiling: { readonly value: string; readonly currency: string };
  readonly nbf: number;
  readonly exp: number;
  readonly jti: string;
  readonly iat: number;
  readonly [key: string]: unknown;
}

export type AgtpIntentFailureReason =
  // forma / RFC 8725 (§14.8)
  | "jwt_malformed"
  | "alg_none_rejected"
  | "alg_unsupported"
  | "kid_absent"
  | "key_unresolved"
  | "signature_invalid"
  // §5.2 MUSTs
  | "claims_incomplete"
  | "expired"
  | "not_yet_valid"
  | "lifetime_exceeds_maximum"
  | "audience_mismatch"
  | "agent_id_mismatch"
  | "jti_replayed"
  // cotejo con la petición en curso
  | "item_digest_mismatch"
  | "amount_exceeds_ceiling"
  | "currency_mismatch"
  // configuración del verificador (§14.1)
  | "clock_skew_policy_invalid";

export interface AgtpIntentVerificationSuccess {
  readonly valid: true;
  readonly claims: AgtpIntentAssertionClaims;
  /** §5.2 — hay que registrarlo en el Attribution-Record para el uso único. */
  readonly jti: string;
}

export interface AgtpIntentVerificationFailure {
  readonly valid: false;
  readonly reason: AgtpIntentFailureReason;
  readonly detail?: string;
}

export type AgtpIntentVerificationResult =
  | AgtpIntentVerificationSuccess
  | AgtpIntentVerificationFailure;
