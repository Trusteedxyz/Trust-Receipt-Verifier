/**
 * M-01 (plan de evolución 2026-08-21, §3) — Merchant Identity Assertions.
 *
 * Implementa `draft-anders-merchant-identity-assertions-01` (R. Anders,
 * RegisteredBrands.AI; Informational; 4-jul-2026; expira 5-ene-2027). El texto
 * normativo está en `docs/referencias/drafts-mia/`.
 *
 * ## Qué es esto y qué no
 *
 * Verifica la MIA de un TERCERO: dado un dominio, dice si la afirmación de
 * identidad publicada ahí es válida y qué reclama. Nada más.
 *
 * El propio draft lo acota, y conviene repetirlo aquí porque es la parte que se
 * malinterpreta: una MIA válida **no** dice que el comerciante sea de fiar, ni
 * solvente, ni recomendable. §5 del draft: *«Reputation, ratings, scoring, and
 * behavioral signals are out of scope»*, y *«An MIA is not a certification,
 * accreditation, or endorsement»*. El resultado es binario más un conjunto de
 * claims; no produce ningún orden.
 *
 * ## Por qué el draft merece un verificador y no una apuesta
 *
 * Es una submission individual, Informational, sin implementaciones, y hay un
 * segundo draft disputando el mismo terreno (`draft-hood-agtp-merchant-identity`).
 * Verificar MIAs ajenas no exige ser QTSP ni depende de InfoCert ni de EUDI, y
 * conserva valor aunque este draft muera: el coste de leer un JSON firmado por
 * otro es bajo y el riesgo de no poder leerlo es alto.
 */

/** §7.1 — `entityType` es un enum cerrado. */
export const MIA_ENTITY_TYPES = [
  "corporation",
  "llc",
  "partnership",
  "sole_proprietor",
  "cooperative",
  "nonprofit",
  "government",
  "other",
] as const;
export type MiaEntityType = (typeof MIA_ENTITY_TYPES)[number];

/** §7.3 — identificador del sobre de prueba. */
export const MIA_PROOF_TYPE = "MerchantIdentityProof-v1";

/** §10.1 — único algoritmo obligatorio. */
export const MIA_ALG_ED25519 = "Ed25519";

/** §7.5 — versión de la especificación, no del emisor. */
export const MIA_VERSION = 1;

/** §8.1 y §8.2 — rutas well-known registradas en §15. */
export const MIA_WELL_KNOWN_PATH = "/.well-known/merchant-identity.json";
export const MIDD_WELL_KNOWN_PATH = "/.well-known/mia-delegation.json";

/** §15.3 y §15.4 — tipos de medio. */
export const MIA_MEDIA_TYPE = "application/merchant-identity+json";
export const MIDD_MEDIA_TYPE = "application/merchant-delegation+json";

/** §8.2(a) — prefijo del registro DNS TXT y nombre bajo el que vive. */
export const MIA_DNS_TXT_PREFIX = "_mia-auth";
export const MIA_DNS_TXT_VERSION = "mia1";

/**
 * §10.4 paso 1 — cota de tamaño de la respuesta. El draft dice que DEBERÍA ser
 * al menos 64 KiB y NO DEBERÍA pasar de 1 MiB. Se toma el mínimo recomendado
 * como defecto: un documento de identidad que no cabe en 64 KiB es sospechoso,
 * no grande.
 */
export const MIA_MIN_MAX_BYTES = 64 * 1024;
export const MIA_ABSOLUTE_MAX_BYTES = 1024 * 1024;

/** §12 — el ERT no puede vivir más de 300 s. */
export const ERT_MAX_LIFETIME_SECONDS = 300;

export interface MiaIssuer {
  readonly name: string;
  readonly domain: string;
  readonly keyDirectory: string;
}

export interface MiaProof {
  readonly type: string;
  readonly alg: string;
  readonly created: string;
  readonly verificationMethod: string;
  readonly proofValue: string;
}

/** §7.1 + §7.2. Los opcionales quedan `unknown` donde el draft no los acota. */
export interface MerchantIdentityAssertion {
  readonly version: number;
  readonly subject: string;
  readonly legalName: string;
  readonly entityType: MiaEntityType;
  readonly jurisdiction: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly issuer: MiaIssuer;
  readonly registrationId?: string;
  readonly evidenceUris?: readonly string[];
  readonly extensions?: Record<string, unknown>;
  /** §11.2 — extensión de revocación, opcional. */
  readonly revocationUri?: string;
  readonly proof: MiaProof;
}

/** §8.2(b) — Merchant Identity Delegation Document. */
export interface MerchantIdentityDelegation {
  readonly version: number;
  readonly type: "MerchantIdentityDelegation";
  readonly subject: string;
  readonly authorizedIssuer: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly proof: MiaProof;
}

/**
 * Motivos de fallo. Cada uno corresponde a un paso concreto del draft, para que
 * un rechazo se pueda rastrear hasta la línea que lo exige en vez de degenerar
 * en un "no válido" sin causa.
 */
export type MiaFailureReason =
  // §10.4 paso 1
  | "retrieval_failed"
  | "redirect_not_followed"
  | "response_too_large"
  // §10.4 paso 2
  | "content_type_invalid"
  // §10.4 paso 3
  | "not_json"
  | "proof_absent"
  // §7.5 / §7.1
  | "version_unrecognized"
  | "claims_shape_invalid"
  // §10.4 paso 4
  | "proof_type_unrecognized"
  | "alg_unrecognized"
  // §10.4 paso 5
  | "verification_method_malformed"
  | "verification_method_not_https"
  | "issuer_domain_mismatch"
  // §10.4 pasos 6-7
  | "key_directory_unreachable"
  | "key_directory_invalid"
  | "kid_not_found"
  | "jwk_parameters_invalid"
  // §10.4 paso 9
  | "signature_invalid"
  // §10.4 paso 10
  | "not_yet_valid"
  | "expired"
  | "created_mismatch"
  // §10.4 paso 11
  | "subject_mismatch"
  // §10.4 paso 12 / §8.2
  | "third_party_not_authorized"
  | "delegation_malformed"
  | "delegation_expired"
  | "delegation_subject_mismatch"
  | "delegation_issuer_mismatch"
  | "delegation_signature_invalid"
  // §2
  | "domain_invalid";

export interface MiaVerificationSuccess {
  readonly valid: true;
  readonly assertion: MerchantIdentityAssertion;
  /**
   * Cómo se estableció la autoridad del emisor. El draft (§9) distingue
   * autoemisión de emisión por tercero porque **la garantía no es la misma**, y
   * quien consuma esto necesita saber cuál tiene delante para aplicar su
   * política (§9.4). Aplanarlo a un booleano perdería justo esa distinción.
   */
  readonly issuance: "self" | "third_party_dns" | "third_party_midd";
}

export interface MiaVerificationFailure {
  readonly valid: false;
  readonly reason: MiaFailureReason;
  readonly detail?: string;
}

export type MiaVerificationResult =
  | MiaVerificationSuccess
  | MiaVerificationFailure;
