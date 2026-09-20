/**
 * §10.4 del draft — procedimiento de verificación, paso a paso.
 *
 * Toda la E/S es inyectable (`fetchDocument`, `fetchKeyDirectory`, `resolveTxt`,
 * `now`). Motivo: el procedimiento del draft tiene trece pasos y la mitad de los
 * fallos interesantes son de red o de reloj. Con la E/S dentro no se pueden
 * escribir vectores de conformidad deterministas, y sin vectores esto no es un
 * verificador, es una intención.
 *
 * Ninguna función lanza. Todo fallo sale como `{valid:false, reason}` con el
 * motivo ligado al paso del draft que lo exige.
 */

import canonicalize from "canonicalize";
import {
  createPublicKey,
  verify as nodeVerify,
  type JsonWebKeyInput,
} from "node:crypto";
import type { JWK } from "jose";
import { canonicalDomain, domainsEqual, httpsAuthority } from "./domain.js";
import {
  ERT_MAX_LIFETIME_SECONDS,
  MIA_ALG_ED25519,
  MIA_DNS_TXT_PREFIX,
  MIA_DNS_TXT_VERSION,
  MIA_ENTITY_TYPES,
  MIA_MEDIA_TYPE,
  MIA_PROOF_TYPE,
  MIA_VERSION,
  MIDD_MEDIA_TYPE,
  type MerchantIdentityAssertion,
  type MerchantIdentityDelegation,
  type MiaFailureReason,
  type MiaVerificationResult,
} from "./types.js";

// ─── E/S inyectable ────────────────────────────────────────────────────────

export interface FetchedDocument {
  readonly status: number;
  readonly contentType: string | null;
  readonly body: string;
  /** §10.4 paso 1: una redirección se trata como fallo de recuperación. */
  readonly redirected?: boolean;
}

export interface MiaVerifierIo {
  /** Recupera un documento HTTPS. Devolver `null` = fallo de red. */
  fetchDocument(url: string): Promise<FetchedDocument | null>;
  /** Recupera un JWKS. Devolver `null` = directorio inalcanzable (§10.2). */
  fetchKeyDirectory(url: string): Promise<{ keys: JWK[] } | null>;
  /** Registros TXT de un nombre. Devolver `null` = fallo de resolución. */
  resolveTxt(name: string): Promise<string[] | null>;
  now(): Date;
}

export interface VerifyMiaOptions {
  /** Dominio para el que se verifica (§10.4 paso 11). */
  readonly expectedSubject: string;
  readonly io: MiaVerifierIo;
  /** Cota de tamaño; el draft pide ≥64 KiB y ≤1 MiB (§10.4 paso 1). */
  readonly maxBytes?: number;
}

function fail(reason: MiaFailureReason, detail?: string): MiaVerificationResult {
  return detail === undefined
    ? { valid: false, reason }
    : { valid: false, reason, detail };
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** RFC 3339 → epoch ms, o `null` si no parsea. */
function parseRfc3339(value: unknown): number | null {
  if (typeof value !== "string" || value.length === 0) return null;
  const ms = Date.parse(value);
  return Number.isNaN(ms) ? null : ms;
}

function decodeBase64Url(value: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return null;
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  try {
    return new Uint8Array(Buffer.from(padded, "base64"));
  } catch {
    return null;
  }
}

// ─── Forma del documento (§7.1, §7.2, §7.3) ────────────────────────────────

/**
 * Comprueba la forma de los claims y de la prueba. Se separa de la verificación
 * criptográfica a propósito: un documento con la forma rota debe rechazarse
 * ANTES de tocar una clave, y el motivo debe distinguirse de "la firma no
 * cuadra".
 */
function validateShape(doc: Record<string, unknown>): MiaFailureReason | null {
  // §7.5 — modelo de rechazo estricto: versión desconocida se rechaza.
  if (doc.version !== MIA_VERSION) return "version_unrecognized";

  for (const field of ["subject", "legalName", "jurisdiction"] as const) {
    if (typeof doc[field] !== "string" || (doc[field] as string).length === 0) {
      return "claims_shape_invalid";
    }
  }
  if (
    typeof doc.entityType !== "string" ||
    !(MIA_ENTITY_TYPES as readonly string[]).includes(doc.entityType)
  ) {
    return "claims_shape_invalid";
  }
  // §7.1 — `subject` DEBE ser un FQDN en minúsculas.
  if (doc.subject !== (doc.subject as string).toLowerCase()) {
    return "claims_shape_invalid";
  }
  if (canonicalDomain(doc.subject as string) === null) return "domain_invalid";

  if (parseRfc3339(doc.issuedAt) === null) return "claims_shape_invalid";
  if (parseRfc3339(doc.expiresAt) === null) return "claims_shape_invalid";

  const issuer = doc.issuer;
  if (!isPlainObject(issuer)) return "claims_shape_invalid";
  for (const field of ["name", "domain", "keyDirectory"] as const) {
    if (
      typeof issuer[field] !== "string" ||
      (issuer[field] as string).length === 0
    ) {
      return "claims_shape_invalid";
    }
  }
  if (canonicalDomain(issuer.domain as string) === null) return "domain_invalid";

  // §7.2 — las claves de `extensions` usan notación de dominio invertido.
  if (doc.extensions !== undefined) {
    if (!isPlainObject(doc.extensions)) return "claims_shape_invalid";
  }
  if (doc.evidenceUris !== undefined) {
    if (
      !Array.isArray(doc.evidenceUris) ||
      doc.evidenceUris.some((u) => typeof u !== "string")
    ) {
      return "claims_shape_invalid";
    }
  }
  return null;
}

function validateProofShape(proof: unknown): MiaFailureReason | null {
  if (!isPlainObject(proof)) return "proof_absent";
  // §10.4 paso 4 — tipo y algoritmo, antes que nada más.
  if (proof.type !== MIA_PROOF_TYPE) return "proof_type_unrecognized";
  if (proof.alg !== MIA_ALG_ED25519) return "alg_unrecognized";
  for (const field of ["created", "verificationMethod", "proofValue"] as const) {
    if (
      typeof proof[field] !== "string" ||
      (proof[field] as string).length === 0
    ) {
      return "claims_shape_invalid";
    }
  }
  return null;
}

// ─── Entrada canónica de firma (§10.3 paso 2) ──────────────────────────────

/**
 * §10.3 paso 2 / §10.4 paso 8 — el documento SIN el campo `proof`,
 * canonicalizado con JCS [RFC8785], en UTF-8.
 *
 * Se elimina `proof` sobre una copia superficial: el draft dice «with the proof
 * field removed», no «con los campos que yo crea que son claims». Un allowlist
 * de campos rompería en cuanto un emisor añada un opcional legítimo — y esos
 * bytes SÍ están firmados.
 */
export function miaSigningInput(doc: Record<string, unknown>): Uint8Array | null {
  const { proof: _proof, ...claims } = doc;
  const canonical = canonicalize(claims);
  if (typeof canonical !== "string") return null;
  return new TextEncoder().encode(canonical);
}

/**
 * §10.4 paso 9 — Ed25519 crudo sobre los bytes canónicos.
 *
 * Se usa `node:crypto` en vez de `crypto.subtle`: la MIA lleva una firma
 * DETACHED sobre bytes, no un JWS, y `createPublicKey({format:"jwk"})` +
 * `verify(null, …)` es la ruta directa. `crypto.subtle` exigiría los tipos DOM,
 * que este paquete no incluye a propósito (se publica para verificación offline
 * en Node).
 *
 * `verify` nunca lanza aquí: una clave malformada devuelve `false`, que es el
 * resultado correcto — una firma que no se puede comprobar no es una firma
 * válida.
 */
function verifyEd25519(
  jwk: JWK,
  signature: Uint8Array,
  signingInput: Uint8Array
): boolean {
  try {
    const key = createPublicKey({
      key: jwk,
      format: "jwk",
    } as unknown as JsonWebKeyInput);
    return nodeVerify(null, signingInput, key, signature);
  } catch {
    return false;
  }
}

/** §10.2 — parámetros JWK exigidos para Ed25519. */
function findEd25519Jwk(keys: readonly JWK[], kid: string): JWK | "invalid" | null {
  const match = keys.find((k) => k.kid === kid);
  if (!match) return null;
  if (match.kty !== "OKP") return "invalid";
  if (match.crv !== "Ed25519") return "invalid";
  if (match.use !== undefined && match.use !== "sig") return "invalid";
  if (typeof match.x !== "string" || match.x.length === 0) return "invalid";
  return match;
}

/**
 * §10.4 paso 5 — separa `verificationMethod` por el ÚLTIMO `#`. Es literal en el
 * draft ("splitting on the last #") y no es un detalle: una URI de directorio
 * puede llevar un `#` antes, y partir por el primero daría otro kid.
 */
export function splitVerificationMethod(
  vm: string
): { keyDirectoryUri: string; kid: string } | null {
  const idx = vm.lastIndexOf("#");
  if (idx <= 0) return null;
  const keyDirectoryUri = vm.slice(0, idx);
  const kid = vm.slice(idx + 1);
  if (kid.length === 0) return null;
  return { keyDirectoryUri, kid };
}

// ─── Prueba compartida (MIA y MIDD usan el mismo sobre, §8.2) ───────────────

async function verifyProofAgainstDirectory(
  doc: Record<string, unknown>,
  io: MiaVerifierIo,
  expectedAuthority: string | null
): Promise<MiaFailureReason | null> {
  const proof = doc.proof as Record<string, unknown>;
  const split = splitVerificationMethod(proof.verificationMethod as string);
  if (!split) return "verification_method_malformed";

  const authority = httpsAuthority(split.keyDirectoryUri);
  if (authority === null) return "verification_method_not_https";
  if (expectedAuthority !== null && !domainsEqual(authority, expectedAuthority)) {
    return "issuer_domain_mismatch";
  }

  const directory = await io.fetchKeyDirectory(split.keyDirectoryUri);
  if (directory === null) return "key_directory_unreachable";
  if (!Array.isArray(directory.keys)) return "key_directory_invalid";

  const jwk = findEd25519Jwk(directory.keys, split.kid);
  if (jwk === null) return "kid_not_found";
  if (jwk === "invalid") return "jwk_parameters_invalid";

  const signature = decodeBase64Url(proof.proofValue as string);
  if (signature === null) return "signature_invalid";

  const signingInput = miaSigningInput(doc);
  if (signingInput === null) return "claims_shape_invalid";

  const ok = verifyEd25519(jwk, signature, signingInput);
  return ok ? null : "signature_invalid";
}

// ─── §8.2 — autorización de emisor tercero ─────────────────────────────────

function parseDnsAuthorization(records: readonly string[]): string | null {
  for (const raw of records) {
    // "v=mia1; issuer=trust.example.org"
    const parts = raw.split(";").map((p) => p.trim());
    const version = parts.find((p) => p.startsWith("v="))?.slice(2);
    if (version !== MIA_DNS_TXT_VERSION) continue;
    const issuer = parts.find((p) => p.startsWith("issuer="))?.slice(7);
    if (issuer && issuer.length > 0) return issuer;
  }
  return null;
}

function validateDelegationShape(
  doc: Record<string, unknown>
): MiaFailureReason | null {
  if (doc.version !== 1) return "delegation_malformed";
  if (doc.type !== "MerchantIdentityDelegation") return "delegation_malformed";
  for (const f of ["subject", "authorizedIssuer"] as const) {
    if (typeof doc[f] !== "string" || (doc[f] as string).length === 0) {
      return "delegation_malformed";
    }
  }
  if (parseRfc3339(doc.issuedAt) === null) return "delegation_malformed";
  if (parseRfc3339(doc.expiresAt) === null) return "delegation_malformed";
  if (validateProofShape(doc.proof) !== null) return "delegation_malformed";
  return null;
}

async function verifyThirdPartyAuthorization(
  assertion: MerchantIdentityAssertion,
  io: MiaVerifierIo,
  maxBytes: number
): Promise<
  | { ok: true; via: "third_party_dns" | "third_party_midd" }
  | { ok: false; reason: MiaFailureReason; detail?: string }
> {
  const subject = canonicalDomain(assertion.subject);
  if (subject === null) return { ok: false, reason: "domain_invalid" };

  // (a) TXT DNS. Se intenta primero: es la más barata y no exige que el
  // dominio del comerciante opere un Key Directory (§8.2, último párrafo).
  const txt = await io.resolveTxt(`${MIA_DNS_TXT_PREFIX}.${subject}`);
  if (txt !== null) {
    const declared = parseDnsAuthorization(txt);
    if (declared !== null) {
      // §8.2(a) — «MUST exactly match the issuer.domain field».
      if (domainsEqual(declared, assertion.issuer.domain)) {
        return { ok: true, via: "third_party_dns" };
      }
      return {
        ok: false,
        reason: "third_party_not_authorized",
        detail: `DNS authorizes "${declared}", assertion issuer is "${assertion.issuer.domain}"`,
      };
    }
  }

  // (b) Documento de delegación firmado por el DOMINIO DEL COMERCIANTE.
  const middUrl = `https://${subject}/.well-known/mia-delegation.json`;
  const fetched = await io.fetchDocument(middUrl);
  if (fetched === null) return { ok: false, reason: "third_party_not_authorized" };
  if (fetched.redirected === true) {
    return { ok: false, reason: "third_party_not_authorized" };
  }
  if (fetched.status < 200 || fetched.status >= 300) {
    return { ok: false, reason: "third_party_not_authorized" };
  }
  if (Buffer.byteLength(fetched.body, "utf8") > maxBytes) {
    return { ok: false, reason: "response_too_large" };
  }
  if (
    fetched.contentType === null ||
    !fetched.contentType.toLowerCase().startsWith(MIDD_MEDIA_TYPE)
  ) {
    return { ok: false, reason: "delegation_malformed" };
  }

  let midd: Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(fetched.body);
    if (!isPlainObject(parsed)) {
      return { ok: false, reason: "delegation_malformed" };
    }
    midd = parsed;
  } catch {
    return { ok: false, reason: "delegation_malformed" };
  }

  const shape = validateDelegationShape(midd);
  if (shape !== null) return { ok: false, reason: shape };

  const delegation = midd as unknown as MerchantIdentityDelegation;
  if (!domainsEqual(delegation.subject, assertion.subject)) {
    return { ok: false, reason: "delegation_subject_mismatch" };
  }
  if (!domainsEqual(delegation.authorizedIssuer, assertion.issuer.domain)) {
    return { ok: false, reason: "delegation_issuer_mismatch" };
  }

  const nowMs = io.now().getTime();
  const from = parseRfc3339(delegation.issuedAt)!;
  const to = parseRfc3339(delegation.expiresAt)!;
  if (nowMs <= from || nowMs >= to) {
    return { ok: false, reason: "delegation_expired" };
  }

  // §8.2 — la delegación la firma una clave del Key Directory DEL COMERCIANTE,
  // no del emisor. Ésta es la comprobación que impide que un emisor malicioso
  // se autoconceda delegación.
  const proofFailure = await verifyProofAgainstDirectory(midd, io, subject);
  if (proofFailure !== null) {
    return {
      ok: false,
      reason:
        proofFailure === "signature_invalid"
          ? "delegation_signature_invalid"
          : proofFailure,
    };
  }
  return { ok: true, via: "third_party_midd" };
}

// ─── §10.4 — procedimiento completo ────────────────────────────────────────

/**
 * Verifica una MIA ya recuperada. Separado de la recuperación para que un
 * llamante que ya tiene el documento (caché, vector de conformidad, pack de
 * evidencia) no tenga que fingir una respuesta HTTP.
 */
export async function verifyMiaDocument(
  fetched: FetchedDocument,
  options: VerifyMiaOptions
): Promise<MiaVerificationResult> {
  const maxBytes = options.maxBytes ?? 64 * 1024;

  // Paso 1 — recuperación.
  if (fetched.redirected === true) return fail("redirect_not_followed");
  if (fetched.status < 200 || fetched.status >= 300) {
    return fail("retrieval_failed", `HTTP ${fetched.status}`);
  }
  if (Buffer.byteLength(fetched.body, "utf8") > maxBytes) {
    return fail("response_too_large");
  }

  // Paso 2 — Content-Type.
  if (
    fetched.contentType === null ||
    !fetched.contentType.toLowerCase().startsWith(MIA_MEDIA_TYPE)
  ) {
    return fail("content_type_invalid", fetched.contentType ?? "(absent)");
  }

  // Paso 3 — parseo y presencia de la prueba.
  let doc: Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(fetched.body);
    if (!isPlainObject(parsed)) return fail("not_json");
    doc = parsed;
  } catch {
    return fail("not_json");
  }
  if (doc.proof === undefined) return fail("proof_absent");

  const shapeFailure = validateShape(doc);
  if (shapeFailure !== null) return fail(shapeFailure);

  // Paso 4 — tipo de prueba y algoritmo.
  const proofFailure = validateProofShape(doc.proof);
  if (proofFailure !== null) return fail(proofFailure);

  const assertion = doc as unknown as MerchantIdentityAssertion;

  // §7.3 — `created` DEBE coincidir con `issuedAt`.
  if (assertion.proof.created !== assertion.issuedAt) {
    return fail("created_mismatch");
  }

  // Pasos 5-9 — clave y firma. La autoridad esperada es `issuer.domain`.
  const cryptoFailure = await verifyProofAgainstDirectory(
    doc,
    options.io,
    canonicalDomain(assertion.issuer.domain)
  );
  if (cryptoFailure !== null) return fail(cryptoFailure);

  // Paso 10 — vigencia, ESTRICTAMENTE entre issuedAt y expiresAt.
  const nowMs = options.io.now().getTime();
  const from = parseRfc3339(assertion.issuedAt)!;
  const to = parseRfc3339(assertion.expiresAt)!;
  if (nowMs <= from) return fail("not_yet_valid");
  if (nowMs >= to) return fail("expired");

  // Paso 11 — el subject es el dominio consultado.
  if (!domainsEqual(assertion.subject, options.expectedSubject)) {
    return fail("subject_mismatch");
  }

  // Paso 12 — emisión por tercero.
  if (!domainsEqual(assertion.issuer.domain, assertion.subject)) {
    const authorized = await verifyThirdPartyAuthorization(
      assertion,
      options.io,
      maxBytes
    );
    if (!authorized.ok) {
      return authorized.detail === undefined
        ? fail(authorized.reason)
        : fail(authorized.reason, authorized.detail);
    }
    return { valid: true, assertion, issuance: authorized.via };
  }

  // Paso 13.
  return { valid: true, assertion, issuance: "self" };
}

/** Recupera desde el well-known del dominio y verifica (§8.1 + §10.4). */
export async function verifyMiaForDomain(
  domain: string,
  options: Omit<VerifyMiaOptions, "expectedSubject"> & {
    readonly expectedSubject?: string;
  }
): Promise<MiaVerificationResult> {
  const canonical = canonicalDomain(domain);
  if (canonical === null) return fail("domain_invalid");
  const fetched = await options.io.fetchDocument(
    `https://${canonical}/.well-known/merchant-identity.json`
  );
  if (fetched === null) return fail("retrieval_failed");
  return verifyMiaDocument(fetched, {
    ...options,
    expectedSubject: options.expectedSubject ?? canonical,
  });
}

export { ERT_MAX_LIFETIME_SECONDS };
