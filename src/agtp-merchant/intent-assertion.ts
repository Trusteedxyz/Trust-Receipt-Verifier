/**
 * §5 del draft — verificación de la Intent Assertion.
 *
 * §5.3 la diseña explícitamente para que un tercero la verifique: «The Intent
 * Assertion is structured as a standalone JWT precisely so that it can be
 * forwarded… The payment network verifies the signature against the issuing
 * governance platform's public key». Nosotros somos ese receptor, y por eso es
 * la parte del draft que se puede implementar sin hablar AGTP.
 *
 * La resolución de clave entra inyectada: quién publica el JWKS de la
 * plataforma de gobernanza es cosa del despliegue, no del formato.
 */

import {
  createPublicKey,
  verify as nodeVerify,
  type JsonWebKeyInput,
} from "node:crypto";
import type { JWK } from "jose";
import {
  AGENT_ID_PATTERN,
  INTENT_ASSERTION_MAX_LIFETIME_SECONDS,
  INTENT_ASSERTION_MAX_SKEW_SECONDS,
  INTENT_ASSERTION_RECOMMENDED_SKEW_SECONDS,
  type AgtpIntentAssertionClaims,
  type AgtpIntentFailureReason,
  type AgtpIntentVerificationResult,
} from "./types.js";

/** §12.2 base / §5 — JWS EdDSA. */
export const INTENT_ASSERTION_ALG = "EdDSA";

export interface IntentAssertionKeyLookup {
  /** `null` = no resoluble. Nunca lanzar: un fallo de red es `key_unresolved`. */
  (params: {
    readonly iss: string;
    readonly kid: string;
  }): Promise<JWK | null> | JWK | null;
}

export interface VerifyIntentAssertionOptions {
  /** §5.2 — el `Merchant-ID` de la petición PURCHASE; debe casar con `aud`. */
  readonly expectedMerchantId: string;
  /** §5.2 — el `Agent-ID` de la petición; debe casar con `agent_id`. */
  readonly expectedAgentId: string;
  readonly resolveKey: IntentAssertionKeyLookup;
  readonly now: () => Date;
  /**
   * §14.1 — tolerancia de reloj. Por defecto la recomendada (60 s). Un valor
   * mayor que 300 s NO se acepta en silencio: el draft dice que nunca debe
   * superarlo porque extendería la ventana de repetición más allá de la vida
   * del token, así que se rechaza la configuración, no la aserción.
   */
  readonly clockSkewSeconds?: number;
  /**
   * §5.2 — uso único. `true` = ese `jti` ya se registró en un Attribution-Record.
   * Sin este puerto no hay defensa de repetición y la aserción sola no la da.
   */
  readonly isJtiSeen?: (jti: string) => Promise<boolean> | boolean;
  /** §6 — el Cart-Digest de la petición en curso, si se quiere cotejar. */
  readonly expectedItemDigest?: string;
  /** Importe que se va a cobrar, para contrastarlo con `amount_ceiling`. */
  readonly requestedAmount?: { readonly value: string; readonly currency: string };
}

function fail(
  reason: AgtpIntentFailureReason,
  detail?: string
): AgtpIntentVerificationResult {
  return detail === undefined
    ? { valid: false, reason }
    : { valid: false, reason, detail };
}

function decodeSegment(segment: string): unknown {
  const json = Buffer.from(segment, "base64url").toString("utf8");
  return JSON.parse(json) as unknown;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * Compara dos importes decimales expresados como cadena, sin pasar por `number`.
 * Un `amount_ceiling` es un techo de gasto: convertirlo a coma flotante para
 * compararlo es exactamente el sitio donde un céntimo se pierde.
 *
 * Devuelve `null` si alguno no es un decimal no negativo bien formado.
 */
export function compareDecimalStrings(a: string, b: string): -1 | 0 | 1 | null {
  const pattern = /^(\d+)(?:\.(\d+))?$/;
  const ma = pattern.exec(a);
  const mb = pattern.exec(b);
  if (ma === null || mb === null) return null;
  const intA = ma[1].replace(/^0+(?=\d)/, "");
  const intB = mb[1].replace(/^0+(?=\d)/, "");
  if (intA.length !== intB.length) return intA.length < intB.length ? -1 : 1;
  if (intA !== intB) return intA < intB ? -1 : 1;
  const width = Math.max(ma[2]?.length ?? 0, mb[2]?.length ?? 0);
  const fracA = (ma[2] ?? "").padEnd(width, "0");
  const fracB = (mb[2] ?? "").padEnd(width, "0");
  if (fracA === fracB) return 0;
  return fracA < fracB ? -1 : 1;
}

function verifyEdDsa(
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

const REQUIRED_CLAIMS = [
  "iss",
  "sub",
  "aud",
  "agent_id",
  "item_digest",
  "amount_ceiling",
  "nbf",
  "exp",
  "jti",
  "iat",
] as const;

function readClaims(raw: unknown): AgtpIntentAssertionClaims | null {
  if (!isPlainObject(raw)) return null;
  for (const claim of REQUIRED_CLAIMS) {
    if (raw[claim] === undefined || raw[claim] === null) return null;
  }
  for (const numeric of ["nbf", "exp", "iat"] as const) {
    if (typeof raw[numeric] !== "number" || !Number.isFinite(raw[numeric])) {
      return null;
    }
  }
  for (const text of ["iss", "sub", "aud", "agent_id", "item_digest", "jti"] as const) {
    if (typeof raw[text] !== "string" || (raw[text] as string).length === 0) {
      return null;
    }
  }
  const ceiling = raw.amount_ceiling;
  if (
    !isPlainObject(ceiling) ||
    typeof ceiling.value !== "string" ||
    typeof ceiling.currency !== "string"
  ) {
    return null;
  }
  return raw as unknown as AgtpIntentAssertionClaims;
}

/**
 * Verifica una Intent Assertion reenviada.
 *
 * Orden: forma → algoritmo → firma → tiempo → cotejo con la petición → repetición.
 * La firma se comprueba **antes** que los claims a propósito: razonar sobre
 * claims no autenticados y devolver motivos distintos según su contenido
 * convierte al verificador en un oráculo de contenidos no firmados.
 */
export async function verifyIntentAssertion(
  compactJwt: string,
  options: VerifyIntentAssertionOptions
): Promise<AgtpIntentVerificationResult> {
  const skew = options.clockSkewSeconds ?? INTENT_ASSERTION_RECOMMENDED_SKEW_SECONDS;
  if (!Number.isFinite(skew) || skew < 0 || skew > INTENT_ASSERTION_MAX_SKEW_SECONDS) {
    return fail(
      "clock_skew_policy_invalid",
      `clock skew must be between 0 and ${INTENT_ASSERTION_MAX_SKEW_SECONDS}s (§14.1)`
    );
  }

  if (typeof compactJwt !== "string") return fail("jwt_malformed");
  const parts = compactJwt.split(".");
  if (parts.length !== 3 || parts.some((p) => p.length === 0)) {
    return fail("jwt_malformed", "expected three non-empty compact segments");
  }

  let header: unknown;
  let payload: unknown;
  let signature: Buffer;
  try {
    header = decodeSegment(parts[0]);
    payload = decodeSegment(parts[1]);
    signature = Buffer.from(parts[2], "base64url");
  } catch {
    return fail("jwt_malformed", "segment is not base64url-encoded JSON");
  }
  if (!isPlainObject(header)) return fail("jwt_malformed", "header is not an object");

  // §14.8 / RFC 8725 — `alg` se valida explícitamente y `none` se rechaza por su
  // nombre, con un motivo propio: confundirlo con «algoritmo no soportado»
  // borraría la señal de que alguien intentó quitar la firma.
  const alg = header.alg;
  if (alg === "none" || alg === "None" || alg === "NONE") {
    return fail("alg_none_rejected");
  }
  if (alg !== INTENT_ASSERTION_ALG) {
    return fail("alg_unsupported", typeof alg === "string" ? alg : String(alg));
  }
  if (typeof header.kid !== "string" || header.kid.length === 0) {
    return fail("kid_absent");
  }

  const claims = readClaims(payload);
  if (claims === null) return fail("claims_incomplete");

  let jwk: JWK | null;
  try {
    jwk = await options.resolveKey({ iss: claims.iss, kid: header.kid });
  } catch {
    jwk = null;
  }
  if (jwk === null) return fail("key_unresolved", header.kid);

  const signingInput = Buffer.from(`${parts[0]}.${parts[1]}`, "ascii");
  if (!verifyEdDsa(jwk, signature, signingInput)) {
    return fail("signature_invalid");
  }

  // §5.2 — `exp` NO puede exceder `iat` + 300 s. Se comprueba sobre el contenido
  // firmado, no contra el reloj: es una propiedad del token, no del momento.
  if (claims.exp <= claims.iat) {
    return fail("lifetime_exceeds_maximum", "exp must be after iat");
  }
  if (claims.exp - claims.iat > INTENT_ASSERTION_MAX_LIFETIME_SECONDS) {
    return fail(
      "lifetime_exceeds_maximum",
      `${claims.exp - claims.iat}s exceeds ${INTENT_ASSERTION_MAX_LIFETIME_SECONDS}s`
    );
  }

  const nowSeconds = Math.floor(options.now().getTime() / 1000);
  if (nowSeconds >= claims.exp + skew) return fail("expired");
  if (nowSeconds + skew < claims.nbf) return fail("not_yet_valid");

  if (claims.aud !== options.expectedMerchantId) return fail("audience_mismatch");
  if (claims.agent_id !== options.expectedAgentId) return fail("agent_id_mismatch");
  if (!AGENT_ID_PATTERN.test(claims.agent_id)) {
    return fail("agent_id_mismatch", "agent_id is not a canonical Agent-ID (§2)");
  }

  if (
    options.expectedItemDigest !== undefined &&
    claims.item_digest !== options.expectedItemDigest
  ) {
    return fail("item_digest_mismatch");
  }

  if (options.requestedAmount !== undefined) {
    if (options.requestedAmount.currency !== claims.amount_ceiling.currency) {
      return fail("currency_mismatch");
    }
    const cmp = compareDecimalStrings(
      options.requestedAmount.value,
      claims.amount_ceiling.value
    );
    // Un importe que no parsea NO puede considerarse por debajo del techo.
    if (cmp === null || cmp > 0) return fail("amount_exceeds_ceiling");
  }

  if (options.isJtiSeen !== undefined && (await options.isJtiSeen(claims.jti))) {
    return fail("jti_replayed", claims.jti);
  }

  return { valid: true, claims, jti: claims.jti };
}
