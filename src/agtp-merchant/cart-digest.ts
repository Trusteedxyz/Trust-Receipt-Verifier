/**
 * §6 y §9.4 del draft — Cart-Digest.
 *
 * §9.4 exige un hash resistente a colisiones, SHA-256 como base, «computed over
 * a canonical serialization of the cart contents» — y **nunca dice cuál es esa
 * serialización canónica**. MIA sí cita RFC 8785 (JCS) de forma expresa; este
 * draft no cita ninguna. Consecuencia real: dos implementaciones conformes
 * pueden producir digests distintos para el mismo carrito, y §6.3 manda
 * rechazar con 409 cuando no casan.
 *
 * Por eso aquí la canonicalización **entra como parámetro**. Elegir JCS en
 * silencio dentro de la librería daría la impresión de interoperabilidad que el
 * draft no garantiza; que el llamante tenga que nombrarla deja el hueco a la
 * vista, que es lo honesto mientras el draft no lo cierre.
 */

import { createHash } from "node:crypto";

/** §2 — prefijo de algoritmo + digest hex. */
export const CART_DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/;

export type CartDigestFailureReason =
  | "digest_malformed"
  | "digest_mismatch"
  | "canonicalization_failed";

export type CartDigestResult =
  | { readonly valid: true; readonly digest: string }
  | { readonly valid: false; readonly reason: CartDigestFailureReason; readonly detail?: string };

export function isWellFormedCartDigest(value: unknown): value is string {
  return typeof value === "string" && CART_DIGEST_PATTERN.test(value);
}

export function computeCartDigest(
  cart: unknown,
  canonicalize: (value: unknown) => string | undefined
): string | null {
  const canonical = canonicalize(cart);
  if (typeof canonical !== "string") return null;
  return `sha256:${createHash("sha256").update(Buffer.from(canonical, "utf8")).digest("hex")}`;
}

/**
 * §6.3 — el servidor DEBE rechazar (409 Conflict) si el digest presentado no
 * casa con una cotización válida y no caducada. Aquí sólo se comprueba la
 * correspondencia con el carrito; la vigencia de la cotización es del llamante,
 * que es quien la tiene.
 */
export function verifyCartDigest(
  presented: unknown,
  cart: unknown,
  canonicalize: (value: unknown) => string | undefined
): CartDigestResult {
  if (!isWellFormedCartDigest(presented)) {
    return { valid: false, reason: "digest_malformed" };
  }
  const computed = computeCartDigest(cart, canonicalize);
  if (computed === null) {
    return { valid: false, reason: "canonicalization_failed" };
  }
  return computed === presented
    ? { valid: true, digest: computed }
    : { valid: false, reason: "digest_mismatch", detail: computed };
}
