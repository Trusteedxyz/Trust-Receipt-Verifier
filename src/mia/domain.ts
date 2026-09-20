/**
 * §2 del draft — «Domain Comparison», normativo.
 *
 * El draft lo define UNA vez y lo invoca desde tres sitios distintos (subject vs
 * dominio consultado, autoridad de `verificationMethod` vs `issuer.domain`, y el
 * valor del TXT DNS vs `issuer.domain`). Aquí también vive una sola vez: tres
 * comparaciones de dominio escritas a mano en tres sitios es exactamente cómo se
 * cuela un fallo de identidad silencioso.
 *
 * Reglas, literales:
 *   - ambos valores a su forma A-label según IDNA2008 [RFC5890];
 *   - se quita el punto final si lo hay;
 *   - se comparan las etiquetas ASCII **sin distinguir mayúsculas**;
 *   - un IDN que sólo difiera en U-label vs A-label DEBE tratarse como igual;
 *   - se RECHAZA un FQDN con puntos de código no permitidos o que falle IDNA2008.
 */

/**
 * `URL` de Node aplica IDNA2008 (UTS-46) al construir el host: es la ruta a
 * A-label que ya está en la plataforma. Usarla evita meter una dependencia de
 * punycode propia y, con ella, una segunda interpretación de IDNA.
 */
function toAscii(fqdn: string): string | null {
  const trimmed = fqdn.trim();
  if (trimmed.length === 0) return null;
  // Un FQDN no lleva esquema, puerto, ruta ni credenciales. Rechazar antes de
  // construir la URL evita que `evil.com/path` o `a@b` pasen por dominio.
  if (/[/\\?#@:\s]/.test(trimmed)) return null;
  const withoutTrailingDot = trimmed.endsWith(".")
    ? trimmed.slice(0, -1)
    : trimmed;
  if (withoutTrailingDot.length === 0) return null;
  let host: string;
  try {
    host = new URL(`https://${withoutTrailingDot}`).hostname;
  } catch {
    return null;
  }
  // `URL` deja `xn--` vacío o corchetes de IPv6 pasar; ninguno es un FQDN válido
  // para este uso. Y si el punycode falló, el host conserva algo no-ASCII.
  if (host.length === 0) return null;
  if (host.startsWith("[")) return null;
  // eslint-disable-next-line no-control-regex
  if (/[^\x00-\x7F]/.test(host)) return null;
  return host.toLowerCase();
}

/** Forma canónica para comparar, o `null` si el valor no es un FQDN válido. */
export function canonicalDomain(fqdn: string): string | null {
  return toAscii(fqdn);
}

/**
 * ¿Son el mismo dominio? `null`/inválido nunca casa con nada — ni consigo mismo.
 * Un FQDN que no se puede canonicalizar es un rechazo, no un empate.
 */
export function domainsEqual(a: string, b: string): boolean {
  const ca = toAscii(a);
  const cb = toAscii(b);
  if (ca === null || cb === null) return false;
  return ca === cb;
}

/**
 * §10.4 paso 5 — «only the authority component is compared». Devuelve la
 * autoridad (host) de una URI HTTPS, o `null` si no es HTTPS o no parsea.
 *
 * Que sea HTTPS es normativo en todo el draft: §7.4 prohíbe servir o aceptar
 * MIAs sobre HTTP plano, y §10.2 exige el Key Directory sobre HTTPS.
 */
export function httpsAuthority(uri: string): string | null {
  let url: URL;
  try {
    url = new URL(uri);
  } catch {
    return null;
  }
  if (url.protocol !== "https:") return null;
  const host = url.hostname.toLowerCase();
  if (host.length === 0) return null;
  return host;
}
