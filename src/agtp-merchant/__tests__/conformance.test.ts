/**
 * M-01, segundo draft — vectores de conformidad del verificador AGTP-merchant.
 *
 * Mismo patrón que los vectores MIA: un fichero JSON por caso, el runner los
 * descubre del directorio y no sabe nada de ellos. Las firmas EdDSA son REALES
 * (generadas con un par Ed25519 y verificadas con la misma primitiva que usa el
 * verificador): un vector con firma inventada probaría que el parser corre, no
 * que la criptografía cuadra.
 *
 * Cada caso cita la sección del draft que lo exige. Y cada rechazo declara
 * además `retryable`, porque §8.2 lo hace parte del contrato del 458 — no una
 * decisión del que verifica.
 */
import { describe, expect, it } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import canonicalize from "canonicalize";
import type { JWK } from "jose";
import {
  computeManifestFingerprint,
  verifyMerchantIdentityDocument,
} from "../identity-document.js";
import { verifyIntentAssertion } from "../intent-assertion.js";
import { verifyCartDigest } from "../cart-digest.js";
import type { AgtpTrustTier } from "../types.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const VECTOR_DIR = path.resolve(
  __dirname,
  "../../../conformance/agtp-merchant-vectors"
);

const canon = (value: unknown): string => {
  const out = canonicalize(value);
  if (typeof out !== "string") throw new Error("canonicalization failed");
  return out;
};

interface BaseVector {
  readonly name: string;
  readonly description: string;
  readonly expected: {
    readonly valid: boolean;
    readonly reason?: string;
    readonly retryable?: boolean;
  };
}

interface IdentityVector extends BaseVector {
  readonly kind: "identity";
  readonly document: unknown;
  readonly expectedMerchantId: string;
  readonly presentedFingerprint?: string | null;
  readonly minimumTrustTier?: AgtpTrustTier;
}

interface IntentVector extends BaseVector {
  readonly kind: "intent";
  readonly jwt: string;
  readonly now: string;
  readonly expectedMerchantId: string;
  readonly expectedAgentId: string;
  readonly resolvableKids: string[];
  readonly jtiSeen?: string[];
  readonly clockSkewSeconds?: number;
  readonly expectedItemDigest?: string;
  readonly requestedAmount?: { value: string; currency: string };
}

interface CartVector extends BaseVector {
  readonly kind: "cart";
  readonly cart: unknown;
  readonly presented: unknown;
}

type Vector = IdentityVector | IntentVector | CartVector;

const { platformJwk } = JSON.parse(
  readFileSync(path.join(VECTOR_DIR, "_keys.json"), "utf8")
) as { platformJwk: JWK };

const vectors: Vector[] = readdirSync(VECTOR_DIR)
  .filter((f) => f.endsWith(".json") && !f.startsWith("_"))
  .sort()
  .map((f) => JSON.parse(readFileSync(path.join(VECTOR_DIR, f), "utf8")) as Vector);

async function run(v: Vector) {
  if (v.kind === "identity") {
    const presented =
      v.presentedFingerprint === "@computed"
        ? computeManifestFingerprint(v.document, canon)
        : v.presentedFingerprint;
    return verifyMerchantIdentityDocument(v.document, {
      expectedMerchantId: v.expectedMerchantId,
      canonicalize: canon,
      ...(presented !== undefined ? { presentedFingerprint: presented } : {}),
      ...(v.minimumTrustTier !== undefined
        ? { minimumTrustTier: v.minimumTrustTier }
        : {}),
    });
  }
  if (v.kind === "intent") {
    const seen = new Set(v.jtiSeen ?? []);
    return verifyIntentAssertion(v.jwt, {
      expectedMerchantId: v.expectedMerchantId,
      expectedAgentId: v.expectedAgentId,
      resolveKey: ({ kid }) => (v.resolvableKids.includes(kid) ? platformJwk : null),
      now: () => new Date(v.now),
      isJtiSeen: (jti) => seen.has(jti),
      ...(v.clockSkewSeconds !== undefined
        ? { clockSkewSeconds: v.clockSkewSeconds }
        : {}),
      ...(v.expectedItemDigest !== undefined
        ? { expectedItemDigest: v.expectedItemDigest }
        : {}),
      ...(v.requestedAmount !== undefined
        ? { requestedAmount: v.requestedAmount }
        : {}),
    });
  }
  return verifyCartDigest(v.presented, v.cart, canonicalize);
}

describe("AGTP merchant identity — vectores de conformidad", () => {
  it("descubre los vectores del directorio", () => {
    // Si el glob deja de casar, todo lo de abajo pasaría por vacío: el modo de
    // fallo más caro de una suite basada en ficheros.
    expect(vectors.length).toBeGreaterThanOrEqual(45);
  });

  it.each(vectors.map((v) => [v.name, v] as const))("%s", async (_name, v) => {
    const result = await run(v);
    expect(result.valid, `${v.name}: ${v.description}`).toBe(v.expected.valid);
    if (!result.valid) {
      if (v.expected.reason !== undefined) {
        expect(result.reason).toBe(v.expected.reason);
      }
      if (v.expected.retryable !== undefined && "retryable" in result) {
        expect(result.retryable, `${v.name}: §8.2 retryable`).toBe(
          v.expected.retryable
        );
      }
    }
  });
});

describe("cobertura de los vectores", () => {
  const names = vectors.map((v) => v.name);

  it("cubre los tres artefactos verificables sin transporte AGTP", () => {
    for (const kind of ["identity", "intent", "cart"] as const) {
      expect(vectors.some((v) => v.kind === kind), kind).toBe(true);
    }
  });

  it("cubre la divergencia de ciclo de vida entre los dos drafts", () => {
    // Defecto 2 del extracto normativo: `Revoked` (merchant v02) y `retired`
    // (base v09) son el mismo estado con dos nombres. Sin vector, un verificador
    // estricto con uno rechazaría documentos legítimos del otro.
    expect(names.some((n) => n.includes("retired-base-draft-spelling"))).toBe(true);
  });

  it("distingue el 458 reintentable del que no lo es", () => {
    // §8.2: Suspended se reintenta, Revoked/Deprecated no. Un único
    // `lifecycle_not_active` reintentable mandaría a un cliente a repetir
    // eternamente contra un comerciante revocado.
    const lifecycle = vectors.filter(
      (v) => v.expected.reason === "lifecycle_not_active"
    );
    expect(lifecycle.some((v) => v.expected.retryable === true)).toBe(true);
    expect(lifecycle.some((v) => v.expected.retryable === false)).toBe(true);
  });

  it("cubre las fronteras EXACTAS de tiempo e importe", () => {
    // En MIA, la ausencia de vectores de frontera dejó pasar una mutación de
    // `<` a `<=`. Aquí las fronteras entran desde el principio.
    expect(names.some((n) => n.includes("boundary-exactly-expired"))).toBe(true);
    expect(names.some((n) => n.includes("boundary-one-second-inside"))).toBe(true);
    expect(names.some((n) => n.includes("lifetime-exactly-300s"))).toBe(true);
    expect(names.some((n) => n.includes("amount-exactly-ceiling"))).toBe(true);
  });

  it("cubre `alg: none` con un motivo propio", () => {
    // RFC 8725 (§14.8). Si se confundiera con "algoritmo no soportado" se
    // borraría la señal de que alguien intentó quitar la firma.
    expect(names.some((n) => n.includes("alg-none"))).toBe(true);
  });

  it("cada vector negativo declara el motivo esperado", () => {
    for (const v of vectors) {
      if (!v.expected.valid) {
        expect(v.expected.reason, `${v.name} sin motivo esperado`).toBeTruthy();
      }
    }
  });
});
