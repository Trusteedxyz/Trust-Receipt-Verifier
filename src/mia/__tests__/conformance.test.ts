/**
 * M-01 — vectores de conformidad del verificador MIA.
 *
 * Mismo patrón que los vectores de spec-054: un fichero JSON por caso, con el
 * documento, el entorno (DNS, directorios de claves, reloj) y el resultado
 * esperado. El runner no sabe nada de los casos; los descubre del directorio.
 *
 * Las firmas son REALES: los vectores se generaron con pares Ed25519 y se
 * verifican con la misma primitiva que usa el verificador. Un vector con una
 * firma inventada probaría que el parser corre, no que la criptografía cuadra.
 *
 * Cada caso cita el paso del draft que lo exige, para que un rechazo se pueda
 * rastrear hasta la línea normativa en vez de quedarse en "no válido".
 */
import { describe, expect, it } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { JWK } from "jose";
import { verifyMiaDocument, type MiaVerifierIo } from "../verify.js";
import { MIA_MEDIA_TYPE, MIDD_MEDIA_TYPE } from "../types.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const VECTOR_DIR = path.resolve(__dirname, "../../../conformance/mia-vectors");

interface Vector {
  readonly name: string;
  readonly description: string;
  readonly now: string;
  readonly document: Record<string, unknown>;
  readonly contentType?: string;
  readonly redirected?: boolean;
  readonly expectedSubject?: string;
  readonly dns?: Record<string, string[]>;
  readonly midd?: Record<string, unknown>;
  readonly unreachableDirectories?: string[];
  readonly badCurveDirectories?: string[];
  readonly directoryOverrides?: Record<string, "merchant" | "issuer">;
  readonly expected: { valid: boolean; reason?: string; issuance?: string };
}

const keys = JSON.parse(
  readFileSync(path.join(VECTOR_DIR, "_keys.json"), "utf8")
) as { issuerJwk: JWK; merchantJwk: JWK };
const directories = JSON.parse(
  readFileSync(path.join(VECTOR_DIR, "_directories.json"), "utf8")
) as Record<string, { keys: JWK[] }>;

const vectors: Vector[] = readdirSync(VECTOR_DIR)
  .filter((f) => f.endsWith(".json") && !f.startsWith("_"))
  .sort()
  .map(
    (f) => JSON.parse(readFileSync(path.join(VECTOR_DIR, f), "utf8")) as Vector
  );

function makeIo(v: Vector): MiaVerifierIo {
  const dirs: Record<string, { keys: JWK[] }> = { ...directories };
  for (const [url, which] of Object.entries(v.directoryOverrides ?? {})) {
    dirs[url] = {
      keys: [which === "merchant" ? keys.merchantJwk : keys.issuerJwk],
    };
  }
  for (const url of v.badCurveDirectories ?? []) {
    dirs[url] = { keys: [{ ...(keys.merchantJwk as JWK), crv: "P-256" }] };
  }
  const unreachable = new Set(v.unreachableDirectories ?? []);

  return {
    async fetchDocument(url) {
      if (v.midd && url.endsWith("/.well-known/mia-delegation.json")) {
        return {
          status: 200,
          contentType: MIDD_MEDIA_TYPE,
          body: JSON.stringify(v.midd),
        };
      }
      return null;
    },
    async fetchKeyDirectory(url) {
      if (unreachable.has(url)) return null;
      return dirs[url] ?? null;
    },
    async resolveTxt(name) {
      return v.dns?.[name] ?? null;
    },
    now: () => new Date(v.now),
  };
}

describe("MIA conformance vectors (M-01)", () => {
  it("descubre los vectores del directorio", () => {
    // Si el glob deja de casar, los tests de abajo pasarían por vacío — el modo
    // de fallo más caro de una suite basada en ficheros.
    expect(vectors.length).toBeGreaterThanOrEqual(30);
  });

  it.each(vectors.map((v) => [v.name, v] as const))("%s", async (_name, v) => {
    const result = await verifyMiaDocument(
      {
        status: 200,
        contentType: v.contentType ?? MIA_MEDIA_TYPE,
        body: JSON.stringify(v.document),
        ...(v.redirected === true ? { redirected: true } : {}),
      },
      {
        expectedSubject:
          v.expectedSubject ?? (v.document.subject as string) ?? "",
        io: makeIo(v),
      }
    );

    expect(result.valid, `${v.name}: ${v.description}`).toBe(v.expected.valid);
    if (v.expected.valid) {
      if (result.valid && v.expected.issuance !== undefined) {
        expect(result.issuance).toBe(v.expected.issuance);
      }
    } else if (!result.valid && v.expected.reason !== undefined) {
      expect(result.reason).toBe(v.expected.reason);
    }
  });
});

describe("cobertura de los vectores", () => {
  it("cubre las dos vías de autorización de tercero y la autoemisión", () => {
    const issuances = vectors
      .filter((v) => v.expected.valid)
      .map((v) => v.expected.issuance);
    expect(issuances).toContain("self");
    expect(issuances).toContain("third_party_dns");
    expect(issuances).toContain("third_party_midd");
  });

  it("cubre el ataque de delegación autoconcedida", () => {
    // §8.2 existe para impedir que un emisor publique MIAs de un dominio que no
    // le ha autorizado. Un vector que lo pruebe es el que da valor al resto.
    const names = vectors.map((v) => v.name);
    expect(names.some((n) => n.includes("midd-self-granted"))).toBe(true);
  });

  it("cubre las fronteras EXACTAS de vigencia", () => {
    // El draft dice "strictly between ... (exclusive)". Sin un vector en la
    // frontera exacta, una comprobación inclusiva pasa desapercibida: lo
    // detectó una mutación deliberada del verificador, no una revisión.
    const names = vectors.map((v) => v.name);
    expect(names.some((n) => n.includes("boundary-exactly-issued-at"))).toBe(true);
    expect(names.some((n) => n.includes("boundary-exactly-expires-at"))).toBe(true);
  });

  it("cada vector negativo declara el motivo esperado", () => {
    for (const v of vectors) {
      if (!v.expected.valid) {
        expect(v.expected.reason, `${v.name} sin motivo esperado`).toBeTruthy();
      }
    }
  });
});
