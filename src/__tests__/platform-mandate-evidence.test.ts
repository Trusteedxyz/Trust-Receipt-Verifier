/**
 * Evidencia del mandato emitido por la plataforma 
 * campos hermanos opcionales + invariantes. No toca el esquema congelado.
 */
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { CompactSign, exportJWK, generateKeyPair } from "jose";
import { describe, expect, it } from "vitest";
import {
  MandateApprovalMethodSchema,
  PLATFORM_MANDATE_EVIDENCE_KEYS,
  PlatformMandateEvidenceFields,
  platformMandateEvidenceIssues,
} from "../schema/platform-mandate-evidence.js";
import { TrustReceiptLegacyCompactSchema } from "../schema/trust-receipt-legacy.schema.js";
import { TrustReceiptV11BodySchema } from "../zod-1.1.js";
import { verifyTrustReceipt } from "../verifier.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const KID = "pm-evidence-test-key";

const EVIDENCE = {
  mandate_verification: "signature_verified",
  mandate_issuer: "https://api.example.test",
  mandate_kid: "payment-mandate-key-1",
  mandate_approval_method: "agent_bound",
  mandate_human_presence_verified: false,
  mandate_cart_hash: "cart-hash-1",
} as const;

async function signLegacy(extra: Record<string, unknown>) {
  const { privateKey, publicKey } = await generateKeyPair("EdDSA", {
    extractable: true,
  });
  const jwk = { ...(await exportJWK(publicKey)), kid: KID, alg: "EdDSA" };
  const iat = Math.floor(Date.now() / 1000);
  const payload = {
    iss: "merchant:store_1",
    sub: "call_1",
    iat,
    callId: "call_1",
    merchantId: "store_1",
    agentId: "did:agent:x",
    bucket: "checkout",
    tool: "complete_checkout",
    inputHash: "a".repeat(64),
    outputHash: "b".repeat(64),
    outputHashStatus: "captured",
    trust_provider_assertions: [],
    kid: KID,
    schema_version: "1.0",
    canon: "jcs",
    expires_at: iat + 86_400,
    protocol: "MCP",
    policy_decision: "allow",
    ...extra,
  };
  const jws = await new CompactSign(
    new TextEncoder().encode(JSON.stringify(payload))
  )
    .setProtectedHeader({ alg: "EdDSA", kid: KID, typ: "trust-receipt+jwt" })
    .sign(privateKey);
  return { jws, jwks: [jwk] as never, payload };
}

describe("PlatformMandateEvidenceFields", () => {
  it("declara los cinco campos, todos opcionales", () => {
    expect([...PLATFORM_MANDATE_EVIDENCE_KEYS].sort()).toEqual(
      [
        "mandate_issuer",
        "mandate_kid",
        "mandate_approval_method",
        "mandate_human_presence_verified",
        "mandate_cart_hash",
      ].sort()
    );
    for (const key of PLATFORM_MANDATE_EVIDENCE_KEYS) {
      expect(
        PlatformMandateEvidenceFields[key].safeParse(undefined).success,
        key
      ).toBe(true);
    }
  });

  it("la clase de aprobacion es un enum cerrado", () => {
    for (const ok of ["agent_bound", "magic_link", "passkey"]) {
      expect(MandateApprovalMethodSchema.safeParse(ok).success).toBe(true);
    }
    expect(MandateApprovalMethodSchema.safeParse("biometric").success).toBe(
      false
    );
  });
});

describe("platformMandateEvidenceIssues", () => {
  it("presencia humana con agent_bound => incoherente", () => {
    expect(
      platformMandateEvidenceIssues({
        ...EVIDENCE,
        mandate_human_presence_verified: true,
      })
    ).toHaveLength(1);
  });

  it("presencia humana con magic_link => incoherente; con passkey => coherente", () => {
    expect(
      platformMandateEvidenceIssues({
        ...EVIDENCE,
        mandate_approval_method: "magic_link",
        mandate_human_presence_verified: true,
      })
    ).toHaveLength(1);
    expect(
      platformMandateEvidenceIssues({
        ...EVIDENCE,
        mandate_approval_method: "passkey",
        mandate_human_presence_verified: true,
      })
    ).toEqual([]);
  });

  it("signature_verified sin decir quien firmo => incoherente", () => {
    expect(
      platformMandateEvidenceIssues({
        mandate_verification: "signature_verified",
      })
    ).toHaveLength(3);
    expect(platformMandateEvidenceIssues(EVIDENCE)).toEqual([]);
  });

  it("structure_only y recibos sin campos no tienen nada que comprobar", () => {
    expect(
      platformMandateEvidenceIssues({ mandate_verification: "structure_only" })
    ).toEqual([]);
    expect(platformMandateEvidenceIssues({})).toEqual([]);
  });
});

describe("el verificador aplica las invariantes (legacy compacto)", () => {
  it("un recibo coherente verifica y conserva los campos tras parsear", async () => {
    const { jws, jwks, payload } = await signLegacy(EVIDENCE);
    const r = await verifyTrustReceipt(jws, { jwks });
    expect(r.valid).toBe(true);
    const parsed = TrustReceiptLegacyCompactSchema.parse(payload);
    for (const key of PLATFORM_MANDATE_EVIDENCE_KEYS) {
      expect(parsed, key).toHaveProperty(key);
    }
    expect(parsed).toHaveProperty("mandate_verification", "signature_verified");
  });

  it("hpv:true con agent_bound => el verificador rechaza el recibo", async () => {
    const { jws, jwks } = await signLegacy({
      ...EVIDENCE,
      mandate_human_presence_verified: true,
    });
    const r = await verifyTrustReceipt(jws, { jwks });
    expect(r.valid).toBe(false);
    expect(r.reason).toBe("schema_invalid");
    expect(r.errors?.join(" ")).toContain("passkey");
  });

  it("signature_verified sin issuer/kid/metodo => rechazado", async () => {
    const { jws, jwks } = await signLegacy({
      mandate_verification: "signature_verified",
    });
    const r = await verifyTrustReceipt(jws, { jwks });
    expect(r.valid).toBe(false);
    expect(r.reason).toBe("schema_invalid");
  });

  it("un recibo sin ningun campo nuevo verifica igual que antes", async () => {
    const { jws, jwks } = await signLegacy({});
    expect((await verifyTrustReceipt(jws, { jwks })).valid).toBe(true);
  });
});

describe("v1.1: declarado y con la misma invariante", () => {
  const body = (): Record<string, unknown> => {
    const vec = JSON.parse(
      readFileSync(
        path.resolve(
          HERE,
          "../../test-vectors/v11/011-buyer-agent-happy-path.json"
        ),
        "utf8"
      )
    ) as { envelope: { receipt: string } };
    const seg = vec.envelope.receipt.split(".")[1]!;
    return JSON.parse(Buffer.from(seg, "base64url").toString("utf8"));
  };

  it("la base del vector 011 parsea (linea base)", () => {
    expect(TrustReceiptV11BodySchema.safeParse(body()).success).toBe(true);
  });

  it("con los campos nuevos parsea y CONSERVA las claves", () => {
    const r = TrustReceiptV11BodySchema.safeParse({ ...body(), ...EVIDENCE });
    expect(r.success).toBe(true);
    if (r.success) {
      for (const key of Object.keys(EVIDENCE))
        expect(r.data).toHaveProperty(key);
    }
  });

  it("hpv:true con agent_bound => el esquema v1.1 lo rechaza", () => {
    const r = TrustReceiptV11BodySchema.safeParse({
      ...body(),
      ...EVIDENCE,
      mandate_human_presence_verified: true,
    });
    expect(r.success).toBe(false);
  });
});

describe("el vector compartido L008", () => {
  it("existe y lo verifica este puerto", async () => {
    const v = JSON.parse(
      readFileSync(
        path.resolve(
          HERE,
          "../../conformance/legacy-compact-vectors/L008-platform-mandate-evidence.json"
        ),
        "utf8"
      )
    ) as { jws: string; jwks: never };
    const r = await verifyTrustReceipt(v.jws, {
      jwks: v.jwks,
      clockToleranceSeconds: 0,
    });
    expect(r.valid).toBe(true);
    expect(r.variant).toBe("legacy_compact");
  });
});
