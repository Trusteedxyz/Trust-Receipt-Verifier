/**
 * Export-bundle root selection and JWKS snapshot binding.
 *
 *  Root: the bundle's jwks-history.jws must be verified against the root FOUND
 *       BY FINGERPRINT (`trust-anchor.pem` sha), never against whichever root is
 *       "active" today. Matrix built with TWO test roots (no T420 dependency).
 *  Snapshot: jwks-snapshot.json is no longer a name-only requirement: it is bound to
 *       the signed evidence (committed digest, or the signed JWKS history).
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import AdmZip from "adm-zip";
import canonicalize from "canonicalize";
import { createHash, generateKeyPairSync, type KeyObject } from "node:crypto";
import { CompactSign } from "jose";

const h = vi.hoisted(() => {
  const { generateKeyPairSync, createHash } = require("node:crypto") as typeof import("node:crypto");
  const mk = () => {
    const kp = generateKeyPairSync("ed25519");
    const pem = kp.publicKey.export({ type: "spki", format: "pem" }) as string;
    return {
      priv: kp.privateKey,
      pem,
      sha256: createHash("sha256").update(pem, "utf8").digest("hex"),
    };
  };
  return { active: mk(), retired: mk(), verifyEnvelope: vi.fn() };
});

vi.mock("../embedded-issuer-root.js", () => {
  const entries = Object.freeze([
    Object.freeze({ pem: h.active.pem, sha256: h.active.sha256, validFrom: 2_000, validTo: null, verifierMinVersion: "2.0.0" }),
    Object.freeze({ pem: h.retired.pem, sha256: h.retired.sha256, validFrom: 1_000, validTo: 2_000, verifierMinVersion: "1.0.0" }),
  ]);
  return {
    EMBEDDED_ISSUER_ROOTS: entries,
    findIssuerRootBySha256: (s: string) => entries.find((e) => e.sha256 === s.toLowerCase()) ?? null,
    getActiveIssuerRoot: () => entries[0],
  };
});
vi.mock("../verify-1.1.js", () => ({
  verifyReceiptEnvelope: (e: unknown, o: unknown) => h.verifyEnvelope(e, o),
}));

const { verifyExportBundle } = await import("../verify-export-bundle.js");

const KID = "k1";
const { publicKey: opPub } = generateKeyPairSync("ed25519");
const opJwk = { ...(opPub.export({ format: "jwk" }) as Record<string, string>), kid: KID, alg: "EdDSA", use: "sig" };
const otherJwk = {
  ...((generateKeyPairSync("ed25519").publicKey.export({ format: "jwk" })) as Record<string, string>),
  kid: KID, alg: "EdDSA", use: "sig",
};
const jcsSha = (v: unknown) => createHash("sha256").update(canonicalize(v) as string, "utf8").digest("hex");

const ENVELOPE = {
  receipt: "h.p.s",
  timestamp_evidence: { type: "unavailable", reason: "tsa_unavailable", attempted_tsa: ["x"], attempted_at: 1 },
  envelope_metadata: { receipt_id: "11111111-1111-1111-1111-111111111111", created_at: 1000, legal_posture: "ades_candidate_no_tsa", legal_posture_warnings: [] },
};
const RETENTION = { jurisdiction: "US", min_retention_years: 7 };

async function historyJws(signer: KeyObject): Promise<string> {
  const payload = { schema_version: "1.0", entries: [{ kid: KID, jwk_pub: opJwk, valid_from: 1, valid_to: null }], history_chain_sha256: "0".repeat(64) };
  return new CompactSign(new TextEncoder().encode(JSON.stringify(payload))).setProtectedHeader({ alg: "EdDSA" }).sign(signer);
}

interface Fx {
  anchorPem: string;
  signer: KeyObject;
  snapshot?: unknown;
  committedDigest?: string;
}
async function bundle(fx: Fx): Promise<Buffer> {
  const zip = new AdmZip();
  zip.addFile("receipt-envelope.json", Buffer.from(JSON.stringify(ENVELOPE)));
  zip.addFile("jwks-snapshot.json", Buffer.from(JSON.stringify(fx.snapshot ?? { keys: [opJwk] })));
  zip.addFile("jwks-history.jws", Buffer.from(await historyJws(fx.signer)));
  zip.addFile("trust-anchor.pem", Buffer.from(fx.anchorPem));
  zip.addFile("retention-policy.json", Buffer.from(JSON.stringify(RETENTION)));
  return zip.toBuffer();
}

function accepted(committed: string) {
  return {
    outcome: "accepted",
    schema_version: "1.1",
    warnings: [],
    envelope: ENVELOPE,
    receipt: { verification_methods: { jwks: { uri: "https://x/jwks.json", kid: KID }, jwks_sha256: committed, trust_anchor_sha256: "a".repeat(64) } },
  };
}

beforeEach(() => {
  h.verifyEnvelope.mockReset();
  h.verifyEnvelope.mockResolvedValue(accepted(jcsSha({ keys: [opJwk] })));
});

describe("root selection by fingerprint", () => {
  it("accepts an OLD bundle signed by the RETIRED root after rotation", async () => {
    const r = await verifyExportBundle(await bundle({ anchorPem: h.retired.pem, signer: h.retired.priv }), { trustAnchorPemSha256: h.retired.sha256 });
    expect(r.errorCode).toBeUndefined();
    expect(r.outcome).toBe("accepted");
  });
  it("accepts a bundle signed by the ACTIVE root", async () => {
    const r = await verifyExportBundle(await bundle({ anchorPem: h.active.pem, signer: h.active.priv }), { trustAnchorPemSha256: h.active.sha256 });
    expect(r.outcome).toBe("accepted");
  });
  it("rejects a bundle whose trust-anchor.pem claims the ACTIVE root but is signed by the retired one", async () => {
    const r = await verifyExportBundle(await bundle({ anchorPem: h.active.pem, signer: h.retired.priv }), { trustAnchorPemSha256: h.active.sha256 });
    expect(r.outcome).toBe("rejected");
    expect(r.errorCode).toBe("jwks_history_signature_invalid");
  });
  it("rejects a bundle claiming the RETIRED root but signed by the active one", async () => {
    const r = await verifyExportBundle(await bundle({ anchorPem: h.retired.pem, signer: h.active.priv }), { trustAnchorPemSha256: h.retired.sha256 });
    expect(r.outcome).toBe("rejected");
    expect(r.errorCode).toBe("jwks_history_signature_invalid");
  });
});

describe("jwks-snapshot.json is validated, not just required", () => {
  const ok = { anchorPem: "", signer: undefined as unknown as KeyObject };
  const base = (): Fx => ({ ...ok, anchorPem: h.active.pem, signer: h.active.priv });
  const opts = () => ({ trustAnchorPemSha256: h.active.sha256 });

  it("accepts a snapshot whose JCS sha256 equals the signed jwks_sha256", async () => {
    const r = await verifyExportBundle(await bundle(base()), opts());
    expect(r.outcome).toBe("accepted");
    expect(r.warnings).not.toContain("jwks_snapshot_history_derived");
  });
  it("REJECTS a substituted snapshot (other key material under the same kid)", async () => {
    const r = await verifyExportBundle(await bundle({ ...base(), snapshot: { keys: [otherJwk] } }), opts());
    expect(r.outcome).toBe("rejected");
    expect(r.errorCode).toBe("jwks_snapshot_mismatch");
  });
  it("REJECTS a snapshot that does not contain the receipt's kid", async () => {
    const r = await verifyExportBundle(await bundle({ ...base(), snapshot: { keys: [{ ...opJwk, kid: "zzz" }] } }), opts());
    expect(r.outcome).toBe("rejected");
    expect(r.errorCode).toBe("jwks_snapshot_mismatch");
  });
  it("REJECTS a snapshot whose digest matches but which lacks the receipt's signing kid", async () => {
    const res = accepted(jcsSha({ keys: [opJwk] })) as { receipt: { verification_methods: { jwks: { kid: string } } } };
    res.receipt.verification_methods.jwks.kid = "signing-kid-not-in-snapshot";
    h.verifyEnvelope.mockResolvedValue(res);
    const r = await verifyExportBundle(await bundle(base()), opts());
    expect(r.outcome).toBe("rejected");
    expect(r.errorCode).toBe("jwks_snapshot_mismatch");
    expect(r.errorDetail).toContain("signing kid");
  });
  it("REJECTS a snapshot that is not a {keys:[]} JSON object", async () => {
    const r = await verifyExportBundle(await bundle({ ...base(), snapshot: { nope: 1 } }), opts());
    expect(r.outcome).toBe("rejected");
    expect(r.errorCode).toBe("jwks_snapshot_invalid");
  });
  it("accepts the at-issuance-from-signed-history variant (digest cannot match by construction) with a warning", async () => {
    // Producer output when the live JWKS had several keys: the snapshot holds
    // only the signing key, taken from the signed history.
    h.verifyEnvelope.mockResolvedValue(accepted("e".repeat(64)));
    const snap = { keys: [opJwk], _snapshot_provenance: { source: "at-issuance-from-signed-history", issuance_kid: KID } };
    const r = await verifyExportBundle(await bundle({ ...base(), snapshot: snap }), opts());
    expect(r.outcome).toBe("accepted");
    expect(r.warnings).toContain("jwks_snapshot_history_derived");
  });
  it("REJECTS a history-derived claim whose key is not the one in the signed history", async () => {
    h.verifyEnvelope.mockResolvedValue(accepted("e".repeat(64)));
    const snap = { keys: [otherJwk], _snapshot_provenance: { source: "at-issuance-from-signed-history" } };
    const r = await verifyExportBundle(await bundle({ ...base(), snapshot: snap }), opts());
    expect(r.outcome).toBe("rejected");
    expect(r.errorCode).toBe("jwks_snapshot_mismatch");
  });
  it("REJECTS a non-history snapshot whose digest is not the committed one (no provenance escape hatch)", async () => {
    h.verifyEnvelope.mockResolvedValue(accepted("e".repeat(64)));
    const r = await verifyExportBundle(await bundle(base()), opts());
    expect(r.outcome).toBe("rejected");
    expect(r.errorCode).toBe("jwks_snapshot_mismatch");
  });
});
