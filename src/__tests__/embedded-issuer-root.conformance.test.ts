/**
 * Conformance gate for the embedded issuer roots.
 *
 * Every entry of EMBEDDED_ISSUER_ROOTS that is not the documented staging stub
 * must be production-grade: parseable X.509 PEM, Ed25519 key, no "(STAGING)"
 * marker, SHA-256 of the PEM matching `entry.sha256`, and that SHA-256
 * different from the stub's. The stub constant is a DETECTOR, so it must NOT
 * equal any embedded root: holding the production fingerprint there would
 * classify the real root as a stub.
 *
 * The mutation cases below prove the checker rejects each defect. Ephemeral
 * material is generated with openssl in a tmpdir and deleted afterwards.
 */
import { execFileSync } from "node:child_process";
import { createHash, X509Certificate } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import {
  EMBEDDED_ISSUER_ROOTS,
  type IssuerRootEntry,
} from "../embedded-issuer-root.js";

const verifierSrc = readFileSync(
  resolve(__dirname, "../embedded-issuer-root.ts"),
  "utf8"
);

function extractConst(src: string, name: string): string | null {
  const m = new RegExp(`${name}\\s*=\\s*"([0-9a-f]{64})"`).exec(src);
  return m ? m[1] : null;
}

const VERIFIER_STUB_SHA = extractConst(verifierSrc, "_STAGING_STUB_ROOT_SHA256");

function hasStagingMarker(pem: string): boolean {
  const body = pem
    .replace(/-----BEGIN [^-]+-----/g, "")
    .replace(/-----END [^-]+-----/g, "")
    .replace(/\s+/g, "");
  return Buffer.from(body, "base64").toString("binary").includes("(STAGING)");
}

/** Returns the list of violations for a non-stub (production) entry. */
function productionViolations(
  entry: Pick<IssuerRootEntry, "pem" | "sha256">,
  stubSha: string
): string[] {
  const v: string[] = [];
  if (hasStagingMarker(entry.pem)) v.push("staging_marker");
  if (entry.sha256.toLowerCase() === stubSha) v.push("is_stub_sha");
  const actual = createHash("sha256").update(entry.pem, "utf8").digest("hex");
  if (actual !== entry.sha256.toLowerCase()) v.push("sha256_mismatch");
  try {
    const cert = new X509Certificate(entry.pem);
    if (cert.publicKey.asymmetricKeyType !== "ed25519") v.push("not_ed25519");
    if (!cert.verify(cert.publicKey)) v.push("not_self_signed");
  } catch {
    v.push("unparseable_pem");
  }
  return v;
}

const tmp = mkdtempSync(join(tmpdir(), "root-gate-"));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

function haveOpenssl(): boolean {
  try {
    execFileSync("openssl", ["version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

function genCert(alg: "Ed25519" | "RSA", cn: string): string {
  const key = join(tmp, `${alg}-${cn.length}.key`);
  const crt = join(tmp, `${alg}-${cn.length}.pem`);
  const genArgs =
    alg === "RSA"
      ? ["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", key]
      : ["genpkey", "-algorithm", "Ed25519", "-out", key];
  execFileSync("openssl", genArgs, { stdio: "ignore" });
  execFileSync(
    "openssl",
    ["req", "-new", "-x509", "-key", key, "-out", crt, "-days", "30", "-subj", `/CN=${cn}`],
    { stdio: "ignore" }
  );
  return readFileSync(crt, "utf8");
}

const sha = (pem: string) => createHash("sha256").update(pem, "utf8").digest("hex");

describe("embedded issuer roots conformance", () => {
  it("the stub detector constant is found", () => {
    expect(VERIFIER_STUB_SHA).not.toBeNull();
  });

  it("the stub detector never matches an embedded root", () => {
    for (const r of EMBEDDED_ISSUER_ROOTS) {
      expect(
        r.sha256.toLowerCase(),
        "embedded root equals the stub detector"
      ).not.toBe(VERIFIER_STUB_SHA);
    }
  });

  it("exactly one active root and non-empty list", () => {
    expect(EMBEDDED_ISSUER_ROOTS.length).toBeGreaterThan(0);
    expect(EMBEDDED_ISSUER_ROOTS.filter((r) => r.validTo === null)).toHaveLength(1);
  });

  it("the stub entry (if present) is byte-coherent with the constant", () => {
    const stubs = EMBEDDED_ISSUER_ROOTS.filter((r) => hasStagingMarker(r.pem));
    for (const s of stubs) {
      expect(s.sha256).toBe(VERIFIER_STUB_SHA);
      expect(sha(s.pem)).toBe(VERIFIER_STUB_SHA);
    }
  });

  it("every non-stub embedded root is production-grade", () => {
    const prod = EMBEDDED_ISSUER_ROOTS.filter(
      (r) => r.sha256.toLowerCase() !== VERIFIER_STUB_SHA
    );
    for (const r of prod) {
      expect(productionViolations(r, VERIFIER_STUB_SHA!), r.sha256).toEqual([]);
    }
  });

  it("embedded entries never carry a staging marker unless they ARE the stub", () => {
    for (const r of EMBEDDED_ISSUER_ROOTS) {
      if (hasStagingMarker(r.pem)) expect(r.sha256).toBe(VERIFIER_STUB_SHA);
    }
  });

  describe.skipIf(!haveOpenssl())("mutation: the checker rejects bad roots", () => {
    it("accepts a good ephemeral Ed25519 self-signed root", () => {
      const pem = genCert("Ed25519", "TrustReceipt Issuer Root");
      expect(productionViolations({ pem, sha256: sha(pem) }, VERIFIER_STUB_SHA!)).toEqual([]);
    });
    it("rejects the (STAGING) marker", () => {
      const pem = genCert("Ed25519", "Root (STAGING)");
      expect(productionViolations({ pem, sha256: sha(pem) }, VERIFIER_STUB_SHA!)).toContain("staging_marker");
    });
    it("rejects a non-Ed25519 key", () => {
      const pem = genCert("RSA", "Root RSA");
      expect(productionViolations({ pem, sha256: sha(pem) }, VERIFIER_STUB_SHA!)).toContain("not_ed25519");
    });
    it("rejects a wrong sha256", () => {
      const pem = genCert("Ed25519", "Root wrong sha");
      expect(productionViolations({ pem, sha256: "0".repeat(64) }, VERIFIER_STUB_SHA!)).toContain("sha256_mismatch");
    });
    it("rejects an unparseable PEM", () => {
      const pem = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
      expect(productionViolations({ pem, sha256: sha(pem) }, VERIFIER_STUB_SHA!)).toContain("unparseable_pem");
    });
    it("rejects the stub sha presented as production", () => {
      const pem = genCert("Ed25519", "Root stub sha");
      expect(productionViolations({ pem, sha256: VERIFIER_STUB_SHA! }, VERIFIER_STUB_SHA!)).toContain("is_stub_sha");
    });
  });
});
