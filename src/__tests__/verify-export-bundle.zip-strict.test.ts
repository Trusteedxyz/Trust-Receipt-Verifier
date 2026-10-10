/**
 * The bundle verifier maps the strict ZIP reader's findings onto its existing
 * verdicts: structural problems -> bundle_zip_invalid, limits -> bundle_limits_exceeded.
 */
import { describe, it, expect, vi } from "vitest";
import AdmZip from "adm-zip";
import { createHash } from "node:crypto";

const verifyReceiptEnvelope = vi.fn();
vi.mock("../verify-1.1.js", () => ({
  verifyReceiptEnvelope: (envelope: unknown, opts: unknown) =>
    verifyReceiptEnvelope(envelope, opts),
}));
const { verifyExportBundle } = await import("../verify-export-bundle.js");

const PEM = "-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----\n";
const opts = {
  trustAnchorPemSha256: createHash("sha256").update(PEM).digest("hex"),
  allowStagingRoots: true,
} as const;

function zipWith(names: string[]): Buffer {
  const z = new AdmZip();
  z.addFile("receipt-envelope.json", Buffer.from("{}"));
  z.addFile("jwks-snapshot.json", Buffer.from('{"keys":[]}'));
  z.addFile("jwks-history.jws", Buffer.from("a.b.c"));
  z.addFile("trust-anchor.pem", Buffer.from(PEM));
  z.addFile("retention-policy.json", Buffer.from("{}"));
  for (const n of names) z.addFile(n, Buffer.from("x"));
  return z.toBuffer();
}

describe("verifyExportBundle with the strict reader", () => {
  it("rejects a corrupted entry (CRC) as bundle_zip_invalid", async () => {
    const buf = zipWith([]);
    // corrupt the CRC-32 recorded in the first central-directory record
    const bad = Buffer.from(buf);
    const cd = bad.indexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02]));
    bad[cd + 16] ^= 0xff;
    const r = await verifyExportBundle(bad, opts);
    expect(r.errorCode).toBe("bundle_zip_invalid");
  });

  it("rejects a traversal entry name instead of silently skipping it", async () => {
    const buf = zipWith([]);
    // rename "README.md"-length entry: add one then patch both name copies
    const z = new AdmZip(buf);
    z.addFile("zz/evil.txt", Buffer.from("x"));
    const out = z.toBuffer();
    const patched = Buffer.from(out.toString("latin1").replaceAll("zz/evil.txt", "../evil.txt"), "latin1");
    const r = await verifyExportBundle(patched, opts);
    expect(r.errorCode).toBe("bundle_zip_invalid");
  });

  it("still skips (with a warning) unknown plain files and subdirectory members", async () => {
    verifyReceiptEnvelope.mockResolvedValue({ outcome: "rejected", errorCode: "sentinel", warnings: [] });
    const r = await verifyExportBundle(zipWith(["extra.txt", "sub/inner.txt"]), opts);
    expect(r.errorCode).not.toBe("bundle_zip_invalid");
    expect(r.warnings).toContain("bundle_unknown_artifact:extra.txt");
  });
});
