/**
 * Resource limits for export-bundle unpacking (zip-bomb defence).
 *
 * Declared sizes are checked BEFORE inflating, and the real inflated size is
 * bounded independently of what the (attacker-controlled) ZIP headers claim.
 * Bombs are built in-test; no binary fixture is committed.
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

const MIB = 1024 * 1024;
const TRUST_ANCHOR_PEM =
  "-----BEGIN CERTIFICATE-----\nstub-trust-anchor\n-----END CERTIFICATE-----\n";
const PIN = createHash("sha256").update(TRUST_ANCHOR_PEM).digest("hex");

function baseZip(extra?: (zip: AdmZip) => void): Buffer {
  const zip = new AdmZip();
  zip.addFile("receipt-envelope.json", Buffer.from("{}"));
  zip.addFile("jwks-snapshot.json", Buffer.from('{"keys":[]}'));
  zip.addFile("jwks-history.jws", Buffer.from("eyJhIjoxfQ.eyJlbnRyaWVzIjpbXX0.x"));
  zip.addFile("trust-anchor.pem", Buffer.from(TRUST_ANCHOR_PEM));
  zip.addFile("retention-policy.json", Buffer.from("{}"));
  extra?.(zip);
  return zip.toBuffer();
}

/** Rewrites the uncompressed-size field of every central-directory record. */
function lieAboutSize(buf: Buffer, declared: number): Buffer {
  const out = Buffer.from(buf);
  for (let i = 0; i + 28 < out.length; i++) {
    if (out.readUInt32LE(i) === 0x02014b50) out.writeUInt32LE(declared, i + 24);
  }
  return out;
}

const opts = { trustAnchorPemSha256: PIN, allowStagingRoots: true } as const;

describe("verifyExportBundle resource limits", () => {
  it("rejects a declared-size zip bomb (50 MiB of zeros, a few KB zipped) without inflating it", async () => {
    const zip = baseZip((z) => z.addFile("README.md", Buffer.alloc(50 * MIB)));
    expect(zip.length).toBeLessThan(200 * 1024);
    const result = await verifyExportBundle(zip, opts);
    expect(result.outcome).toBe("rejected");
    expect(result.errorCode).toBe("bundle_limits_exceeded");
    expect(verifyReceiptEnvelope).not.toHaveBeenCalled();
  });

  it("rejects a bundle whose total declared size exceeds the total cap", async () => {
    const zip = baseZip((z) => {
      // 3 x 4 MiB of incompressible-ish data would pass per-entry, fail total.
      z.addFile("tsa-cert-chain.pem", Buffer.alloc(4 * MIB, 1));
      z.addFile("README.md", Buffer.alloc(4 * MIB, 2));
    });
    const result = await verifyExportBundle(zip, {
      ...opts,
      limits: { maxTotalBytes: 6 * MIB, maxCompressionRatio: 100_000 },
    });
    expect(result.errorCode).toBe("bundle_limits_exceeded");
  });

  it("rejects a bundle with too many entries", async () => {
    const zip = baseZip((z) => {
      for (let i = 0; i < 200; i++) z.addFile(`extra-${i}.txt`, Buffer.from("x"));
    });
    const result = await verifyExportBundle(zip, opts);
    expect(result.errorCode).toBe("bundle_limits_exceeded");
  });

  it("rejects a bundle larger than the compressed-size cap before parsing it", async () => {
    const zip = baseZip();
    const result = await verifyExportBundle(zip, {
      ...opts,
      limits: { maxCompressedBytes: 100 },
    });
    expect(result.errorCode).toBe("bundle_limits_exceeded");
  });

  it("rejects an entry whose compression ratio is implausible even if under the size cap", async () => {
    const zip = baseZip((z) => z.addFile("README.md", Buffer.alloc(8 * MIB)));
    const result = await verifyExportBundle(zip, {
      ...opts,
      limits: { maxEntryBytes: 16 * MIB, maxTotalBytes: 32 * MIB },
    });
    expect(result.errorCode).toBe("bundle_limits_exceeded");
  });

  it.each([100, 0])(
    "does not trust a header that LIES about the size (declared %i, real 50 MiB)",
    async (declared) => {
      const honest = baseZip((z) => z.addFile("README.md", Buffer.alloc(50 * MIB)));
      const zip = lieAboutSize(honest, declared);
      const before = process.memoryUsage().rss;
      const result = await verifyExportBundle(zip, opts);
      expect(result.outcome).toBe("rejected");
      expect(result.errorCode).toBe("bundle_limits_exceeded");
      // never materialised the 50 MiB payload
      expect(process.memoryUsage().rss - before).toBeLessThan(40 * MIB);
    }
  );

  it("still verifies a normal bundle with default limits", async () => {
    verifyReceiptEnvelope.mockReset();
    verifyReceiptEnvelope.mockResolvedValue({
      outcome: "rejected",
      errorCode: "sentinel",
      warnings: [],
    });
    const result = await verifyExportBundle(baseZip(), opts);
    expect(result.errorCode).not.toBe("bundle_limits_exceeded");
    expect(result.errorCode).not.toBe("bundle_zip_invalid");
  });
});
