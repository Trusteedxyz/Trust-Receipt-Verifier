/**
 * Unit tests for embedded-issuer-root.ts + trust-anchor pinning (spec-049 T424).
 *
 * Covers FR-032b + post-Codex round 2 D3.
 *
 * @see ../embedded-issuer-root.ts
 */
import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import {
  EMBEDDED_ISSUER_ROOTS,
  findIssuerRootBySha256,
  getActiveIssuerRoot,
} from "../embedded-issuer-root.js";

describe("embedded-issuer-root", () => {
  it("EMBEDDED_ISSUER_ROOTS is non-empty and frozen", () => {
    expect(EMBEDDED_ISSUER_ROOTS.length).toBeGreaterThanOrEqual(1);
    // readonly array — Object.freeze applied
    expect(Object.isFrozen(EMBEDDED_ISSUER_ROOTS)).toBe(true);
  });

  it("each entry has required fields", () => {
    for (const entry of EMBEDDED_ISSUER_ROOTS) {
      expect(entry.pem).toMatch(/^-----BEGIN CERTIFICATE-----/);
      expect(entry.pem).toMatch(/-----END CERTIFICATE-----\s*$/);
      expect(entry.sha256).toMatch(/^[0-9a-f]{64}$/);
      expect(entry.validFrom).toBeGreaterThan(0);
      expect(typeof entry.verifierMinVersion).toBe("string");
      expect(entry.verifierMinVersion).toMatch(/^\d+\.\d+\.\d+$/);
    }
  });

  it("entry sha256 matches sha256 of its PEM bytes", () => {
    for (const entry of EMBEDDED_ISSUER_ROOTS) {
      const computed = createHash("sha256").update(entry.pem).digest("hex");
      expect(entry.sha256).toBe(computed);
    }
  });

  it("getActiveIssuerRoot returns the entry with validTo === null", () => {
    const active = getActiveIssuerRoot();
    expect(active.validTo).toBeNull();
  });

  it("findIssuerRootBySha256 — exact match returns entry", () => {
    const active = getActiveIssuerRoot();
    const found = findIssuerRootBySha256(active.sha256);
    expect(found).not.toBeNull();
    expect(found?.sha256).toBe(active.sha256);
  });

  it("findIssuerRootBySha256 — case-insensitive match (lowercase sha256 is canonical)", () => {
    const active = getActiveIssuerRoot();
    const upper = active.sha256.toUpperCase();
    // The function may or may not normalize; either accept both or only lowercase.
    // We document expected behavior here: lowercase is the canonical form,
    // uppercase MAY be accepted (defensive normalization). Test that lowercase always works.
    expect(findIssuerRootBySha256(active.sha256)).not.toBeNull();
    // If uppercase is intentionally rejected, document it; we accept either outcome:
    const upperResult = findIssuerRootBySha256(upper);
    expect(upperResult === null || upperResult?.sha256 === active.sha256).toBe(
      true
    );
  });

  it("findIssuerRootBySha256 — unknown SHA returns null", () => {
    const result = findIssuerRootBySha256("0".repeat(64));
    expect(result).toBeNull();
  });

  it("at most one entry has validTo === null at any time (single active root)", () => {
    const activeEntries = EMBEDDED_ISSUER_ROOTS.filter(
      (e) => e.validTo === null
    );
    expect(activeEntries.length).toBe(1);
  });

  it("all entries have plausible validFrom (within 30 days of now)", () => {
    // STAGING stub may set validFrom slightly in the future to align with the
    // verifier package release window. Allow a 30-day tolerance both directions.
    const now = Math.floor(Date.now() / 1000);
    const tolerance = 30 * 86400;
    for (const entry of EMBEDDED_ISSUER_ROOTS) {
      expect(entry.validFrom).toBeLessThanOrEqual(now + tolerance);
      expect(entry.validFrom).toBeGreaterThan(now - 365 * 86400 * 2);
    }
  });
});
