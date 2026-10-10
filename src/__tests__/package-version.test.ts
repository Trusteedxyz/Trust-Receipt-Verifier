import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { readPackageVersion } from "../package-version.js";
import * as api from "../index.js";

describe("package version and public exports", () => {
  it("readPackageVersion returns the version in package.json, not a hardcoded one", () => {
    const pkg = JSON.parse(
      readFileSync(new URL("../../package.json", import.meta.url), "utf8")
    ) as { version: string };
    expect(readPackageVersion()).toBe(pkg.version);
  });

  it("the bundle verifier and its default limits are part of the public API", () => {
    expect(typeof api.verifyExportBundle).toBe("function");
    expect(api.DEFAULT_BUNDLE_LIMITS.maxEntries).toBeGreaterThan(0);
  });
});
