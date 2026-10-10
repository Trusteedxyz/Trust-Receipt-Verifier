import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const PACKAGE_NAME = "trust-receipt-verifier";

/**
 * Version of this package, read from its own package.json.
 *
 * The file is looked up from this module's location upwards instead of at a fixed
 * relative path, because the same source runs from `src/` (tests), from `dist/`
 * and from `dist/src/` (the CLI build), and the package.json sits at a different
 * depth in each. Returns "unknown" if it cannot be found.
 */
export function readPackageVersion(): string {
  let dir = path.dirname(fileURLToPath(import.meta.url));
  for (let depth = 0; depth < 6; depth += 1) {
    const candidate = path.join(dir, "package.json");
    if (existsSync(candidate)) {
      try {
        const parsed = JSON.parse(readFileSync(candidate, "utf8")) as {
          name?: string;
          version?: string;
        };
        if (parsed.name === PACKAGE_NAME && typeof parsed.version === "string") {
          return parsed.version;
        }
      } catch {
        // keep walking up
      }
    }
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return "unknown";
}
