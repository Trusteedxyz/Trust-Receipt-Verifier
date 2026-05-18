#!/usr/bin/env node
/**
 * verify-bundle CLI
 *
 * Offline verifier for TrustReceipt export bundles (ZIP). Wraps the
 * clean-room verifier `verifyExportBundle`
 * (`../src/verify-export-bundle.js`) so users can run:
 *
 *   npx @agenticmcpstores/trust-receipt-verifier verify-bundle ./trust-receipt-export-<id>.zip
 *
 * Reference: specs/049-trust-receipt-eidas-hardening/quickstart.md §A.3
 *
 * Usage:
 *   verify-bundle <zip-path>
 *     [--trust-anchor-sha256 HEX]
 *     [--expected-bundle-sha256 HEX]
 *     [--policy-oid OID]            (repeatable)
 *     [--expected-subject buyer_agent|merchant_admin]
 *     [--json]
 *     [--quiet]
 *     [--help]
 *
 * Exit codes:
 *   0  outcome === "accepted"
 *   1  outcome === "rejected"
 *   2  CLI error (missing zip, malformed flags, file read failure)
 */

import { readFile } from "node:fs/promises";
import { parseArgs } from "node:util";
// NOTE: `verifyExportBundle` (T153) is loaded via dynamic import inside `main()`
// so that `--help` and arg-validation paths work even before T153 ships.
// Type-only import keeps strict typing without forcing eager module resolution.
import type { BundleVerifyResult } from "../src/verify-export-bundle.js";

const VERSION = "0.1.0";
const VALID_SUBJECTS = ["buyer_agent", "merchant_admin"] as const;
type ExpectedSubject = (typeof VALID_SUBJECTS)[number];

interface CliOptions {
  readonly zipPath: string;
  readonly trustAnchorSha256: string | undefined;
  readonly expectedBundleSha256: string | undefined;
  readonly policyOids: readonly string[];
  readonly expectedSubject: ExpectedSubject | undefined;
  readonly json: boolean;
  readonly quiet: boolean;
}

function out(line: string): void {
  process.stdout.write(line + "\n");
}

function err(line: string): void {
  process.stderr.write(line + "\n");
}

function printHelp(): void {
  out(
    [
      `verify-bundle v${VERSION} — TrustReceipt export bundle offline verifier`,
      "",
      "Usage:",
      "  verify-bundle <zip-path> [options]",
      "",
      "Options:",
      "  --trust-anchor-sha256 HEX        Pinned issuer root SHA-256 (hex).",
      "                                   TODO(T423): replaced by embedded-issuer-root.ts.",
      "  --expected-bundle-sha256 HEX     Pinned bundle SHA-256 for integrity check.",
      "  --policy-oid OID                 Required claims policy OID (repeatable).",
      "  --expected-subject SUBJECT       'buyer_agent' or 'merchant_admin'.",
      "  --json                           Emit JSON BundleVerifyResult instead of text.",
      "  --quiet                          Suppress per-check lines (final verdict only).",
      "  --help                           Show this help and exit 0.",
      "",
      "Exit codes: 0 accepted · 1 rejected · 2 CLI error.",
    ].join("\n")
  );
}

function isExpectedSubject(v: string): v is ExpectedSubject {
  return (VALID_SUBJECTS as readonly string[]).includes(v);
}

function parseCliArgs(argv: readonly string[]): CliOptions | null {
  const parsed = parseArgs({
    args: argv.slice(2),
    allowPositionals: true,
    strict: true,
    options: {
      "trust-anchor-sha256": { type: "string" },
      "expected-bundle-sha256": { type: "string" },
      "policy-oid": { type: "string", multiple: true },
      "expected-subject": { type: "string" },
      json: { type: "boolean", default: false },
      quiet: { type: "boolean", default: false },
      help: { type: "boolean", default: false },
    },
  });

  if (parsed.values.help === true) {
    printHelp();
    return null;
  }

  const positionals = parsed.positionals;
  if (positionals.length === 0) {
    err("verify-bundle: missing <zip-path> argument. Run --help.");
    process.exit(2);
  }
  if (positionals.length > 1) {
    err(
      `verify-bundle: unexpected extra arguments: ${positionals.slice(1).join(" ")}`
    );
    process.exit(2);
  }

  const subjectRaw = parsed.values["expected-subject"];
  let expectedSubject: ExpectedSubject | undefined;
  if (typeof subjectRaw === "string") {
    if (!isExpectedSubject(subjectRaw)) {
      err(
        `verify-bundle: --expected-subject must be one of ${VALID_SUBJECTS.join("|")} (got "${subjectRaw}")`
      );
      process.exit(2);
    }
    expectedSubject = subjectRaw;
  }

  const policyOids = parsed.values["policy-oid"];
  return {
    zipPath: positionals[0] ?? "",
    trustAnchorSha256:
      typeof parsed.values["trust-anchor-sha256"] === "string"
        ? parsed.values["trust-anchor-sha256"]
        : undefined,
    expectedBundleSha256:
      typeof parsed.values["expected-bundle-sha256"] === "string"
        ? parsed.values["expected-bundle-sha256"]
        : undefined,
    policyOids: Array.isArray(policyOids) ? policyOids : [],
    expectedSubject,
    json: parsed.values.json === true,
    quiet: parsed.values.quiet === true,
  };
}

function getCheck(
  result: BundleVerifyResult,
  key: string
): { ok: boolean; detail?: string } | undefined {
  const checks = (
    result as unknown as {
      checks?: Record<string, { ok: boolean; detail?: string }>;
    }
  ).checks;
  if (!checks || typeof checks !== "object") return undefined;
  const v = checks[key];
  return v && typeof v.ok === "boolean" ? v : undefined;
}

function renderHuman(result: BundleVerifyResult, opts: CliOptions): void {
  const r = result as unknown as {
    outcome: string;
    error_code?: string;
    error_detail?: string;
    retention?: { jurisdiction?: string; min_retention_years?: number };
  };

  if (!opts.quiet) {
    const jws = getCheck(result, "jws_signature");
    if (jws) {
      out(
        jws.ok
          ? "✓ JWS signature valid (verified against jwks-history.jws)"
          : `✗ JWS signature INVALID — ${jws.detail ?? "verification failed"}`
      );
    }
    const ts = getCheck(result, "timestamp");
    if (ts) {
      if (ts.ok)
        out("✓ RFC 3161 timestamp valid (verified against tsa-root-cert.pem)");
      else if (ts.detail === "absent" || ts.detail === "fail_open")
        out(
          "○ RFC 3161 timestamp absent — receipt issued under fail-open path"
        );
      else
        out(
          `✗ RFC 3161 timestamp INVALID — ${ts.detail ?? "verification failed"}`
        );
    }
    const consent = getCheck(result, "redacted_consent");
    if (consent) {
      out(
        consent.ok
          ? "✓ Redacted consent record present (HMAC keys are KMS-held; no salts in bundle)"
          : `✗ Redacted consent record check failed — ${consent.detail ?? "missing"}`
      );
    }
    const retention = getCheck(result, "retention_policy");
    if (retention) {
      if (retention.ok && r.retention)
        out(
          `✓ Retention policy: ${r.retention.jurisdiction ?? "?"}, min ${r.retention.min_retention_years ?? "?"}y`
        );
      else if (retention.ok) out("✓ Retention policy present");
      else
        out(
          `✗ Retention policy check failed — ${retention.detail ?? "invalid"}`
        );
    }
    const bundleHash = getCheck(result, "bundle_sha256");
    if (bundleHash) {
      if (bundleHash.ok) out("✓ Bundle SHA-256 matches manifest");
      else if (bundleHash.detail === "skipped")
        out("⚠ bundle_sha256 not provided — skipping integrity check");
      else
        out(
          `✗ Bundle SHA-256 mismatch — ${bundleHash.detail ?? "expected vs actual differ"}`
        );
    }
  }

  if (r.outcome === "accepted") out("ACCEPTED");
  else
    out(
      `REJECTED ${r.error_code ?? "UNKNOWN"}${r.error_detail ? ` ${r.error_detail}` : ""}`
    );
}

async function main(): Promise<void> {
  const opts = parseCliArgs(process.argv);
  if (opts === null) {
    process.exit(0);
    return;
  }

  let zipBuffer: Buffer;
  try {
    zipBuffer = await readFile(opts.zipPath);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    err(`verify-bundle: cannot read ZIP at "${opts.zipPath}": ${msg}`);
    process.exit(2);
    return;
  }

  // TODO(T423 / Phase 9): replace --trust-anchor-sha256 flag with the
  // embedded issuer root from `src/embedded-issuer-root.ts`. Until then,
  // the CLI relies on the operator pinning the anchor explicitly.
  const mod = (await import("../src/verify-export-bundle.js")) as {
    verifyExportBundle: (
      zip: Buffer,
      opts: {
        trustAnchorSha256?: string;
        expectedBundleSha256?: string;
        expectedPolicyOids?: readonly string[];
        expectedSubject?: ExpectedSubject;
      }
    ) => Promise<BundleVerifyResult>;
  };
  const verifyResult = await mod.verifyExportBundle(zipBuffer, {
    trustAnchorSha256: opts.trustAnchorSha256,
    expectedBundleSha256: opts.expectedBundleSha256,
    expectedPolicyOids:
      opts.policyOids.length > 0 ? opts.policyOids : undefined,
    expectedSubject: opts.expectedSubject,
  });

  if (opts.json) {
    out(JSON.stringify(verifyResult, null, 2));
  } else {
    renderHuman(verifyResult, opts);
  }

  process.exit(verifyResult.outcome === "accepted" ? 0 : 1);
}

main().catch((e: unknown) => {
  const msg = e instanceof Error ? e.message : String(e);
  err(`verify-bundle: fatal: ${msg}`);
  process.exit(2);
});
