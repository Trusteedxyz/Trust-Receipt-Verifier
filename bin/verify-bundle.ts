#!/usr/bin/env node
/**
 * verify-bundle CLI — spec-049 T154
 *
 * Offline verifier for TrustReceipt export bundles (ZIP). Wraps the
 * clean-room verifier `verifyExportBundle` (T153 —
 * `../src/verify-export-bundle.js`) so users can run:
 *
 *   npx @agenticmcpstores/trust-receipt-verifier verify-bundle ./trust-receipt-export-<id>.zip
 *
 * Reference: specs/049-trust-receipt-eidas-hardening/quickstart.md §A.3
 *
 * Usage:
 *   verify-bundle <zip-path>
 *     [--trust-anchor-sha256 HEX]
 *     [--expected-bundle-sha256 HEX]
 *     [--manifest URL]              (T502: fetch external signed manifest.jws)
 *     [--policy-oid OID]            (repeatable)
 *     [--expected-subject buyer_agent|merchant_admin]
 *     [--json]
 *     [--quiet]
 *     [--help]
 *
 * The bundle ZIP intentionally does NOT carry its own SHA-256 internally
 * (Codex round 2 D31 — manifest is EXTERNAL). The bundle integrity record
 * lives in the separately-signed `manifest.jws` returned by
 * `GET /api/v1/trust/export/:receiptId/manifest.jws`. With `--manifest URL`
 * the CLI fetches that endpoint, decodes the JWS Compact payload, extracts
 * `bundle_sha256`, and pins the integrity check. If the fetch fails, the
 * CLI emits a warning and falls back to partial offline verification — the
 * bundle is still self-consistent (envelope + JWKS-history + retention) but
 * its container integrity is NOT pinned.
 *
 * Exit codes:
 *   0  outcome === "accepted"
 *   1  outcome === "rejected" OR "accepted_degraded"
 *   2  CLI error (missing zip, malformed flags, file read failure)
 *
 * `accepted_degraded` deliberately exits NON-ZERO so existing automation stays
 * fail-closed: a receipt that declares an unverifiable trust anchor must never
 * be treated as fully verified just because a script checked `$? -eq 0`. The
 * printed verdict distinguishes it from a genuine rejection, so callers that
 * want to accept the weaker guarantee can read the outcome instead of the
 * exit code. Reusing code 1 (rather than minting a new one) keeps the
 * documented contract stable for scripts that only test for zero.
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
  readonly manifestUrl: string | undefined;
  readonly policyOids: readonly string[];
  readonly tsaRootAllowlist: readonly string[];
  readonly expectedSubject: ExpectedSubject | undefined;
  readonly allowStagingRoots: boolean;
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
      "  --manifest URL                   Fetch external signed manifest.jws (T502).",
      "                                   Overrides --expected-bundle-sha256 on success.",
      "                                   On fetch failure: warning + partial offline verify.",
      "  --policy-oid OID                 Required claims policy OID (repeatable).",
      "  --tsa-root-allowlist HEX[,HEX]   Comma-separated 64-hex SHA-256 of",
      "                                   pre-approved TSA root certs. Default empty",
      "                                   ⇒ fail-closed on any RFC 3161 timestamp",
      "                                   (T-CR-002 — envelope-supplied roots are",
      "                                   never trusted on their own).",
      "  --expected-subject SUBJECT       'buyer_agent' or 'merchant_admin'.",
      "  --allow-staging-roots            Opt-in: accept staging-stub embedded",
      "                                   issuer roots (T-CR-001). Default OFF —",
      "                                   bundles whose JWKS history root is not in",
      "                                   the verifier's trust anchor list are",
      "                                   REJECTED with detail",
      "                                   'root_not_in_trust_anchor'. NEVER enable",
      "                                   in production.",
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
      manifest: { type: "string" },
      "policy-oid": { type: "string", multiple: true },
      "tsa-root-allowlist": { type: "string" },
      "expected-subject": { type: "string" },
      "allow-staging-roots": { type: "boolean", default: false },
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
  const tsaRootAllowlistRaw = parsed.values["tsa-root-allowlist"];
  let tsaRootAllowlist: readonly string[] = [];
  if (
    typeof tsaRootAllowlistRaw === "string" &&
    tsaRootAllowlistRaw.length > 0
  ) {
    const items = tsaRootAllowlistRaw
      .split(",")
      .map((s) => s.trim().toLowerCase())
      .filter((s) => s.length > 0);
    for (const hex of items) {
      if (!/^[0-9a-f]{64}$/.test(hex)) {
        err(
          `verify-bundle: --tsa-root-allowlist entry must be 64-hex (got "${hex}")`
        );
        process.exit(2);
      }
    }
    tsaRootAllowlist = items;
  }
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
    manifestUrl:
      typeof parsed.values.manifest === "string"
        ? parsed.values.manifest
        : undefined,
    policyOids: Array.isArray(policyOids) ? policyOids : [],
    tsaRootAllowlist,
    expectedSubject,
    allowStagingRoots: parsed.values["allow-staging-roots"] === true,
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
  else if (r.outcome === "accepted_degraded")
    // Reporting this as "REJECTED UNKNOWN" would be a false statement about
    // what happened: the bundle verified, but the receipt declares its trust
    // anchor is unverifiable. Say exactly that. Exit stays non-zero (below) so
    // automation remains fail-closed.
    out(
      "ACCEPTED (DEGRADED) — signature and structure verified, but the receipt " +
        "declares an unverifiable trust anchor. Attests internal consistency " +
        "and issuer intent, NOT issuer authenticity."
    );
  else
    out(
      `REJECTED ${r.error_code ?? "UNKNOWN"}${r.error_detail ? ` ${r.error_detail}` : ""}`
    );
}

interface ManifestFetchResult {
  readonly bundleSha256: string | undefined;
  readonly warning: string | undefined;
}

/**
 * Fetch external manifest.jws from `url`, decode the JWS Compact payload, and
 * extract `bundle_sha256`. Returns `{ bundleSha256: undefined, warning }` on
 * any failure so the caller can fall back to partial offline verification.
 *
 * NOTE: This step does NOT cryptographically verify the manifest signature —
 * the embedded issuer root + JWS verifier path lives in
 * `verify-export-bundle.ts` (T423). Here we only extract the integrity hash
 * to feed into the bundle verifier as `expectedBundleSha256`.
 */
async function fetchManifestBundleSha256(
  url: string
): Promise<ManifestFetchResult> {
  let response: Response;
  try {
    response = await fetch(url, {
      headers: { Accept: "application/jose" },
    });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return {
      bundleSha256: undefined,
      warning: `manifest_fetch_failed:${msg}`,
    };
  }
  if (!response.ok) {
    return {
      bundleSha256: undefined,
      warning: `manifest_fetch_http_${response.status}`,
    };
  }
  let jwsCompact: string;
  try {
    jwsCompact = (await response.text()).trim();
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return {
      bundleSha256: undefined,
      warning: `manifest_body_read_failed:${msg}`,
    };
  }
  const parts = jwsCompact.split(".");
  if (parts.length !== 3 || !parts[1]) {
    return {
      bundleSha256: undefined,
      warning: "manifest_jws_malformed",
    };
  }
  let payload: { bundle_sha256?: unknown };
  try {
    payload = JSON.parse(
      Buffer.from(parts[1], "base64url").toString("utf8")
    ) as { bundle_sha256?: unknown };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return {
      bundleSha256: undefined,
      warning: `manifest_payload_decode_failed:${msg}`,
    };
  }
  const raw = payload.bundle_sha256;
  if (typeof raw !== "string") {
    return {
      bundleSha256: undefined,
      warning: "manifest_bundle_sha256_missing",
    };
  }
  // Manifest emits `sha256:<hex>` (per ManifestPayload contract). Strip prefix.
  const hex = raw.startsWith("sha256:") ? raw.slice("sha256:".length) : raw;
  if (!/^[0-9a-f]{64}$/.test(hex)) {
    return {
      bundleSha256: undefined,
      warning: "manifest_bundle_sha256_invalid_format",
    };
  }
  return { bundleSha256: hex, warning: undefined };
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

  // T502: External manifest fetch. If --manifest is supplied, override the
  // explicit --expected-bundle-sha256 with the value from manifest.jws. On
  // fetch failure, emit a warning to stderr and continue with whatever pin
  // the operator already supplied (partial offline verification).
  let effectiveExpectedSha256 = opts.expectedBundleSha256;
  if (opts.manifestUrl !== undefined) {
    const { bundleSha256, warning } = await fetchManifestBundleSha256(
      opts.manifestUrl
    );
    if (warning && !opts.quiet) {
      err(
        `verify-bundle: WARNING manifest fetch incomplete (${warning}) — ` +
          `partial offline verification: bundle integrity NOT pinned externally.`
      );
    }
    if (bundleSha256) {
      effectiveExpectedSha256 = bundleSha256;
    }
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
        allowStagingRoots?: boolean;
        tsaRootCertSha256Allowlist?: readonly string[];
      }
    ) => Promise<BundleVerifyResult>;
  };
  const verifyResult = await mod.verifyExportBundle(zipBuffer, {
    trustAnchorSha256: opts.trustAnchorSha256,
    expectedBundleSha256: effectiveExpectedSha256,
    expectedPolicyOids:
      opts.policyOids.length > 0 ? opts.policyOids : undefined,
    expectedSubject: opts.expectedSubject,
    allowStagingRoots: opts.allowStagingRoots,
    tsaRootCertSha256Allowlist:
      opts.tsaRootAllowlist.length > 0 ? opts.tsaRootAllowlist : undefined,
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
