/**
 * Spec 054 T102 — CLI auditor helper.
 *
 * Standalone command-line front-end for VerifierX402Extension. Designed for
 * auditors and external partners — receives the 5 binding components (file
 * paths) + ReceiptEnvelope + JWKS source and produces a human-readable
 * verification report on stdout. Exit codes:
 *
 *   0  verification succeeded (valid: true)
 *   1  verification failed     (valid: false)
 *   2  input error / I/O / network failure
 *
 * Usage:
 *   audit-command \
 *     --envelope envelope.json \
 *     --payment-requirements paymentRequirements.json \
 *     --payment-payload paymentPayload.json \
 *     --authorization-scheme evm_permit2 \
 *     --resource-uri "https://merchant.example.com/api/paid-resource" \
 *     --settlement-evidence settlementEvidence.json \
 *     --output-commitment output-commitment.json \
 *     --jwks-url "https://merchant.example.com/.well-known/jwks.json"
 *     [--jwks-file path/to/jwks.json]
 *     [--declared-payment-requirements ...] [--declared-payment-payload ...] ...
 *     [--expected-binding-profile-version 1.0.0]
 *     [--no-binding-recompute]
 *
 * For test/CI use, prefer `--jwks-file` to bypass network.
 *
 * @see specs/058-trustreceipt-x402-binding/tasks.md T102
 */

import { readFile } from "node:fs/promises";

import {
  recomputeBindingHash,
  type BindingHashRecomputeInput,
  type RecomputeAuthorizationScheme,
  type SettlementEvidenceInput,
} from "../x402-binding/binding-hash-recompute.js";
import type { MerchantJwksDocument } from "../x402-binding/delegation-validator.js";
import {
  VerifierX402Extension,
  type ReceiptEnvelopeInput,
  type VerifierExtensionResult,
} from "../x402-binding/verifier-x402-extension.js";
import type { OutputCommitment } from "../zod-1.1.js";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface RunCliResult {
  readonly exitCode: 0 | 1 | 2;
  readonly stdout: string;
  readonly stderr: string;
}

// ---------------------------------------------------------------------------
// Arg parsing (zero dependencies — use only stdlib semantics)
// ---------------------------------------------------------------------------

interface ParsedArgs {
  readonly envelope: string;
  readonly paymentRequirements?: string;
  readonly paymentPayload?: string;
  readonly authorizationScheme?: string;
  readonly resourceUri?: string;
  readonly settlementEvidence?: string;
  readonly outputCommitment?: string;
  readonly jwksUrl?: string;
  readonly jwksFile?: string;
  readonly declaredPaymentRequirements?: string;
  readonly declaredPaymentPayload?: string;
  readonly declaredResourceUri?: string;
  readonly declaredSettlementEvidence?: string;
  readonly declaredOutputCommitment?: string;
  readonly expectedBindingProfileVersion?: string;
  readonly noBindingRecompute?: boolean;
}

const STRING_FLAGS: Record<string, keyof ParsedArgs> = {
  "--envelope": "envelope",
  "--payment-requirements": "paymentRequirements",
  "--payment-payload": "paymentPayload",
  "--authorization-scheme": "authorizationScheme",
  "--resource-uri": "resourceUri",
  "--settlement-evidence": "settlementEvidence",
  "--output-commitment": "outputCommitment",
  "--jwks-url": "jwksUrl",
  "--jwks-file": "jwksFile",
  "--declared-payment-requirements": "declaredPaymentRequirements",
  "--declared-payment-payload": "declaredPaymentPayload",
  "--declared-resource-uri": "declaredResourceUri",
  "--declared-settlement-evidence": "declaredSettlementEvidence",
  "--declared-output-commitment": "declaredOutputCommitment",
  "--expected-binding-profile-version": "expectedBindingProfileVersion",
};

function parseArgs(
  argv: readonly string[]
):
  | { readonly ok: true; readonly parsed: ParsedArgs }
  | { readonly ok: false; readonly error: string } {
  const out: Record<string, unknown> = {};
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token === "--no-binding-recompute") {
      out.noBindingRecompute = true;
      continue;
    }
    const key = STRING_FLAGS[token];
    if (!key) {
      return { ok: false, error: `unknown flag: ${token}` };
    }
    const value = argv[i + 1];
    if (value === undefined || value.startsWith("--")) {
      return { ok: false, error: `missing value for ${token}` };
    }
    out[key] = value;
    i += 1;
  }
  if (typeof out.envelope !== "string") {
    return { ok: false, error: "missing required arg: --envelope" };
  }
  return { ok: true, parsed: out as unknown as ParsedArgs };
}

// ---------------------------------------------------------------------------
// File / network loaders
// ---------------------------------------------------------------------------

async function readJsonFile<T = unknown>(path: string): Promise<T> {
  const raw = await readFile(path, "utf8");
  return JSON.parse(raw) as T;
}

async function loadJwks(args: ParsedArgs): Promise<MerchantJwksDocument> {
  if (args.jwksFile !== undefined) {
    return readJsonFile<MerchantJwksDocument>(args.jwksFile);
  }
  if (args.jwksUrl !== undefined) {
    const res = await fetch(args.jwksUrl);
    if (!res.ok) {
      throw new Error(`fetch ${args.jwksUrl} failed: HTTP ${res.status}`);
    }
    return (await res.json()) as MerchantJwksDocument;
  }
  throw new Error("missing required arg: one of --jwks-url or --jwks-file");
}

async function maybeBuildComponents(
  prefix: "" | "declared",
  args: ParsedArgs
): Promise<BindingHashRecomputeInput | undefined> {
  // Discriminator fields (excluding `authorizationScheme`, which is shared
  // between verification and declared sets).
  const map = {
    paymentRequirements:
      prefix === "declared"
        ? args.declaredPaymentRequirements
        : args.paymentRequirements,
    paymentPayload:
      prefix === "declared" ? args.declaredPaymentPayload : args.paymentPayload,
    resourceUri:
      prefix === "declared" ? args.declaredResourceUri : args.resourceUri,
    settlementEvidence:
      prefix === "declared"
        ? args.declaredSettlementEvidence
        : args.settlementEvidence,
    outputCommitment:
      prefix === "declared"
        ? args.declaredOutputCommitment
        : args.outputCommitment,
  };
  const allUndefined = Object.values(map).every((v) => v === undefined);
  if (allUndefined) return undefined;
  if (args.authorizationScheme === undefined) {
    throw new Error("missing required arg: --authorization-scheme");
  }
  const missing = Object.entries(map)
    .filter(([, v]) => v === undefined)
    .map(([k]) => k);
  if (missing.length > 0) {
    throw new Error(
      `partial ${prefix === "declared" ? "declared " : ""}component set; missing: ${missing.join(", ")}`
    );
  }
  const paymentRequirements = await readJsonFile<Record<string, unknown>>(
    map.paymentRequirements as string
  );
  const paymentPayload = await readJsonFile<Record<string, unknown>>(
    map.paymentPayload as string
  );
  const settlementEvidence = await readJsonFile<SettlementEvidenceInput>(
    map.settlementEvidence as string
  );
  const outputCommitment = await readJsonFile<OutputCommitment>(
    map.outputCommitment as string
  );
  return {
    paymentRequirements,
    paymentPayload,
    authorizationScheme:
      args.authorizationScheme as RecomputeAuthorizationScheme,
    resourceUri: map.resourceUri as string,
    settlementEvidence,
    outputCommitment,
  };
}

// ---------------------------------------------------------------------------
// Report formatter
// ---------------------------------------------------------------------------

function formatReport(
  result: VerifierExtensionResult,
  ctx: {
    readonly componentsProvided: boolean;
    readonly recomputed?: ReturnType<typeof recomputeBindingHash>;
    readonly declared?: ReturnType<typeof recomputeBindingHash>;
  }
): string {
  const lines: string[] = [];
  if (result.valid) {
    lines.push(
      `[OK] JWS signature valid (branch: ${result.delegation_branch}, kid: ${result.kid}, posture: ${result.posture})`
    );
    lines.push(`[OK] verification_posture: ${result.verification_posture}`);
    if (ctx.componentsProvided) {
      if (result.binding_hash_match) {
        lines.push("[OK] binding_hash recomputation matches declared");
        if (ctx.recomputed) {
          let idx = 0;
          for (const [name, hash] of Object.entries(
            ctx.recomputed.componentHashesTagged
          )) {
            idx += 1;
            lines.push(`[OK] Component ${idx}/5 ${name}: ${hash}`);
          }
        }
      } else {
        lines.push("[WARN] binding_hash recomputation skipped or failed");
      }
    } else {
      lines.push("[INFO] no components provided; signature-only verification");
    }
    for (const w of result.warnings) {
      lines.push(`[WARN] ${w}`);
    }
    lines.push("Result: VALID");
  } else {
    lines.push(`[FAIL] reason: ${result.reason}`);
    if (result.reason === "binding_mismatch") {
      if (ctx.recomputed && ctx.declared) {
        const components = [
          "payment_requirements",
          "payment_payload",
          "resource_uri",
          "settlement_evidence_subset",
          "output_commitment",
        ] as const;
        let idx = 0;
        for (const c of components) {
          idx += 1;
          const r = ctx.recomputed.componentHashesTagged[c];
          const d = ctx.declared.componentHashesTagged[c];
          if (r === d) {
            lines.push(`[OK] Component ${idx}/5 ${c}: match`);
          } else {
            lines.push(
              `[FAIL] Component ${idx}/5 ${c}: MISMATCH (declared=${d}, recomputed=${r})`
            );
          }
        }
      }
      if (result.mismatched_component) {
        lines.push(
          `Result: BINDING_MISMATCH (component: ${result.mismatched_component})`
        );
      } else {
        lines.push("Result: BINDING_MISMATCH");
      }
    } else {
      if (result.details) {
        lines.push(`[DETAILS] ${JSON.stringify(result.details)}`);
      }
      lines.push(`Result: INVALID (${result.reason})`);
    }
    for (const w of result.warnings) {
      lines.push(`[WARN] ${w}`);
    }
  }
  return `${lines.join("\n")}\n`;
}

// ---------------------------------------------------------------------------
// Public entry — testable programmatic shape
// ---------------------------------------------------------------------------

export async function runCli(argv: readonly string[]): Promise<RunCliResult> {
  const parseResult = parseArgs(argv);
  if (!parseResult.ok) {
    return {
      exitCode: 2,
      stdout: "",
      stderr: `audit-command: ${parseResult.error}\n`,
    };
  }
  const args = parseResult.parsed;

  let envelope: ReceiptEnvelopeInput;
  let jwks: MerchantJwksDocument;
  let components: BindingHashRecomputeInput | undefined;
  let declared: BindingHashRecomputeInput | undefined;
  try {
    envelope = await readJsonFile<ReceiptEnvelopeInput>(args.envelope);
  } catch (err) {
    return {
      exitCode: 2,
      stdout: "",
      stderr: `audit-command: failed to load envelope: ${(err as Error).message}\n`,
    };
  }
  try {
    jwks = await loadJwks(args);
  } catch (err) {
    return {
      exitCode: 2,
      stdout: "",
      stderr: `audit-command: failed to load JWKS: ${(err as Error).message}\n`,
    };
  }
  try {
    if (args.noBindingRecompute !== true) {
      components = await maybeBuildComponents("", args);
      declared = await maybeBuildComponents("declared", args);
    }
  } catch (err) {
    return {
      exitCode: 2,
      stdout: "",
      stderr: `audit-command: failed to load components: ${(err as Error).message}\n`,
    };
  }

  const verifier = new VerifierX402Extension();
  const result = verifier.verify({
    envelope,
    jwks,
    componentsForBinding: components,
    declaredComponentsForLocalization: declared,
    ...(args.expectedBindingProfileVersion !== undefined
      ? { expectedBindingProfileVersion: args.expectedBindingProfileVersion }
      : {}),
  });

  // Recompute for the report (best-effort; ignore errors).
  let recomputed;
  let declaredRecomputed;
  try {
    if (components) recomputed = recomputeBindingHash(components);
  } catch {
    /* ignore */
  }
  try {
    if (declared) declaredRecomputed = recomputeBindingHash(declared);
  } catch {
    /* ignore */
  }

  const stdout = formatReport(result, {
    componentsProvided: components !== undefined,
    recomputed,
    declared: declaredRecomputed,
  });
  return {
    exitCode: result.valid ? 0 : 1,
    stdout,
    stderr: "",
  };
}
