/**
 * Bind envelope sidecars to what the JWS signed.
 *
 * The envelope is NOT signed, so `protocol_artifact_sidecars` is attacker
 * controlled. A sidecar is only evidence if it is bound to a signed
 * `body.protocol_artifacts[]` entry on ALL of:
 *   - `type`      (a payload cannot be re-labelled),
 *   - `hash`      (algorithm tag AND digest, compared as one tagged string),
 *   - uniqueness  (one sidecar per signed artifact),
 * and its digest is recomputed with the algorithm the tag DECLARES.
 *
 * `hmac-sha256` needs a key the verifier does not hold, so a sidecar under it
 * can never be checked: it is rejected (`protocol_artifact_sidecar_unverifiable`)
 * rather than waved through. This holds in both strict and compat modes: a
 * warning in compat would let a forged payload through.
 */
import { createHash } from "node:crypto";

export type SidecarErrorCode =
  | "protocol_artifact_sidecar_hash_mismatch"
  | "protocol_artifact_sidecar_duplicate"
  | "protocol_artifact_sidecar_unverifiable";

export interface SidecarViolation {
  readonly code: SidecarErrorCode;
  readonly detail: string;
}

interface SignedArtifact {
  readonly type: string;
  readonly hash: string;
}
interface Sidecar {
  readonly type: string;
  readonly hash: string;
  readonly payload_b64: string;
}

const TAG = /^(sha256|sha512|hmac-sha256):([0-9a-f]+)$/;

export function verifyProtocolArtifactSidecars(
  signed: readonly SignedArtifact[],
  sidecars: readonly Sidecar[]
): SidecarViolation | null {
  const index = new Set(signed.map((a) => `${a.type}\u0000${a.hash}`));
  const seen = new Set<string>();

  for (const sc of sidecars) {
    const key = `${sc.type}\u0000${sc.hash}`;
    if (seen.has(key)) {
      return {
        code: "protocol_artifact_sidecar_duplicate",
        detail: `sidecar ${sc.type}: ${sc.hash} delivered more than once`,
      };
    }
    seen.add(key);

    if (!index.has(key)) {
      return {
        code: "protocol_artifact_sidecar_hash_mismatch",
        detail: `sidecar ${sc.type}: ${sc.hash} matches no signed body.protocol_artifacts[] entry of the same type`,
      };
    }

    const m = TAG.exec(sc.hash);
    if (!m) {
      return {
        code: "protocol_artifact_sidecar_hash_mismatch",
        detail: `sidecar ${sc.type}: unsupported hash tag`,
      };
    }
    const [, alg, digest] = m as unknown as [string, string, string];
    if (alg === "hmac-sha256") {
      return {
        code: "protocol_artifact_sidecar_unverifiable",
        detail: `sidecar ${sc.type}: hmac-sha256 needs a key the verifier does not hold; payload cannot be checked`,
      };
    }
    const payload = Buffer.from(sc.payload_b64, "base64");
    const computed = createHash(alg).update(payload).digest("hex");
    if (computed !== digest) {
      return {
        code: "protocol_artifact_sidecar_hash_mismatch",
        detail: `sidecar ${sc.type}: computed ${alg}:${computed} != declared ${sc.hash}`,
      };
    }
  }
  return null;
}
