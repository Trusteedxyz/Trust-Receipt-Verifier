/**
 * The staging-stub issuer root that shipped in earlier releases, kept as a
 * TEST FIXTURE.
 *
 * Tests that exercise "a stub root fail-closes" used to read the embedded
 * root, which only worked while the shipped root WAS the stub. They now pass
 * this fixture explicitly, so they keep testing the stub path whatever root
 * the package ships.
 *
 * Its body carries the `(STAGING)` marker and does NOT decode to a usable
 * Ed25519 key, and its SHA-256 is `_STAGING_STUB_ROOT_SHA256`
 * (`6c8e57a3…d722`) in `embedded-issuer-root.ts`.
 */
import type { IssuerRootEntry } from "../../embedded-issuer-root.js";

export const STAGING_STUB_ROOT_PEM = `-----BEGIN CERTIFICATE-----
MIIBKjCB3aADAgECAhRTcGVjMDQ5U3RhZ2luZ1N0dWJSdDAFBgMrZXAwLDEqMCgG
A1UEAwwhVHJ1c3RSZWNlaXB0IElzc3VlciBSb290IChTVEFHSU5HKTAeFw0yNjA1
MDQwMDAwMDBaFw00NjA1MDQwMDAwMDBaMCwxKjAoBgNVBAMMIVRydXN0UmVjZWlw
dCBJc3N1ZXIgUm9vdCAoU1RBR0lORykwKjAFBgMrZXADIQAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAADAFBgMrZXADQQDzZXJvLXNpZ25hdHVyZS1zdGFn
aW5nLXBsYWNlaG9sZGVyLXN3YXAtb24tcm90YXRpb24tdDQyMC1jZXJlbW9ueQAA
-----END CERTIFICATE-----
`;

export const STAGING_STUB_ROOT_SHA256 =
  "6c8e57a39f46de1fe7698365fbd0c0031dc180719c2c656a73207a890f80d722";

export const STAGING_STUB_ROOT_ENTRY: IssuerRootEntry = Object.freeze({
  pem: STAGING_STUB_ROOT_PEM,
  sha256: STAGING_STUB_ROOT_SHA256,
  // 2026-05-04T00:00:00Z — the stub's original staging cutover.
  validFrom: 1778198400,
  validTo: null,
  verifierMinVersion: "0.1.0",
});
