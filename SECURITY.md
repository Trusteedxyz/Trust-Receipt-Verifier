# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities **privately**, by email to **github@trusteed.xyz**. Do not open a public
issue, pull request or discussion for a vulnerability.

For a verifier, the failures that matter most are a wrong verdict: a forged, tampered, expired or revoked receipt
reported as valid, or a key or trust anchor taken from data the verifier should not trust. Reports about those, and
about parsing untrusted input (receipts, JWKS documents, ZIP export bundles, RFC 3161 timestamp tokens), are especially
welcome.

A useful report includes:

- the package version (or commit) and your Node.js version;
- the input that triggers the problem (a receipt, bundle or JWKS document, with any real keys removed);
- the verdict you expected and the one you got.

If you would like to be credited, tell us how you want your name to appear. Reporters who ask for it are
acknowledged in the README (see "Security Acknowledgements").

## Scope

This policy covers the code in this repository: the verification library, the `trust-receipt` and `verify-bundle`
command-line tools, the schemas, and the test vectors. The deliberately invalid receipts in `test-vectors/` and
`conformance/` are fixtures, not vulnerabilities. Reports about the hosted Trusteed service (`trusteed.xyz`) can be sent
to the same address.

## Supported versions

Fixes are made on `main` and shipped in the next release. We do not maintain older release lines, so please update to
the latest release before reporting.
