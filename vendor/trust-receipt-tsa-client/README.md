# @agenticmcpstores/trust-receipt-tsa-client

RFC 3161 + RFC 5816 Time-Stamp Protocol client for TrustReceipt v1.1 envelopes (spec-049).

## Responsibilities

- **Issuance side**: build `TimeStampReq` over SHA-256 of the JWS Compact bytes with a fresh 16-byte nonce, POST to a configured TSA endpoint, capture full `TimeStampResp` (Base64 `tsr`) plus extracted `TimeStampToken` (`tst`), persist cert chain + revocation evidence (OCSP or CRL) at `genTime`.
- **Verifier side**: parse `tsr`, assert `PKIStatusInfo.status == granted`, extract TST and confirm it equals `tst`, validate signature against pinned TSA root, check nonce match, policy OID allowlist, EKU `id-kp-timeStamping`, cert validity at `genTime`, revocation evidence, accuracy/tolerance window vs receipt `issued_at`, and imprint = SHA-256 of receipt JWS Compact bytes.

## Constraints (post-Codex round 2)

- Token bucket: 0.8 req/s sustained, 5 req/s burst, queue depth 50, queue timeout 250 ms (FR-024)
- Alternate provider: `ts.ssl.com/free` configured as automatic failover
- ENTERPRISE-tier paid TSA opt-in (DigiCert / Sectigo)
- Full TimeStampResp embedded — `status: granted` lives in TimeStampResp not TimeStampToken (post-Codex round 2 D25)

