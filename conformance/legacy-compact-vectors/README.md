# Legacy-compact cross-port vectors

Shared fixtures for the v0.9-legacy compact path — the shape 100% of
production emits. Consumed by BOTH publishable verifiers:

- TypeScript: `src/__tests__/legacy-compact-vectors.test.ts`
- Python: `packages/verifier-python/tests/test_legacy_compact_vectors.py`

Each file carries the signed JWS and the public JWKS, never a private key,
so both ports verify the SAME bytes instead of each signing their own.

Regenerate deliberately (a new key means new vectors):

```
pnpm --filter trust-receipt-verifier exec tsx scripts/generate-legacy-compact-vectors.ts
```

Generated 7 vectors.
