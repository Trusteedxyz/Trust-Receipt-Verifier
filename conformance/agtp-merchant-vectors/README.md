# Vectores — `draft-hood-agtp-merchant-identity-02`

50 vectores del verificador `src/agtp-merchant/`. Runner:
`src/agtp-merchant/__tests__/conformance.test.ts` (los descubre del directorio;
no conoce ningún caso).

- `_keys.json` — clave pública Ed25519 de la plataforma de gobernanza ficticia
  con la que están firmadas las Intent Assertions. Las firmas son **reales**:
  las verifica la misma primitiva que usa el verificador.
- `A0xx-identity-*` — §3/§4, Agent Identity Document con rol de comerciante.
- `A0xx-intent-*` — §5, Intent Assertion reenviada.
- `A0xx-cart-*` — §6/§9.4, Cart-Digest.

Cada vector negativo declara **`reason` y `retryable`**: §8.2 hace de la
retriabilidad parte del contrato del 458, no una decisión del que verifica.

La suite se probó por mutación. Seis mutaciones deliberadas del verificador
(frontera de expiración `>=`→`>`, vida máxima `>`→`>=`, techo de gasto
`>`→`>=`, retriabilidad de `Suspended` extendida a `Revoked`, digest que
siempre casa, y desactivar el patrón de Agent-ID canónico): las cinco primeras
las cazó la suite; **la sexta sobrevivió**, y por eso existe
`A050-intent-agent-id-not-canonical`. Sin esa mutación el hueco no se veía.

Los vectores son artefactos congelados: si hay que regenerarlos, hacerlo con un
cambio explícito y revisando el diff caso a caso.
