<!-- generated-by: gsd-doc-writer -->

[English](README.md) | [Español](README.es.md) | [Français](README.fr.md) | **Deutsch**

# TrustReceipt

**Nachweisschicht auf Händlerseite für agentischen Handel: signiert, portabel, offline verifizierbar**

[![Version](https://img.shields.io/badge/spec-v1.1-blue)](SPEC.md)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![npm](https://img.shields.io/npm/v/trust-receipt-verifier)](https://www.npmjs.com/package/trust-receipt-verifier)
[![TrustReceipt Conformant](https://img.shields.io/badge/TrustReceipt-v1.0%20Conformant-blue)](https://github.com/trust-receipt/spec)

---

## Was es ist

TrustReceipt ist ein offenes Belegformat für Händler. Es hält Nachweise über Transaktionen im agentischen Handel in einer Form fest, die jeder offline verifizieren kann, und zwar über Protokolle wie ACP, AP2, x402, MCP, UCP und MCAP hinweg. Es steht neben diesen Protokollen und konkurriert nicht mit ihnen. AP2-Mandate, ACP-Checkout-Sitzungen, Visa-TAP-Signaturen und x402-Abwicklungen bleiben unverändert, und TrustReceipt ergänzt für jede davon einen portablen kryptografischen Nachweis der angewendeten Richtlinienentscheidung.

Ein TrustReceipt ist eine als JWS signierte JSON-Nutzlast, die Sie offline gegen einen öffentlichen JWKS-Endpunkt verifizieren können. Jeder Beleg hält fest, wer der Agent war, welches Protokoll lief, welche Vertrauensanbieter für die Transaktion gebürgt haben, welche Richtlinie galt und zu welcher Entscheidung sie kam. Das alles steckt in einem einzigen, in sich geschlossenen Token, das jede Partei prüfen kann, ohne den Aussteller anzufragen.

Dieses Paket ist die Referenzimplementierung von Verifizierer und Aussteller. Es gehört zum Merchant-Control-Stack von Trusteed (Richtlinien-Snapshots + Agenten-Kontrollpunkte + Belege), aber das Belegformat selbst ist offen und über Aussteller hinweg portabel.

---

## Fähigkeitsstatus

| Fähigkeit                                                 | Status                                | Anmerkungen                                                                              |
| ------------------------------------------------------------ | ---------------------------------------- | ---------------------------------------------------------------------------------------------- |
| JWS-Verifikation (Ed25519)                                | ✅ Implementiert                        | CLI + Bibliothek, keine eigene Kryptografie (verwendet `jose` v6)                               |
| JWKS-basierte Auflösung öffentlicher Schlüssel             | ✅ Implementiert                        | Zwischengespeicherter Abruf mit TTL; auch ein inline JWK-Set wird unterstützt                   |
| Schema v1.0                                                | ✅ Stabil                               | 10 Konformitätsvektoren bestehen                                                                |
| Schema v1.1 (eIDAS-ausgerichtete Felder)                  | 🟡 Codevollständig / experimentell       | 12 zusätzliche Vektoren bestehen; die Feldmenge kann sich vor v1.2 weiterentwickeln             |
| Kanonisches JSON gemäß RFC 8785                            | ✅ Implementiert                        | Verwendet zum Signieren + für Hashes der Audit-Kette                                            |
| Audit-Kette (`hash_chain_prev`)                            | ✅ Implementiert                        | Verkettung pro Händler, Manipulationen sind erkennbar                                           |
| eIDAS-Haltung als fortgeschrittenes elektronisches Siegel  | 🟡 Kandidat                              | Unterstützung auf Feldebene; **kein** qualifiziertes elektronisches Siegel (kein QTSP)          |
| ESIGN-/UETA-Nachweisform                                   | 🟡 Teilweise                             | `esign_disclosure_hash` + Einwilligungskontext; vollständiger Offenlegungs-Workflow in Arbeit   |
| RFC-3161-Vertrauenszeitstempel-Nachweis                    | 🟡 Optional / integrationsabhängig       | Hook vorhanden über `trust-receipt-tsa-client`; abhängig vom TSA-Anbieter                        |
| Ausstellerseitige Signierung mit AWS KMS                   | 🟡 Optional / ausstellerseitig           | Bereitgestellt vom Schwesterpaket `trust-receipt-kms-signer`; für die Verifikation nicht erforderlich |
| Referenz-Ports (TS) / Sprach-Ports (Python, Go, Java)      | 🟡 Bisher nur TS                         | Ports sind willkommen, siehe `CONTRIBUTING.md`                                                   |
| Export/Verifikation des AIVS-Proof-Bundles (`aivs-export.ts`) | 🟡 Codevollständig                  | Projiziert einen signierten v1.0-Beleg in ein AIVS-kompatibles Bundle `{ manifest_hash, session_sig, audit_log }`. Offline verifizierbar, ganz ohne Trusteed-Code (spec-062 US1: Angleichung, kein Treuhandverfahren) |
| Verifikation von Erweiterungsartefakten (`verify-extension-artifact.ts`) | 🟡 Codevollständig        | Verifiziert vom Entwickler signierte Löschbelege und Erweiterungsmanifeste aus dem Trusteed Extension Marketplace |
| Kompakte v1.0-Legacy-Belegform (`verifier.ts`)             | ✅ Implementiert                        | `verifyTrustReceipt` akzeptiert auch die kompakte Nutzlast im JWT-Stil, die der Plattform-Aussteller seit spec-040 ausgibt. Zu finden als `result.variant` / `result.legacyReceipt` |

> ✅ = produktionsreife Implementierung. 🟡 = vorhanden und getestet, aber vor der GA von v1.2 änderbar, oder von betreiberseitiger Integration abhängig.

---

## Funktionsweise

Ein TrustReceipt wird in zwei voneinander unabhängigen Vorgängen bearbeitet: Ausstellung und Verifikation. Sie können auf verschiedenen Systemen zu verschiedenen Zeiten laufen, und keiner von beiden braucht ein gemeinsames Geheimnis.

### Ausstellung eines Belegs

```mermaid
sequenceDiagram
    autonumber
    participant Agent as 🤖 Agent / Plattform
    participant Issuer as 🏭 Aussteller (trusteed.xyz)
    participant KMS as 🔑 KMS / Ed25519-Schlüssel

    Agent->>Issuer: Transaktionsereignis<br/>(protocol, merchant_id, agent_id,<br/>cart_hash, user_intent_hash, …)
    Issuer->>Issuer: Baut Nutzlast mit 24 Feldern auf<br/>(5 Gruppen: Kern, Teilnehmer,<br/>Nachweis, Vertrauensaussagen, Compliance)
    Issuer->>Issuer: Kanonische Serialisierung gemäß RFC 8785<br/>(sortierte Schlüssel, keine Leerzeichen)
    Issuer->>KMS: Signiert die kanonischen Bytes
    KMS-->>Issuer: Ed25519-Signatur
    Issuer->>Issuer: Kodiert als kompaktes JWS<br/>header.payload.signature (base64url)
    Issuer-->>Agent: 📄 Kompaktes JWS-Token
```

### Verifikation eines Belegs

```mermaid
sequenceDiagram
    autonumber
    participant Verifier as 🔍 Verifizierer (beliebige Partei)
    participant JWKS as 🌐 JWKS-Endpunkt<br/>/.well-known/jwks.json
    participant Schema as 📐 Zod-Schema

    Verifier->>Verifier: Parst den JWS-Header<br/>extrahiert kid + alg
    Verifier->>JWKS: GET öffentliche Schlüssel<br/>(zwischengespeichert, TTL 1h)
    JWKS-->>Verifier: Öffentliches JWK-Set
    Verifier->>Verifier: Ordnet kid → öffentlichem Schlüssel zu
    Verifier->>Verifier: Verifiziert Ed25519-Signatur<br/>(jose — keine eigene Kryptografie)
    Verifier->>Schema: Validiert die dekodierte Nutzlast
    Schema-->>Verifier: Ergebnis des Zod-Parsens
    Verifier->>Verifier: Prüft issued_at / expires_at<br/>(± Uhrentoleranz)
    Verifier-->>Verifier: ✅ VerifyResult { valid, receipt }<br/>oder ❌ { valid: false, reason, errors }
```

### Gesamtbild

```mermaid
flowchart LR
    subgraph Protocols
        P1[x402]
        P2[AP2]
        P3[ACP]
        P4[MCP]
        P5[UCP]
        P6[MCAP]
    end

    subgraph Issuer ["Aussteller (trusteed.xyz)"]
        direction TB
        B1["Baut Nutzlast auf\n24 Felder · 5 Gruppen"]
        B2["Kanonisiert gemäß RFC 8785"]
        B3["Signiert Ed25519\n(kid festgelegt)"]
        B4["Kompaktes JWS"]
        B1 --> B2 --> B3 --> B4
    end

    subgraph Verifier ["Verifizierer (beliebige Partei, offlinefähig)"]
        direction TB
        V1["Parst Header\nextrahiert kid"]
        V2["Ruft JWKS ab\n(oder inline JWK-Set)"]
        V3["Ordnet kid → Schlüssel zu\nverifiziert Signatur"]
        V4["Prüft Zod-Schema\nprüft Ablauf"]
        V5{Ergebnis}
        V1 --> V2 --> V3 --> V4 --> V5
    end

    Protocols --> Issuer
    Issuer -->|"📄 JWS-Token"| Verifier
    V5 -->|gültig| R1["✅ receipt-Objekt\n(policy_decision, agent_id, …)"]
    V5 -->|ungültig| R2["❌ Grund + Fehler\n(manipuliert / abgelaufen / schema_invalid / …)"]
```

**Wesentliche Eigenschaften:**

- Die Verifikation funktioniert offline. Sie braucht nur die JWKS-URL (öffentlich zwischengespeichert) und fragt nie beim Aussteller nach
- Ein einziges Belegformat deckt x402, AP2, ACP, MCP, UCP und MCAP über `protocol_artifacts` ab
- `hash_chain_prev` verknüpft Belege zu einer Kette pro Händler, in der sich Manipulationen erkennen lassen (RFC 8785)
- `legal_posture` hält die Compliance-Haltung jedes Belegs zu eIDAS, ESIGN und UK-DIATF fest

---

## Rechtlicher Hinweis

> Verifizierbares Siegel für agentischen Handel. Jedes TrustReceipt erzeugt einen portablen kryptografischen Nachweis von Herkunft, Integrität, Einwilligung, Agentenautorisierung und auditierbarer Aufbewahrung.
> Konzipiert so, dass er an ESIGN/UETA in den USA und an eIDAS in der EU ausgerichtet ist (als Kandidatennachweis für ein fortgeschrittenes elektronisches Siegel) und mit dem britischen Rahmenwerk für elektronische Signaturen und Vertrauensdienste (UK Electronic Signatures and Trust Services) kompatibel ist.
> Qualifizierte Siegel/Signaturen erfordern Ausstellung oder Validierung durch einen zutreffenden QTSP.

> **Haftungsausschluss**: TrustReceipt ist kryptografisch verifizierbarer technischer Nachweis. Er bestimmt für sich genommen keine rechtliche Haftung. Ob ein bestimmter Beleg in einer konkreten Jurisdiktion oder einem Verfahren zulässig oder überzeugend ist, hängt vom anwendbaren lokalen Recht, den Vereinbarungen der einwilligenden Parteien und weiteren Tatsachen ab, die über den Umfang dieses Belegformats hinausgehen.

_Die vollständige Claims Policy ist die TrustReceipt Claims Policy (`docs/legal/trust-receipt-claims-policy.md` im Trusteed-Monorepo). Sie ist nicht Teil dieses Repositorys._

### Status der regulatorischen Kompatibilität

| Rahmenwerk                                     | Jurisdiktion | Status                                                                                                                                                                                                                        | v1.1-Felder                                                                                                  |
| ------------------------------------------------ | ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| **eIDAS** (Verordnung 910/2014)                 | EU           | 🟡 Kandidat. `legal_posture` schreitet fort `ades_candidate_no_tsa` → `ades_candidate_timestamped` → `ades_candidate_kms`. Das qualifizierte Siegel (QeSeal) erfordert einen QTSP.                                          | `legal_posture`, `legal_posture_warnings`, `timestamp_evidence`, `esign_disclosure_hash`                     |
| **ESIGN / UETA**                                | USA          | 🟡 Teilweise. Verifizierbares Siegel mit Einwilligungsnachweis, Agentenzurechnung, versionierter Offenlegung und auditierbarer Aufbewahrung, konzipiert zur Unterstützung von ESIGN/UETA. Vollständiger Offenlegungs-Workflow (Widerrufs-URI, Versionsfestlegung) in Arbeit. | `esign_disclosure_hash`, `consent_context.consent_disclosure_version`, `consent_context.withdrawal_uri_hash` |
| **Electronic Communications Act 2000 / DIATF**  | UK           | 🟡 Schemakompatibel. Jurisdiktionsbewusste Aufbewahrung (UK: standardmäßig 7 Jahre) und das Feld `legal_posture` transportieren Nachweise britischer Vertrauensdienste. Die DIATF-Ausrichtung ist auf Schemaebene verifiziert. Die operative Zertifizierung steht noch aus. | `legal_posture`, `privacy_classification.jurisdiction`, `export_bundle.retention_policy`                     |

> ⚠️ Nichts vom Vorstehenden stellt eine Rechtsberatung dar. Der regulatorische Qualifikationsstatus kann sich mit der Weiterentwicklung der Implementierung ändern. Konsultieren Sie qualifizierten Rechtsbeistand für jurisdiktionsspezifische Anforderungen.

---

## Schnelle Verifikation

```bash
npm install trust-receipt-verifier
```

**v1.0-Beleg (kompaktes JWS):**

```typescript
import { verifyTrustReceipt } from "trust-receipt-verifier";

const result = await verifyTrustReceipt(jwsToken, {
  jwksUrl: "https://trusteed.xyz/.well-known/jwks.json",
});

if (result.valid) {
  console.log(result.receipt.policy_decision); // "allow"
} else {
  console.error(result.reason, result.errors);
}
```

**v1.1-Umschlag (`receipt` + `envelope_metadata` + optionale Sidecars):**

```typescript
import { verifyReceiptEnvelope } from "trust-receipt-verifier";
import type { VerifyOptions } from "trust-receipt-verifier";

const opts: VerifyOptions = {
  jwksHistory: {
    jws_compact: "<SignedJwksHistory JWS>",
    signed_by_root_sha256: "<issuer-root-sha256>",
  },
  trustAnchorPemSha256: "dd43bf2cd65023d79e41358226ed1197fcea36bc693f1c0fadde0e318bfd76a1",
  policyOidAllowlist: ["1.2.3.4.5.6.7.8.9"],
  // toleranceSeconds: 30,  // Standard-Uhrentoleranz (Sekunden)
  // mode: "strict",        // Standard "compat" — siehe „Strict vs. Compat" unten
  // allowStagingRoots: true, // nur Staging/CI — niemals in Produktion setzen
};

const result = await verifyReceiptEnvelope(envelope, opts);

if (result.outcome === "accepted") {
  console.log(result.recomputedLegalPosture); // "ades_candidate_timestamped"
  if (result.warnings.includes("unknown_trust_provider_present")) {
    // der Umschlag referenziert einen Vertrauensanbieter, der von dieser Verifizierer-Version noch nicht erkannt wird
  }
} else {
  console.error(result.errorCode, result.detail);
  // errorCode kann sein: "receipt_expired" | "receipt_not_yet_valid" |
  // "jwks_history_signature_invalid" | "unknown_kid" | "schema_invalid" | …
}
```

> **`allowStagingRoots`**: Standardmäßig `false`. Wenn `false` (Produktionsstandard), führt jedes `jwksHistory.signed_by_root_sha256`, das nicht in der eingebetteten Vertrauensanker-Liste vorhanden ist, zur sofortigen Ablehnung (`jwks_history_signature_invalid`). Nur in Staging- oder CI-Umgebungen auf `true` setzen, die unsignierte/Stub-JWKS-Historien-Bundles verwenden.

---

## Anatomie des Belegs

Eine TrustReceipt-Nutzlast enthält 24 Felder in fünf Gruppen:

**Kern**

| Feld              | Typ           | Beschreibung                    |
| ----------------- | ------------- | -------------------------------- |
| `receipt_id`     | UUID v4        | Eindeutiger Belegbezeichner       |
| `schema_version` | `"1.0"`        | Schema-Versionsliteral            |
| `issued_at`      | Unix-Sekunden  | Wann der Beleg erstellt wurde     |
| `expires_at`     | Unix-Sekunden  | Wann der Beleg abläuft            |
| `issuer`         | string         | Domäne der ausstellenden Plattform |

**Teilnehmer**

| Feld              | Typ    | Beschreibung                                          |
| ----------------- | ------ | -------------------------------------------------------- |
| `merchant_id`    | string | Händlerbezeichner                                          |
| `agent_id`       | string | Sitzungs- oder Instanzbezeichner des Agenten                |
| `agent_provider` | string | KI-Anbieter (`anthropic`, `openai`, `google`, …)          |

**Transaktionsnachweis**

| Feld                  | Typ                | Beschreibung                                                                                    |
| --------------------- | ------------------ | ---------------------------------------------------------------------------------------------------- |
| `user_intent_hash`   | string (nicht leer)| Hash der ursprünglichen Nutzerabsicht. Darf nicht leer sein (SHA-256-Hex empfohlen)                    |
| `cart_hash`          | SHA-256-Hex        | Hash des Warenkorbinhalts zum Entscheidungszeitpunkt (optional)                                        |
| `order_hash`         | SHA-256-Hex        | Hash des abgewickelten Bestellobjekts (optional)                                                       |
| `transaction_id`     | string             | Transaktionsreferenz der Plattform (optional)                                                          |
| `protocol`           | enum               | `x402 \| AP2 \| ACP \| MCP \| UCP \| MCAP`                                                              |
| `protocol_artifacts` | array              | Hashes protokollspezifischer Nachweisobjekte                                                           |
| `payment_reference`  | object             | PSP-Name + Referenz, keine Rohzahlungsdaten (optional)                                                 |

**Vertrauensaussagen**

| Feld                         | Typ   | Beschreibung                                                       |
| ------------------------------ | ----- | ------------------------------------------------------------------------ |
| `risk_signals`              | array | Normalisierte Signale vom Aussteller oder von Anbietern                    |
| `trust_provider_assertions` | array | Bewertete Aussagen von ClearSale, Trulioo, Mastercard usw.                |
| `policy_decision`           | enum  | `allow \| deny \| review \| challenge`                                     |

**Compliance**

| Feld                       | Typ         | Beschreibung                                                            |
| ---------------------------- | ----------- | ------------------------------------------------------------------------- |
| `liability_context`      | object      | Urheber der Aussage und Umfang (optional)                                    |
| `consent_context`        | object      | Einwilligungs-Hash, Umfang, Zeitstempel (optional)                            |
| `privacy_classification` | object      | PII-Kennzeichen, Aufbewahrungstage, Jurisdiktion (optional)                    |
| `verification_methods`   | array       | JWKS-URL oder DID zur Schlüsselauflösung. Mindestens ein Eintrag erforderlich   |
| `kid`                    | string      | Schlüssel-ID, mit der dieser Beleg signiert wurde                             |
| `hash_chain_prev`        | SHA-256-Hex | Vorheriger Beleg in der Audit-Kette (optional)                                 |
| `attachments`            | array       | Benannte, gehashte Dateireferenzen (optional)                                  |

---

## Protokollunterstützung

| Protokoll                                                                                                  | Artefakt-Mapping | Primäre Artefakttypen                                       |
| ----------------------------------------------------------------------------------------------------------- | ------------------- | ---------------------------------------------------------------- |
| [MCAP](https://developer.mastercard.com/mastercard-checkout-solutions/documentation/use-cases/agent-pay/) | Definiert           | `mcap_consent_hash`, `mcap_nonce`                                 |
| [x402](https://github.com/x402-foundation/x402)                                                           | Definiert           | `permit2_hash`, `settlement_hash`, `upto_envelope_hash`           |
| [AP2](https://github.com/google-agentic-commerce/AP2)                                                     | Definiert           | `mandate_hash`, `ap2_consent_hash`                                |
| [MCP](https://modelcontextprotocol.io)                                                                    | Definiert           | `mcp_call_hash`, `tool_call_hash`                                 |
| [ACP](https://github.com/agentic-commerce-protocol/agentic-commerce-protocol)                             | Definiert           | `acp_session_hash`, `acp_policy_hash`                             |
| [UCP](https://github.com/Universal-Commerce-Protocol/ucp)                                                 | Definiert           | `ucp_token_hash`                                                  |

---

## Konformität

Eine Verifizierer-Implementierung muss alle 10 Testvektoren (v1.0) bestehen, um TrustReceipt-Konformität zu beanspruchen. Es sind drei Stufen definiert:

> **v1.1-Status (2026-05-06).** Die eIDAS-Härtung fügt 12 v1.1-Vektoren unter `test-vectors/v11/` hinzu. Das v1.1-Schema entfernt die Legacy-Felder `mandate_hash` / `permit2` / `mcp` (Rail) und führt `payment_authorization_hash`, `authorization_scheme`, `legal_posture_warnings` und `esign_disclosure_hash` ein. Kombinierte Suite 58/58 bestanden.

| Stufe | Name      | Anforderung                                                                     |
| ------- | --------- | -------------------------------------------------------------------------------------- |
| 1       | Verifier  | Besteht alle 10 Testvektoren                                                            |
| 2       | Issuer    | Stufe 1 + stellt korrekt gültige Belege aus                                              |
| 3       | Provider  | Stufe 2 + Ko-Autorenschaft von ≥1 `trust_provider_assertions`-Typ mit echten Daten       |

Diese Referenzimplementierung ist konform zu Stufe 2. Es gibt zwei Möglichkeiten, die Konformitätssuite auszuführen:

**(a) Unit-Tests.** Verifiziert alle 10 Vektoren mit vorgefertigter Testinfrastruktur (10 Tests):

```bash
pnpm test
```

**(b) End-to-End-JWS-Konformität.** Erzeugt ein neues Schlüsselpaar, signiert alle 10 Vektoren, ruft `verifyTrustReceipt` auf und meldet pro Vektor bestanden oder nicht bestanden:

```bash
# Über die CLI (das Paket muss zuvor gebaut werden)
trust-receipt conformance

# Oder direkt mit tsx (kein Build erforderlich)
npx tsx scripts/validate-vectors.ts
```

Fügen Sie Ihrem Projekt das Badge hinzu, sobald alle 10 bestanden sind:

```markdown
[![TrustReceipt Conformant](https://img.shields.io/badge/TrustReceipt-v1.0%20Conformant-blue)](https://github.com/trust-receipt/spec)
```

---

## Repo-Struktur

```
trust-receipt-verifier/
├── SPEC.md                            — formale Spezifikation (maßgeblich)
├── CONTRIBUTING.md                    — wie man Vektoren, Ports und Anbieterschemata beiträgt
├── LICENSE                            — MIT
├── src/
│   ├── index.ts                       — Paket-Exports
│   ├── verifier.ts                    — verifyTrustReceipt() + parseTrustReceiptUnsafe() (v1.0, inkl. legacy-compact-Form)
│   ├── verify-1.0.ts                  — v1.0-Verifizierer-Interna
│   ├── verify-1.1.ts                  — verifyReceiptEnvelope() (v1.1-eIDAS-Umschlag) + typisierte Vertrauensanbieter-Prädikate
│   ├── zod-1.1.ts                     — v1.1-Zod-Schema (strikte Wurzel — lehnt unbekannte Top-Level-Schlüssel ab)
│   ├── types-1.1.ts                   — typisierte Formen der Vertrauensanbieter-Aussagen
│   ├── issuer.ts                       — issueTrustReceipt()
│   ├── embedded-issuer-root.ts        — kompilierzeitlicher Vertrauensanker + validateChain()
│   ├── verify-jwks-history.ts         — Verifikation der JWKS-Historienkette
│   ├── verify-timestamp-evidence.ts   — Verifikation des RFC-3161-Zeitstempels
│   ├── verify-export-bundle.ts        — Offline-Verifikation von Export-Bundles
│   ├── verify-extension-artifact.ts   — Verifikation von Löschbelegen / Erweiterungsmanifesten (Extension Marketplace)
│   ├── aivs-export.ts                 — Export/Verifikation des AIVS-Proof-Bundles (spec-062 US1)
│   ├── __tests__/                     — Unit- + Konformitätstests
│   └── schema/
│       ├── trust-receipt.schema.ts        — Zod-Schema (Quelle der Wahrheit für die v1.0-TypeScript-Typen)
│       └── trust-receipt-legacy.schema.ts — kompakte v1.0-Legacy-Form (seit spec-040 von der Plattform ausgestellt)
├── test-vectors/
│   ├── README.md                    — wie man die Vektoren verwendet
│   ├── vectors.json                 — Vektormanifest mit erwarteten Ergebnissen
│   ├── valid/                       — TC-001 bis TC-005
│   ├── invalid/                     — TC-006 bis TC-010
│   └── v11/, v11-strict/            — v1.1- + Strict-Mode-Konformitätsvektoren
├── bin/
│   └── trust-receipt.ts (Quelle) → dist/bin/trust-receipt.js (kompiliert) — CLI: verify, inspect, generate-key, conformance
└── demo/                            — ausführbare Demo-Skripte
```

---

## Einen Beleg ausstellen

```typescript
import { issueTrustReceipt } from "trust-receipt-verifier";

const jws = await issueTrustReceipt({
  payload: {
    issuer: "trusteed.xyz",
    merchant_id: "merchant-001",
    agent_id: "agent-session-xyz",
    agent_provider: "anthropic",
    user_intent_hash: "<sha256-hex-of-user-intent>",
    protocol: "MCP",
    protocol_artifacts: [{ type: "mcp_call_hash", hash: "<sha256-hex>" }],
    policy_decision: "allow",
    verification_methods: [
      { type: "jwks", value: "https://trusteed.xyz/.well-known/jwks.json" },
    ],
    kid: "tr-ed25519-2026-04-29",
  },
  privateKeyJwk: myEd25519PrivateKey,
  kid: "tr-ed25519-2026-04-29",
});
```

> **Kanonisierung**: Die Nutzlast wird vor der Signierung mit RFC 8785 serialisiert (sortierte Schlüssel, keine Leerzeichen), sodass `SHA-256(payload)` in jeder konformen Implementierung identisch ist.

## Zugehörige Artefakt-Verifizierer

**AIVS-Proof-Bundle-Export.** Projiziert einen signierten v1.0-Beleg in ein AIVS-kompatibles Bundle (`draft-stone-aivs-00`). Sie können es offline verifizieren, allein mit dem JWS und dem JWKS des Ausstellers:

```typescript
import { exportAivsProofBundle, verifyAivsProofBundle } from "trust-receipt-verifier";

const bundle = exportAivsProofBundle(receiptJws); // { manifest_hash, session_sig, kid, alg, audit_log }
const result = await verifyAivsProofBundle(bundle, { jwks: issuerJwks });
```

**Extension-Marketplace-Artefakte.** Verifizieren Sie vom Entwickler signierte Löschbelege (Nachweis der Datenvernichtung nach der Deinstallation) oder Erweiterungsmanifeste:

```typescript
import { verifyExtensionArtifact } from "trust-receipt-verifier";

const result = await verifyExtensionArtifact(jws, {
  kind: "erasure", // oder "manifest" — der Aufrufer gibt an, um welches Artefakt es sich handelt
  jwksUrl: "https://trusteed.xyz/.well-known/jwks.json",
});
// result.valid: boolean; result.reason bei Fehlschlag ("malformed_jws" | "unsupported_alg" | "missing_kid" | "jwks_unreachable" | "kid_not_found" | "signature_invalid" | "payload_not_json" | "shape_invalid")
```

## CLI

```bash
# Erzeugt ein Ed25519-Schlüsselpaar
trust-receipt generate-key

# Verifiziert einen v1.0-Beleg (kompaktes JWS)
trust-receipt verify receipt.jws --jwks-url https://trusteed.xyz/.well-known/jwks.json

# Verifiziert einen v1.1-Umschlag (JSON-Objekt mit `receipt` + `envelope_metadata`)
trust-receipt verify envelope.json \
  --type receipt-v11 \
  --jwks-history-file issuer-jwks-history.json \
  --trust-anchor-sha256 dd43bf2cd65023d79e41358226ed1197fcea36bc693f1c0fadde0e318bfd76a1 \
  --policy-oid 1.2.3.4.5.6.7.8.9

# Verifiziert einen v1.1-Umschlag im STRICT-Modus (semantische Durchsetzung des Vertrauensankers)
trust-receipt verify envelope.json \
  --type receipt-v11 \
  --jwks-history-file issuer-jwks-history.json \
  --trust-anchor-sha256 dd43bf2cd65023d79e41358226ed1197fcea36bc693f1c0fadde0e318bfd76a1 \
  --strict

# Nur Staging / CI — überspringt die Prüfung des Wurzelankers (niemals in Produktion verwenden)
trust-receipt verify envelope.json --type receipt-v11 \
  --jwks-history-file issuer-jwks-history.json \
  --trust-anchor-sha256 <sha256> \
  --allow-staging-roots

# Inspiziert einen Beleg, ohne die Signatur zu verifizieren
trust-receipt inspect receipt.jws

# Führt die vollständige End-to-End-Konformitätssuite aus (signiert + verifiziert alle 10 Vektoren)
trust-receipt conformance
```

> **`--type`-Autoerkennung**: Wenn `--type` weggelassen wird, untersucht die CLI die Form der Eingabe. Ein JSON-Objekt mit sowohl `receipt`- als auch `envelope_metadata`-Schlüsseln wird automatisch als `receipt-v11` behandelt. Eine kompakte `header.payload.sig`-Zeichenkette wird als `receipt` (v1.0) behandelt. `--type` akzeptiert außerdem `erasure`, `manifest` und `jwks-history` für die oben beschriebenen Artefakt-Verifizierer. Geben Sie es explizit an, wenn die Autoerkennung mehrdeutig ist (sowohl erasure- als auch manifest-Nutzlasten sind kompakte JWS ohne `receipt`-/`envelope_metadata`-Schlüssel).

---

## Strict- vs. Compat-Verifikationsmodus (v1.1)

Auf der Schemaebene prüft der v1.1-Verifizierer `verification_methods.trust_anchor_sha256`
und `verification_methods.jwks_sha256` nur nach dem Regex-Format (64 Hex-Zeichen). Diese
Prüfung lässt einen opaken Stub-Anker durch, also einen Wert aus lauter Nullen oder aus
einem einzelnen Nibble. Der Stub ist wohlgeformt, hat aber keine echte Bindung an die
Vertrauenskette, und Aussteller geben solche Stubs vor einer Produktions-Ankerzeremonie
aus. Die Option `mode` (Bibliothek) und das Flag `--strict` (CLI) fügen eine semantische
Ebene hinzu:

| Bedingung                                                              | `compat` (Standard, Canary)              | `strict`                                       |
| -------------------------------------------------------------------------- | -------------------------------------------- | ---------------------------------------------------- |
| `trust_anchor_sha256` ist ein opaker Stub (nur Nullen / einzelnes Nibble)  | warnt `trust_anchor_sha256_stub`             | lehnt ab `trust_anchor_stub_rejected`                |
| `jwks_sha256` ist ein opaker Stub                                          | warnt `jwks_sha256_stub`                     | lehnt ab `jwks_sha256_stub_rejected`                 |
| `trust_anchor_sha256` ≠ vom Betreiber festgelegter `trustAnchorPemSha256` | warnt `trust_anchor_sha256_mismatch`         | lehnt ab `trust_anchor_mismatch`                     |
| buyer_agent-Beleg ohne Agentenidentitätsbindung                            | warnt `agent_identity_absent`                | lehnt ab `agent_identity_required_strict`            |
| RFC-3161-/LOTL-Zeitstempel beeinträchtigt (z. B. TSA nicht verfügbar)      | warnt (`tsa_unavailable`)                    | warnt (`tsa_unavailable`), in beiden Modi akzeptiert |

`compat` ist der Standard, damit der Rollout niemanden stört, solange sich
Beobachtungsdaten ansammeln. Wechseln Sie zu `strict`, sobald die Aussteller die
Produktions-Ankerzeremonie abgeschlossen haben. Die vier benannten negativen
Konformitätsvektoren liegen in `test-vectors/v11-strict/` und werden von
`scripts/generate-strict-mode-vectors.ts` neu erzeugt.

```ts
// Verwendung als Bibliothek
import { verifyReceiptEnvelope } from "trust-receipt-verifier";

const result = await verifyReceiptEnvelope(envelope, {
  jwksHistory,
  trustAnchorPemSha256: "<64-hex-pinned-anchor>",
  policyOidAllowlist: ["1.2.3.4.5.6.7.8.9"],
  mode: "strict", // Standard ist "compat"
});
```

---

## Dokumentation

| Dokument                                      | Beschreibung                                                                                                |
| ------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------ |
| [SPEC.md](SPEC.md)                             | Formale Spezifikation: Wire-Format, Feldreferenz, Konformitätsregeln                                               |
| [docs/architecture.md](docs/architecture.md)  | Interne Architektur: Signierumschlag, Schlüsselauflösung, Verifikationspipeline, Sicherheitseigenschaften            |
| [CONTRIBUTING.md](CONTRIBUTING.md)            | Wie man Konformitätsvektoren, Sprach-Ports oder Vertrauensanbieterschemata hinzufügt                                |
| [CHANGELOG.md](CHANGELOG.md)                  | Versionshistorie und Breaking Changes                                                                              |

---

## Mitwirken

Siehe [CONTRIBUTING.md](CONTRIBUTING.md), wie man Konformitätsvektoren hinzufügt, den Verifizierer in eine andere Sprache portiert oder als Vertrauensanbieter-Partner ein `trust_provider_assertions`-Schema mitverfasst.

---

## Was ein TrustReceipt NICHT belegt

Ein Beleg ist technischer Nachweis, keine rechtliche Beweisführung und keine operative Garantie. Er behauptet bewusst **nicht**:

- **Dass die Zahlung erfasst oder abgewickelt wurde.** Ein Beleg mit `policy_decision: "allow"` protokolliert die Entscheidung und Absicht. Die Abwicklung wird vom zugrunde liegenden PSP/Rail erfasst (Stripe-Belastung, x402-On-Chain-Transaktion, ACP-Abschluss usw.) und über `payment_reference` oder `protocol_artifacts` referenziert, nicht durch den Beleg selbst.
- **Dass Waren oder Dienstleistungen geliefert wurden.** Der Erfüllungsnachweis liegt im Bestellsystem des Händlers.
- **KYC-/KYA-Compliance.** Ein Beleg protokolliert, dass ein Vertrauensanbieter zum Ausstellungszeitpunkt ein Niveau bestätigt hat (z. B. `kya_status`). Er ist kein Ersatz für eine unabhängige KYC-/KYA-Verifikation.
- **Den Status eines qualifizierten elektronischen Siegels gemäß eIDAS.** Selbst mit befülltem `legal_posture` ist ein TrustReceipt bestenfalls ein Kandidat für ein **fortgeschrittenes** elektronisches Siegel. Qualifizierte Siegel erfordern die Ausstellung durch einen in der EU gelisteten QTSP, was außerhalb des Umfangs dieses Pakets liegt.
- **Rechtliche Haftung oder Zulässigkeit.** Ein Beleg ist kryptografischer Nachweis. Ob er in einer bestimmten Jurisdiktion zulässig oder überzeugend ist, hängt vom lokalen Recht, den Vereinbarungen der Parteien und Tatsachen ab, die über das Belegformat hinausgehen.
- **Dass der Nutzer tatsächlich das beabsichtigte, was der Agent getan hat.** Der Beleg protokolliert `user_intent_hash`, was zeigt, dass ein Absichtstext existierte und gehasht wurde. Er zeigt nicht, dass der Hash mit einer verifizierten menschlichen Äußerung übereinstimmt.

Wenn Ihr Anwendungsfall eine der genannten Garantien braucht, setzen Sie den Beleg als Audit-Primitiv neben diesen Mechanismen ein. Er ersetzt sie nicht.

---

## Bedrohungsmodell

Der Verifizierer ist darauf ausgelegt, die folgenden Klassen von Manipulation zu erkennen. Für jede gibt der Verifizierer ein strukturiertes `{ valid: false, reason }` zurück, statt eine Exception zu werfen.

| Bedrohung                                | Abwehr                                                                                                                        | Verifizierer-Verhalten (v1.0 / v1.1)                                                        |
| -------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------- |
| Signaturfälschung / Nutzlast-Manipulation    | Ed25519 über kanonische RFC-8785-Bytes; `kid` im Header und in der Nutzlast festgelegt                                                | `"signature_invalid"` / `"signature_invalid"`                                                        |
| Falscher Schlüssel zum Signieren verwendet   | `kid`-Abweichung zwischen JWS-Header und JWKS-Eintrag                                                                                 | `"kid_not_found"` / `"unknown_kid"`                                                                  |
| Abgelaufener Beleg                           | `expires_at` wird gegen die Uhr des Verifizierers mit konfigurierbarer Toleranz geprüft (Standard ±30 s)                             | `"expired"` / `"receipt_expired"`                                                                     |
| Beleg in der Zukunft ausgestellt             | `issued_at` wird gegen die Uhr des Verifizierers mit derselben Toleranz geprüft                                                       | `"not_yet_valid"` / `"receipt_not_yet_valid"`                                                        |
| Schema-Downgrade / unbekannte Felder         | Zod-Schema-Validierung strikt auf bekannte Felder; unbekannte Top-Level-Schlüssel abgelehnt                                          | `"schema_invalid"` / `"schema_invalid"`                                                              |
| Gefälschte / unsignierte JWKS-Historie       | `jwksHistory.signed_by_root_sha256` muss mit einem eingebetteten Vertrauensanker übereinstimmen; harter Fehlschlag bei Unbekanntheit, sofern nicht `allowStagingRoots` | n. z. (v1.0) / `"jwks_history_signature_invalid"`                                                     |
| Unbekannte Vertrauensanbieter-Aussage        | Der Verifizierer warnt, lehnt aber nicht ab, um Abwärtskompatibilität zu wahren                                                       | n. z. (v1.0) / Warnung `"unknown_trust_provider_present"`                                             |
| Wiederholung (Replay) eines alten Belegs     | **Außerhalb des Umfangs des Verifizierers allein.** Konsumenten müssen Eindeutigkeit über `receipt_id` + `issued_at` + Geschäftsregeln erzwingen | n. z. Der Verifizierer gibt `valid: true` / `outcome: "accepted"` für noch nicht abgelaufene Wiederholungen zurück |
| JWKS-Rotation, während ein Beleg aktiv ist   | Der JWKS-Abruf wird bei einem `kid`-Fehltreffer aktualisiert; alte Schlüssel können während des Rotations-Gnadenfensters im JWKS-Set verbleiben | Verifiziert, solange der `kid` noch veröffentlicht ist                                                |
| Kompromittierter Aussteller-Schlüssel        | Der Widerruf von Schlüsseln liegt beim Betreiber: den `kid` aus dem JWKS-Set entfernen; Verifizierer lehnen dann ab (fail closed)  | `"kid_not_found"` / `"unknown_kid"` nach Entfernung                                                    |
| Uhrendrift zwischen Aussteller/Verifizierer  | Option `toleranceSeconds` (Standard 30 s)                                                                                             | Innerhalb der Toleranz: besteht. Außerhalb: `"expired"` / `"receipt_expired"` oder `"receipt_not_yet_valid"` |
| MITM am JWKS-Endpunkt                        | TLS zum JWKS-Host liegt in der Verantwortung des Betreibers; das Festlegen der JWKS-URL außerhalb des Kanals schützt vor betrügerischer Substitution | n. z. Der Verifizierer vertraut der konfigurierten URL                                                |

**Nicht-Ziele.** Der Verifizierer validiert **nicht**: (a) ob die zugrunde liegende Zahlung abgewickelt wurde, (b) ob die Händlerrichtlinie korrekt konfiguriert war, (c) die jurisdiktionelle Zulässigkeit, (d) Widerrufslisten außerhalb des JWKS-Endpunkts, oder (e) protokollspezifischen Nachweis innerhalb von `protocol_artifacts` (diese werden vom Aufrufer gegen die Spezifikation des jeweiligen Protokolls validiert).

---

## Versionierungsrichtlinie

Dieses Paket folgt der **semantischen Versionierung** in Bezug auf die öffentliche API _und_ das Wire-Format des Belegs.

| Änderungstyp                                          | Bump   | Kompatibilität                                                                                              |
| ---------------------------------------------------------- | ------ | ------------------------------------------------------------------------------------------------------------------ |
| Optionales Nutzlastfeld hinzufügen                          | minor  | Ältere Verifizierer ignorieren unbekannte Felder **nur, wenn** das Feld namensräumlich getrennt oder explizit als optional markiert ist |
| Erforderliches Nutzlastfeld hinzufügen                      | major  | Ältere Verifizierer lehnen ab. Koordinierter Umstieg erforderlich                                                   |
| Nutzlastfeld entfernen oder umbenennen                      | major  | Inkompatible Änderung. Aussteller müssen weiterhin v1.x-Belege ausgeben, bis die Verifizierer nachgezogen haben      |
| Neuen `protocol`-Enum-Wert hinzufügen                       | minor  | Ältere Verifizierer lehnen unbekannte Enum-Werte ab. Den neuen Wert erst ausgeben, wenn die Verifizierer ihn unterstützen |
| Zod-Constraint verschärfen (z. B. Format, Länge)            | minor  | Zum Parse-Zeitpunkt abwärtskompatibel. Die neue Einschränkung gilt nur für die Zukunft                               |
| API-Änderung der Verifizierer-Bibliothek (Funktionssignatur) | major  | Aufrufender Code muss aktualisiert werden                                                                            |
| API-Änderung der Verifizierer-Bibliothek (neues optionales Argument) | minor  | Bestehende Aufrufer sind nicht betroffen                                                                             |

**Versionsübergreifende Verifikation.** Verifizierer v1.1.x verifiziert Belege, die unter Schema v1.0 _und_ Schema v1.1 ausgestellt wurden. v1.0-Belege haben schlicht keine v1.1-Felder (`legal_posture`, `consent_context` usw.), und der Verifizierer behandelt diese als optional. Es ist nicht geplant, die v1.0-Verifikation in irgendeiner v1.x-Version zu streichen. Sie zu streichen erfordert einen Major-Bump auf v2.0 und ein Deprecation-Fenster von mindestens 12 Monaten.

**Feld `schema_version`.** Belege tragen `schema_version: "1.0"` oder `schema_version: "1.1"`. Der Verifizierer leitet die Schemavalidierung anhand dieses Feldes weiter. Belege ohne `schema_version` werden abgelehnt (`reason: "schema_invalid"`).

---

## Danksagungen

TrustReceipt ist ein protokollübergreifendes Nachweisformat. Die folgenden externen Parteien definieren Schemata, Protokolle oder Infrastruktur, auf die TrustReceipt-Belege verweisen oder die sie bestätigen können. Keine dieser Organisationen ist ein formeller Mitwirkender an diesem Repository. Die Beziehungen sind Interoperabilitätsintegrationen. Sie sind keine Empfehlungen.

### Protokollautoren (definieren Schemafelder)

| Protokoll | Autor | TrustReceipt-Schemafeld |
| ----------- | ------ | -------------------------- |
| [ACP (Agentic Commerce Protocol)](https://github.com/agentcommerceprotocol/acp) | [OpenAI](https://openai.com) + [Stripe](https://stripe.com) | `authorization_scheme: "acp_session_token"`, `protocol: "ACP"` |
| [AP2 (Agent Payment Protocol v2)](https://developers.google.com/wallet) | [Google](https://google.com) | `authorization_scheme: "ap2_mandate_jws"`, `protocol: "AP2"`, `ap2_consent_hash` |
| [x402 (Stablecoin-Zahlung)](https://github.com/x402-foundation/x402) | [Coinbase](https://coinbase.com) + [Cloudflare](https://cloudflare.com) | `authorization_scheme: "evm_permit2" / "svm_token_authorization" / "x402_native"`, `protocol: "x402"` |
| [MCAP (Mastercard Agent Pay)](https://developer.mastercard.com/product/agent-pay/) | [Mastercard](https://mastercard.com) | `authorization_scheme: "mcap_cart_binding"`, `protocol: "MCAP"`, `mcap_consent_hash` |
| [MCP (Model Context Protocol)](https://github.com/modelcontextprotocol/specification) | [Anthropic](https://anthropic.com) | `authorization_scheme: "mcp_tool_invocation"`, `protocol: "MCP"` |
| [UCP (Universal Commerce Protocol)](https://github.com/Universal-Commerce-Protocol/ucp) | [Google](https://google.com) | `authorization_scheme: "ucp_rule_set_plus_agent_token"`, `protocol: "UCP"` |

### Aktive Laufzeitanbieter (verdrahtet in `trust_provider_assertions[]`)

Diese Anbieter erzeugen strukturierte Aussagen, die die `recomputeLegalPosture`-Logik in `verify-1.1.ts` bei der Bestimmung der vom Verifizierer maßgeblichen `LegalPosture` liest. Verwenden Sie die exportierten Typ-Prädikate (`isRfc9421ProviderAssertion`, `isHumanProviderAssertion`, `isVisaTapProviderAssertion`), um auf die in `types-1.1.ts` definierten typisierten Formen einzugrenzen.

| Anbieter | `provider`-Feld der Aussage | Integration |
| ---------- | ------------------------------ | -------------- |
| [IETF RFC 9421](https://www.rfc-editor.org/rfc/rfc9421) (HTTP Message Signatures) | `"rfc9421-native"` | Verifiziert HTTP-Message-Signaturen von jedem Agenten mit öffentlichem JWKS-Endpunkt. Der Aussteller bindet dies optional ein |
| [HUMAN Security — AgenticTrust](https://www.humansecurity.com/agentictrust) | `"human"` | Optionale Agentenidentitätsintegration. In dieses Verifizierer-Paket wird kein HUMAN-SDK importiert |
| [Visa TAP](https://developer.visa.com/) (Trusted Agent Protocol) | `"visa"` | Validiert, wenn die Signierer-Domäne `*.visa.com` oder `*.visa.net` mit dem Tag `"agent-browser-auth"` oder `"agent-payer-auth"` ist |

### Ausstellerseitige Infrastruktur (von diesem Verifizierer-Paket nicht verwendet)

| Werkzeug | Rolle |
| ---------- | ----- |
| [freeTSA](https://freetsa.org/) | Standard-RFC-3161-Zeitstempelbehörde der Phase 1. Die URL steht pro Beleg im Feld `tsa_endpoint` und ist hier nicht fest codiert |
| [AWS KMS](https://aws.amazon.com/kms/) | Ed25519-Ausstellersignaturschlüssel und HMAC-CMKs für aus PII abgeleitete Hashes; verwaltet vom Schwesterpaket `trust-receipt-kms-signer` |

---

## Hinweis zu Markenzeichen

TrustReceipt ist nicht mit Mastercard, Anthropic, Skyfire, Coinbase, HUMAN Security, Visa oder einem anderen in dieser Spezifikation genannten Protokolleigentümer oder Unternehmen verbunden, von diesen befürwortet oder offiziell unterstützt. Protokollnamen (AP2, MCAP, ACP, MCP, x402, UCP) werden ausschließlich beschreibend verwendet, um Interoperabilitätsziele anzugeben. Alle Marken und eingetragenen Marken sind Eigentum ihrer jeweiligen Inhaber.

---

## Lizenz

MIT, siehe [LICENSE](LICENSE). Copyright MCPWebStore (trusteed.xyz), 2026.
