/**
 * Evidencia de política del TrustReceipt — SSOT de los campos R-02.
 *
 * ## Por qué existen
 *
 * Hasta 2026-07-29 el receipt firmaba `policy_decision` y nada más: un enum de
 * cuatro valores. Eso convierte el artefacto en "el veredicto" pero no en "la
 * política que lo produjo", y un adjudicador que pregunte *qué regla, con qué
 * umbral, en qué versión* no obtiene respuesta del receipt. La información ya
 * existe en `RuleSnapshot` y `EnforcementEvent`; lo que no hacía era viajar en
 * el artefacto portable, que es justamente lo que lo hace portable.
 *
 * El §3.4 del A-Comm Evidence Protocol (v1.0.3-rc.2) exige diez campos en su
 * artefacto de política. Estos cuatro conceptos son los que tenemos con datos
 * reales detrás; declarar más sería inventarlos.
 *
 * ## Por qué son opcionales y NO hay versión nueva
 *
 * `verifier.ts` verifica la firma con `compactVerify` sobre los **bytes crudos
 * del JWS** (`:374`) y sólo DESPUÉS parsea (`:393`). Añadir campos por tanto no
 * puede invalidar ninguna firma existente. Y el dispatcher **falla ruidosamente
 * ante versiones futuras** por diseño, así que estrenar un `schema_version`
 * "1.2" haría que todo verificador desplegado —TypeScript y Python— rechazara
 * esos receipts hasta actualizarse. Campos opcionales sobre las versiones que
 * ya existen no rompen a nadie.
 *
 * Contrato publicado: **presentes ⇒ autoritativos; ausentes ⇒ el receipt no
 * atestigua política**. Ausencia nunca significa "no se evaluó nada": significa
 * que este receipt no lo declara.
 *
 * ## Por qué se declaran incluso en los `z.object` no estrictos
 *
 * No estricto significa que Zod ACEPTA claves no declaradas, pero las DESCARTA
 * del objeto parseado. Sin estas declaraciones los campos verificarían bien y
 * jamás llegarían al tipo público — el mismo fallo que ya mordió con el
 * enriquecimiento T1.3 (ver `trust-receipt-legacy.schema.ts:68-77`).
 */

import { z } from "zod";

/**
 * Qué hizo el motor con el veredicto, que NO es lo mismo que el veredicto.
 *
 * Un `policy_decision: "deny"` evaluado en modo observación no bloqueó nada.
 * Sin este campo las dos situaciones son indistinguibles en el artefacto, y la
 * diferencia es exactamente la que importa en una disputa.
 *
 * Los valores son proyección del enum `EnforcementDecision` de Prisma
 * (`OBSERVE`, `FAIL_OPEN`, `FAIL_CLOSED`, `KILL_SWITCH`, `ALLOWLISTED`,
 * `TIMEOUT`, …), que hoy se pierde al serializar el receipt.
 */
export const EnforcementResultSchema = z.enum([
  /** La decisión se aplicó: se bloqueó, se escaló o se permitió de verdad. */
  "enforced",
  /** Modo observación: se evaluó y se registró, no se actuó. */
  "observed",
  /** Kill-switch o allowlist del comerciante ganó por encima de la regla. */
  "overridden",
  /** El evaluador falló y la política era fail-open: pasó sin evaluar. */
  "failed_open",
  /** El evaluador falló y la política era fail-closed: se rechazó sin evaluar. */
  "failed_closed",
  /** No había reglas aplicables a esta operación. */
  "not_applicable",
]);

/**
 * A quién se escaló cuando la decisión fue `review`.
 *
 * El evaluador ya distingue los dos casos (`RuleDecisionKind`: `hitl` =
 * aprobación del comerciante, `confirmation` = confirmación del comprador) y el
 * receipt los colapsaba en un único `"review"`. Son responsabilidades distintas
 * y la distinción es la que decide quién respondía de la operación.
 */
export const EscalationTargetSchema = z.enum([
  /** Aprobación fuera de banda del comerciante (nuestro `hitl`). */
  "merchant",
  /** Confirmación explícita del comprador (nuestro `confirmation`). */
  "consumer",
]);

/**
 * Los cuatro conceptos, listos para esparcir dentro de un `z.object`.
 *
 * Se exporta como objeto plano —no como `z.object`— para poder inyectarlo tal
 * cual en los tres esquemas (v1.0 canónico, v1.0 legacy compacto y v1.1
 * estricto) sin que ninguno de ellos herede la estrictez de otro.
 */
export const PolicyEvidenceFields = {
  /**
   * Identidad de la evaluación que produjo el veredicto — el `id` de la fila
   * decisiva de `EnforcementEvent`.
   *
   * Desde el 2026-08-06 el evaluador y la fila comparten un único UUID: antes
   * `append()` acuñaba el de la fila y `build*Response` otro para la respuesta,
   * de modo que casar el veredicto publicado con su fila exigía la heurística
   * «el último evento de este comerciante hace milisegundos». Con el campo
   * dentro del cuerpo firmado, un tercero puede pedir el expediente **por
   * identidad** en vez de por proximidad temporal.
   *
   * ⚠️ **Identifica la EVALUACIÓN, no la operación.** En un acierto de caché el
   * veredicto se reutiliza tal cual, así que varias operaciones distintas
   * pueden traer el mismo `evaluation_id`, y apunta a la evaluación cuyo
   * veredicto se aplicó — que es lo que interesa probar, pero **no** es una
   * relación 1:1 con el recibo. Un consumidor que asuma unicidad por operación
   * se equivocará. Por eso tampoco sirve como clave de idempotencia: el emisor
   * de recibos de denegación deriva su `callId` por otra vía a propósito.
   *
   * Cadena laxa y no `z.string().uuid()` deliberadamente: el mismo criterio que
   * {@link evaluated_rules}. Un emisor de otra implementación puede identificar
   * sus evaluaciones de otra forma, y rechazar el recibo ENTERO por la forma de
   * un identificador opaco convierte un artefacto válido en inválido. Lo que sí
   * se rechaza es la cadena vacía —una identidad que no identifica— y una
   * desmesurada.
   */
  evaluation_id: z.string().min(1).max(128).optional(),

  /**
   * SHA-256 hex sobre la forma canónica RFC 8785 del `RuleSnapshot` vigente en
   * el momento de evaluar. Origen: `RuleSnapshot.payloadHashSha256`.
   *
   * Es lo que permite a un tercero pedir el snapshot y comprobar que la
   * política que se le enseña es la que se aplicó — sin él, "la versión 7 de
   * las reglas" es una afirmación no verificable.
   */
  policy_snapshot_hash: z
    .string()
    .regex(/^[0-9a-f]{64}$/)
    .optional(),

  /**
   * Códigos canónicos de las reglas que dispararon, en el orden en que las
   * ordena el evaluador. Vacío es distinto de ausente: vacío ⇒ se evaluó y no
   * disparó ninguna.
   */
  rules_triggered: z.array(z.string()).optional(),

  /**
   * La regla que determinó el veredicto, por la precedencia
   * `(tier, precedence, ruleCode)` que ya calcula el evaluador.
   *
   * Existe porque `rules_triggered` puede traer varias y "cuál mandó" no se
   * deduce del orden alfabético — ese fue precisamente un defecto real: R031
   * (kill-switch de tienda) se reportaba como otra regla por ir después en el
   * alfabeto.
   */
  deciding_rule: z.string().optional(),

  /**
   * Versión del conjunto de reglas bajo el que se evaluó — `RuleSnapshot.
   * ruleSetVersion`, único por `(merchant_id, rule_set_version)`.
   *
   * Va junto a {@link policy_snapshot_hash} y no en su lugar: el hash prueba
   * QUÉ política era, la versión dice CUÁL pedir. Un hash sin versión obliga a
   * barrer el historial del comerciante para encontrar la fila; una versión sin
   * hash es una afirmación no verificable. Ambos salen de la MISMA fila por
   * construcción — se resuelve el snapshot POR esta versión, no por "el más
   * reciente", que era una segunda lectura capaz de discrepar de la primera
   * dentro del mismo recibo firmado.
   */
  rule_set_version: z.number().int().nonnegative().optional(),

  /**
   * Los códigos de las reglas que CORRIERON en esta evaluación, ya filtradas
   * por la partición `appliesTo` y en orden de precedencia.
   *
   * Distinto de {@link rules_triggered}, y la diferencia es la que responde el
   * caso que motivó el campo: "se evaluaron estas nueve y ninguna casó" es una
   * afirmación fuerte sobre los controles aplicados; "casó ésta" no dice nada
   * sobre las otras ocho. Vacío ⇒ el comerciante no tenía reglas activas
   * aplicables; ausente ⇒ el recibo no lo declara.
   *
   * Cadena laxa y no un enum de códigos conocidos a propósito: los valores
   * vienen de filas de configuración del comerciante, y un verificador que
   * rechace un recibo por un código que no reconoce convierte una regla
   * personalizada en evidencia inválida.
   */
  evaluated_rules: z.array(z.string().min(1).max(128)).max(128).optional(),

  /** Ver {@link EnforcementResultSchema}. */
  enforcement_result: EnforcementResultSchema.optional(),

  /** Ver {@link EscalationTargetSchema}. Sólo tiene sentido con `review`. */
  escalation_target: EscalationTargetSchema.optional(),
} as const;

export type EnforcementResult = z.infer<typeof EnforcementResultSchema>;
export type EscalationTarget = z.infer<typeof EscalationTargetSchema>;

/** Las claves que componen la evidencia de política, para gates y vectores. */
export const POLICY_EVIDENCE_KEYS = Object.keys(
  PolicyEvidenceFields
) as readonly (keyof typeof PolicyEvidenceFields)[];
