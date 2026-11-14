/**
 * Option parsing for the sino plugin.
 *
 * Options arrive from `opencode.json`:
 *
 *   {
 *     "plugins": [
 *       { "package": "opencode-sino", "options": { ... } }
 *     ]
 *   }
 */

export type JudgeTransport = "auto" | "plugin" | "fetch"

export interface JudgeModel {
  providerID: string
  id: string
  variant?: string
}

export interface FetchJudgeOptions {
  baseURL: string
  path: string
  model: string
  apiKeyEnv: string
  /** Read the key from a file when the environment variable is absent. */
  apiKeyFile: string | null
  /**
   * Fallback argv used to resolve the key, e.g.
   * ["zsh", "-c", "printf %s \"$OPENAI_API_KEY\""].
   * The OpenCode server may not share the shell's environment, so this keeps
   * keys that live in ~/.zshenv usable.
   */
  apiKeyCommand: string[] | null
  headers?: Record<string, string>
}

export interface LogOptions {
  enabled: boolean
  storage: boolean
  /** JSONL mirror path; relative paths resolve against the project directory. `null` disables. */
  file: string | null
}

export interface GuardOptions {
  /** false = observe only (log evaluations, never change the effect). Used by M0. */
  enforce: boolean
  transport: JudgeTransport
  /** Model for `ctx.experimental.generate.decisions` (plugin transport). */
  model: JudgeModel
  /** Direct `/v1/decisions` endpoint (fetch transport / fallback). */
  fetch: FetchJudgeOptions
  timeoutMs: number
  /**
   * Minimum top probability for an Allow to run unattended. The decision
   * model's separate `confidence` field is unreliable (it can be 0 on a
   * decisive Allow), so the probability distribution is what gates.
   * Deny always stands regardless of this value.
   */
  allowThreshold: number
  cache: boolean
  log: LogOptions
  /** Extra judge policy text appended to the built-in policy. */
  policy?: string
  /** Deny without consulting the model when the injection tripwire fires. */
  denyOnTripwire: boolean
}

const DEFAULTS: GuardOptions = {
  enforce: true,
  transport: "auto",
  model: {
    providerID: "opencode",
    id: "jev-1.13",
  },
  fetch: {
    baseURL: "https://api.openai.com/v1",
    path: "/decisions",
    model: "gpt-6-luna",
    apiKeyEnv: "OPENAI_API_KEY",
    apiKeyFile: null,
    apiKeyCommand: null,
  },
  timeoutMs: 2000,
  // With two levels the model's argmax is the verdict, so this only rejects
  // near-ties: Allow must beat Deny by 10 points to run. A denial is cheap
  // (the agent can ask the user), so a small margin costs little.
  allowThreshold: 0.55,
  cache: true,
  log: {
    enabled: true,
    storage: true,
    file: ".opencode/sino/verdicts.jsonl",
  },
  denyOnTripwire: true,
}

function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value))
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {}
}

function asString(value: unknown, fallback: string): string {
  return typeof value === "string" && value.length > 0 ? value : fallback
}

function asBoolean(value: unknown, fallback: boolean): boolean {
  return typeof value === "boolean" ? value : fallback
}

export function loadOptions(raw: unknown): GuardOptions {
  const input = asRecord(raw)
  const model = asRecord(input.model)
  const fetchOptions = asRecord(input.fetch)
  const log = asRecord(input.log)

  const transport = asString(input.transport, DEFAULTS.transport)
  const parsedTransport: JudgeTransport =
    transport === "plugin" || transport === "fetch" || transport === "auto"
      ? transport
      : DEFAULTS.transport

  return {
    enforce: asBoolean(input.enforce, DEFAULTS.enforce),
    transport: parsedTransport,
    model: {
      providerID: asString(model.providerID, DEFAULTS.model.providerID),
      id: asString(model.id, DEFAULTS.model.id),
      ...(typeof model.variant === "string" ? { variant: model.variant } : {}),
    },
    fetch: {
      baseURL: asString(fetchOptions.baseURL, DEFAULTS.fetch.baseURL).replace(/\/+$/, ""),
      path: asString(fetchOptions.path, DEFAULTS.fetch.path),
      model: asString(fetchOptions.model, DEFAULTS.fetch.model),
      apiKeyEnv: asString(fetchOptions.apiKeyEnv, DEFAULTS.fetch.apiKeyEnv),
      apiKeyFile: typeof fetchOptions.apiKeyFile === "string" ? fetchOptions.apiKeyFile : null,
      apiKeyCommand: Array.isArray(fetchOptions.apiKeyCommand)
        ? fetchOptions.apiKeyCommand.map((arg) => String(arg))
        : null,
      ...(fetchOptions.headers && typeof fetchOptions.headers === "object"
        ? { headers: fetchOptions.headers as Record<string, string> }
        : {}),
    },
    timeoutMs: clamp(
      typeof input.timeoutMs === "number" ? input.timeoutMs : DEFAULTS.timeoutMs,
      250,
      60_000,
    ),
    allowThreshold: clamp(
      typeof input.allowThreshold === "number"
        ? input.allowThreshold
        : typeof input.confidenceFloor === "number"
          ? input.confidenceFloor
          : DEFAULTS.allowThreshold,
      0,
      1,
    ),
    cache: asBoolean(input.cache, DEFAULTS.cache),
    log: {
      enabled: asBoolean(log.enabled, DEFAULTS.log.enabled),
      storage: asBoolean(log.storage, DEFAULTS.log.storage),
      file:
        log.file === null
          ? null
          : typeof log.file === "string"
            ? log.file
            : DEFAULTS.log.file,
    },
    ...(typeof input.policy === "string" ? { policy: input.policy } : {}),
    denyOnTripwire: asBoolean(
      input.denyOnTripwire ?? input.escalateOnTripwire,
      DEFAULTS.denyOnTripwire,
    ),
  }
}
