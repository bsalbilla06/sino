/**
 * Judge transports. The verdict comes from a decision model: either through
 * OpenCode's experimental `generate.decisions` API or a direct POST to an
 * OpenAI-compatible `/decisions` endpoint.
 *
 * Every failure path is fail-closed: timeout, transport error, malformed
 * answers, or an error answer all resolve to Deny.
 */

import type { GuardOptions } from "./options"
import type { CommandAnalysis } from "./sanitize"
import { readFile } from "node:fs/promises"
import {
  buildJudgeInput,
  REASON_CHOICES,
  VERDICT_LEVELS,
  verdictInstructions,
} from "./policy"

export type Verdict = "allow" | "deny"

export interface JudgeRequest {
  analysis: CommandAnalysis
  raw: string
  userRequest?: string
  cwd: string
  platform: string
}

export interface JudgeResult {
  verdict: Verdict
  reasonCode: string
  confidence: number
  /** Top probability of the winning level, for calibration auditing. */
  probability?: number
  /** Top probability of the reason answer, for audit clarity. */
  reasonConfidence?: number
  transport: "plugin" | "fetch" | "tripwire" | "fallback"
  latencyMs: number
  error?: string
  rawAnswer?: unknown
}

export interface Judge {
  decide(request: JudgeRequest): Promise<JudgeResult>
}

interface DecisionAnswer {
  type?: string
  name?: string
  score?: number
  choice?: string | boolean
  confidence?: number
  probabilities?: Array<{ value?: number | string | boolean; label?: string; probability?: number }>
  reason?: string
  message?: string
}

function clampVerdictIndex(value: number): number {
  if (!Number.isFinite(value)) return VERDICT_LEVELS.length - 1
  return Math.min(VERDICT_LEVELS.length - 1, Math.max(0, Math.round(value)))
}

function indexToVerdict(index: number): Verdict {
  return index === 0 ? "allow" : "deny"
}

/** Pick the highest-probability level when the API returns probabilities. */
function scoreIndex(answer: DecisionAnswer): number {
  const probabilities = answer.probabilities ?? []
  let best: { value: number; probability: number } | undefined
  for (const entry of probabilities) {
    if (typeof entry.value !== "number" || typeof entry.probability !== "number") continue
    if (!best || entry.probability > best.probability) {
      best = { value: entry.value, probability: entry.probability }
    }
  }
  if (best) return clampVerdictIndex(best.value)
  return clampVerdictIndex(answer.score ?? 2)
}

function answersOf(result: unknown): DecisionAnswer[] {
  if (!result || typeof result !== "object") return []
  const record = result as Record<string, unknown>
  const answers = record.answers
  if (Array.isArray(answers)) return answers as DecisionAnswer[]
  if (answers && typeof answers === "object") {
    return Object.values(answers as Record<string, DecisionAnswer>)
  }
  return []
}

/** Top probability across a choice answer's probabilities. */
function topProbability(answer: DecisionAnswer | undefined): number | undefined {
  const probabilities = answer?.probabilities ?? []
  let best: number | undefined
  for (const entry of probabilities) {
    if (typeof entry.probability !== "number") continue
    if (best === undefined || entry.probability > best) best = entry.probability
  }
  return best
}

/** Top two probabilities of a score answer, highest first. */
function topProbabilities(answer: DecisionAnswer): { top: number; second: number } | undefined {
  const values: number[] = []
  for (const entry of answer.probabilities ?? []) {
    if (typeof entry.probability === "number") values.push(entry.probability)
  }
  if (values.length === 0) return undefined
  values.sort((a, b) => b - a)
  return { top: values[0]!, second: values[1] ?? 0 }
}

export function parseJudgeAnswers(
  result: unknown,
  options: Pick<GuardOptions, "allowThreshold">,
): Pick<
  JudgeResult,
  "verdict" | "reasonCode" | "confidence" | "probability" | "reasonConfidence"
> {
  const answers = answersOf(result)
  const verdictAnswer = answers.find((a) => a.name === "verdict")
  const reasonAnswer = answers.find((a) => a.name === "reason")

  if (!verdictAnswer) {
    return {
      verdict: "deny",
      reasonCode: "judge_unparseable",
      confidence: 0,
      reasonConfidence: 0,
    }
  }

  if (verdictAnswer.type === "error") {
    return {
      verdict: "deny",
      reasonCode: "judge_error",
      confidence: 0,
      reasonConfidence: 0,
    }
  }

  let verdict = indexToVerdict(scoreIndex(verdictAnswer))
  const confidence =
    typeof verdictAnswer.confidence === "number" ? verdictAnswer.confidence : 1

  // Gate an Allow on the probability of the winning level. The API's separate
  // `confidence` field is not comparable across answers: it reads 0 even when
  // Allow leads clearly and the reason answer says "safe and within intent".
  // With no probabilities at all, fall back to that field.
  const spread = topProbabilities(verdictAnswer)
  const allowance = spread ? spread.top : confidence
  const uncertain = verdict === "allow" && allowance < options.allowThreshold
  if (uncertain) verdict = "deny"

  const reasonConfidence =
    typeof reasonAnswer?.confidence === "number"
      ? reasonAnswer.confidence
      : (topProbability(reasonAnswer) ?? 1)

  const fallbackReason = verdict === "allow" ? "within_intent_safe" : "outside_user_intent"

  // The reason answer describes the command, not the verdict, so an Allow may
  // legitimately carry "destructive_irreversible" (a bounded delete). Only an
  // Allow we refused for its own uncertainty needs a reason that matches the
  // outcome we are reporting.
  const reasonCode = uncertain
    ? "insufficient_confidence"
    : typeof reasonAnswer?.choice === "string"
      ? reasonAnswer.choice
      : fallbackReason

  return { verdict, reasonCode, confidence, probability: allowance, reasonConfidence }
}

function questions(options: GuardOptions) {
  return [
    {
      type: "score" as const,
      name: "verdict",
      instructions: `${verdictInstructions(options)}

Should the agent be allowed to run this command?`,
      levels: VERDICT_LEVELS.map((level) => ({ ...level })),
    },
    {
      type: "choice" as const,
      name: "reason",
      instructions: "What is the primary reason for this verdict?",
      choices: REASON_CHOICES.map((choice) => ({ ...choice })),
    },
  ]
}

type Decider = (input: {
  analysis: CommandAnalysis
  raw: string
  userRequest?: string
  cwd: string
  platform: string
}) => Promise<unknown>

function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  return new Promise<T>((resolvePromise, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`judge timed out after ${timeoutMs}ms`))
    }, timeoutMs)

    promise.then(
      (value) => {
        clearTimeout(timer)
        resolvePromise(value)
      },
      (error) => {
        clearTimeout(timer)
        reject(error)
      },
    )
  })
}

function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message
  if (typeof error === "string") return error
  try {
    return JSON.stringify(error)
  } catch {
    return "unknown judge error"
  }
}

function expandHome(path: string): string {
  if (path === "~") return process.env.HOME ?? path
  if (path.startsWith("~/")) return `${process.env.HOME ?? "~"}${path.slice(1)}`
  return path
}

let cachedApiKey: string | undefined

/**
 * Resolve the API key the same way the user's shell would: process env first,
 * then an optional file, then an optional argv probe (e.g. `zsh -c` reading
 * ~/.zshenv). The OpenCode server process often does not inherit the shell's
 * environment.
 */
async function resolveApiKey(options: GuardOptions): Promise<string | undefined> {
  if (cachedApiKey) return cachedApiKey

  const fromEnv = process.env[options.fetch.apiKeyEnv]
  if (fromEnv?.trim()) {
    cachedApiKey = fromEnv.trim()
    return cachedApiKey
  }

  if (options.fetch.apiKeyFile) {
    try {
      const value = (
        await readFile(expandHome(options.fetch.apiKeyFile), "utf8")
      ).trim()
      if (value) {
        cachedApiKey = value
        return cachedApiKey
      }
    } catch {
      // Fall through to the command probe.
    }
  }

  const command = options.fetch.apiKeyCommand
  if (command && command.length > 0) {
    try {
      const bun = (globalThis as { Bun?: { spawnSync: Function } }).Bun
      if (bun?.spawnSync) {
        const result = bun.spawnSync(command, { stdout: "pipe", stderr: "pipe" })
        const value = new TextDecoder().decode(result.stdout ?? new Uint8Array()).trim()
        if (value) {
          cachedApiKey = value
          return cachedApiKey
        }
      }
    } catch {
      // Fall through to the error below.
    }
  }

  return undefined
}

export function createJudge(ctx: any, options: GuardOptions): Judge {
  const pluginDecider: Decider = async (input) => {
    const text = buildJudgeInput(
      input.analysis,
      input.raw,
      input.userRequest,
      input.cwd,
      input.platform,
    )
    const result = await ctx.experimental.generate.decisions({
      model: options.model,
      input: [{ type: "text", text }],
      questions: questions(options),
    })
    return result
  }

  const fetchDecider: Decider = async (input) => {
    const apiKey = await resolveApiKey(options)
    if (!apiKey) {
      const sources = [
        `$${options.fetch.apiKeyEnv}`,
        options.fetch.apiKeyFile ? `file ${options.fetch.apiKeyFile}` : undefined,
        options.fetch.apiKeyCommand
          ? `command ${options.fetch.apiKeyCommand.join(" ")}`
          : undefined,
      ]
        .filter(Boolean)
        .join(", ")
      throw new Error(`missing API key for /decisions (tried ${sources})`)
    }

    const text = buildJudgeInput(
      input.analysis,
      input.raw,
      input.userRequest,
      input.cwd,
      input.platform,
    )
    const url = `${options.fetch.baseURL}${options.fetch.path}`
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), options.timeoutMs)

    try {
      const response = await fetch(url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${apiKey}`,
          ...(options.fetch.headers ?? {}),
        },
        body: JSON.stringify({
          model: options.fetch.model,
          input: text,
          questions: questions(options),
        }),
        signal: controller.signal,
      })

      if (!response.ok) {
        const body = await response.text().catch(() => "")
        throw new Error(
          `decisions endpoint ${response.status}: ${body.slice(0, 300)}`,
        )
      }

      return await response.json()
    } finally {
      clearTimeout(timer)
    }
  }

  const run = async (
    decider: Decider,
    transport: "plugin" | "fetch",
    request: JudgeRequest,
    startedAt: number,
  ): Promise<JudgeResult> => {
    try {
      const raw = await withTimeout(
        decider({
          analysis: request.analysis,
          raw: request.raw,
          userRequest: request.userRequest,
          cwd: request.cwd,
          platform: request.platform,
        }),
        options.timeoutMs,
      )
      const parsed = parseJudgeAnswers(raw, options)
      return {
        ...parsed,
        transport,
        latencyMs: Date.now() - startedAt,
        rawAnswer: raw,
      }
    } catch (error) {
      return {
        verdict: "deny",
        reasonCode: "judge_unavailable",
        confidence: 0,
        transport,
        latencyMs: Date.now() - startedAt,
        error: errorMessage(error),
      }
    }
  }

  return {
    async decide(request) {
      const startedAt = Date.now()

      if (request.analysis.tripwire && options.denyOnTripwire) {
        return {
          verdict: "deny",
          reasonCode: "instruction_phrase",
          confidence: 1,
          reasonConfidence: 1,
          transport: "tripwire",
          latencyMs: Date.now() - startedAt,
        }
      }

      if (options.transport === "plugin") {
        return run(pluginDecider, "plugin", request, startedAt)
      }

      if (options.transport === "fetch") {
        return run(fetchDecider, "fetch", request, startedAt)
      }

      // auto: prefer OpenCode's decision API, then the direct endpoint.
      const viaPlugin = await run(pluginDecider, "plugin", request, startedAt)
      if (viaPlugin.verdict !== "deny" || !viaPlugin.error) return viaPlugin

      const viaFetch = await run(fetchDecider, "fetch", request, Date.now())
      if (!viaFetch.error) return { ...viaFetch, transport: "fallback" }

      return {
        verdict: "deny",
        reasonCode: "judge_unavailable",
        confidence: 0,
        transport: "fallback",
        latencyMs: Date.now() - startedAt,
        error: `plugin: ${viaPlugin.error}; fetch: ${viaFetch.error}`,
      }
    },
  }
}
