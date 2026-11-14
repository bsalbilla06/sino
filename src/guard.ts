/**
 * Hook wiring.
 *
 *   1. session "prompt"  → remember the current user request, reset the cache
 *   2. tool "execute.before" → stash the raw shell command + cwd for the call
 *   3. permission "evaluate" → judge the command and set allow/deny
 *
 * Any internal failure sets `deny` (fail closed) and reports the reason.
 */

import { SessionCache, type CachedVerdict } from "./cache"
import { createJudge } from "./judge"
import { createLogger, type VerdictLogEntry } from "./store"
import { analyzeCommand } from "./sanitize"
import { reasonMessage } from "./policy"
import type { GuardOptions } from "./options"

interface PendingCall {
  command?: string
  cwd?: string
  at: number
}

interface PermissionEvent {
  sessionID?: string
  agent?: string
  action?: string
  resources?: string[]
  metadata?: Record<string, unknown>
  source?: { type?: string; messageID?: string; id?: string }
  effect?: "allow" | "deny" | "ask"
  message?: string
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined
}

function firstString(
  record: Record<string, unknown> | undefined,
  keys: string[],
): string | undefined {
  if (!record) return undefined
  for (const key of keys) {
    const value = record[key]
    if (typeof value === "string" && value.length > 0) return value
  }
  return undefined
}

function describeError(error: unknown): string {
  if (error instanceof Error) return error.message
  if (typeof error === "string") return error
  return "unknown error"
}

/**
 * Action names this guard treats as a shell command. `shell` is what OpenCode
 * uses today and `bash` is what the tool hook accepts. A call stashed by the
 * shell tool is judged regardless of name, so a rename cannot bypass the guard
 * — and this set stays narrow so non-shell tools are never judged by accident.
 */
const SHELL_ACTIONS = new Set(["shell", "bash"])

function isShellAction(action: string | undefined): boolean {
  return action ? SHELL_ACTIONS.has(action) : false
}

export function createGuard(ctx: any, options: GuardOptions) {
  const cache = new SessionCache()
  const judge = createJudge(ctx, options)
  const logger = createLogger(ctx, options)
  const pending = new Map<string, PendingCall>()
  const registrations: Array<{ dispose(): Promise<void> }> = []
  const platform = `${process.platform}/${process.arch}`

  const callKey = (
    sessionID: string,
    messageID?: string,
    id?: string,
  ): string | undefined => (messageID && id ? `${sessionID}:${messageID}:${id}` : undefined)

  const prune = (): void => {
    const cutoff = Date.now() - 60_000
    for (const [key, value] of pending) {
      if (value.at < cutoff) pending.delete(key)
    }
  }

  const baseDirectory = (): string =>
    typeof ctx.location?.directory === "string"
      ? ctx.location.directory
      : process.cwd()

  const handlePermission = async (event: PermissionEvent): Promise<void> => {
    const sessionID = event.sessionID ?? "unknown"
    const key = callKey(sessionID, event.source?.messageID, event.source?.id)
    const stashed = key ? pending.get(key) : undefined
    if (key) pending.delete(key)

    // A stashed call came from the shell tool, so this *is* a shell command even
    // if this OpenCode build names the action differently. Skipping judgement
    // here would let a tool rename silently bypass the guard.
    if (!stashed && !isShellAction(event.action)) return

    // From here on a bug must deny this one command, never reach other tools:
    // every failure is converted into a denial inside the catch below.
    try {
      const metadata = asRecord(event.metadata)
      const resources = Array.isArray(event.resources)
        ? event.resources.map((value) => String(value))
        : []

      const raw =
        stashed?.command ??
        firstString(metadata, ["command", "cmd", "raw", "shell", "script"]) ??
        resources.join(" && ")

      const cwd =
        stashed?.cwd ??
        firstString(metadata, ["cwd", "workingDirectory", "directory"]) ??
        baseDirectory()

      const request = cache.request(sessionID)
      const analysis = analyzeCommand(raw, { baseCwd: cwd })
      const startedAt = Date.now()

      if (!raw.trim()) {
        // Nothing to judge: leave the effect untouched rather than guessing.
        return
      }

      if (!options.enforce) {
        await logger.log({
          kind: "observe",
          ts: new Date().toISOString(),
          sessionID,
          agent: event.agent,
          request,
          raw,
          sanitized: analysis.sanitized,
          cwd,
          subcommands: analysis.subcommands,
          flags: analysis.flags,
          resources,
          effect: event.effect,
          metadata,
        })
        return
      }

      let result: CachedVerdict & { latencyMs?: number; error?: string } | undefined
      if (options.cache) result = cache.get(sessionID, cwd, analysis.sanitized)

      if (!result) {
        const judged = await judge.decide({
          analysis,
          raw,
          ...(request ? { userRequest: request } : {}),
          cwd,
          platform,
        })
        result = judged
        // A transport failure is transient: do not let it stick for the rest
        // of the request.
        if (options.cache && judged.reasonCode !== "judge_unavailable") {
          cache.set(sessionID, cwd, analysis.sanitized, {
            verdict: judged.verdict,
            reasonCode: judged.reasonCode,
            confidence: judged.confidence,
            probability: judged.probability,
            reasonConfidence: judged.reasonConfidence,
            transport: judged.transport,
          })
        }
      }

      const effect = result.verdict === "allow" ? "allow" : "deny"

      event.effect = effect
      if (effect === "deny") {
        const detail =
          result.reasonCode === "judge_unavailable" && result.error
            ? `Decision model unavailable, failing closed: ${result.error}`
            : reasonMessage(result.reasonCode, request)
        event.message = `Blocked by sino: ${detail}`
      }

      await logger.log({
        kind: "verdict",
        ts: new Date().toISOString(),
        sessionID,
        agent: event.agent,
        request,
        raw,
        sanitized: analysis.sanitized,
        cwd,
        subcommands: analysis.subcommands,
        flags: analysis.flags,
        resources,
        verdict: result.verdict,
        reasonCode: result.reasonCode,
        confidence: result.confidence,
        probability: result.probability,
        reasonConfidence: result.reasonConfidence,
        latencyMs: result.latencyMs ?? Date.now() - startedAt,
        transport: result.transport ?? "cache",
        error: result.error,
        effect,
      })
    } catch (error) {
      event.effect = "deny"
      event.message = `sino failed closed: ${describeError(error)}`

      await logger.log({
        kind: "verdict",
        ts: new Date().toISOString(),
        sessionID: event.sessionID ?? "unknown",
        agent: event.agent,
        raw: typeof event.resources === "string" ? event.resources : JSON.stringify(event.resources ?? []),
        cwd: baseDirectory(),
        verdict: "deny",
        reasonCode: "guard_exception",
        latencyMs: 0,
        transport: "guard",
        error: describeError(error),
        effect: "deny",
      } satisfies VerdictLogEntry)
    }
  }

  return {
    async start(): Promise<void> {
      registrations.push(
        await ctx.session.hook("prompt", (event: any) => {
          const text =
            typeof event?.prompt?.text === "string" ? event.prompt.text : undefined
          if (event?.sessionID) cache.startRequest(event.sessionID, text)
          pending.clear()
        }),
      )

      registrations.push(
        await ctx.tool.hook("execute.before", (event: any) => {
          if (event?.tool !== "shell" && event?.tool !== "bash") return
          prune()
          const key = callKey(event.sessionID, event.messageID, event.id)
          if (!key) return
          const input = asRecord(event.input)
          const command = firstString(input, ["command", "cmd", "script"])
          const cwd = firstString(input, ["cwd", "workingDirectory", "directory"])
          pending.set(key, {
            ...(command ? { command } : {}),
            ...(cwd ? { cwd } : {}),
            at: Date.now(),
          })
        }),
      )

      registrations.push(await ctx.permission.hook("evaluate", handlePermission))
    },

    async stop(): Promise<void> {
      pending.clear()
      cache.clear()
      await Promise.allSettled(registrations.map((registration) => registration.dispose()))
    },
  }
}
