/**
 * Verdict audit log: one record per judgment, stored through OpenCode's plugin
 * storage and mirrored as JSONL for easy inspection.
 */

import { appendFile, mkdir } from "node:fs/promises"
import { dirname, isAbsolute, resolve } from "node:path"
import type { GuardOptions } from "./options"

export interface VerdictLogEntry {
  kind: "verdict" | "observe"
  ts: string
  sessionID: string
  agent?: string
  request?: string
  raw: string
  sanitized?: string
  cwd: string
  subcommands?: Array<{ command: string; cwd: string }>
  flags?: string[]
  resources?: string[]
  verdict?: string
  reasonCode?: string
  confidence?: number
  probability?: number
  reasonConfidence?: number
  latencyMs?: number
  transport?: string
  error?: string
  effect?: string
  metadata?: Record<string, unknown>
}

export interface Logger {
  log(entry: VerdictLogEntry): Promise<void>
}

/**
 * Audit records must stay useful without becoming a credential store. Commands,
 * prompts, and error strings routinely contain bearer tokens, `KEY=value`
 * assignments, and URLs with inline credentials, so every string is scrubbed
 * before it reaches storage or the JSONL mirror.
 */
const SECRET_PATTERNS: Array<[RegExp, string]> = [
  [/\b(Bearer\s+)[A-Za-z0-9._~+/=-]{6,}/gi, "$1[REDACTED]"],
  [/\bsk-[A-Za-z0-9_-]{8,}/g, "sk-[REDACTED]"],
  [/\bgh[pousr]_[A-Za-z0-9]{20,}/g, "[REDACTED_GITHUB_TOKEN]"],
  [/\bgithub_pat_[A-Za-z0-9_]{20,}/g, "[REDACTED_GITHUB_TOKEN]"],
  [/\bAKIA[0-9A-Z]{16}\b/g, "[REDACTED_AWS_KEY]"],
  [/\bxox[abprs]-[A-Za-z0-9-]{10,}/g, "[REDACTED_SLACK_TOKEN]"],
  [/([a-z][a-z0-9+.-]*:\/\/[^\s:/@]+:)([^\s/@]+)(@)/gi, "$1[REDACTED]$3"],
  [
    /\b([A-Za-z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIAL)[A-Za-z0-9_]*\s*=\s*)('[^']*'|"[^"]*"|[^\s;&|]+)/gi,
    "$1[REDACTED]",
  ],
  [
    /(--(?:password|passwd|token|secret|api-key|apikey|authorization)(?:=|\s+))('[^']*'|"[^"]*"|[^\s;&|]+)/gi,
    "$1[REDACTED]",
  ],
  [/((?:Authorization|Cookie|Set-Cookie)\s*:\s*)([^"'\r\n]+)/gi, "$1[REDACTED]"],
]

function redactText(text: string): string {
  let out = text
  for (const [pattern, replacement] of SECRET_PATTERNS) {
    out = out.replace(pattern, replacement)
  }
  return out
}

/** Deep copy with secrets scrubbed, safe for cycles and BigInt values. */
export function redactLogValue<T>(value: T, seen = new WeakSet<object>()): T {
  if (typeof value === "string") return redactText(value) as T
  if (typeof value === "bigint") return value.toString() as T
  if (Array.isArray(value)) {
    if (seen.has(value)) return "[circular]" as T
    seen.add(value)
    return value.map((item) => redactLogValue(item, seen)) as T
  }
  if (value && typeof value === "object") {
    if (seen.has(value)) return "[circular]" as T
    seen.add(value)
    const copy: Record<string, unknown> = {}
    for (const [key, item] of Object.entries(value)) {
      copy[key] = redactLogValue(item, seen)
    }
    return copy as T
  }
  return value
}

function jsonSafe<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T
}

function truncate(text: string, max: number): string {
  return text.length <= max ? text : `${text.slice(0, max)}…`
}

export function createLogger(ctx: any, options: GuardOptions): Logger {
  const baseDirectory = ctx.location?.directory ?? process.cwd()
  const filePath = options.log.file
    ? isAbsolute(options.log.file)
      ? options.log.file
      : resolve(baseDirectory, options.log.file)
    : null

  let fileReady: Promise<void> | undefined

  const append = async (entry: VerdictLogEntry): Promise<void> => {
    if (!filePath) return
    fileReady ??= mkdir(dirname(filePath), { recursive: true }).then(() => undefined)
    await fileReady
    await appendFile(filePath, `${JSON.stringify(entry)}\n`, "utf8")
  }

  return {
    async log(entry) {
      if (!options.log.enabled) return

      const safe = jsonSafe(
        redactLogValue({
          ...entry,
          raw: truncate(entry.raw, 4000),
          sanitized: entry.sanitized ? truncate(entry.sanitized, 4000) : undefined,
        }),
      )

      if (options.log.storage) {
        try {
          const key = `verdicts/${Date.now()}-${Math.random().toString(36).slice(2, 10)}`
          await ctx.storage.set(key, safe)
        } catch {
          // Logging must never break arbitration.
        }
      }

      try {
        await append(safe)
      } catch {
        // Same: never fail the command because the audit file is unavailable.
      }
    },
  }
}
