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

      const safe = jsonSafe({
        ...entry,
        raw: truncate(entry.raw, 4000),
        sanitized: entry.sanitized ? truncate(entry.sanitized, 4000) : undefined,
      })

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
