#!/usr/bin/env bun
/**
 * Print the verdict log as a compact table.
 *
 *   bun run .opencode/plugins/sino/export.ts [path]
 */

import { readFile } from "node:fs/promises"

const path = process.argv[2] ?? ".opencode/sino/verdicts.jsonl"

const text = await readFile(path, "utf8").catch(() => "")
if (!text.trim()) {
  console.log(`no verdict log at ${path}`)
  process.exit(0)
}

for (const line of text.split("\n")) {
  if (!line.trim()) continue
  try {
    const entry = JSON.parse(line)
    const stamp = entry.ts?.slice(11, 19) ?? "--:--:--"
    const verdict = (entry.verdict ?? entry.kind ?? "?").toUpperCase()
    const transport = entry.transport ?? "-"
    const latency = entry.latencyMs !== undefined ? `${entry.latencyMs}ms` : "-"
    const probability =
      entry.probability !== undefined ? Number(entry.probability).toFixed(2) : "-"
    const command = (entry.sanitized ?? entry.raw ?? "").replace(/\s+/g, " ")
    console.log(
      `${stamp}  ${verdict.padEnd(9)} ${String(transport).padEnd(9)} ${probability.padStart(4)} ${String(latency).padStart(6)}  ${command.slice(0, 110)}`,
    )
  } catch {
    // Skip malformed lines.
  }
}
