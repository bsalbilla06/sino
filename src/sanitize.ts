/**
 * Shell command sanitization and structuring for the judge.
 *
 * The judge must never receive attacker-controlled instruction text in an
 * instruction position. We therefore strip comments and heredoc bodies, split
 * the line into executable segments, and track effective cwd so the judge can
 * tell `cd /tmp && rm -rf *` (bounded) from `rm -rf *` (unbounded).
 *
 * Stripped content is not thrown away: comments and heredoc bodies are returned
 * separately (so the judge can see them under an untrusted heading when the
 * tripwire is disabled) and are always scanned for injection markers.
 */

import { isAbsolute, resolve } from "node:path"

export interface Subcommand {
  /** Command text with comments/heredocs removed. */
  command: string
  /** Effective cwd at the point this segment runs. */
  cwd: string
  /** Operator that joined this segment to the previous one. */
  operator?: string
}

export interface CommandAnalysis {
  /** Full line with comments and heredoc bodies removed, operators preserved. */
  sanitized: string
  /** True when anything was removed from the raw command. */
  stripped: boolean
  /** Comment bodies found in the command. */
  comments: string[]
  /** Heredoc bodies found in the command, in read order. */
  heredocs: string[]
  /** Commands in execution order with effective cwd. */
  subcommands: Subcommand[]
  /**
   * Findings the judge should know about. `tripwire` findings deny the command
   * without consulting the model.
   */
  flags: string[]
  tripwire: boolean
}

export interface AnalyzeOptions {
  baseCwd: string
  home?: string
}

const TRIPWIRE_FLAGS = new Set([
  "comment",
  "heredoc",
  "encoded_payload",
  "instruction_phrase",
  "obfuscated_text",
])

/**
 * Remove shell comments. A `#` starts a comment only at the start of a word,
 * outside quotes, matching POSIX shell behaviour closely enough for judgement.
 */
function stripComments(input: string): { text: string; comments: string[] } {
  const comments: string[] = []
  let out = ""
  let quote: '"' | "'" | null = null
  let escaped = false
  let i = 0

  while (i < input.length) {
    const char = input[i]!

    if (escaped) {
      out += char
      escaped = false
      i += 1
      continue
    }

    if (quote) {
      out += char
      if (char === quote) quote = null
      i += 1
      continue
    }

    if (char === "\\") {
      out += char
      escaped = true
      i += 1
      continue
    }

    if (char === '"' || char === "'") {
      quote = char
      out += char
      i += 1
      continue
    }

    if (char === "#") {
      const prev = i === 0 ? " " : input[i - 1]!
      if (/\s|[;&|(]/.test(prev) || i === 0) {
        const end = input.indexOf("\n", i)
        const stop = end === -1 ? input.length : end
        comments.push(input.slice(i + 1, stop).trim())
        i = stop
        continue
      }
    }

    out += char
    i += 1
  }

  return { text: out, comments }
}

interface HeredocMarker {
  index: number
  length: number
  delimiter: string
}

/**
 * Find the first heredoc operator (`<<EOF`, `<<-EOF`, `<<'EOF'`) on a line,
 * ignoring `<<` inside quotes and the herestring `<<<`.
 */
function findHeredoc(line: string): HeredocMarker | undefined {
  let quote: '"' | "'" | null = null
  let escaped = false

  for (let i = 0; i < line.length; i += 1) {
    const char = line[i]!

    if (escaped) {
      escaped = false
      continue
    }

    if (quote) {
      if (char === quote) quote = null
      continue
    }

    if (char === "\\") {
      escaped = true
      continue
    }

    if (char === '"' || char === "'") {
      quote = char
      continue
    }

    if (char !== "<" || line[i + 1] !== "<") continue
    // `<<< word` is a herestring: the word is an argument, not a body delimiter.
    if (line[i + 2] === "<" || line[i - 1] === "<") continue

    const match = line.slice(i).match(/^<<-?\s*(['"]?)([A-Za-z_][A-Za-z0-9_]*)\1/)
    if (!match) continue

    return { index: i, length: match[0].length, delimiter: match[2]! }
  }

  return undefined
}

/**
 * Remove heredoc bodies (`<<EOF ... EOF`) from the command, returning the
 * bodies separately. Handles several heredocs on one line and quoted or
 * `<<-` (tab-stripped) delimiters.
 */
function stripHeredocs(input: string): {
  text: string
  found: boolean
  bodies: string[]
} {
  const lines = input.split("\n")
  const kept: string[] = []
  const bodies: string[] = []
  let found = false

  for (let i = 0; i < lines.length; i += 1) {
    let rest = lines[i]!
    const delimiters: string[] = []

    for (;;) {
      const marker = findHeredoc(rest)
      if (!marker) break
      delimiters.push(marker.delimiter)
      rest = rest.slice(0, marker.index) + rest.slice(marker.index + marker.length)
    }

    if (delimiters.length === 0) {
      kept.push(lines[i]!)
      continue
    }

    found = true
    // Keep the command and redirections; drop the heredoc markers.
    kept.push(rest.replace(/\s+/g, " ").trim())

    for (const delimiter of delimiters) {
      const body: string[] = []
      i += 1
      while (i < lines.length && lines[i]!.trim() !== delimiter) {
        body.push(lines[i]!)
        i += 1
      }
      // `i` now points at the delimiter line, which is dropped with the body.
      bodies.push(body.join("\n"))
    }
  }

  return { text: kept.join("\n"), found, bodies }
}

/**
 * Split a command into executable segments on unquoted operators. Keeps
 * redirections and substitutions inside their segment.
 *
 * Command and process substitutions (`$(…)`, `` `…` ``, `<(…)`, `>(…)`) are
 * tracked so a pipe inside them is not mistaken for a pipe of the outer
 * command — otherwise `$(curl x | sh)` would look like an ordinary `curl`.
 */
function splitSegments(input: string): {
  segments: Array<{ command: string; operator?: string }>
  substitution: boolean
} {
  const segments: Array<{ command: string; operator?: string }> = []
  let current = ""
  let operator: string | undefined
  let quote: '"' | "'" | null = null
  let escaped = false
  let depth = 0
  let backtick = false
  let substitution = false

  const push = () => {
    const command = current.trim()
    if (command) segments.push({ command, operator })
    current = ""
    operator = undefined
  }

  for (let i = 0; i < input.length; i += 1) {
    const char = input[i]!

    if (escaped) {
      current += char
      escaped = false
      continue
    }

    if (quote) {
      current += char
      if (char === quote) quote = null
      continue
    }

    if (backtick) {
      current += char
      if (char === "`") backtick = false
      continue
    }

    if (char === "\\") {
      current += char
      escaped = true
      continue
    }

    if (char === '"' || char === "'") {
      quote = char
      current += char
      continue
    }

    const two = input.slice(i, i + 2)

    if (char === "`") {
      substitution = true
      backtick = true
      current += char
      continue
    }

    if (two === "$(" || two === "<(" || two === ">(") {
      substitution = true
      depth += 1
      current += two
      i += 1
      continue
    }

    if (depth > 0) {
      if (char === "(") depth += 1
      else if (char === ")") depth -= 1
      current += char
      continue
    }

    if (two === "&&" || two === "||") {
      push()
      operator = two
      i += 1
      continue
    }

    // `|&` pipes stderr too; treat it as a normal pipe.
    if (two === "|&") {
      push()
      operator = "|"
      i += 1
      continue
    }

    // `&>` is a redirect, not a background job.
    if (two === "&>") {
      current += two
      i += 1
      continue
    }

    if (char === "&") {
      // `2>&1`, `>&2`: the ampersand belongs to a redirection.
      const prev = current.slice(-1)
      if (prev === ">" || prev === "<") {
        current += char
        continue
      }
      push()
      operator = "&"
      continue
    }

    if (char === ";" || char === "|" || char === "\n") {
      push()
      operator = char === "\n" ? ";" : char
      continue
    }

    current += char
  }

  push()
  return { segments, substitution }
}

/** Strip surrounding quotes from a single shell word. */
function unquote(word: string): string {
  const trimmed = word.trim()
  if (
    (trimmed.startsWith('"') && trimmed.endsWith('"')) ||
    (trimmed.startsWith("'") && trimmed.endsWith("'"))
  ) {
    return trimmed.slice(1, -1)
  }
  return trimmed
}

/** Compute the effective cwd after a `cd` segment, when statically knowable. */
function applyCd(cwd: string, command: string, home: string): string {
  // Allow a leading subshell/group marker: `(cd /tmp && …)`, `{ cd /tmp; …; }`.
  const match = command.replace(/^[({]\s*/, "").match(/^cd(?:\s+|\s*$)(.*)$/)
  if (!match) return cwd

  let target = unquote(match[1] ?? "")
  if (!target || target === "-") return cwd
  if (/\$|`/.test(target)) return cwd // dynamic, not statically knowable

  if (target === "~") target = home
  else if (target.startsWith("~/")) target = `${home}${target.slice(1)}`

  if (isAbsolute(target)) return resolve(target)
  return resolve(cwd, target)
}

/** Characters that reorder or hide text: bidi overrides, joiners, BOM. */
const HIDDEN_CHARACTERS = /[\u200B\u202A-\u202E\u2060\u2066-\u2069\uFEFF]/

function detectFlags(scan: {
  command: string
  comments: string[]
  heredocs: string[]
  heredoc: boolean
  substitution: boolean
}): string[] {
  const flags: string[] = []
  if (scan.comments.length > 0) flags.push("comment")
  if (scan.heredoc) flags.push("heredoc")
  if (scan.substitution) flags.push("command_substitution")

  // Comments and heredoc bodies are stripped before the judge sees the command
  // line, but they are exactly where instruction smuggling lives, so scan them.
  const scanned = `${scan.comments.join("\n")}\n${scan.heredocs.join("\n")}\n${scan.command}`

  if (/base64\s+(-d|--decode|-D)\b/.test(scanned) || /\bxxd\s+-r\b/.test(scanned)) {
    flags.push("encoded_payload")
  }
  if (/(^|\s)[A-Za-z0-9+/]{120,}={0,2}(\s|$)/.test(scanned)) flags.push("encoded_payload")

  // Only a verdict-like assignment counts as smuggling. Bare `verdict:` in
  // ordinary code (JSON keys, object literals) must not trip this.
  if (
    /\b(score|verdict|decision|confidence)\s*[=:]\s*["'`]?(allow|deny|escalate|approve|pass|true|1)\b/i.test(
      scanned,
    ) ||
    /ignore\s+(all\s+)?(previous|prior|above)\b/i.test(scanned) ||
    // Chat-template markers and role headers. A header only counts at a line
    // start, after an operator, or as the start of a quoted string, so
    // `echo system:foo` stays ordinary while `'system: …'` trips.
    /(?:^|\n|[;&|]\s*|["'`])\s*(?:system|assistant|developer)\s*:/i.test(scanned) ||
    /\[inst\]|\[\/inst\]|<\|im_start\|>|<\|im_end\|>|<<sys>>/i.test(scanned) ||
    /\byou are (an?|the) (ai|assistant|model|agent|language model|system)\b/i.test(scanned) ||
    // `\b` only works after a word character, so each alternative ends on one.
    /\b(?:permission granted|do not block|allow this command(?:-line)?|approve this command(?:-line)?|user explicitly (?:approved|authorized|requested))\b/i.test(
      scanned,
    )
  ) {
    flags.push("instruction_phrase")
  }

  if (HIDDEN_CHARACTERS.test(scanned)) flags.push("obfuscated_text")

  // `eval` as a command, not the substring in a path like test/eval.ts.
  if (/(?:^|[;&|]\s*)eval(?:\s|$)/m.test(scanned)) flags.push("dynamic_eval")

  // Piping a download into an interpreter (or `source`ing one).
  if (
    /\b(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?((ba|z|da|k)?sh|python[0-9.]*|node|deno|perl|ruby|php)\b/.test(
      scanned,
    )
  ) {
    flags.push("download_execute")
  }

  return [...new Set(flags)]
}

export function analyzeCommand(raw: string, options: AnalyzeOptions): CommandAnalysis {
  const home = options.home ?? process.env.HOME ?? "~"
  const { text: withoutComments, comments } = stripComments(raw)
  const { text: withoutHeredocs, found: heredoc, bodies } = stripHeredocs(withoutComments)

  const { segments, substitution } = splitSegments(withoutHeredocs)
  const subcommands: Subcommand[] = []
  let cwd = options.baseCwd

  for (const segment of segments) {
    const effective = cwd
    cwd = applyCd(cwd, segment.command, home)
    subcommands.push({
      command: segment.command,
      cwd: effective,
      ...(segment.operator ? { operator: segment.operator } : {}),
    })
  }

  // Keep the operator that actually joined each segment: `curl x | sh` must not
  // read as `curl x ; sh`, and `a || b` must not read as `a ; b`.
  const sanitized = subcommands
    .map((entry, index) =>
      index === 0 ? entry.command : `${entry.operator ?? ";"} ${entry.command}`,
    )
    .join(" ")

  const flags = detectFlags({
    command: withoutHeredocs,
    comments,
    heredocs: bodies,
    heredoc,
    substitution,
  })
  const stripped = comments.length > 0 || heredoc || sanitized.trim() !== raw.trim()

  return {
    sanitized,
    stripped,
    comments,
    heredocs: bodies,
    subcommands,
    flags,
    tripwire: flags.some((flag) => TRIPWIRE_FLAGS.has(flag)),
  }
}
