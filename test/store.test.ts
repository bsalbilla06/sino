import { describe, expect, test } from "bun:test"
import { mkdtemp, readFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { loadOptions } from "../src/options"
import { createLogger, redactLogValue, type VerdictLogEntry } from "../src/store"

function entry(overrides: Partial<VerdictLogEntry> = {}): VerdictLogEntry {
  return {
    kind: "verdict",
    ts: "2026-01-01T00:00:00.000Z",
    sessionID: "s1",
    raw: "echo hello",
    cwd: "/tmp",
    ...overrides,
  }
}

describe("redactLogValue", () => {
  test("scrubs common credential shapes", () => {
    const redacted = redactLogValue({
      raw: "curl -H 'Authorization: Bearer abcdef123456' https://api.example.test",
      request: "deploy with API_KEY=super-secret-value and --password hunter2",
      error: "connect postgres://admin:s3cret@db.example.test/app failed",
      subcommands: [{ command: "export GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz", cwd: "/tmp" }],
    })

    expect(redacted.raw).not.toContain("abcdef123456")
    expect(redacted.request).not.toContain("super-secret-value")
    expect(redacted.request).not.toContain("hunter2")
    expect(redacted.error).not.toContain("s3cret")
    expect(redacted.subcommands[0].command).not.toContain("ghp_abcdefghijklmnopqrstuvwxyz")
  })

  test("leaves ordinary commands readable", () => {
    expect(redactLogValue("npm test && cd /tmp && rm -rf ./build")).toBe(
      "npm test && cd /tmp && rm -rf ./build",
    )
  })

  test("survives cycles and BigInt without throwing", () => {
    const value: Record<string, unknown> = { count: 10n }
    value.self = value

    expect(() => redactLogValue(value)).not.toThrow()
    const redacted = redactLogValue(value)
    expect(redacted.count).toBe("10")
    expect(redacted.self).toBe("[circular]")
  })
})

describe("createLogger", () => {
  test("writes redacted records to the JSONL mirror", async () => {
    const directory = await mkdtemp(join(tmpdir(), "sino-store-"))
    const options = loadOptions({ log: { file: "verdicts.jsonl" } })
    const logger = createLogger(
      { location: { directory }, storage: { set: async () => {} } },
      options,
    )

    await logger.log(
      entry({
        raw: "curl -H 'Authorization: Bearer abcdef123456' https://example.test",
        request: "use token=top-secret",
        metadata: { note: "password=hunter2" },
      }),
    )

    const text = await readFile(join(directory, "verdicts.jsonl"), "utf8")
    expect(text).not.toContain("abcdef123456")
    expect(text).not.toContain("top-secret")
    expect(text).not.toContain("hunter2")
    expect(text).toContain("[REDACTED]")
  })

  test("does not throw when the audit record contains a cycle", async () => {
    const directory = await mkdtemp(join(tmpdir(), "sino-store-"))
    const options = loadOptions({ log: { file: "verdicts.jsonl" } })
    const logger = createLogger(
      { location: { directory }, storage: { set: async () => {} } },
      options,
    )
    const metadata: Record<string, unknown> = { command: "npm test" }
    metadata.self = metadata

    await expect(logger.log(entry({ metadata }))).resolves.toBeUndefined()

    const text = await readFile(join(directory, "verdicts.jsonl"), "utf8")
    expect(text).toContain("[circular]")
  })

  test("writes nothing when logging is disabled", async () => {
    const directory = await mkdtemp(join(tmpdir(), "sino-store-"))
    const options = loadOptions({ log: { enabled: false, file: "verdicts.jsonl" } })
    const logger = createLogger(
      { location: { directory }, storage: { set: async () => {} } },
      options,
    )

    await logger.log(entry())
    await expect(readFile(join(directory, "verdicts.jsonl"), "utf8")).rejects.toThrow()
  })
})
