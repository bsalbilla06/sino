#!/usr/bin/env bun
/**
 * Local stand-in for the OpenAI `/v1/decisions` endpoint.
 *
 *   bun run test/mock-decisions.ts
 *
 * Denies anything in the COMMAND LINE section containing DENYME, `rm -rf /`, or
 * `evil.sh`; allows everything else. It answers with the same binary
 * Allow/Deny shape GPT-6-Luna returns, so this exercises the real parsing path.
 *
 * Tests import `startMockDecisions()` to bind an ephemeral port.
 */

export interface MockDecisions {
  /** Base URL including `/v1`, ready for `fetch.baseURL`. */
  url: string
  port: number
  /** Number of requests received, for cache and tripwire assertions. */
  requests: () => number
  /** Last decoded request body. */
  lastBody: () => Record<string, unknown> | undefined
  stop: () => void
}

export interface MockOptions {
  port?: number
  /** Delay each answer, for timeout tests. */
  delayMs?: number
}

export function startMockDecisions(options: MockOptions = {}): MockDecisions {
  let requests = 0
  let lastBody: Record<string, unknown> | undefined

  const server = Bun.serve({
    port: options.port ?? 8787,
    async fetch(request) {
      requests += 1

      if (request.method !== "POST") {
        return new Response("method not allowed", { status: 405 })
      }

      const body = (await request.json().catch(() => ({}))) as Record<string, unknown>
      lastBody = body

      const text = typeof body.input === "string" ? body.input : JSON.stringify(body.input ?? "")

      // The judge input contains the trusted request too; only the command
      // section participates in this mock's verdict.
      const commandSection =
        text.match(/COMMAND LINE[^\n]*\n([\s\S]*?)\n\n/)?.[1] ?? text

      if (options.delayMs) await Bun.sleep(options.delayMs)

      const deny = /denyme|rm -rf \/|evil\.sh/i.test(commandSection)
      const index = deny ? 1 : 0

      const answers = [
        {
          type: "score",
          name: "verdict",
          score: index,
          probabilities: [0, 1].map((value) => ({
            value,
            label: ["Allow", "Deny"][value],
            probability: value === index ? 0.96 : 0.04,
          })),
          confidence: 0.4,
        },
        {
          type: "choice",
          name: "reason",
          choice: deny ? "destructive_irreversible" : "within_intent_safe",
          confidence: 0.9,
        },
      ]

      return Response.json({ model: "mock", answers })
    },
  })

  return {
    url: `http://127.0.0.1:${server.port}/v1`,
    port: server.port,
    requests: () => requests,
    lastBody: () => lastBody,
    stop: () => server.stop(true),
  }
}

if (import.meta.main) {
  const mock = startMockDecisions({ port: Number(process.env.PORT ?? 8787) })
  console.log(`mock decisions endpoint listening on ${mock.url}/decisions`)
}
