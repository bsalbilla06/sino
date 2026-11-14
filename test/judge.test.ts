import { describe, expect, test } from "bun:test"
import { parseJudgeAnswers } from "../.opencode/plugins/sino/judge"

const options = { allowThreshold: 0.6 }

/** Two-level score answer: index 0 = Allow, index 1 = Deny. */
function score(levels: Array<[number, number]>, confidence = 0.9) {
  return {
    type: "score",
    name: "verdict",
    score: levels[0]?.[0] ?? 0,
    probabilities: levels.map(([value, probability]) => ({
      value,
      label: ["Allow", "Deny"][value],
      probability,
    })),
    confidence,
  }
}

describe("parseJudgeAnswers", () => {
  test("maps the top-probability level to a verdict", () => {
    const parsed = parseJudgeAnswers(
      {
        answers: [
          score([
            [0, 0.1],
            [1, 0.9],
          ]),
          { type: "choice", name: "reason", choice: "destructive_irreversible", confidence: 0.8 },
        ],
      },
      options,
    )

    expect(parsed.verdict).toBe("deny")
    expect(parsed.reasonCode).toBe("destructive_irreversible")
  })

  test("allows a decisive allow", () => {
    const parsed = parseJudgeAnswers(
      {
        answers: [
          score([
            [0, 0.95],
            [1, 0.05],
          ]),
          { type: "choice", name: "reason", choice: "within_intent_safe" },
        ],
      },
      options,
    )
    expect(parsed.verdict).toBe("allow")
  })

  test("denies an allow the model is split about", () => {
    const parsed = parseJudgeAnswers(
      {
        answers: [
          score(
            [
              [0, 0.5],
              [1, 0.5],
            ],
            0.9,
          ),
        ],
      },
      options,
    )
    expect(parsed.verdict).toBe("deny")
    expect(parsed.reasonCode).toBe("insufficient_confidence")
  })

  test("honours the threshold at the boundary", () => {
    const atThreshold = parseJudgeAnswers(
      {
        answers: [
          score([
            [0, 0.6],
            [1, 0.4],
          ]),
        ],
      },
      options,
    )
    const belowThreshold = parseJudgeAnswers(
      {
        answers: [
          score([
            [0, 0.59],
            [1, 0.41],
          ]),
        ],
      },
      options,
    )

    expect(atThreshold.verdict).toBe("allow")
    expect(belowThreshold.verdict).toBe("deny")
  })

  test("never softens a deny", () => {
    const parsed = parseJudgeAnswers(
      {
        answers: [
          score(
            [
              [0, 0.2],
              [1, 0.5],
            ],
            0.3,
          ),
        ],
      },
      options,
    )
    expect(parsed.verdict).toBe("deny")
  })

  test("fails closed on error answers", () => {
    const parsed = parseJudgeAnswers(
      { answers: [{ type: "error", name: "verdict", reason: "refusal" }] },
      options,
    )
    expect(parsed.verdict).toBe("deny")
    expect(parsed.reasonCode).toBe("judge_error")
  })

  test("fails closed on malformed results", () => {
    expect(parseJudgeAnswers({}, options).verdict).toBe("deny")
    expect(parseJudgeAnswers(null, options).verdict).toBe("deny")
  })

  test("treats a stale three-level escalate answer as a deny", () => {
    // Defensive: if a deployment still returns the old Escalate level, it must
    // not become a runnable command.
    const parsed = parseJudgeAnswers(
      {
        answers: [
          {
            type: "score",
            name: "verdict",
            score: 2,
            probabilities: [{ value: 2, probability: 0.8 }],
            confidence: 0.8,
          },
        ],
      },
      options,
    )
    expect(parsed.verdict).toBe("deny")
  })

  test("allows a decisive allow even when the API reports confidence 0", () => {
    // Observed with bun test / cat / git diff: Allow 0.66, Deny 0.02,
    // confidence 0.01. The distribution is decisive; the field is not.
    const parsed = parseJudgeAnswers(
      {
        answers: [
          score(
            [
              [0, 0.66],
              [1, 0.02],
            ],
            0.01,
          ),
          {
            type: "choice",
            name: "reason",
            choice: "within_intent_safe",
            confidence: 0.76,
          },
        ],
      },
      options,
    )
    expect(parsed.verdict).toBe("allow")
  })

  test("keeps the reason the model chose for an allow", () => {
    // A bounded delete is destructive in nature but allowable in scope; the
    // reason describes the command, not the verdict.
    const parsed = parseJudgeAnswers(
      {
        answers: [
          score(
            [
              [0, 0.94],
              [1, 0.06],
            ],
            0.87,
          ),
          {
            type: "choice",
            name: "reason",
            choice: "destructive_irreversible",
            confidence: 0.72,
          },
        ],
      },
      options,
    )
    expect(parsed.verdict).toBe("allow")
    expect(parsed.reasonCode).toBe("destructive_irreversible")
    expect(parsed.reasonConfidence).toBe(0.72)
  })

  test("keeps a specific deny reason even when the choice is close", () => {
    const parsed = parseJudgeAnswers(
      {
        answers: [
          score(
            [
              [0, 0.03],
              [1, 0.97],
            ],
            0.6,
          ),
          {
            type: "choice",
            name: "reason",
            choice: "destructive_irreversible",
            confidence: 0.42,
            probabilities: [
              { value: "outside_user_intent", probability: 0.4 },
              { value: "destructive_irreversible", probability: 0.5 },
            ],
          },
        ],
      },
      options,
    )
    expect(parsed.verdict).toBe("deny")
    expect(parsed.reasonCode).toBe("destructive_irreversible")
  })

  test("falls back to the verdict's own reason when none is returned", () => {
    const allow = parseJudgeAnswers({ answers: [score([[0, 0.9], [1, 0.1]])] }, options)
    const deny = parseJudgeAnswers({ answers: [score([[0, 0.1], [1, 0.9]])] }, options)

    expect(allow.reasonCode).toBe("within_intent_safe")
    expect(deny.reasonCode).toBe("outside_user_intent")
  })

  test("uses a bare score when probabilities are absent", () => {
    const allow = parseJudgeAnswers(
      { answers: [{ type: "score", name: "verdict", score: 0, confidence: 0.9 }] },
      options,
    )
    const deny = parseJudgeAnswers(
      { answers: [{ type: "score", name: "verdict", score: 1, confidence: 0.9 }] },
      options,
    )

    expect(allow.verdict).toBe("allow")
    expect(deny.verdict).toBe("deny")
  })
})
