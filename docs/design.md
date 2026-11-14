# Design notes

How sino decides, and why it is built this way.

## Verdict handling

The judge scores `Allow` and `Deny`, then answers a separate reason question. The plugin:

- takes the highest-probability level as the verdict,
- never softens a `Deny`, regardless of confidence,
- turns an `Allow` whose top probability is below `allowThreshold` (default `0.55`) into a `Deny`
  with reason `insufficient_confidence`,
- keeps the model's reason otherwise.

The reason describes the command, not the verdict, so an `Allow` can legitimately carry
`destructive_irreversible` for a bounded delete.

`allowThreshold` gates on the probability of the winning level, not on the endpoint's `confidence`
field. That field is not usable as a gate: GPT-6-Luna has returned `confidence: 0.01` for an Allow
scored `Allow=0.66 / Deny=0.34` with a confidently safe reason, while returning `0.97` for a
near-certain Allow. When the endpoint returns no probability distribution, the gate falls back to
`confidence`. Verdicts are deterministic for a given policy and input, so the policy — not the
threshold — is the place to fix a systematically wrong verdict.

Normal verdict records log both numbers (`confidence`, the endpoint field, and `probability`, the
winning level), so calibration stays visible without replaying a command; observe-mode and
`guard_exception` records may omit them. Commands, prompts, and error strings are redacted before a
record is written. In live use, routine commands land at `0.88`–`1.00`, while a borderline command
under a vague request lands near `0.6`.

## The deny → ask → retry loop

A denial message names the reason and the current request, and carries:

> If this command is required, ask the user to approve it explicitly, then retry.

That hint is added only for reasons a user approval can resolve (intent, scope, privilege,
credential access, low confidence, tripwire), not for transport failures. When the user approves,
their message becomes the new request, the per-request cache resets, and the judge re-evaluates
with the approval as trusted intent.

Because the cache is scoped to one request, retrying the identical command inside the same request
stays denied. That is what makes the loop ask the user instead of spinning.

A third "ask" verdict was rejected by design: non-interactive sessions would auto-approve it, which
is a silent allow. The verdict is binary on purpose.

## Tripwire

Comments, heredoc bodies, encoded payloads, instruction-like text, and hidden characters raise a
tripwire that skips the model and denies.

| Flag | Trips | Notes |
|---|---|---|
| `comment` | any shell comment | comment bodies are scanned for the markers below |
| `heredoc` | any heredoc | bodies are captured, not lost |
| `encoded_payload` | `base64 -d`, `xxd -r`, very long base64 | |
| `instruction_phrase` | `score=Allow`, `verdict: deny`, `ignore previous`, line-start `system:`, chat-template tokens, `permission granted`, `user explicitly approved` | verdict-like **assignments** only; `verdict:e.verdict` in ordinary code does not trip |
| `obfuscated_text` | bidi overrides, zero-width space, BOM | emoji ZWJ sequences are fine |

These are context flags, not tripwires — the judge weighs them:

| Flag | Meaning |
|---|---|
| `command_substitution` | `$(…)`, backticks, or `<(…)` present |
| `dynamic_eval` | `eval` used as a command |
| `download_execute` | `curl`/`wget` piped into `sh`, `python`, `node`, `perl`, `ruby`, or `php` |

`echo "left << right"` is not a heredoc, `wc -c <<< hello` is not a heredoc, and `echo system:foo`
is not a role header. Those were false trips in earlier versions and are covered by tests now.

With `"denyOnTripwire": false`, stripped comments and heredoc bodies are included in the judge input
under explicitly untrusted headings, so nothing the model needs is hidden from it.

## Failure containment

The hook has two layers of protection against its own bugs:

- inside `permission.evaluate`, any internal error becomes a deny for that one command with
  `sino failed closed: …`;
- a non-shell tool (`read`, `edit`, `grep`) is never judged, and a call stashed by the shell tool is
  judged even if OpenCode renames the action, so a rename cannot silently bypass the guard.

An earlier build threw before that boundary existed, which broke every tool in the session, not just
shell commands. `test/guard.test.ts` asserts that non-shell tools are untouched.

## Credentials and models

- `generate.decisions` rejects chat models (`UnsupportedModelError`). Use a model whose provider
  supports the decision capability (`opencode/jev-1.13` in the OpenCode catalog), or use `fetch`.
- `fetch` expects the OpenAI decision shape:

  ```json
  { "model": "gpt-6-luna", "input": "…", "questions": [ … ] }
  ```

  and resolves the API key in this order:

  1. the environment variable named by `apiKeyEnv` (`OPENAI_API_KEY`),
  2. the file at `apiKeyFile` (when set),
  3. the argv at `apiKeyCommand` (when set) — useful when the key lives in `~/.zshenv` and OpenCode
     was started without that environment.

  The resolved key is cached for the life of the server process.
- There are no static shell deny rules in this setup; the decision model is the gate.

The OpenCode server often does not inherit `~/.zshenv`, so an `apiKeyCommand` probe keeps shell-only
keys usable. With `"transport": "fetch"` and no credential available, every shell command fails
closed; `"auto"` behaves the same when the plugin transport cannot answer. That is the configured
policy, not a bug.

## Observe mode

Set `"enforce": false` to log without gating while developing or provisioning credentials, then
inspect what the scanner hands the hook:

```sh
bun run audit
```

Each record contains `resources` (the scanner's parsed subcommands), `metadata`, the raw command
when the tool input is available, and the current effect. The table also shows the winning level's
`probability` and latency, which is how calibration is checked without replaying a command.

## Verifying without credentials

`test/mock-decisions.ts` is a local `/decisions` stand-in. Point `fetch.baseURL` at
`http://127.0.0.1:8787/v1` and `apiKeyEnv` at `MOCK_KEY`, then:

```sh
bun run test/mock-decisions.ts &
MOCK_KEY=test opencode run --standalone -m opencode/deepseek-v4.1-flash-free \
  "Run echo guard-ok, then echo DENYME, with the shell tool."
```

`echo guard-ok` runs. `echo DENYME` is denied with a reason, and the agent continues.
