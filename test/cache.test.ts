import { describe, expect, test } from "bun:test"
import { SessionCache } from "../src/cache"

describe("SessionCache", () => {
  test("scopes verdicts to the current user request", () => {
    const cache = new SessionCache()
    cache.startRequest("s1", "install drivers and reboot")
    cache.set("s1", "/tmp", "reboot", {
      verdict: "allow",
      reasonCode: "within_intent_safe",
      confidence: 0.9,
    })

    expect(cache.get("s1", "/tmp", "reboot")?.verdict).toBe("allow")

    cache.startRequest("s1", "install docker")
    expect(cache.get("s1", "/tmp", "reboot")).toBeUndefined()
    expect(cache.request("s1")).toBe("install docker")
  })

  test("keys by cwd as well as command text", () => {
    const cache = new SessionCache()
    cache.startRequest("s1", "clean temp")
    cache.set("s1", "/tmp", "rm -rf *", {
      verdict: "allow",
      reasonCode: "within_intent_safe",
      confidence: 0.9,
    })

    expect(cache.get("s1", "/tmp", "rm -rf *")?.verdict).toBe("allow")
    expect(cache.get("s1", "/Users/me/repo", "rm -rf *")).toBeUndefined()
  })

  test("caches denials as well as allows", () => {
    const cache = new SessionCache()
    cache.startRequest("s1", "do something")

    cache.set("s1", "/tmp", "rm -rf /", {
      verdict: "deny",
      reasonCode: "destructive_irreversible",
      confidence: 0.9,
    })

    expect(cache.get("s1", "/tmp", "rm -rf /")?.verdict).toBe("deny")
  })

  test("isolates sessions", () => {
    const cache = new SessionCache()
    cache.startRequest("s1", "one")
    cache.startRequest("s2", "two")

    cache.set("s1", "/tmp", "ls", {
      verdict: "allow",
      reasonCode: "within_intent_safe",
      confidence: 0.9,
    })

    expect(cache.get("s2", "/tmp", "ls")).toBeUndefined()
  })
})
