import { describe, expect, test } from "bun:test"
import plugin from "../src/index"

type Hook = (event: any) => unknown

/**
 * The plugin entrypoint is the piece OpenCode loads. A config reload loads the
 * new instance before disposing the old one, and a directory can also be loaded
 * twice (discovery plus an explicit `plugins` entry). Either way setup must
 * leave exactly one live set of hooks, and a stale cleanup must not stop the
 * guard that replaced it.
 */
function createFakeContext() {
  const state = {
    registered: 0,
    disposed: 0,
    hooks: {} as Record<string, Hook>,
  }

  const registration = {
    dispose: async () => {
      state.disposed += 1
    },
  }

  const register = (name: string, callback: Hook) => {
    state.registered += 1
    state.hooks[name] = callback
    return registration
  }

  const ctx = {
    location: { directory: "/Users/test/project" },
    options: { enforce: false },
    storage: { set: async () => {} },
    session: { hook: async (name: string, callback: Hook) => register(`session:${name}`, callback) },
    tool: { hook: async (name: string, callback: Hook) => register(`tool:${name}`, callback) },
    permission: {
      hook: async (name: string, callback: Hook) => register(`permission:${name}`, callback),
    },
    experimental: { generate: { decisions: async () => ({}) } },
  }

  return { ctx: ctx as any, state }
}

describe("plugin entrypoint", () => {
  test("a duplicate load replaces the previous hooks instead of stacking them", async () => {
    const first = createFakeContext()
    await plugin.setup(first.ctx)

    const second = createFakeContext()
    await plugin.setup(second.ctx)

    // The first instance was torn down, so exactly one live hook per event.
    expect(first.state.disposed).toBe(3)
    expect(second.state.registered).toBe(3)
    expect(second.state.disposed).toBe(0)

    // Clean up module state for other tests.
    await plugin.setup(createFakeContext().ctx)
  })

  test("the old cleanup does not stop the guard that replaced it", async () => {
    const first = createFakeContext()
    const disposeFirst = await plugin.setup(first.ctx)

    const second = createFakeContext()
    const disposeSecond = await plugin.setup(second.ctx)

    // A reload can dispose the previous instance after the new setup ran.
    await (disposeFirst as () => Promise<void>)()
    expect(second.state.disposed).toBe(0)

    // The live guard still tears itself down when its own cleanup runs.
    await (disposeSecond as () => Promise<void>)()
    expect(second.state.disposed).toBe(3)
  })

  test("setup registers hooks again after a full teardown", async () => {
    const first = createFakeContext()
    const disposeFirst = await plugin.setup(first.ctx)
    await (disposeFirst as () => Promise<void>)()

    const second = createFakeContext()
    await plugin.setup(second.ctx)
    expect(second.state.registered).toBe(3)

    await plugin.setup(createFakeContext().ctx)
  })
})
