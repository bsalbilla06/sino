import { Plugin } from "@opencode/plugin"
import { loadOptions } from "./options"
import { createGuard } from "./guard"

/**
 * sino: routes every shell command the agent proposes to a decision
 * model and enforces allow / deny before any shell is spawned.
 */
let running: { stop(): Promise<void> } | undefined

export default Plugin.define({
  id: "sino",
  async setup(ctx) {
    // A directory can be auto-discovered and also listed in `plugins` for its
    // options, and a config reload loads a new instance before disposing the
    // old one. Keep exactly one guard: a duplicate load replaces the previous
    // hooks instead of stacking them, and a stale cleanup cannot tear down the
    // guard that replaced it.
    if (running) {
      const previous = running
      running = undefined
      await previous.stop()
    }

    const guard = createGuard(ctx, loadOptions(ctx.options))
    await guard.start()
    running = guard
    return async () => {
      await guard.stop()
      if (running === guard) running = undefined
    }
  },
})
