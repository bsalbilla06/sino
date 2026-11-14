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
    // The directory can be auto-discovered and also listed in `plugins` for its
    // options; never register the hooks twice.
    if (running) return () => running?.stop()

    const guard = createGuard(ctx, loadOptions(ctx.options))
    await guard.start()
    running = guard
    return () => guard.stop()
  },
})
