/**
 * Per-user-request verdict cache.
 *
 * A user request is one task: installing drivers (where `reboot` makes sense)
 * is a different request from installing Docker (where it does not). Verdicts
 * are therefore scoped to the current request and dropped whenever a new user
 * prompt is admitted.
 */

export interface CachedVerdict {
  verdict: "allow" | "deny"
  reasonCode: string
  confidence: number
  probability?: number
  reasonConfidence?: number
  transport?: string
}

interface RequestState {
  sequence: number
  request?: string
  entries: Map<string, CachedVerdict>
}

export class SessionCache {
  private sessions = new Map<string, RequestState>()

  startRequest(sessionID: string, request: string | undefined): void {
    const previous = this.sessions.get(sessionID)
    this.sessions.set(sessionID, {
      sequence: (previous?.sequence ?? 0) + 1,
      ...(request ? { request } : {}),
      entries: new Map(),
    })
  }

  request(sessionID: string): string | undefined {
    return this.sessions.get(sessionID)?.request
  }

  get(sessionID: string, cwd: string, sanitized: string): CachedVerdict | undefined {
    return this.sessions.get(sessionID)?.entries.get(this.key(cwd, sanitized))
  }

  set(
    sessionID: string,
    cwd: string,
    sanitized: string,
    verdict: CachedVerdict,
  ): void {
    const state = this.sessions.get(sessionID)
    if (!state) return
    state.entries.set(this.key(cwd, sanitized), verdict)
  }

  clear(sessionID?: string): void {
    if (sessionID) this.sessions.delete(sessionID)
    else this.sessions.clear()
  }

  private key(cwd: string, sanitized: string): string {
    return `${cwd}\u0000${sanitized}`
  }
}
