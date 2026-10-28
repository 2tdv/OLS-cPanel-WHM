// The cPanel dashboard's "Clear cache" icon purges when its page opens: a dashboard link can only navigate, and the one-click
// purge is what the icon is for. A reload or a back-navigation to that page within REPEAT_WINDOW_MS must not purge again, so
// the time and result of the last purge of this tab are kept in sessionStorage and shown instead. Storage can be missing or
// throw (private windows, blocked site data, previews): every access is guarded and then the page simply purges, as before.
export const PURGE_MEMORY_KEY = 'olsc.cpanel.purgeNow.last'
export const REPEAT_WINDOW_MS = 60000

/** sessionStorage of this tab, or null when the browser refuses it. */
export function sessionStore() {
  try {
    return globalThis.sessionStorage ?? null
  } catch {
    return null
  }
}

/** The purge of this tab less than REPEAT_WINDOW_MS ago: { at, removed } (removed may be null), or null. */
export function recentPurge(storage, now = Date.now()) {
  try {
    const raw = storage?.getItem(PURGE_MEMORY_KEY)
    if (!raw) return null
    const last = JSON.parse(raw)
    if (!Number.isFinite(last?.at) || now < last.at || now - last.at >= REPEAT_WINDOW_MS) return null
    return { at: last.at, removed: Number.isInteger(last.removed) && last.removed >= 0 ? last.removed : null }
  } catch {
    return null
  }
}

/** Records a successful purge (a failed one is not remembered, so opening the page again tries again). */
export function rememberPurge(storage, removed, now = Date.now()) {
  try {
    storage?.setItem(PURGE_MEMORY_KEY, JSON.stringify({ at: now, removed: Number.isInteger(removed) ? removed : null }))
  } catch {
    // storage refused: the next open purges again, which is the behaviour without memory
  }
}
