// Formatting helpers. Unknown stays unknown (UIX-01): every helper returns null for a missing or
// malformed value and the caller shows the catalog's "Unknown", never 0.

/** Epoch seconds, epoch milliseconds or an ISO 8601 text to epoch milliseconds. */
export function toMillis(value) {
  if (typeof value === 'number' && Number.isFinite(value) && value > 0) return value < 1e12 ? value * 1000 : value
  if (typeof value === 'string' && value) {
    if (/^\d+$/.test(value)) return toMillis(Number(value))
    const parsed = Date.parse(value)
    return Number.isNaN(parsed) ? null : parsed
  }
  return null
}

const dateTime = new Intl.DateTimeFormat('en', { dateStyle: 'medium', timeStyle: 'medium' })
const dateOnly = new Intl.DateTimeFormat('en', { dateStyle: 'medium' })
const number = new Intl.NumberFormat('en', { maximumFractionDigits: 1 })

export function formatDateTime(value) {
  const ms = toMillis(value)
  return ms === null ? null : dateTime.format(new Date(ms))
}

export function formatDate(value) {
  const ms = toMillis(value)
  return ms === null ? null : dateOnly.format(new Date(ms))
}

export function formatNumber(value) {
  return typeof value === 'number' && Number.isFinite(value) ? number.format(value) : null
}

const UNITS = ['B', 'KB', 'MB', 'GB', 'TB']
export function formatBytes(value) {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) return null
  let n = value
  let unit = 0
  while (n >= 1024 && unit < UNITS.length - 1) {
    n /= 1024
    unit++
  }
  return `${number.format(n)} ${UNITS[unit]}`
}

/** Age in whole units: { n, unit } with unit one of seconds/minutes/hours/days, or null. */
export function age(fromMs, nowMs) {
  if (fromMs === null || fromMs === undefined || nowMs === null) return null
  const seconds = Math.max(0, Math.round((nowMs - fromMs) / 1000))
  if (seconds < 60) return { n: seconds, unit: 'seconds' }
  if (seconds < 3600) return { n: Math.floor(seconds / 60), unit: 'minutes' }
  if (seconds < 86400) return { n: Math.floor(seconds / 3600), unit: 'hours' }
  return { n: Math.floor(seconds / 86400), unit: 'days' }
}

/** Certificate expiry class: 'expired', 'soon' (within warnDays), 'ok', or 'unknown'. */
export function certificateState(notAfter, nowMs, warnDays = 21) {
  const ms = toMillis(notAfter)
  if (ms === null) return { state: 'unknown', days: null }
  const days = Math.floor((ms - nowMs) / 86400000)
  if (ms <= nowMs) return { state: 'expired', days }
  return { state: days < warnDays ? 'soon' : 'ok', days }
}
