import { cutOver, serverEngine } from '../shared/engine.js'

// Product-state health for the operator: plain statements derived from the status operation, the PHP
// environment and the platform facts of the doctor report. Nothing here reads the qualification data.
// Each statement is {key, tone, params, link}; the view turns `key` into text (whm.health.<key>).

const OS_NAMES = { almalinux: 'AlmaLinux', rocky: 'Rocky Linux', cloudlinux: 'CloudLinux' }
const SUPPORTED_MAJORS = [8, 9]

/** Platform facts of a doctor report: {os, cpanel, supported} or null when nothing usable was observed. */
export function platformFacts(report) {
  const osValue = report?.platform?.os?.value
  const id = typeof osValue?.ID === 'string' ? osValue.ID.toLowerCase() : null
  const version = typeof osValue?.VERSION_ID === 'string' ? osValue.VERSION_ID : null
  const cpanelRaw = report?.platform?.cpanel?.value
  const cpanel = typeof cpanelRaw === 'string' && /^\d+\.\d+/.test(cpanelRaw) ? cpanelRaw.split('.').slice(0, 2).join('.') : null
  if (!id || !version || !cpanel) return null
  const major = parseInt(version, 10)
  const arch = report?.runtime?.architecture
  const php = String(report?.runtime?.php ?? '').split('.').map(n => parseInt(n, 10))
  const phpOk = php[0] > 8 || (php[0] === 8 && php[1] >= 4)
  const supported = id in OS_NAMES && SUPPORTED_MAJORS.includes(major) && arch === 'x86_64' && phpOk
  return { os: `${OS_NAMES[id] || id} ${version}`, cpanel, supported }
}

export function healthStatements(status, php, doctorReport) {
  const out = []
  const engine = serverEngine(status)
  const switched = cutOver(status)
  if (status && typeof status === 'object') {
    if (engine === 'ols' && status.ols_active !== false) out.push({ key: 'serving', tone: 'ok' })
    else if (switched === true) out.push({ key: 'notAnswering', tone: 'warn' })
    else if (engine === 'apache') out.push({ key: 'apacheServing', tone: 'info' })
    else if (engine === 'none') out.push({ key: 'noneServing', tone: 'warn' })
    if (switched === true) {
      const events = status.pending_events
      const pending = Array.isArray(events) ? events.length : Number.isInteger(events) ? events : 0
      out.push(pending > 0 ? { key: 'configUpdating', tone: 'pending', params: { n: pending } } : { key: 'configCurrent', tone: 'ok' })
    }
    const hybrid = Array.isArray(status.hybrid_vhosts) ? status.hybrid_vhosts.length : 0
    if (hybrid > 0) out.push({ key: 'hybrid', tone: 'info', params: { n: hybrid }, link: 'accounts' })
  }
  const versions = php?.environment?.versions
  if (Array.isArray(versions) && versions.length) {
    const open = versions.filter(v => v?.status !== 'complete').length
    out.push(open === 0 ? { key: 'phpComplete', tone: 'ok' } : { key: 'phpRepairing', tone: 'pending', params: { n: open }, link: 'php' })
  }
  const facts = platformFacts(doctorReport)
  if (facts) out.push({ key: facts.supported ? 'platformSupported' : 'platformOutside', tone: facts.supported ? 'ok' : 'warn', params: facts })
  return out
}
