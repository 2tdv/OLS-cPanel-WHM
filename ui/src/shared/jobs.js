import { i18n } from './i18n.js'

const STATES = ['running', 'done', 'failed']

export function jobTone(state) {
  return { running: 'pending', done: 'ok', failed: 'bad' }[state] || 'neutral'
}

export function jobStateLabel(state) {
  return i18n.global.t(`jobs.state.${STATES.includes(state) ? state : 'unknown'}`)
}

/** "ols.cutover" -> the catalog's "Cut over to OpenLiteSpeed"; unknown actions are shown as sent. */
export function actionLabel(action) {
  const key = `actions.${String(action || '').replace(/[^a-z_]/g, '_')}`
  return i18n.global.te(key) ? i18n.global.t(key) : String(action || i18n.global.t('state.unknown'))
}

/** The running job in a job.list reply, if any (one job at a time). */
export function runningJob(list) {
  const jobs = Array.isArray(list) ? list : list?.jobs
  return Array.isArray(jobs) ? jobs.find(j => j?.state === 'running') || null : null
}

export function jobRows(list) {
  const jobs = Array.isArray(list) ? list : list?.jobs
  return Array.isArray(jobs) ? jobs : []
}
