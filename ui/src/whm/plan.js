import { normalizeBlocker } from '../shared/findings.js'
import { toMillis } from '../shared/format.js'

// A cutover plan (plan.latest: plans/<id>.json written by `install --prepare`, Deployment\CutoverPlan) in
// the shape the Switch center shows. Hybrid vhosts are {vhost, reasons} (or bare names, whose reasons
// then come from an embedded compile summary). The digest the cutover action echoes back is the plan
// file's SHA-256 that plan.latest reports (never the compile digest inside the plan).
const strings = value => (Array.isArray(value) ? value.map(String) : null)

/**
 * The plan in a `plan.latest` reply: `{plan: {id, digest, modified_at, valid, content} | null}`. The digest
 * is the SHA-256 of the plan file, which is what `ols.cutover` binds to. Returns null without a plan, and
 * `{id, digest, valid: false}` for a plan file that is not readable JSON.
 */
export function planFromLatest(reply) {
  const plan = reply && typeof reply === 'object' && 'plan' in reply ? reply.plan : reply
  if (!plan || typeof plan !== 'object' || typeof plan.id !== 'string') return null
  if (!('content' in plan)) return plan
  const content = plan.content && typeof plan.content === 'object' ? plan.content : {}
  return { ...content, id: plan.id, digest: plan.digest, created: content.created ?? plan.modified_at, valid: plan.valid !== false }
}

export function normalizePlan(plan) {
  if (!plan || typeof plan !== 'object' || typeof plan.id !== 'string') return null
  const summary = plan.summary && typeof plan.summary === 'object' ? plan.summary : {}
  const perVhost = summary.htaccess_blockers && typeof summary.htaccess_blockers === 'object' ? summary.htaccess_blockers : {}
  const hybrid = (Array.isArray(plan.hybrid_vhosts) ? plan.hybrid_vhosts : summary.hybrid_vhosts || []).map(item => {
    const vhost = typeof item === 'string' ? item : String(item?.vhost ?? '')
    const reasons = typeof item === 'object' && Array.isArray(item?.reasons) ? item.reasons : perVhost[vhost] || []
    return { vhost, reasons: reasons.map(normalizeBlocker) }
  })
  // HR-D14: a site held on its previous configuration (or left out) while the rest updates normally.
  const heldRaw = summary.held_vhosts && typeof summary.held_vhosts === 'object' ? summary.held_vhosts : {}
  const held = Object.entries(heldRaw).map(([vhost, why]) => ({ vhost, reasons: Array.isArray(why) ? why.map(String) : [String(why)] }))
  const blockers = (Array.isArray(plan.blockers) ? plan.blockers : []).map(item => {
    const vhost = typeof item === 'object' && item ? item.vhost ?? null : null
    return { vhost, ...normalizeBlocker(item) }
  })
  const vhosts = Number.isInteger(plan.vhost_count) ? plan.vhost_count
    : Array.isArray(plan.vhosts) ? plan.vhosts.length : null
  const ports = Array.isArray(plan.profile?.hybrid_ports) ? plan.profile.hybrid_ports
    : Array.isArray(plan.hybrid_ports) ? plan.hybrid_ports : null
  const digest = typeof plan.digest === 'string' && /^[0-9a-f]{64}$/.test(plan.digest) ? plan.digest : null
  return {
    id: plan.id,
    valid: plan.valid !== false,
    digest,
    createdAt: toMillis(plan.created ?? plan.created_at),
    profile: ports && ports.length ? 'hybrid' : 'native',
    ports: ports && ports.length ? ports : null,
    vhosts,
    hybrid,
    held,
    olsVhosts: vhosts === null ? null : vhosts - hybrid.length,
    blockers,
    certification: strings(plan.certification_blockers) || [],
    hostChanges: strings(plan.host_changes) || [],
    backups: strings(plan.backups_needed ?? plan.backups),
    olsPackage: typeof plan.ols_package === 'string' ? plan.ols_package : null,
    checks: Array.isArray(plan.checks) ? plan.checks.filter(c => c && typeof c === 'object') : [],
  }
}
