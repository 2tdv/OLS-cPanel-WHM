// OLS_FIXTURE_TRANSPORT: development-only replacement of src/shared/transport.js (vite.config.js aliases
// it only with OLS_UI_FIXTURES=1 and --mode fixtures; production builds refuse both). It answers like the
// gateways (plugins/whm/index.cgi, plugins/cpanel/index.live.php) and the broker behind them
// (docs/product-interfaces.md, "As implemented by the broker"): the reply shapes of dev/fixtures, the query
// grammars (BAD_QUERY), the POST rules (REQUEST_HEADER, BAD_BODY, STALE, BUSY, 202 with {job}), job ids
// j<10 digits>-<8 hex>, observed_at in Unix seconds. Jobs run in memory so the switch flow can be walked.
//
// Scenarios (page query ?fixture=<name>): default (Apache, hybrid plan prepared), cutover (switched,
// hybrid), metrics-stale (switched, stale report), empty, unauthorized, session, error,
// metrics-unavailable, slow.
import whmStatus from './fixtures/whm/status.json'
import whmMetrics from './fixtures/whm/metrics.json'
import whmInventory from './fixtures/whm/inventory.json'
import whmCompat from './fixtures/whm/compat.json'
import whmPlan from './fixtures/whm/plan.json'
import whmGenerations from './fixtures/whm/generations.json'
import whmDoctor from './fixtures/whm/doctor.json'
import whmJobs from './fixtures/whm/jobs.json'
import whmJob from './fixtures/whm/job.json'
import whmAction from './fixtures/whm/action.json'
import whmCache from './fixtures/whm/cache.json'
import whmPhp from './fixtures/whm/php.json'
import whmCacheLimits from './fixtures/whm/cache_limits.json'
import whmObjcache from './fixtures/whm/objcache.json'
import whmAudit from './fixtures/whm/audit.json'
import whmNotify from './fixtures/whm/notify.json'
import whmSchedule from './fixtures/whm/schedule.json'
import whmUpdate from './fixtures/whm/update.json'
import whmBundle from './fixtures/whm/bundle.json'
import cpanelStatus from './fixtures/cpanel/status.json'
import cpanelSites from './fixtures/cpanel/sites.json'
import cpanelHtaccess from './fixtures/cpanel/htaccess.json'
import cpanelCache from './fixtures/cpanel/cache.json'
import cpanelPhp from './fixtures/cpanel/php.json'
import cpanelObjcache from './fixtures/cpanel/objcache.json'
import whmHistory from './fixtures/whm/history.json'
import cpanelHistory from './fixtures/cpanel/history.json'
import { historyReply } from './history.js'
import cpanelLogs from './fixtures/cpanel/logs.json'
import cpanelPhpErrors from './fixtures/cpanel/php_errors.json'
import cpanelPerf from './fixtures/cpanel/perf.json'
import cpanelRequests from './fixtures/cpanel/requests.json'
import cpanelBackups from './fixtures/cpanel/htaccess_backups.json'
import whmRequests from './fixtures/whm/requests.json'

export const FIXTURES = {
  whm: {
    status: whmStatus, metrics: whmMetrics, inventory: whmInventory, compat: whmCompat, plan: whmPlan,
    generations: whmGenerations, doctor: whmDoctor, jobs: whmJobs, job: whmJob, cache: whmCache, cache_limits: whmCacheLimits, objcache: whmObjcache, php: whmPhp,
    history: whmHistory, requests: whmRequests, audit: whmAudit, notify: whmNotify, schedule: whmSchedule, update: whmUpdate, bundle: whmBundle,
  },
  cpanel: {
    status: cpanelStatus, sites: cpanelSites, htaccess: cpanelHtaccess, cache: cpanelCache, php: cpanelPhp, objcache: cpanelObjcache,
    history: cpanelHistory, logs: cpanelLogs, php_errors: cpanelPhpErrors, perf: cpanelPerf, requests: cpanelRequests, htaccess_backups: cpanelBackups,
  },
  action: whmAction,
}
// plugins/cpanel/index.live.php: logs, PHP errors and the speed check of the account's own domains (the broker checks the domain).
function tenantTools(state, name, params, scenario) {
  const domains = FIXTURES.cpanel.sites.sites.map(site => site.domain)
  const domain = params.get('domain') ?? ''
  const allowed = name === 'logs' ? ['api', 'domain', 'kind', 'lines', 'search'] : ['api', 'domain']
  if (!PARAMS.domain.test(domain) || [...params.keys()].some(k => !allowed.includes(k)) || !['access', 'access_http', 'error'].includes(params.get('kind') ?? 'access')) {
    return fail(400, 'BAD_QUERY', 'Invalid query arguments for this API.')
  }
  if (!domains.includes(domain)) return fail(404, 'NOT_FOUND', 'that is not one of your domains')
  if (name === 'logs') {
    const kind = params.get('kind') ?? 'access'
    const search = params.get('search') ?? ''
    const all = Array.from({ length: 40 }, (_, i) => (kind === 'error'
      ? `2026-10-28 10:${String(i).padStart(2, '0')}:00.000 [NOTICE] [${domain}] request ${i} handled`
      : `${domain}:443 203.0.113.${i} - - [28/Oct/2026:10:${String(i).padStart(2, '0')}:00 +0000] "GET /page-${i}?token=[redacted] HTTP/2.0" 200 ${1000 + i}`))
    const n = Math.min(Number(params.get('lines') ?? 200), 500)
    const kept = all.filter(l => l.includes(search)).slice(-n)
    return ok({ ...clone(FIXTURES.cpanel.logs), domain, kind, file: `${domain}-ssl_log`, observed_at: nowSeconds(), search: search || null,
      exists: scenario !== 'empty', lines: kept, count: kept.length })
  }
  if (name === 'php_errors') {
    const report = clone(FIXTURES.cpanel.php_errors)
    return ok({ ...report, domain, observed_at: nowSeconds(), groups: scenario === 'empty' ? [] : report.groups })
  }
  return ok({ ...clone(FIXTURES.cpanel.perf), domain, observed_at: nowSeconds() })
}

// plugins/whm/index.cgi: ACTIONS (scope "server", a plan id, or a cache purge scope) and the query grammars.
const ACTION_SCOPES = {
  'ols.sync': 'server', 'ols.rollback': 'server', 'ols.plan': 'server', 'ols.plan_hybrid': 'server',
  'ols.cutover': 'plan', 'ols.apache_return': 'server', 'ols.cache_purge': 'cache', 'ols.php_restart': 'php_restart', 'ols.opcache_install': 'opcache', 'ols.php_env_repair': 'server',
  'ols.support_bundle': 'server', 'ols.support_bundle_raw': 'server', 'ols.update': 'server',
}
export const ACTION_NAMES = Object.keys(ACTION_SCOPES)
const API_PARAMS = { inventory: ['query', 'page', 'size'], compat: ['query', 'page', 'size'], job: ['job'], cache: ['account', 'domain'], cache_limits: [], objcache: [], php: [], history: ['resolution', 'vhost'],
  audit: ['query', 'page', 'size', 'event', 'result'], notify: [], schedule: [], update: ['refresh'], bundle: [] }
// plugins/whm/index.cgi CACHE_LIMITS: the settings of the automatic cache cleanup (POST ?action=cache_limits), inclusive bounds.
const CACHE_LIMIT_BOUNDS = { per_site_mb: [16, 102400], server_percent: [1, 50], server_max_gb: [1, 2048] }
const PARAMS = {
  query: /^[A-Za-z0-9._-]{0,253}$/, page: /^[1-9][0-9]{0,5}$/, size: /^(?:[1-9][0-9]?|1[0-9]{2}|200)$/,
  job: /^j[0-9]{10}-[0-9a-f]{8}$/, account: /^[a-z0-9][a-z0-9_-]{0,31}$/,
  domain: /^(?=.{3,253}$)[a-z0-9][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)+$/,
  vhost: /^(?=.{3,253}$)[a-z0-9][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)+$/, resolution: /^(?:hour|day|week)$/,
  event: /^[a-z_]{1,40}$/, result: /^(?:ok|failed)$/, refresh: /^1$/,
}
const CACHE_SCOPE = /^(?:server|account:[a-z0-9][a-z0-9_-]{0,31}|domain:(?=.{3,253}$)[a-z0-9][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)+)$/
const PHP_RESTART_SCOPE = /^(?:server|account:[a-z0-9][a-z0-9_-]{0,31})$/
const OPCACHE_SCOPE = /^(?:server|version:ea-php[0-9]{2,3})$/
const REQUEST_SUBJECTS = ['cache', 'php', 'htaccess', 'ssl', 'performance', 'logs', 'domains', 'other']
const TENANT_PURGE_SECONDS = 10
const TENANT_RESTART_SECONDS = 30
const clone = value => JSON.parse(JSON.stringify(value))
const nowSeconds = () => Math.floor(Date.now() / 1000)

// LSCache stores: the report of `ols-cpanel cache stats`, filtered and purged in memory.
function cacheTotals(stores) {
  const sum = key => stores.reduce((n, st) => n + st[key], 0)
  return { stores: stores.filter(st => st.present).length, entries: sum('entries'), bytes: sum('bytes'),
    private_entries: sum('private_entries'), private_bytes: sum('private_bytes') }
}
function selectStores(stores, { account, domain }) {
  return stores.filter(st => (!account || st.account === account) && (!domain || st.domains.includes(domain)))
}
function purgeStores(stores, selected) {
  const now = nowSeconds()
  const removed = clone(selected) // what the purge removed, counted before the stores are emptied
  for (const st of selected) {
    Object.assign(st, { public_entries: 0, public_bytes: 0, private_entries: 0, private_bytes: 0, entries: 0, bytes: 0 })
    if (st.present) st.last_purge = now
  }
  return { selected: removed, purged_at: now }
}
function scopeSelector(scope) {
  if (scope === 'server') return {}
  const [kind, value] = scope.split(/:(.*)/s)
  return kind === 'account' ? { account: value } : { domain: value }
}
const hex = n => Array.from({ length: n }, () => Math.floor(Math.random() * 16).toString(16)).join('')
const ok = (result, status = 200) => ({ status, body: { v: 1, ok: true, result } })
const fail = (status, code, message) => ({ status, body: { v: 1, ok: false, error: { code, message } } })

// Generated rows so paging and search can be tried at 10,000+ domains.
const ENGINES = ['ols', 'ols', 'ols', 'hybrid', 'apache', 'unknown']
function generatedDomains(count) {
  const rows = []
  for (let i = 0; i < count; i++) {
    const user = `acct${String(i % 2600).padStart(4, '0')}`
    const type = i < 2600 ? 'main' : ['sub', 'addon', 'parked'][i % 3]
    const domain = `site${i}.fixture-domain.test`
    rows.push({ user, domain, type, parent: domain, docroot: `/home/${user}/public_html${type === 'sub' ? `/s${i}` : ''}`,
      vhost: domain, engine: ENGINES[i % ENGINES.length], php_version: 'ea-php83', php: 'ea-php83',
      php_handler: i % 7 === 0 ? 'cgi' : 'fpm', tls: i % 5 !== 0, suspended: i % 97 === 0 })
  }
  return rows
}
function generatedCompat(count) {
  const rows = []
  for (let i = 0; i < count; i++) {
    const user = `acct${String(i % 2600).padStart(4, '0')}`
    rows.push({ vhost: `site${i}.fixture-domain.test`, user, docroot: `/home/${user}/public_html`, engine: 'hybrid', hybrid: true,
      findings: [{ kind: 'htaccess', severity: 'blocker', directory: '/', file: `/home/${user}/public_html/.htaccess`, line: null,
        key: 'htaccess.directive', message: `/: unsupported directive 'php_value memory_limit ${128 + (i % 4) * 64}M'` }] })
  }
  return rows
}

function createState(scenario) {
  const state = {
    status: clone(FIXTURES.whm.status),
    plan: clone(FIXTURES.whm.plan.plan),
    generations: clone(FIXTURES.whm.generations.output),
    jobs: clone(FIXTURES.whm.jobs.jobs),
    details: { [FIXTURES.whm.job.job]: clone(FIXTURES.whm.job) },
    domains: [...clone(FIXTURES.whm.inventory.domains), ...generatedDomains(12000)],
    compat: [...clone(FIXTURES.whm.compat.vhosts), ...generatedCompat(420)],
    cache: clone(FIXTURES.whm.cache.output),
    cacheLimits: clone(FIXTURES.whm.cache_limits.output),
    objcache: clone(FIXTURES.whm.objcache.output),
    cpanelCache: clone(FIXTURES.cpanel.cache),
    lastTenantPurge: 0,
    lastTenantRestart: 0,
    php: clone(FIXTURES.whm.php.output),
    cpanelPhp: clone(FIXTURES.cpanel.php),
    requests: clone(FIXTURES.whm.requests.requests).map(r => ({ ...r, created_at: nowSeconds() - 7200 })),
    changes: [],
    htaccessFixed: false,
    lastRequest: 0,
    audit: clone(FIXTURES.whm.audit.records),
    notify: clone(FIXTURES.whm.notify.output),
    schedule: clone(FIXTURES.whm.schedule.output),
    bundles: clone(FIXTURES.whm.bundle.bundles),
    updateChecked: FIXTURES.whm.update.output.checked_at,
    update: clone(FIXTURES.whm.update.output),
  }
  if (scenario === 'cutover' || scenario === 'metrics-stale') switchTo(state, true)
  if (scenario === 'empty') {
    Object.assign(state, { plan: null, jobs: [], domains: [], compat: [], audit: [], bundles: [], requests: [] })
    state.objcache.accounts = []
    state.schedule.entries = []
    state.cache = { ...state.cache, stores: [], totals: cacheTotals([]) }
    state.cpanelCache = { ...state.cpanelCache, stores: [], totals: cacheTotals([]) }
    state.generations = { active: null, generations: [] }
    state.php.opcache = { ...state.php.opcache, versions: [] }
    state.php.processes = { ...state.php.processes, accounts: [], totals: { accounts: 0, processes: 0, children: 0, rss_kb: 0, runaway: 0 } }
    state.cpanelPhp = { ...state.cpanelPhp, sites: [], opcache: [], processes: null }
  }
  return state
}

function switchTo(state, olsOn) {
  const s = state.status
  s.cut_over = olsOn
  s.ols_active = olsOn
  s.ports = olsOn ? { 80: ['litespeed'], 443: ['litespeed'] } : { 80: ['httpd'], 443: ['httpd'] }
  s.profile = olsOn ? { production: true, hybrid_ports: [81, 444] } : null
  s.active_generation = olsOn ? state.generations.active : null
  s.hybrid_vhosts = olsOn ? state.plan?.content.hybrid_vhosts.map(h => h.vhost) ?? [] : []
  s.digest = hex(64) // the broker's digest covers the fields above
}

const SCRIPTS = {
  'ols.plan': ['preflight: platform almalinux 9', 'compile: 14 vhosts', 'lint: passed', 'plan written'],
  'ols.plan_hybrid': ['preflight: platform almalinux 9', 'compile: 14 vhosts, 2 kept on Apache', 'suexec_module: loaded', 'plan written'],
  'ols.cutover': ['backup written', 'recover.sh written, recovery timer armed', 'Apache moved to 81/444', 'OLS started on 80/443',
    'health: 14 of 14 vhosts answer'],
  'ols.apache_return': ['OLS stopped', 'Apache restored on 80/443', 'Apache verified', 'profile removed, hooks unregistered'],
  'ols.rollback': ['candidate generation selected', 'validated', 'activated'],
  'ols.sync': ['source digest unchanged', 'nothing to activate'],
  'ols.cache_purge': ['stores selected', 'entries removed', 'purge recorded'],
  'ols.php_restart': ['lsphp processes selected', 'SIGTERM sent', 'processes ended', 'OLS starts new ones on the next request'],
  'ols.opcache_install': ['ea-php package installed', 'tuning file written', 'extension verified with php -i', 'lsphp restarted for the accounts on it'],
  'ols.support_bundle': ['versions and reports collected', 'configuration and logs redacted', 'archive written'],
  'ols.support_bundle_raw': ['versions and reports collected', 'configuration and logs redacted', 'archive written'],
  'ols.update': ['updating OLS-cPanel 0.9.4 to release 0.9.5', 'downloading install.sh and its signature', 'install.sh of release 0.9.5 verified',
    'running the verified installer', 'release 0.9.5 installed; the product applies the upgrade by itself'],
  'ols.php_env_repair': ['every EA4 PHP version checked', 'ea-phpXX-php-litespeed installed where missing', 'OPcache and redis verified', 'state recorded'],
}

function finishJob(state, detail) {
  Object.assign(detail, { state: 'done', exit_code: 0, finished: nowSeconds() })
  if (detail.action === 'ols.cutover') switchTo(state, true)
  if (detail.action === 'ols.apache_return') switchTo(state, false)
  if (detail.action === 'ols.php_restart') {
    const account = detail.scope.startsWith('account:') ? detail.scope.slice(8) : null
    const rows = state.php.processes.accounts.filter(a => account === null || a.account === account)
    detail.output = { command: 'php restart', result: 'restarted', scope: account === null ? 'all' : 'account', account,
      found: rows.reduce((n, a) => n + a.parents + a.children, 0), killed: rows.reduce((n, a) => n + a.parents + a.children, 0), remaining: 0 }
    for (const a of rows) Object.assign(a, { parents: 0, children: 0, rss_kb: 0, cpu_percent: 0, runaway: 0 })
    const totals = state.php.processes.totals
    totals.processes = state.php.processes.accounts.reduce((n, a) => n + a.parents + a.children, 0)
    totals.children = state.php.processes.accounts.reduce((n, a) => n + a.children, 0)
    totals.rss_kb = state.php.processes.accounts.reduce((n, a) => n + a.rss_kb, 0)
    totals.runaway = state.php.processes.accounts.reduce((n, a) => n + a.runaway, 0)
  } else if (detail.action === 'ols.opcache_install') {
    const only = detail.scope.startsWith('version:') ? detail.scope.slice(8) : null
    const done = []
    for (const v of state.php.opcache.versions.filter(x => only === null || x.version === only)) {
      if (!v.tuned) done.push({ version: v.version, result: v.loaded ? 'tuned' : 'installed' })
      Object.assign(v, { package_installed: true, loaded: true, tuned: true, ini_file: true,
        settings: { enable: 'On', validate_root: 'On', validate_permission: 'On', memory_consumption: v.wanted.memory_consumption, max_accelerated_files: '20000', revalidate_freq: '2' } })
    }
    detail.output = { command: 'php opcache install', result: 'installed', changed: done.length, failed: 0, versions: done }
  } else if (detail.action === 'ols.php_env_repair') {
    const env = state.php.environment
    const repaired = env.versions.filter(v => v.status !== 'complete')
    for (const v of env.versions) Object.assign(v, { status: 'complete', lsphp: true, opcache: v.opcache === 'failed' ? 'repaired' : v.opcache,
      redis: 'active', error: null, attempts: 0, retry_at: null, checked_at: nowSeconds() })
    env.checked_at = nowSeconds()
    detail.output = { command: 'php env repair', result: repaired.length ? 'repaired' : 'unchanged', forced: true,
      versions: env.versions.map(v => ({ version: v.version, status: v.status })) }
  } else if (detail.action === 'ols.update') {
    // update install --latest: the release is installed and the cached check dropped, so the view shows the new version.
    const previous = state.update.installed_version
    const version = state.update.available_release?.version ?? previous
    state.update = { ...state.update, installed_version: version, available_release: null, update_available: false,
      verified_release: { ...state.update.verified_release, version, installed_at: nowSeconds() },
      packages: state.update.packages.map(p => (p.package === 'ols-cpanel' ? { ...p, installed: `${version}-1.el9.x86_64`, release_verified: true } : p)) }
    detail.output = { command: 'update install', result: 'updated', code: 0, previous_version: previous, version, installer_exit_code: 0,
      output_tail: [`Upgraded to OLS-cPanel ${version}.`], next: 'The product applies the upgrade by itself within a minute; sites keep being served.' }
  } else if (detail.action === 'ols.support_bundle' || detail.action === 'ols.support_bundle_raw') {
    const name = `bundle-${nowSeconds()}-${hex(8)}.tar.gz`
    state.bundles.unshift({ name, size: 1228800 + Math.floor(Math.random() * 400000), created: nowSeconds() })
    state.bundles = state.bundles.slice(0, 3)
    detail.output = { command: 'support bundle', created: { name, anonymized: detail.action === 'ols.support_bundle' }, bundles: clone(state.bundles) }
  } else if (detail.action === 'ols.cache_purge') {
    const { selected, purged_at: purgedAt } = purgeStores(state.cache.stores, selectStores(state.cache.stores, scopeSelector(detail.scope)))
    state.cache.totals = cacheTotals(state.cache.stores)
    detail.output = { command: 'cache purge', scope: scopeSelector(detail.scope), purged_at: purgedAt, stores: selected,
      totals: cacheTotals(selected) }
  } else if (detail.action === 'ols.plan' || detail.action === 'ols.plan_hybrid') {
    const id = `p${new Date().toISOString().replace(/\D/g, '').slice(0, 14)}-${hex(6)}`
    const content = { ...clone(FIXTURES.whm.plan.plan.content), id, created: new Date().toISOString() }
    if (detail.action === 'ols.plan') {
      content.profile.hybrid_ports = null
      content.hybrid_vhosts = []
    }
    state.plan = { id, digest: hex(64), modified_at: nowSeconds(), valid: true, content }
    detail.output = { command: 'install --prepare', result: 'prepared', plan: id }
  } else {
    detail.output = { action: detail.action, result: 'committed' }
  }
  const row = state.jobs.find(j => j.job === detail.job)
  Object.assign(row, { state: 'done', exit_code: 0, finished: detail.finished })
  state.audit.unshift({ time: detail.finished, event: 'job_finish', actor: 'root', action: detail.action, scope: null, job: detail.job, result: 'ok', detail: 'exit_code=0 state=done' })
}

function page(rows, args, key, extra) {
  const pageNo = args.page ?? 1
  const size = args.size ?? 50
  const query = (args.query || '').toLowerCase()
  const matched = query ? rows.filter(r => [r.domain, r.user, r.vhost].some(v => String(v ?? '').toLowerCase().includes(query))) : rows
  return ok({ observed_at: nowSeconds(), ...extra, total: matched.length, page: pageNo, size,
    [key]: matched.slice((pageNo - 1) * size, pageNo * size) })
}

// "+90d" in the fixtures: a certificate expiry relative to now, as the broker reports it (Unix seconds).
const relative = value => {
  const m = typeof value === 'string' && value.match(/^([+-]\d+)d$/)
  return m ? nowSeconds() + Number(m[1]) * 86400 : value
}

function apiArguments(name, params) {
  const allowed = API_PARAMS[name] || []
  const args = {}
  for (const [key, value] of params) {
    if (key === 'api') continue
    if (!allowed.includes(key) || !PARAMS[key].test(value)) return null
    args[key] = key === 'page' || key === 'size' ? Number(value) : value
  }
  if (name === 'job' && !args.job) return null
  return args
}

function read(state, app, name, params, scenario) {
  const stamp = data => ({ ...data, observed_at: nowSeconds() })
  if (app === 'cpanel') {
    if (name === 'status') return ok(stamp({ ...FIXTURES.cpanel.status, ...(scenario === 'cutover' ? { ols_active: true } : {}) }))
    if (name === 'sites') {
      const sites = scenario === 'empty' ? [] : FIXTURES.cpanel.sites.sites.map(s => ({ ...s, tls: { ...s.tls, not_after: relative(s.tls.not_after) } }))
      return ok({ ...stamp(FIXTURES.cpanel.sites), sites })
    }
    if (name === 'php') return ok({ ...clone(state.cpanelPhp), observed_at: nowSeconds() })
    if (name === 'history') {
      // plugins/cpanel/index.live.php: only resolution and vhost, validated; the broker answers NOT_FOUND for a vhost that is not the account's.
      const args = {}
      for (const [key, value] of params) {
        if (key === 'api') continue
        if (!['resolution', 'vhost'].includes(key) || !PARAMS[key].test(value)) return fail(400, 'BAD_QUERY', 'Invalid query.')
        args[key] = value
      }
      const vhosts = scenario === 'empty' ? [] : FIXTURES.cpanel.history.vhosts
      if (args.vhost && !vhosts.includes(args.vhost)) return fail(404, 'NOT_FOUND', 'no such site')
      return ok(historyReply({ resolution: args.resolution || 'hour', vhost: args.vhost || vhosts[0] || null, vhosts, user: 'legacy' }))
    }
    if (name === 'objcache') {
      const view = { ...clone(FIXTURES.cpanel.objcache), observed_at: nowSeconds() }
      return ok(scenario === 'empty' ? { ...view, enabled: false, origin: null, state: 'inactive', connection: null, wordpress: [], usage: null } : view)
    }
    if (name === 'cache') {
      return ok({ ...state.cpanelCache, observed_at: nowSeconds(), user: state.cpanelCache.user })
    }
    if (name === 'logs' || name === 'php_errors' || name === 'perf') return tenantTools(state, name, params, scenario)
    if (name === 'requests') {
      return ok({ user: state.cpanelPhp.user, observed_at: nowSeconds(), subjects: REQUEST_SUBJECTS, max_text: 1000,
        requests: clone(state.requests.filter(r => r.user === state.cpanelPhp.user)) })
    }
    if (name === 'htaccess_backups') return ok({ backups: clone(state.changes) })
    if (name === 'htaccess') {
      const report = clone(FIXTURES.cpanel.htaccess)
      if (state.htaccessFixed) for (const f of report.files) f.fixes = []
      return ok(scenario === 'empty' ? { roots: 0, files: [], truncated: false, stopped: null, limit: 200 } : report)
    }
    return fail(404, 'UNKNOWN_API', 'Unknown API.')
  }
  if (name === 'requests') {
    return ok({ observed_at: nowSeconds(), open: state.requests.filter(r => r.status === 'open').length, total: state.requests.length, requests: clone(state.requests) })
  }
  if (!(name in FIXTURES.whm)) return fail(404, 'UNKNOWN_API', 'Unknown API.')
  const args = apiArguments(name, params)
  if (args === null) return fail(400, 'BAD_QUERY', 'Invalid query arguments for this API.')
  switch (name) {
    case 'status': return ok(stamp(clone(state.status)))
    case 'metrics': {
      if (scenario === 'metrics-unavailable' || !state.status.ols_active) {
        return ok({ observed_at: nowSeconds(), status: 'unavailable', source: FIXTURES.whm.metrics.source, server: null, vhosts: [] })
      }
      const metrics = clone(FIXTURES.whm.metrics)
      metrics.server.requests_per_second = Math.round(metrics.server.requests_per_second * (0.9 + Math.random() * 0.2) * 10) / 10
      return ok({ ...stamp(metrics), status: scenario === 'metrics-stale' ? 'stale' : 'ok' })
    }
    case 'inventory': return page(state.domains, args, 'domains',
      { source: '/etc/userdatadomains', engine_source: FIXTURES.whm.inventory.engine_source, rejected_rows: 0 })
    case 'compat': return page(state.compat, args, 'vhosts', { source: FIXTURES.whm.compat.source, engine_source: FIXTURES.whm.compat.engine_source })
    case 'cache': {
      const selected = selectStores(state.cache.stores, args)
      if ((args.account || args.domain) && !selected.length) return fail(422, 'REFUSED', args.domain ? `unknown domain ${args.domain}` : `unknown account ${args.account}`)
      return ok({ observed_at: nowSeconds(), source: FIXTURES.whm.cache.source, exit_code: 0,
        output: { ...clone(state.cache), scope: { scope: args.domain ? 'domain' : args.account ? 'account' : 'server', account: args.account ?? null,
          domain: args.domain ?? null }, observed_at: nowSeconds(), stores: clone(selected), totals: cacheTotals(selected) } })
    }
    case 'cache_limits': return ok({ observed_at: nowSeconds(), source: FIXTURES.whm.cache_limits.source, exit_code: 0,
      output: { ...clone(state.cacheLimits), observed_at: nowSeconds() } })
    case 'objcache': return ok({ observed_at: nowSeconds(), source: FIXTURES.whm.objcache.source, exit_code: 0, output: clone(state.objcache) })
    case 'php': return ok({ observed_at: nowSeconds(), source: FIXTURES.whm.php.source, exit_code: 0, output: { ...clone(state.php), observed_at: nowSeconds() } })
    case 'history': {
      const vhosts = FIXTURES.whm.history.vhosts
      if (args.vhost && !vhosts.includes(args.vhost)) return ok(historyReply({ resolution: args.resolution || 'hour', vhost: args.vhost, vhosts, gap: false }))
      return ok(historyReply({ resolution: args.resolution || 'hour', vhost: args.vhost || null, vhosts }))
    }
    case 'audit': {
      const query = (args.query || '').toLowerCase()
      const rows = state.audit.filter(r => (!args.event || r.event === args.event) && (!args.result || r.result === args.result)
        && (!query || [r.event, r.actor, r.action, r.scope, r.job, r.detail].some(v => String(v ?? '').toLowerCase().includes(query))))
      const size = args.size ?? 50
      const pageNo = args.page ?? 1
      return ok({ ...clone(FIXTURES.whm.audit), observed_at: nowSeconds(), total: rows.length, page: pageNo, size,
        events: [...new Set(state.audit.map(r => r.event))].sort(), records: clone(rows.slice((pageNo - 1) * size, pageNo * size)) })
    }
    case 'notify': return ok({ observed_at: nowSeconds(), source: FIXTURES.whm.notify.source, exit_code: 0, output: clone(state.notify) })
    case 'schedule': return ok({ observed_at: nowSeconds(), source: FIXTURES.whm.schedule.source, exit_code: 0,
      output: { ...clone(state.schedule), now: nowSeconds() } })
    case 'update': {
      if (args.refresh) state.updateChecked = nowSeconds()
      return ok({ observed_at: nowSeconds(), source: FIXTURES.whm.update.source, exit_code: 0,
        output: { ...clone(state.update), checked_at: state.updateChecked, cached: !args.refresh } })
    }
    case 'bundle': return ok({ ...clone(FIXTURES.whm.bundle), observed_at: nowSeconds(), bundles: clone(state.bundles) })
    case 'plan': return ok({ observed_at: nowSeconds(), source: FIXTURES.whm.plan.source, plan: state.plan ? clone(state.plan) : null })
    case 'generations': return ok({ ...stamp(FIXTURES.whm.generations), output: clone(state.generations) })
    case 'doctor': return ok(stamp(clone(FIXTURES.whm.doctor)))
    case 'jobs': return ok({ observed_at: nowSeconds(), running: state.jobs.find(j => j.state === 'running')?.job ?? null, jobs: clone(state.jobs) })
    case 'job': {
      const detail = state.details[args.job]
      if (!detail) return fail(404, 'NOT_FOUND', 'no such job')
      if (detail.state === 'running') {
        const script = SCRIPTS[detail.action] || []
        if (detail.log.length < script.length) detail.log.push(script[detail.log.length])
        else finishJob(state, detail)
      }
      return ok(stamp(clone(detail)))
    }
    default: return fail(404, 'UNKNOWN_API', 'Unknown API.')
  }
}

// POST ?action=cache_limits: a settings change (no job), strict body, inclusive bounds; the caps follow from the fixture disk.
function setCacheLimits(state, body) {
  let payload = null
  try {
    payload = JSON.parse(body)
  } catch { /* refused below */ }
  const keys = payload && typeof payload === 'object' && !Array.isArray(payload) ? Object.keys(payload) : []
  const valid = keys.length > 0 && keys.every(k => k in CACHE_LIMIT_BOUNDS && Number.isInteger(payload[k])
    && payload[k] >= CACHE_LIMIT_BOUNDS[k][0] && payload[k] <= CACHE_LIMIT_BOUNDS[k][1])
  if (!valid) return fail(400, 'BAD_BODY', 'The body must be a JSON object with per_site_mb, server_percent and/or server_max_gb as whole numbers inside their bounds.')
  const out = state.cacheLimits
  Object.assign(out.limits, payload)
  out.per_site_bytes = out.limits.per_site_mb * 1024 ** 2
  out.server_bytes = Math.min(Math.floor(out.filesystem.total_bytes * out.limits.server_percent / 100), out.limits.server_max_gb * 1024 ** 3)
  out.changed = true
  return ok({ observed_at: nowSeconds(), source: FIXTURES.whm.cache_limits.source, exit_code: 0, output: clone(out) })
}

// plugins/whm/index.cgi SETTINGS: settings changes and small operations (no job, no digest), strict bodies.
const EMAIL = /^[A-Za-z0-9][A-Za-z0-9._%+-]{0,63}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/
const NOTIFY_EVENTS = ['job', 'held', 'php_env', 'upgrade', 'cache_emergency', 'disk', 'objcache', 'schedule']
const SETTINGS = ['cache_limits', 'request_status', 'notify_settings', 'notify_test', 'schedule_add', 'schedule_cancel', 'objcache_automatic']
const BAD_BODY = 'The body does not fit this action: see docs/product-interfaces.md, "Gateways".'
const isObject = value => value !== null && typeof value === 'object' && !Array.isArray(value)
const webhookOk = value => {
  if (typeof value !== 'string' || value.length > 512 || !/^https:\/\/[A-Za-z0-9._~:\/?#@!$&()*+,;=%-]+$/.test(value)) return false
  try {
    const url = new URL(value)
    return url.username === '' && url.password === ''
  } catch {
    return false
  }
}

// POST ?action=objcache_automatic: exactly {automatic: bool}; off removes the accounts the automatic mode set up (the pass
// the command starts), the reply is the state after the change (admin.objcache).
function setObjcacheAutomatic(state, body) {
  if (!isObject(body) || Object.keys(body).join() !== 'automatic' || typeof body.automatic !== 'boolean') return fail(400, 'BAD_BODY', BAD_BODY)
  const out = state.objcache
  out.automatic = body.automatic
  if (!body.automatic) out.accounts = out.accounts.filter(a => a.origin !== 'automatic')
  state.audit.unshift({ time: nowSeconds(), event: 'objcache_automatic_set', actor: 'system', action: null, scope: null, job: null, result: 'ok',
    detail: body.automatic ? '--on' : '--off' })
  return ok({ observed_at: nowSeconds(), source: FIXTURES.whm.objcache.source, exit_code: 0, output: clone(out) })
}

function setRequestStatus(state, change) {
  const keys = isObject(change) ? Object.keys(change).join() : ''
  if (keys !== 'id,status' || !/^r[0-9]{10}-[0-9a-f]{8}$/.test(change.id) || !['open', 'done'].includes(change.status)) return fail(400, 'BAD_BODY', BAD_BODY)
  const found = state.requests.find(r => r.id === change.id)
  if (!found) return fail(404, 'NOT_FOUND', 'no such request')
  Object.assign(found, { status: change.status, done_at: change.status === 'done' ? nowSeconds() : null })
  return ok({ request: clone(found) })
}

function setNotify(state, body) {
  const keys = isObject(body) ? Object.keys(body) : []
  const emails = body?.emails ?? []
  const events = body?.events ?? []
  const valid = keys.length > 0 && keys.every(k => ['emails', 'webhook', 'events'].includes(k))
    && Array.isArray(emails) && emails.length <= 5 && emails.every(e => typeof e === 'string' && e.length <= 254 && EMAIL.test(e))
    && (!('webhook' in body) || body.webhook === '' || webhookOk(body.webhook))
    && Array.isArray(events) && events.every(e => NOTIFY_EVENTS.includes(e))
  if (!valid) return fail(400, 'BAD_BODY', BAD_BODY)
  const s = state.notify.settings
  if ('emails' in body) s.emails = [...new Set(emails.map(e => e.toLowerCase()))]
  if ('webhook' in body) s.webhook = body.webhook === '' ? { set: false, host: null } : { set: true, host: new URL(body.webhook).hostname }
  if ('events' in body) s.events = [...events]
  const wasOn = s.enabled
  s.enabled = s.emails.length > 0 || s.webhook.set
  s.enabled_since = s.enabled ? (wasOn ? s.enabled_since : nowSeconds()) : null
  state.audit.unshift({ time: nowSeconds(), event: 'notify_settings_set', actor: 'system', action: null, scope: null, job: null, result: 'ok', detail: '' })
  return ok({ observed_at: nowSeconds(), source: FIXTURES.whm.notify.source, exit_code: 0, output: clone(state.notify) })
}

function testNotify(state, body) {
  if (!Array.isArray(body) && !(isObject(body) && Object.keys(body).length === 0)) return fail(400, 'BAD_BODY', BAD_BODY)
  const s = state.notify.settings
  const channels = [...(s.emails.length ? [{ channel: 'email', ok: true, error: null }] : []), ...(s.webhook.set ? [{ channel: 'webhook', ok: true, error: null }] : [])]
  if (!channels.length) return ok({ observed_at: nowSeconds(), source: 'ols-cpanel notify test --format=json', exit_code: 0, output: { command: 'notify test', result: 'not-configured', channels } })
  state.audit.unshift({ time: nowSeconds(), event: 'notify_test', actor: 'system', action: null, scope: null, job: null, result: 'ok', detail: '' })
  return ok({ observed_at: nowSeconds(), source: 'ols-cpanel notify test --format=json', exit_code: 0, output: { command: 'notify test', result: 'sent', channels } })
}

function addSchedule(state, body) {
  const keys = isObject(body) ? Object.keys(body) : []
  const planId = /^[0-9A-Za-z_][0-9A-Za-z_-]{0,63}$/
  const valid = keys.length > 0 && keys.every(k => ['action', 'scope', 'digest', 'at', 'window'].includes(k))
    && ['ols.cutover', 'ols.apache_return'].includes(body.action)
    && typeof body.scope === 'string' && (body.action === 'ols.apache_return' ? body.scope === 'server' : body.scope !== 'server' && planId.test(body.scope))
    && /^[0-9a-f]{64}$/.test(body.digest ?? '') && Number.isInteger(body.at) && body.at > 0
    && (!('window' in body) || (Number.isInteger(body.window) && body.window >= 15 && body.window <= 720))
  if (!valid) return fail(400, 'BAD_BODY', BAD_BODY)
  // The broker: the digest must be the plan's (switch) or the status' (return) right now.
  if (body.action === 'ols.cutover') {
    if (state.plan?.id !== body.scope) return fail(404, 'NOT_FOUND', 'no such plan')
    if (state.plan.digest !== body.digest) return fail(409, 'STALE', 'the plan changed since it was shown')
  } else if (state.status.digest !== body.digest) {
    return fail(409, 'STALE', 'the server state changed since it was shown')
  }
  const now = nowSeconds()
  const out = state.schedule
  if (body.at < now + 60 || body.at > now + 90 * 86400) return fail(422, 'REFUSED', 'the start time must be between one minute and 90 days from now')
  if (out.entries.filter(e => e.state === 'scheduled').length >= 10) return fail(422, 'REFUSED', 'at most 10 scheduled jobs; cancel one first')
  const stamp = new Date(now * 1000).toISOString().replace(/\D/g, '').slice(0, 14)
  const entry = { id: `s${stamp}-${hex(6)}`, action: body.action, scope: body.scope, at: body.at, window_minutes: body.window ?? 60, state: 'scheduled',
    created: now, updated: now, job: null, note: null }
  out.entries.push(entry)
  out.entries.sort((a, b) => a.at - b.at)
  state.audit.unshift({ time: now, event: 'schedule_add', actor: 'system', action: body.action, scope: body.scope, job: null, result: 'ok', detail: '' })
  return ok({ observed_at: now, source: FIXTURES.whm.schedule.source, exit_code: 0, output: { command: 'schedule add', added: entry, ...clone(out), now } })
}

function cancelSchedule(state, body) {
  if (!isObject(body) || Object.keys(body).join() !== 'id' || !/^s[0-9]{14}-[0-9a-f]{6}$/.test(body.id ?? '')) return fail(400, 'BAD_BODY', BAD_BODY)
  const entry = state.schedule.entries.find(e => e.id === body.id)
  if (!entry) return fail(422, 'REFUSED', 'no such scheduled job')
  if (entry.state !== 'scheduled') return fail(422, 'REFUSED', 'only a scheduled job that has not started can be cancelled')
  Object.assign(entry, { state: 'cancelled', updated: nowSeconds(), note: 'cancelled by the operator' })
  state.audit.unshift({ time: nowSeconds(), event: 'schedule_cancel', actor: 'system', action: null, scope: entry.id, job: null, result: 'ok', detail: '' })
  return ok({ observed_at: nowSeconds(), source: FIXTURES.whm.schedule.source, exit_code: 0, output: { command: 'schedule cancel', cancelled: entry.id, ...clone(state.schedule), now: nowSeconds() } })
}

function act(state, parsed, headers, body) {
  const action = parsed.searchParams.get('action')
  if ([...parsed.searchParams.keys()].join() !== 'action') return fail(405, 'METHOD', 'Read operations use GET; actions use POST ?action=<name>.')
  if (!(action in ACTION_SCOPES) && !SETTINGS.includes(action)) return fail(404, 'UNKNOWN_ACTION', 'Unknown action.')
  if (headers?.['X-OLS-cPanel-Request'] !== '1') return fail(403, 'REQUEST_HEADER', 'The X-OLS-cPanel-Request header is required.')
  if (action === 'cache_limits') return setCacheLimits(state, body)
  if (SETTINGS.includes(action)) {
    let parsedBody = null
    try {
      parsedBody = JSON.parse(body)
    } catch { /* refused below */ }
    return { request_status: setRequestStatus, notify_settings: setNotify, notify_test: testNotify, schedule_add: addSchedule, schedule_cancel: cancelSchedule, objcache_automatic: setObjcacheAutomatic }[action](state, parsedBody)
  }
  let payload = null
  try {
    payload = JSON.parse(body)
  } catch { /* refused below */ }
  const scopeOk = typeof payload?.scope === 'string' && (ACTION_SCOPES[action] === 'server' ? payload.scope === 'server'
    : ACTION_SCOPES[action] === 'cache' ? CACHE_SCOPE.test(payload.scope)
      : ACTION_SCOPES[action] === 'php_restart' ? PHP_RESTART_SCOPE.test(payload.scope)
        : ACTION_SCOPES[action] === 'opcache' ? OPCACHE_SCOPE.test(payload.scope)
      : payload.scope !== 'server' && /^[0-9A-Za-z_][0-9A-Za-z_-]{0,63}$/.test(payload.scope))
  if (!payload || Array.isArray(payload) || Object.keys(payload).length !== 2 || !scopeOk || !/^[0-9a-f]{64}$/.test(payload.digest ?? '')) {
    return fail(400, 'BAD_BODY', 'The body must be {"scope", "digest"} with the scope this action takes and a SHA-256 digest.')
  }
  if (action === 'ols.cutover') {
    if (state.plan?.id !== payload.scope) return fail(404, 'NOT_FOUND', 'no such plan')
    if (state.plan.digest !== payload.digest) return fail(409, 'STALE', 'the plan changed since it was shown')
  } else if (state.status.digest !== payload.digest) {
    return fail(409, 'STALE', 'the server state changed since it was shown')
  }
  if (state.jobs.some(j => j.state === 'running')) return fail(409, 'BUSY', 'another job is running')
  const job = `j${nowSeconds()}-${hex(8)}`
  const started = nowSeconds()
  state.jobs.unshift({ job, action, scope: payload.scope, state: 'running', started, finished: null, exit_code: null })
  state.jobs = state.jobs.slice(0, 50)
  state.audit.unshift({ time: started, event: 'job_start', actor: 'root', action, scope: payload.scope === 'server' ? null : payload.scope, job, result: 'ok', detail: '' })
  state.details[job] = { job, action, scope: payload.scope, principal: 'root', state: 'running', started, finished: null,
    exit_code: null, reason: null, log: [], output: null }
  return ok({ ...FIXTURES.action, job }, 202)
}

// plugins/cpanel/index.live.php: POST ?action=cache_purge with {} or {domain}; the broker checks ownership and
// allows one purge per account every 10 s.
function tenantPurge(state, parsed, headers, body) {
  if ([...parsed.searchParams.keys()].join() !== 'action') return fail(405, 'METHOD', 'Actions use POST ?action=<name>.')
  const action = parsed.searchParams.get('action')
  if (!['cache_purge', 'php_restart', 'htaccess_apply', 'htaccess_undo', 'request'].includes(action)) return fail(404, 'UNKNOWN_ACTION', 'Unknown action.')
  if (headers?.['X-OLS-cPanel-Request'] !== '1') return fail(403, 'REQUEST_HEADER', 'The X-OLS-cPanel-Request header is required.')
  let payload = null
  try {
    payload = JSON.parse(body)
  } catch { /* refused below */ }
  const keys = payload && typeof payload === 'object' && !Array.isArray(payload) ? Object.keys(payload) : null
  if (action === 'php_restart') return tenantPhpRestart(state, keys)
  if (action === 'request') return tenantRequest(state, payload, keys)
  if (action === 'htaccess_apply' || action === 'htaccess_undo') return tenantHtaccess(state, action, payload, keys)
  const shapeOk = keys !== null && (keys.length === 0 || (keys.length === 1 && keys[0] === 'domain' && PARAMS.domain.test(payload.domain ?? '')))
  if (!shapeOk) return fail(400, 'BAD_BODY', 'The body must be {} or {"domain": "<one of your domains>"}.')
  const stores = state.cpanelCache.stores
  const selected = payload.domain ? stores.filter(st => st.vhost === payload.domain) : stores
  if (!selected.length) return fail(404, 'NOT_FOUND', payload.domain ? 'that is not one of your domains' : 'this account has no domains')
  if (Date.now() - state.lastTenantPurge < TENANT_PURGE_SECONDS * 1000) {
    return fail(429, 'RATE_LIMITED', `a cache purge is allowed every ${TENANT_PURGE_SECONDS} s; try again shortly`)
  }
  state.lastTenantPurge = Date.now()
  const { selected: done, purged_at: purgedAt } = purgeStores(stores, selected)
  state.cpanelCache.totals = cacheTotals(stores)
  return ok({ user: state.cpanelCache.user, domain: payload.domain ?? null, observed_at: nowSeconds(), purged_at: purgedAt,
    stores: done, totals: cacheTotals(done) })
}

// POST ?action=request with {subject, text}: one request per account every minute.
function tenantRequest(state, payload, keys) {
  const shapeOk = keys?.join() === 'subject,text' && REQUEST_SUBJECTS.includes(payload.subject) && typeof payload.text === 'string'
    && payload.text.trim() !== '' && [...payload.text].length <= 1000
  if (!shapeOk) return fail(400, 'BAD_BODY', 'The request body does not fit this action.')
  if (Date.now() - state.lastRequest < 60000) return fail(429, 'RATE_LIMITED', 'a request can be sent every 60 s; try again shortly')
  state.lastRequest = Date.now()
  const request = { id: `r${nowSeconds()}-${hex(8)}`, user: state.cpanelPhp.user, subject: payload.subject, text: payload.text, created_at: nowSeconds(), status: 'open', done_at: null }
  state.requests.unshift(request)
  return ok({ user: request.user, request })
}

// POST ?action=htaccess_apply {path, digest} and htaccess_undo {id}: run in the page as the account.
function tenantHtaccess(state, action, payload, keys) {
  const fixable = FIXTURES.cpanel.htaccess.files.find(f => Array.isArray(f.fixes) && f.fixes.length)
  if (action === 'htaccess_undo') {
    if (keys?.join() !== 'id' || !/^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$/.test(payload.id)) return fail(400, 'BAD_BODY', 'The request body does not fit this action.')
    const change = state.changes.find(c => c.id === payload.id && !c.undone)
    if (!change) return fail(404, 'NOT_FOUND', 'There is no such change to undo.')
    change.undone = true
    state.htaccessFixed = false
    return ok({ id: change.id, path: change.path, digest: fixable.digest })
  }
  if (keys?.join() !== 'path,digest' || !/^~\/(?:(?!\.{1,2}\/)[A-Za-z0-9._-]+\/)*\.htaccess$/.test(payload.path) || !/^[0-9a-f]{64}$/.test(payload.digest)) {
    return fail(400, 'BAD_BODY', 'The request body does not fit this action.')
  }
  if (!fixable || payload.path !== fixable.path || state.htaccessFixed) return fail(422, 'NO_REWRITE', 'There is nothing to rewrite safely in this file.')
  if (payload.digest !== fixable.digest) return fail(409, 'STALE', 'The file changed since it was checked; check it again.')
  const when = new Date()
  const id = `${when.toISOString().replace(/[-:]/g, '').slice(0, 15)}Z-${hex(8)}`
  state.changes.unshift({ id, path: payload.path, applied_at: nowSeconds(), undone: false, rules: fixable.fixes })
  state.htaccessFixed = true
  return ok({ id, path: payload.path, before_digest: fixable.digest, after_digest: 'f'.repeat(64), rules: fixable.fixes })
}

// POST ?action=php_restart with {}: the account's own lsphp processes, one restart per account every 30 s.
function tenantPhpRestart(state, keys) {
  if (keys === null || keys.length !== 0) return fail(400, 'BAD_BODY', 'The body must be {}.')
  const mine = state.cpanelPhp.processes
  if (!state.cpanelPhp.sites.length) return fail(404, 'NOT_FOUND', 'this account has no domains')
  if (Date.now() - state.lastTenantRestart < TENANT_RESTART_SECONDS * 1000) {
    return fail(429, 'RATE_LIMITED', `a PHP restart is allowed every ${TENANT_RESTART_SECONDS} s; try again shortly`)
  }
  state.lastTenantRestart = Date.now()
  const found = mine ? mine.parents + mine.children : 0
  if (mine) state.cpanelPhp.processes = null
  return ok({ user: state.cpanelPhp.user, observed_at: nowSeconds(), result: 'restarted', found, killed: found, remaining: 0 })
}

let shared = null
export function createFixtureSend(scenario = 'default', { latency = 120 } = {}) {
  const state = createState(scenario)
  return async function send({ method, url, headers, body }) {
    await new Promise(resolve => setTimeout(resolve, scenario === 'slow' ? 2500 : latency))
    if (scenario === 'unauthorized') return fail(403, url.startsWith('index.live.php') ? 'FEATURE_DISABLED' : 'FORBIDDEN', 'not allowed')
    if (scenario === 'session') return { status: 200, body: null }
    if (scenario === 'error') return fail(502, 'BROKER_UNAVAILABLE', 'The OLS-cPanel service is not available.')
    const parsed = new URL(url, 'http://fixture.invalid/')
    const app = parsed.pathname.endsWith('index.live.php') ? 'cpanel' : 'whm'
    if (method === 'POST') {
      return app === 'whm' ? act(state, parsed, headers, body) : tenantPurge(state, parsed, headers, body)
    }
    return read(state, app, parsed.searchParams.get('api'), parsed.searchParams, scenario)
  }
}

export function send(request) {
  if (shared === null) shared = createFixtureSend(new URLSearchParams(globalThis.location?.search || '').get('fixture') || 'default')
  return shared(request)
}
