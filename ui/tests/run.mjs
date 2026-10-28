// Interface unit and component tests with the packages of the lockfile only (no test framework is
// installed): Vite loads the sources (SFCs included) for server-side rendering, node:assert checks.
// Runs offline in the pinned Node image: build/ui/test.sh.
import assert from 'node:assert/strict'
import { readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs'
import { join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createServer } from 'vite'
import vue from '@vitejs/plugin-vue'

const UI = fileURLToPath(new URL('..', import.meta.url))
const server = await createServer({
  configFile: false,
  root: UI,
  logLevel: 'error',
  plugins: [vue()],
  define: { __OLS_FIXTURES__: 'false' },
  resolve: { alias: { '@ols/transport': join(UI, 'dev/transport.js') } },
  server: { middlewareMode: true, hmr: false, watch: null },
  appType: 'custom',
  optimizeDeps: { noDiscovery: true, include: [] },
})
const load = path => server.ssrLoadModule(path)

let passed = 0
const failures = []
async function test(name, fn) {
  try {
    await fn()
    passed++
  } catch (e) {
    failures.push(`${name}: ${e.stack || e}`)
  }
}

const { createSSRApp, h, ref, shallowRef } = await import('vue')
const { renderToString } = await import('vue/server-renderer')
const ElementPlus = (await import('element-plus')).default
const { ID_INJECTION_KEY, ZINDEX_INJECTION_KEY } = await import('element-plus')
const format = await load('/src/shared/format.js')
const router = await load('/src/shared/router.js')
const polling = await load('/src/shared/polling.js')
const csv = await load('/src/shared/csv.js')
const api = await load('/src/shared/api.js')
const findings = await load('/src/shared/findings.js')
const engine = await load('/src/shared/engine.js')
const jobs = await load('/src/shared/jobs.js')
const { i18n, errorMessage } = await load('/src/shared/i18n.js')
const { normalizePlan, planFromLatest } = await load('/src/whm/plan.js')
const fixtures = await load('/dev/transport.js')

// ---- Pure modules ----------------------------------------------------------------------------------
await test('format', () => {
  assert.equal(format.toMillis(1761130000), 1761130000000)
  assert.equal(format.toMillis(1761130000000), 1761130000000)
  assert.equal(format.toMillis('1761130000'), 1761130000000)
  assert.equal(format.toMillis('2026-10-22T10:15:00+00:00'), Date.UTC(2026, 9, 22, 10, 15))
  for (const bad of [null, undefined, '', 'soon', 0, -5, NaN]) assert.equal(format.toMillis(bad), null)
  assert.equal(format.formatBytes(1536), '1.5 KB')
  assert.equal(format.formatBytes(null), null)
  assert.equal(format.formatNumber('12'), null)
  assert.deepEqual(format.age(0, 59000), { n: 59, unit: 'seconds' })
  assert.deepEqual(format.age(0, 7200000), { n: 2, unit: 'hours' })
  const now = Date.UTC(2026, 9, 22)
  assert.equal(format.certificateState('2026-10-20T00:00:00Z', now).state, 'expired')
  assert.equal(format.certificateState('2026-10-30T00:00:00Z', now).state, 'soon')
  assert.equal(format.certificateState('2027-01-30T00:00:00Z', now).state, 'ok')
  assert.equal(format.certificateState(null, now).state, 'unknown')
})

await test('purge memory: a reload or back-navigation within a minute does not purge again', async () => {
  const memory = await load('/src/cpanel/purgeMemory.js')
  const store = () => { const m = new Map(); return { getItem: k => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)) } }
  const s = store()
  assert.equal(memory.recentPurge(s, 1000), null)
  memory.rememberPurge(s, 42, 1000)
  assert.deepEqual(memory.recentPurge(s, 1000 + 59999), { at: 1000, removed: 42 })
  assert.equal(memory.recentPurge(s, 1000 + memory.REPEAT_WINDOW_MS), null)
  assert.equal(memory.recentPurge(s, 999), null)
  memory.rememberPurge(s, null, 5000)
  assert.deepEqual(memory.recentPurge(s, 5001), { at: 5000, removed: null })
  const broken = { getItem: () => { throw new Error('denied') }, setItem: () => { throw new Error('denied') } }
  assert.equal(memory.recentPurge(broken, 1), null)
  assert.doesNotThrow(() => memory.rememberPurge(broken, 1, 1))
  assert.equal(memory.recentPurge(null, 1), null)
  const junk = store()
  junk.setItem(memory.PURGE_MEMORY_KEY, '{not json')
  assert.equal(memory.recentPurge(junk, 1), null)
  const source = readFileSync(join(UI, 'src/cpanel/views/PurgeNowView.vue'), 'utf8')
  assert.match(source, /recentPurge\(store\)[\s\S]*return\n[\s\S]*mutation\.run\(CPANEL_ACTIONS\.cachePurge/)
})

await test('router', () => {
  assert.deepEqual(router.parseHash('#/jobs/j%2F1'), ['jobs', 'j/1'])
  assert.deepEqual(router.parseHash(''), [])
  const routes = [{ name: 'overview', path: 'overview' }, { name: 'job', path: 'jobs/:id' }]
  assert.deepEqual(router.matchRoute(routes, ['jobs', 'j1'], 'overview').params, { id: 'j1' })
  assert.equal(router.matchRoute(routes, ['nope'], 'overview').route.name, 'overview')
  // cPanel dashboard icons open a view with ?view=<route name>; an existing fragment wins; unknown or parameterised names are ignored.
  assert.equal(router.initialHash(routes, { search: '?view=overview', hash: '' }), '#/overview')
  assert.equal(router.initialHash(routes, { search: '?view=overview', hash: '#/jobs/x' }), '#/jobs/x')
  assert.equal(router.initialHash(routes, { search: '?view=job', hash: '' }), '')
  assert.equal(router.initialHash(routes, { search: '?view=%3Cscript%3E', hash: '' }), '')
  assert.equal(router.href('jobs/a b'), '#/jobs/a%20b')
})

await test('route registries', () => {
  for (const app of ['whm', 'cpanel']) {
    const text = readFileSync(join(UI, `src/${app}/routes.js`), 'utf8').split('\n').filter(l => !l.trim().startsWith('//')).join('\n')
    const entries = [...text.matchAll(/\{ name: '([a-z0-9]+)', path: '([a-z0-9/:]+)'(, nav: '[a-z0-9]+')?/g)]
    assert.ok(entries.length >= 2, app)
    assert.equal(new Set(entries.map(m => m[2])).size, entries.length, `${app}: duplicate paths`)
    for (const [, name, , nested] of entries) {
      if (!nested) assert.ok(i18n.global.te(`${app}.nav.${name}`), `${app}.nav.${name} missing from the catalog`)
    }
    assert.ok(!/unavailable|not available/i.test(text), `${app}: placeholder views are not part of release 1 navigation`)
  }
})

await test('poller: one request at a time, backoff, visibility', async () => {
  const timers = { queue: [], setTimeout(fn, ms) { const t = { fn, ms }; this.queue.push(t); return t }, clearTimeout(t) { this.queue = this.queue.filter(x => x !== t) } }
  const listeners = {}
  const doc = { hidden: false, addEventListener: (e, f) => { listeners[e] = f }, removeEventListener: e => { delete listeners[e] } }
  let calls = 0
  let succeed = false
  const poller = polling.createPoller(async () => { calls++; return succeed }, { interval: 1000, maxInterval: 8000, timers, doc })
  poller.start()
  await new Promise(r => setImmediate(r))
  assert.equal(calls, 1)
  assert.equal(timers.queue.length, 1)
  assert.equal(timers.queue[0].ms, 2000) // failed once: doubled
  for (let i = 0; i < 4; i++) {
    const next = timers.queue.shift()
    await next.fn()
  }
  assert.equal(timers.queue[0].ms, 8000) // capped
  succeed = true
  await timers.queue.shift().fn()
  assert.equal(timers.queue[0].ms, 1000) // reset on success
  doc.hidden = true
  await timers.queue.shift().fn()
  assert.equal(timers.queue.length, 0) // hidden: nothing scheduled, nothing fetched
  const before = calls
  doc.hidden = false
  listeners.visibilitychange()
  await new Promise(r => setImmediate(r))
  assert.equal(calls, before + 1)
  poller.stop()
  assert.equal(timers.queue.length, 0)
  assert.equal(listeners.visibilitychange, undefined)
  assert.equal(polling.nextDelay(1000, 50, 5000), 5000)
})

await test('csv', () => {
  assert.equal(csv.csvCell('=cmd|calc'), "'=cmd|calc")
  assert.equal(csv.csvCell('-1'), "'-1")
  assert.equal(csv.csvCell('a,"b"'), '"a,""b"""')
  assert.equal(csv.csvCell(null), '')
  assert.equal(csv.csvCell(['a', 'b']), 'a b')
  assert.equal(csv.toCsv([{ x: 1 }], [{ label: 'X', value: r => r.x }]), 'X\r\n1\r\n')
})

await test('api client: URLs, header, errors', async () => {
  const sent = []
  let reply = { status: 200, body: { ok: true, result: { x: 1 } } }
  const client = api.createClient('index.cgi', async request => { sent.push(request); if (reply instanceof Error) throw reply; return reply })
  assert.deepEqual(await client.get('inventory', { query: '', page: 2, size: 50 }), { x: 1 })
  assert.equal(sent[0].url, 'index.cgi?api=inventory&page=2&size=50')
  assert.equal(sent[0].method, 'GET')
  await client.act('ols.cutover', { scope: 'p1', digest: 'd1' })
  assert.equal(sent[1].method, 'POST')
  assert.equal(sent[1].url, 'index.cgi?action=ols.cutover')
  assert.equal(sent[1].headers['X-OLS-cPanel-Request'], '1')
  assert.deepEqual(JSON.parse(sent[1].body), { scope: 'p1', digest: 'd1' })
  assert.throws(() => client.act('rm -rf', { scope: 's', digest: 'd' }), /rm -rf/)
  const code = async () => { try { await client.get('status') } catch (e) { return e } }
  reply = { status: 403, body: { ok: false, error: { code: 'FORBIDDEN', message: 'Root access is required.' } } }
  let e = await code()
  assert.equal(e.code, 'FORBIDDEN')
  assert.ok(e.unauthorized)
  reply = { status: 200, body: null }
  assert.equal((await code()).code, 'SESSION')
  reply = { status: 0, body: null }
  assert.equal((await code()).code, 'SESSION')
  reply = { status: 502, body: { ok: false, error: { code: 'BUSY', message: 'job running' } } }
  e = await code()
  assert.equal(e.code, 'BUSY')
  assert.ok(!e.unauthorized)
  assert.match(errorMessage(e), /Another job is running.*BUSY.*job running/)
  reply = new Error('offline')
  assert.equal((await code()).code, 'NETWORK')
})

await test('resource: newest request wins, failed refresh keeps data', async () => {
  const pending = []
  const client = { get: () => new Promise((resolve, reject) => pending.push({ resolve, reject })) }
  const resource = api.useResource(client, 'inventory')
  const first = resource.load()
  const second = resource.load()
  pending[1].resolve({ page: 2, observed_at: 1761130000 })
  pending[0].resolve({ page: 1 })
  await Promise.all([first, second])
  assert.equal(resource.data.value.page, 2)
  assert.equal(resource.observedAt.value, 1761130000000)
  assert.equal(api.freshness(resource, Date.now()), 'fresh')
  const third = resource.load()
  pending[2].reject(new api.ApiError('NETWORK', 'down'))
  assert.equal(await third, false)
  assert.equal(resource.data.value.page, 2)
  assert.equal(api.freshness(resource, Date.now()), 'stale')
  const fourth = resource.load()
  pending[3].reject(new api.ApiError('SESSION', '', 0))
  await fourth
  assert.equal(resource.data.value, null) // never keep data past an ended session
})

await test('findings and engine', () => {
  const cases = {
    "/x: unsafe path": 'unsafe_path', '/: unsupported Directory Privacy section': 'privacy',
    "/: <Files x> with unsupported body": 'files_block', "/: unsupported access rule combination ['a']": 'access_rules',
    "/: unsupported Options 'ExecCGI'": 'options', "/: unsupported conditional Header 'x'": 'conditional_header',
    "/: unsupported RewriteRule 'x'": 'rewrite', "/: unsupported directive 'AddHandler'": 'directive',
  }
  for (const [message, key] of Object.entries(cases)) assert.equal(findings.classifyBlocker(message), key, message)
  const broker = findings.normalizeBlocker({ kind: 'php', severity: 'blocker', directory: null, file: null, line: null,
    key: 'php.handler', message: "unsupported PHP handler 'lsapi'" })
  assert.deepEqual([broker.explanation, broker.severity, broker.location], ['php_handler', 'blocker', null])
  for (const [key, topic] of Object.entries(findings.BROKER_KEYS)) {
    assert.equal(findings.normalizeBlocker({ key, message: 'x' }).explanation, topic)
    assert.ok(findings.EXPLANATION_KEYS.includes(topic), topic)
  }
  assert.equal(engine.portOwner({ ports: { 80: 'httpd' } }, 80), 'apache')
  const b = findings.normalizeBlocker({ message: "/admin: unsupported directive 'X'", line: 4 })
  assert.deepEqual([b.location, b.detail, b.line, b.explanation], ['/admin', "unsupported directive 'X'", 4, 'directive'])
  assert.equal(engine.portOwner({ ports: { 80: ['litespeed'] } }, 80), 'ols')
  assert.equal(engine.portOwner({ ports: { 80: ['httpd'] } }, 80), 'apache')
  assert.equal(engine.portOwner({ ports: { 80: [] } }, 80), 'none')
  assert.equal(engine.portOwner({ ports: { 80: ['nginx'] } }, 80), 'other')
  assert.equal(engine.portOwner({}, 80), 'unknown')
  assert.equal(engine.serverEngine({ ports: { 80: ['litespeed'], 443: ['httpd'] } }), 'unknown')
  assert.equal(engine.serverEngine({ ols_active: true, apache_active: true }), 'ols')
  assert.equal(engine.serverEngine(null), 'unknown')
  assert.equal(engine.profileName({ production: true, hybrid_ports: [81, 444] }), 'hybrid')
  assert.equal(engine.profileName({ error: 'malformed' }), 'invalid')
  assert.equal(engine.cutOver({ cut_over: false, profile: {} }), false)
  assert.equal(jobs.runningJob({ jobs: [{ job: 'a', state: 'done' }, { job: 'b', state: 'running' }] }).job, 'b')
  assert.equal(jobs.actionLabel('ols.apache_return'), 'Return to Apache')
  assert.equal(jobs.actionLabel('ols.unknown_thing'), 'ols.unknown_thing')
})

await test('plan normalization', () => {
  const plan = normalizePlan(planFromLatest(fixtures.FIXTURES.whm.plan))
  assert.equal(plan.id, 'p20261022101500-a1b2c3')
  assert.equal(plan.digest, fixtures.FIXTURES.whm.plan.plan.digest) // the plan file's SHA-256, not compile_sha256
  assert.notEqual(plan.digest, fixtures.FIXTURES.whm.plan.plan.content.compile_sha256)
  assert.ok(plan.valid)
  assert.equal(planFromLatest({ plan: null }), null)
  assert.equal(normalizePlan(planFromLatest({ plan: { id: 'p1', digest: 'a'.repeat(64), valid: false, content: null } })).valid, false)
  assert.equal(plan.profile, 'hybrid')
  assert.equal(plan.vhosts, 14)
  assert.equal(plan.olsVhosts, 12)
  assert.equal(plan.hybrid[0].reasons[0].explanation, 'conditional_header')
  assert.equal(normalizePlan(null), null)
  const bare = normalizePlan({ id: 'p1', hybrid_vhosts: ['a.test'], summary: { htaccess_blockers: { 'a.test': ["/: unsafe path"] } } })
  assert.equal(bare.hybrid[0].reasons[0].explanation, 'unsafe_path')
  assert.equal(bare.digest, null)
})

// ---- Catalog (UIX-05) -------------------------------------------------------------------------------
function sources(dir) {
  return readdirSync(dir).flatMap(name => {
    const path = join(dir, name)
    return statSync(path).isDirectory() ? sources(path) : /\.(vue|js)$/.test(name) ? [path] : []
  })
}
const catalog = i18n.global.messages.value.en
function leaves(node, prefix = '') {
  return Object.entries(node).flatMap(([k, v]) => (typeof v === 'object' ? leaves(v, `${prefix}${k}.`) : [[`${prefix}${k}`, v]]))
}
await test('components: every Element Plus tag in a view is registered by mount.js', () => {
  // An unregistered component renders nothing (lab finding 2026-10-28: the purge and restart buttons inside
  // <el-popconfirm> were invisible in both plugins).
  const mount = readFileSync(join(UI, 'src/shared/mount.js'), 'utf8')
  const list = mount.match(/export const COMPONENTS = \[([^\]]*)\]/)
  assert.ok(list, 'COMPONENTS list in mount.js')
  const registered = new Set(list[1].split(',').map(s => s.trim()).filter(Boolean))
  const missing = []
  for (const file of sources(join(UI, 'src'))) {
    for (const m of readFileSync(file, 'utf8').matchAll(/<el-([a-z-]+)/g)) {
      const name = 'El' + m[1].split('-').map(w => w[0].toUpperCase() + w.slice(1)).join('')
      if (!registered.has(name)) missing.push(`${relative(UI, file)}: el-${m[1]}`)
    }
  }
  assert.deepEqual([...new Set(missing)], [])
  for (const name of registered) {
    const dir = name.slice(2).replace(/[A-Z]/g, (c, i) => (i ? '-' : '') + c.toLowerCase())
    assert.ok(mount.includes(`element-plus/es/components/${dir}/style/css`), `${name} has its stylesheet`)
  }
})
await test('components: every listed Element Plus component is really installed (no-op installs register nothing)', async () => {
  // ElRadioGroup and ElRadioButton are no-op installs (ElRadio installs them): listed alone, the history range picker
  // rendered as unknown <el-radio-group> elements in the browser check (2026-10-28).
  const EP = await import('element-plus')
  const mount = readFileSync(join(UI, 'src/shared/mount.js'), 'utf8')
  const names = mount.match(/export const COMPONENTS = \[([^\]]*)\]/)[1].split(',').map(s => s.trim()).filter(Boolean)
  const app = createSSRApp({})
  for (const name of names) app.use(EP[name])
  for (const name of names) assert.ok(app.component(name), `${name} is not registered by app.use`)
  for (const name of ['ElRadioGroup', 'ElRadioButton', 'ElCheckboxGroup', 'ElCollapseItem', 'ElTableColumn', 'ElOption']) {
    assert.ok(app.component(name), `${name} is not registered`)
  }
})
await test('catalog: every static key exists, messages compile, English only', () => {
  const missing = []
  for (const file of sources(join(UI, 'src'))) {
    const text = readFileSync(file, 'utf8')
    for (const m of text.matchAll(/\bt\('([a-zA-Z0-9_.]+)'/g)) if (!i18n.global.te(m[1])) missing.push(`${relative(UI, file)}: ${m[1]}`)
  }
  assert.deepEqual(missing, [])
  for (const [key, value] of leaves(catalog)) {
    assert.ok(!/[\u0600-\u06ff\ufb50-\ufdff\ufe70-\ufeff]/.test(value), key) // tests/english_only.py ranges
    assert.ok(!/[@|$]/.test(value), `${key} uses a reserved message character`)
    assert.equal(typeof i18n.global.t(key, { n: 1, id: 'x', code: 'X', text: 'T', detail: 'D' }), 'string')
  }
})
await test('catalog: every dynamic key family is complete', () => {
  const need = []
  for (const k of findings.EXPLANATION_KEYS) for (const part of ['title', 'body', 'ols', 'fix']) need.push(`help.${k}.${part}`)
  for (const k of ['profile', 'cutover', 'apache_return', 'generations', 'doctor']) need.push(`help.${k}.title`, `help.${k}.body`)
  for (const k of ['ols', 'hybrid', 'apache', 'none', 'unknown']) need.push(`engine.${k}`)
  for (const k of ['ols', 'apache', 'none', 'other', 'unknown']) need.push(`owner.${k}`)
  for (const k of ['native', 'hybrid', 'none', 'invalid', 'unknown']) need.push(`profile.${k}`)
  for (const k of findings.SEVERITIES) need.push(`severity.${k}`)
  for (const k of ['running', 'done', 'failed', 'unknown']) need.push(`jobs.state.${k}`)
  for (const k of ['ready', 'blocked', 'uncertified', 'noPlan', 'unknown']) need.push(`whm.switch.ready.${k}`)
  for (const k of ['seconds', 'minutes', 'hours', 'days']) need.push(`time.ago.${k}`)
  for (const k of ['native', 'hybrid']) need.push(`whm.switch.profileHelp.${k}`)
  for (const k of fixtures.ACTION_NAMES) need.push(`actions.${k.replace('.', '_')}`)
  for (const k of ['job_start', 'job_finish', 'cache_limits_set', 'tenant_cache_purge', 'tenant_php_restart', 'enforcement', 'enforcement_error', 'capability',
    'notify_settings_set', 'notify_test', 'schedule_add', 'schedule_cancel', 'objcache_automatic_set']) need.push(`whm.activity.events.${k}`)
  for (const k of ['automatic', 'administrator', 'package', 'disabled', 'package_off', 'none']) need.push(`whm.objcache.origins.${k}`)
  for (const k of ['active', 'inactive', 'failed', 'activating']) need.push(`whm.objcache.states.${k}`)
  for (const k of ['off', 'providerOff', 'ready']) need.push(`cpanel.objcache.${k}`)
  for (const k of ['job', 'held', 'php_env', 'upgrade', 'cache_emergency', 'disk', 'objcache', 'schedule']) need.push(`whm.notify.events.${k}`)
  for (const k of ['email', 'webhook']) need.push(`whm.notify.channels.${k}`)
  for (const k of ['scheduled', 'running', 'done', 'failed', 'missed', 'refused', 'cancelled', 'unknown']) need.push(`whm.maintenance.state.${k}`)
  for (const k of ['signed', 'signed-key-missing', 'unsigned', 'unknown']) need.push(`whm.updates.sig.${k}`)
  assert.deepEqual(need.filter(k => !i18n.global.te(k)), [])
  assert.ok(Object.keys(findings.HELP_DOCS).every(k => k === 'default' || i18n.global.te(`help.${k}.title`)))
})

// ---- Fixture transport (the contract shapes, offline) -------------------------------------------------
await test('fixture transport follows the gateway rules', async () => {
  const send = fixtures.createFixtureSend('default', { latency: 0 })
  const client = api.createClient('index.cgi', send)
  for (const name of ['status', 'metrics', 'plan', 'generations', 'doctor', 'jobs']) await client.get(name)
  const inventory = await client.get('inventory', { page: 1, size: 200 })
  assert.ok(inventory.total >= 10000 && inventory.domains.length === 200)
  const search = await client.get('inventory', { query: 'legacy', page: 1, size: 50 })
  assert.ok(search.total > 0 && search.total < 100)
  await assert.rejects(client.get('inventory', { size: 201 }), e => e.code === 'BAD_QUERY' && e.status === 400)
  await assert.rejects(client.get('inventory', { query: 'a b' }), e => e.code === 'BAD_QUERY')
  await assert.rejects(client.get('job', { job: 'j1' }), e => e.code === 'BAD_QUERY')
  await assert.rejects(client.get('job', { job: 'j1792627999-00000000' }), e => e.code === 'NOT_FOUND')
  await assert.rejects(client.get('nope'), e => e.code === 'UNKNOWN_API')
  const header = await send({ method: 'POST', url: 'index.cgi?action=ols.plan', headers: {}, body: '{"scope":"server","digest":"x"}' })
  assert.equal(header.status, 403)
  assert.equal(header.body.error.code, 'REQUEST_HEADER')
  const status = await client.get('status')
  assert.match(status.digest, /^[0-9a-f]{64}$/)
  await assert.rejects(client.act('ols.plan', { scope: 'server', digest: 'f'.repeat(64) }), e => e.code === 'STALE' && e.status === 409)
  await assert.rejects(client.act('ols.plan', { scope: 'server', digest: 'short' }), e => e.code === 'BAD_BODY')
  await assert.rejects(client.act('ols.cutover', { scope: 'server', digest: status.digest }), e => e.code === 'BAD_BODY')
  const { job } = await client.act('ols.plan_hybrid', { scope: 'server', digest: status.digest })
  assert.match(job, /^j[0-9]{10}-[0-9a-f]{8}$/)
  await assert.rejects(client.act('ols.plan', { scope: 'server', digest: status.digest }), e => e.code === 'BUSY')
  let detail
  for (let i = 0; i < 10 && detail?.state !== 'done'; i++) detail = await client.get('job', { job })
  assert.equal(detail.state, 'done')
  assert.ok(detail.log.length >= 3)
  const { plan } = await client.get('plan')
  await assert.rejects(client.act('ols.cutover', { scope: plan.id, digest: plan.content.compile_sha256 }), e => e.code === 'STALE')
  const cut = await client.act('ols.cutover', { scope: plan.id, digest: plan.digest })
  for (let i = 0; i < 10; i++) await client.get('job', { job: cut.job })
  const after = await client.get('status')
  assert.equal(after.cut_over, true)
  assert.equal(engine.serverEngine(after), 'ols')
  assert.equal((await client.get('metrics')).status, 'ok')
  const cp = api.createClient('index.live.php', send)
  for (const name of ['status', 'sites', 'htaccess', 'cache', 'php', 'objcache', 'history']) await cp.get(name)
  await assert.rejects(cp.act('ols.sync', { scope: 'server', digest: 'f'.repeat(64) }), e => e.code === 'UNKNOWN_ACTION')
  const denied = api.createClient('index.live.php', fixtures.createFixtureSend('unauthorized', { latency: 0 }))
  await assert.rejects(denied.get('sites'), e => e.code === 'FEATURE_DISABLED' && e.unauthorized)
})

await test('history: chart geometry keeps gaps, scales are nice, the gateways validate', async () => {
  const h = await load('/src/shared/history.js')
  assert.deepEqual([0, 0.3, 1, 1.5, 7, 40, 41, 1234].map(h.niceMax), [1, 0.5, 1, 2, 10, 50, 50, 2000])
  assert.equal(h.scaleMax([[1, null, 3], [8]]), 10)
  assert.equal(h.scaleMax([[], null]), 1)
  const box = { left: 10, top: 0, width: 100, height: 50, max: 10 }
  const { segments, dots } = h.chartPaths([0, 10, null, 5, null, null, 10], box)
  assert.deepEqual(segments, ['M10 50 L26.7 0'])
  assert.deepEqual(dots, [[60, 25], [110, 0]])
  assert.deepEqual(h.chartPaths([null, null], box), { segments: [], dots: [] })
  assert.deepEqual(h.summarize([null, 2, 4, null]), { latest: 4, peak: 4, average: 3, samples: 2 })
  assert.equal(h.summarize([null]), null)
  assert.match(h.timeLabel(1792627900, 'hour'), /^\d\d:\d\d$/)
  assert.match(h.timeLabel(1792627900, 'week'), /^[A-Z][a-z]{2} \d+ \d\d:\d\d$/)
  const send = fixtures.createFixtureSend('cutover', { latency: 0 })
  const client = api.createClient('index.cgi', send)
  const server = await client.get('history')
  assert.deepEqual([server.scope, server.resolution, server.step, server.count], ['server', 'hour', 10, 360])
  assert.equal(server.channels.requests_per_second.length, 360)
  assert.ok(server.channels.requests_per_second.includes(null))
  assert.deepEqual(Object.keys(server.channels), ['requests_per_second', 'requests_processing', 'connections', 'tls_connections',
    'bytes_in_per_second', 'bytes_out_per_second', 'cache_hits_per_second', 'php_in_use'])
  const week = await client.get('history', { resolution: 'week', vhost: 'shop.fixture-domain.test' })
  assert.deepEqual([week.scope, week.step, week.count, Object.keys(week.channels).length], ['vhost', 600, 1008, 4])
  for (const bad of [{ resolution: 'year' }, { vhost: 'A.test' }, { vhost: 'nodot' }, { account: 'x' }]) {
    await assert.rejects(client.get('history', bad), e => e.code === 'BAD_QUERY', JSON.stringify(bad))
  }
  const cp = api.createClient('index.live.php', send)
  const mine = await cp.get('history', { resolution: 'day' })
  assert.deepEqual([mine.user, mine.vhost, mine.step, Object.keys(mine.channels).length], ['legacy', 'legacy.fixture-domain.test', 60, 4])
  assert.equal(mine.scope, undefined)
  await assert.rejects(cp.get('history', { vhost: 'shop.fixture-domain.test' }), e => e.code === 'NOT_FOUND')
  await assert.rejects(cp.get('history', { user: 'other' }), e => e.code === 'BAD_QUERY')
})

await test('account tools fixtures: scope, apply and undo, requests', async () => {
  const send = fixtures.createFixtureSend('default', { latency: 0 })
  const cp = api.createClient('index.live.php', send)
  const site = (await cp.get('sites')).sites[0].domain
  const view = await cp.get('logs', { domain: site, kind: 'error', lines: 5 })
  assert.equal(view.lines.length, 5)
  await assert.rejects(cp.get('logs', { domain: 'other-account.example' }), e => e.code === 'NOT_FOUND' && e.status === 404)
  await assert.rejects(cp.get('logs', { domain: site, kind: 'x' }), e => e.code === 'BAD_QUERY')
  assert.equal((await cp.get('php_errors', { domain: site })).groups.length, 2)
  assert.equal((await cp.get('perf', { domain: site })).slow_urls.available, false)
  const file = (await cp.get('htaccess')).files.find(f => f.fixes.length)
  await assert.rejects(cp.post('htaccess_apply', { path: file.path, digest: '0'.repeat(64) }), e => e.code === 'STALE' && e.status === 409)
  await assert.rejects(cp.post('htaccess_apply', { path: '~/../x/.htaccess', digest: file.digest }), e => e.code === 'BAD_BODY')
  const done = await cp.post('htaccess_apply', { path: file.path, digest: file.digest })
  assert.equal((await cp.get('htaccess_backups')).backups.length, 1)
  assert.ok((await cp.get('htaccess')).files.every(f => f.fixes.length === 0))
  await cp.post('htaccess_undo', { id: done.id })
  await assert.rejects(cp.post('htaccess_undo', { id: done.id }), e => e.code === 'NOT_FOUND')
  await assert.rejects(cp.post('request', { subject: 'money', text: 'x' }), e => e.code === 'BAD_BODY')
  await cp.post('request', { subject: 'php', text: 'hello' })
  await assert.rejects(cp.post('request', { subject: 'php', text: 'again' }), e => e.code === 'RATE_LIMITED' && e.status === 429)
  const whm = api.createClient('index.cgi', send)
  const list = await whm.get('requests')
  assert.equal(list.open, 2)
  await assert.rejects(whm.post('request_status', { id: 'x', status: 'done' }), e => e.code === 'BAD_BODY')
  await whm.post('request_status', { id: list.requests[0].id, status: 'done' })
  assert.equal((await whm.get('requests')).open, 1)
})

await test('cache fixtures: filters, purge job, tenant purge and the gateway rules', async () => {
  const send = fixtures.createFixtureSend('default', { latency: 0 })
  const client = api.createClient('index.cgi', send)
  const all = api.commandOutput(await client.get('cache'))
  assert.ok(all.stores.length >= 5 && all.totals.entries === all.stores.reduce((n, st) => n + st.entries, 0))
  const one = api.commandOutput(await client.get('cache', { account: 'shopco' }))
  assert.deepEqual(one.stores.map(st => st.account), ['shopco', 'shopco'])
  assert.equal(api.commandOutput(await client.get('cache', { domain: 'www.shop.fixture-domain.test' })).stores.length, 1)
  await assert.rejects(client.get('cache', { account: 'Shopco' }), e => e.code === 'BAD_QUERY')
  await assert.rejects(client.get('cache', { domain: 'nodot' }), e => e.code === 'BAD_QUERY')
  await assert.rejects(client.get('cache', { query: 'x' }), e => e.code === 'BAD_QUERY')
  await assert.rejects(client.get('cache', { account: 'nobody' }), e => e.code === 'REFUSED' && e.status === 422)
  const { digest } = await client.get('status')
  for (const scope of ['all', 'account:', 'domain:nodot', 'account:A', 'plan']) {
    await assert.rejects(client.act('ols.cache_purge', { scope, digest }), e => e.code === 'BAD_BODY', scope)
  }
  await assert.rejects(client.act('ols.cache_purge', { scope: 'server', digest: 'f'.repeat(64) }), e => e.code === 'STALE')
  const { job } = await client.act('ols.cache_purge', { scope: 'account:shopco', digest })
  let detail
  for (let i = 0; i < 10 && detail?.state !== 'done'; i++) detail = await client.get('job', { job })
  assert.equal(detail.state, 'done')
  assert.equal(detail.output.totals.entries, 1840 + 12 + 412)
  const after = api.commandOutput(await client.get('cache'))
  assert.equal(after.stores.filter(st => st.account === 'shopco').every(st => st.entries === 0 && st.last_purge !== null), true)
  assert.equal(after.stores.find(st => st.account === 'newbie').entries, 39)
  // The account's side: the header and body rules, ownership, and one purge per interval.
  const cp = api.createClient('index.live.php', send)
  const before = await cp.get('cache')
  assert.equal(before.user, 'legacy')
  const raw = body => send({ method: 'POST', url: 'index.live.php?action=cache_purge', headers: { 'X-OLS-cPanel-Request': '1' }, body })
  assert.equal((await send({ method: 'POST', url: 'index.live.php?action=cache_purge', headers: {}, body: '{}' })).body.error.code, 'REQUEST_HEADER')
  for (const bad of ['{"domain":"../x"}', '{"user":"other"}', '[]', 'nope', '{"domain":"a.test","x":1}']) {
    assert.equal((await raw(bad)).body.error.code, 'BAD_BODY', bad)
  }
  assert.equal((await raw('{"domain":"shop.fixture-domain.test"}')).body.error.code, 'NOT_FOUND')
  const purged = await cp.post('cache_purge', { domain: 'store.fixture-domain.test' })
  assert.equal(purged.domain, 'store.fixture-domain.test')
  assert.equal(purged.totals.entries, 224)
  await assert.rejects(cp.post('cache_purge', {}), e => e.code === 'RATE_LIMITED' && e.status === 429)
  await assert.rejects(async () => cp.post('ols.sync', {}), e => e.code === 'BAD_ACTION')
  assert.equal((await cp.get('cache')).stores[0].entries, 0)
})

await test('cache cleanup limits: read, strict write with the gateway rules, bounds and the fixture caps', async () => {
  const send = fixtures.createFixtureSend('default', { latency: 0 })
  const client = api.createClient('index.cgi', send)
  const before = api.commandOutput(await client.get('cache_limits'))
  assert.deepEqual(before.limits, { per_site_mb: 512, server_percent: 10, server_max_gb: 20 })
  assert.deepEqual(before.bounds.per_site_mb, [16, 102400])
  assert.equal(before.per_site_bytes, 512 * 1024 ** 2)
  await assert.rejects(client.get('cache_limits', { account: 'x' }), e => e.code === 'BAD_QUERY')
  const saved = api.commandOutput(await client.post('cache_limits', { per_site_mb: 1024, server_percent: 5 }))
  assert.deepEqual(saved.limits, { per_site_mb: 1024, server_percent: 5, server_max_gb: 20 })
  assert.equal(saved.per_site_bytes, 1024 * 1024 ** 2)
  assert.equal(saved.server_bytes, Math.floor(saved.filesystem.total_bytes * 5 / 100))
  assert.equal(api.commandOutput(await client.get('cache_limits')).limits.per_site_mb, 1024)
  const raw = (body, headers = { 'X-OLS-cPanel-Request': '1' }) => send({ method: 'POST', url: 'index.cgi?action=cache_limits', headers, body })
  assert.equal((await raw('{"per_site_mb": 600}', {})).body.error.code, 'REQUEST_HEADER')
  for (const bad of ['{}', '[]', '{"per_site_mb": 15}', '{"per_site_mb": 102401}', '{"server_percent": 0}', '{"server_percent": 51}',
    '{"server_max_gb": 0}', '{"server_max_gb": 2049}', '{"per_site_mb": "512"}', '{"per_site_mb": 512.5}', '{"x": 1}', '{"scope": "server", "digest": "x"}', 'text']) {
    const refused = await raw(bad)
    assert.equal(refused.status, 400, bad)
    assert.equal(refused.body.error.code, 'BAD_BODY', bad)
  }
  assert.throws(() => client.post('ols.sync', {}), e => e.code === 'BAD_ACTION')
})

await test('object cache automatic mode: read, strict switch with the gateway rules, off removes only automatic accounts', async () => {
  const send = fixtures.createFixtureSend('default', { latency: 0 })
  const client = api.createClient('index.cgi', send)
  const before = api.commandOutput(await client.get('objcache'))
  assert.equal(before.automatic, true)
  assert.deepEqual(before.accounts.map(a => a.origin), ['automatic', 'administrator', 'package', 'disabled'])
  await assert.rejects(client.get('objcache', { account: 'legacy' }), e => e.code === 'BAD_QUERY')
  const off = api.commandOutput(await client.post('objcache_automatic', { automatic: false }))
  assert.equal(off.automatic, false)
  assert.deepEqual(off.accounts.map(a => a.account), ['shopowner', 'goldsite', 'quietblog'])
  assert.equal(api.commandOutput(await client.get('objcache')).automatic, false)
  assert.equal(api.commandOutput(await client.post('objcache_automatic', { automatic: true })).automatic, true)
  const raw = (body, headers = { 'X-OLS-cPanel-Request': '1' }) => send({ method: 'POST', url: 'index.cgi?action=objcache_automatic', headers, body })
  assert.equal((await raw('{"automatic": false}', {})).body.error.code, 'REQUEST_HEADER')
  for (const bad of ['{}', '[]', '[true]', '{"automatic": "off"}', '{"automatic": 0}', '{"automatic": null}', '{"automatic": true, "x": 1}', 'text']) {
    const refused = await raw(bad)
    assert.equal(refused.status, 400, bad)
    assert.equal(refused.body.error.code, 'BAD_BODY', bad)
  }
})

await test('cPanel object cache: ready when running, the provider\'s off told apart from not started yet', async () => {
  const component = (await load('/src/cpanel/views/ObjectCacheView.vue')).default
  const view = extra => async () => ({ status: 200, body: { v: 1, ok: true, result: { ...fixtures.FIXTURES.cpanel.objcache, ...extra } } })
  const html = async extra => render(component, {}, undefined, api.createClient('index.live.php', view(extra)))
  assert.match(await html({}), /ready and configured for your WordPress sites/)
  const off = { enabled: false, state: 'inactive', connection: null, wordpress: [], usage: null }
  for (const extra of [{ origin: 'disabled' }, { origin: 'package_off' }, { origin: null, automatic: false }]) {
    const text = await html({ ...off, ...extra })
    assert.match(text, /hosting provider turned the object cache off/, JSON.stringify(extra))
    assert.doesNotMatch(text, /ready and configured/)
  }
  assert.match(await html({ ...off, origin: null, automatic: true }), /starts by itself as soon as a WordPress site with LiteSpeed Cache is found/)
})

await test('operations fixtures: activity, notifications, maintenance windows, updates and support bundles follow the gateway rules', async () => {
  const send = fixtures.createFixtureSend('default', { latency: 0 })
  const client = api.createClient('index.cgi', send)
  const post = (action, body, headers = { 'X-OLS-cPanel-Request': '1' }) => send({ method: 'POST', url: `index.cgi?action=${action}`, headers, body: JSON.stringify(body) })
  // Activity: newest first, filters and paging on the server.
  const all = await client.get('audit')
  assert.equal(all.total, 7)
  assert.ok(all.records.every((r, i, rows) => i === 0 || rows[i - 1].time >= r.time))
  assert.equal((await client.get('audit', { result: 'failed' })).total, 1)
  assert.equal((await client.get('audit', { event: 'job_start' })).total, 2)
  assert.equal((await client.get('audit', { query: 'shopco' })).total, 2)
  assert.equal((await client.get('audit', { size: 2, page: 2 })).records.length, 2)
  for (const bad of [{ event: 'Job' }, { event: 'a-b' }, { result: 'maybe' }, { size: 201 }, { account: 'x' }]) {
    await assert.rejects(client.get('audit', bad), e => e.code === 'BAD_QUERY', JSON.stringify(bad))
  }
  // Notifications: opt-in, the webhook is never returned, strict body.
  const off = api.commandOutput(await client.get('notify'))
  assert.equal(off.settings.enabled, false)
  const saved = api.commandOutput(await client.post('notify_settings', { emails: ['Ops@Example.test'], webhook: 'https://hooks.example.com/services/SECRET', events: ['job', 'disk'] }))
  assert.deepEqual([saved.settings.enabled, saved.settings.emails, saved.settings.webhook, saved.settings.events], [true, ['ops@example.test'], { set: true, host: 'hooks.example.com' }, ['job', 'disk']])
  assert.ok(!JSON.stringify(await client.get('notify')).includes('SECRET'), 'the webhook URL is never shown again')
  const kept = api.commandOutput(await client.post('notify_settings', { events: ['job'] }))
  assert.equal(kept.settings.webhook.set, true)
  assert.deepEqual(api.commandOutput(await client.post('notify_test', {})).channels.map(c => c.channel), ['email', 'webhook'])
  assert.equal((await post('notify_settings', { emails: [] }, {})).body.error.code, 'REQUEST_HEADER')
  for (const bad of [{}, [], { x: 1 }, { emails: ['a'] }, { emails: [1] }, { emails: Array.from({ length: 6 }, (_, i) => `u${i}@b.test`) },
    { webhook: 'http://hooks.example.com/x' }, { webhook: 'https://u:p@hooks.example.com/x' }, { webhook: 5 }, { events: ['nonsense'] }, { scope: 'server', digest: 'x' }]) {
    const refused = await post('notify_settings', bad)
    assert.equal(refused.status, 400, JSON.stringify(bad))
    assert.equal(refused.body.error.code, 'BAD_BODY')
  }
  assert.equal((await post('notify_test', { x: 1 })).body.error.code, 'BAD_BODY')
  const cleared = api.commandOutput(await client.post('notify_settings', { emails: [], webhook: '' }))
  assert.deepEqual([cleared.settings.enabled, cleared.settings.enabled_since], [false, null])
  // Maintenance windows: the digest must be the plan's (switch) or the status' (return); strict body; cancel.
  const plan = (await client.get('plan')).plan
  const status = await client.get('status')
  const at = Math.floor(Date.now() / 1000) + 3600
  const window = { action: 'ols.cutover', scope: plan.id, digest: plan.digest, at, window: 90 }
  const added = api.commandOutput(await client.post('schedule_add', window))
  assert.equal(added.added.state, 'scheduled')
  assert.equal(api.commandOutput(await client.get('schedule')).entries.length, 2)
  assert.equal((await post('schedule_add', { ...window, digest: 'f'.repeat(64) })).body.error.code, 'STALE')
  assert.equal((await post('schedule_add', { ...window, scope: 'p-other' })).body.error.code, 'NOT_FOUND')
  assert.equal((await post('schedule_add', { action: 'ols.apache_return', scope: 'server', digest: status.digest, at })).status, 200)
  for (const bad of [{}, { ...window, action: 'ols.sync' }, { ...window, scope: 'server' }, { ...window, digest: 'ab' }, { ...window, at: 'soon' }, { ...window, window: 14 },
    { ...window, window: 721 }, { ...window, x: 1 }, { action: 'ols.apache_return', scope: plan.id, digest: status.digest, at }]) {
    assert.equal((await post('schedule_add', bad)).body.error.code, 'BAD_BODY', JSON.stringify(bad))
  }
  assert.equal((await post('schedule_add', { ...window, at: Math.floor(Date.now() / 1000) + 5 })).body.error.code, 'REFUSED')
  const cancelled = api.commandOutput(await client.post('schedule_cancel', { id: added.added.id }))
  assert.equal(cancelled.entries.find(e => e.id === added.added.id).state, 'cancelled')
  assert.equal((await post('schedule_cancel', { id: added.added.id })).body.error.code, 'REFUSED')
  assert.equal((await post('schedule_cancel', { id: '../x' })).body.error.code, 'BAD_BODY')
  // Updates: read-only; a refresh asks again; only `refresh=1` is accepted.
  const first = api.commandOutput(await client.get('update'))
  assert.equal(first.update_available, true)
  assert.equal(first.packages[0].signature.state, 'unsigned')
  assert.equal(api.commandOutput(await client.get('update', { refresh: 1 })).cached, false)
  await assert.rejects(client.get('update', { refresh: 'true' }), e => e.code === 'BAD_QUERY')
  // Support bundles are jobs of the capability flow; the archive appears in the list and the activity.
  const digest = (await client.get('status')).digest
  for (const action of ['ols.support_bundle', 'ols.support_bundle_raw']) {
    await assert.rejects(client.act(action, { scope: plan.id, digest }), e => e.code === 'BAD_BODY')
  }
  const { job } = await client.act('ols.support_bundle', { scope: 'server', digest })
  let detail = await client.get('job', { job })
  for (let i = 0; i < 12 && detail.state === 'running'; i++) detail = await client.get('job', { job })
  assert.equal(detail.state, 'done')
  const bundles = await client.get('bundle')
  assert.equal(bundles.bundles.length, 2)
  assert.ok(/^bundle-\d{10}-[0-9a-f]{8}\.tar\.gz$/.test(bundles.bundles[0].name))
  assert.equal(api.downloadUrl('index.cgi', bundles.bundles[0].name), `index.cgi?download=${bundles.bundles[0].name}`)
  const trail = (await client.get('audit', { size: 5 })).records
  assert.ok(trail.some(r => r.event === 'job_finish' && r.action === 'ols.support_bundle'))
  assert.throws(() => client.post('ols.sync', {}), e => e.code === 'BAD_ACTION')
})

await test('operations: the settings sent by the views fit the gateway schema', async () => {
  const { platformFacts } = await load('/src/whm/health.js')
  const doctor = api.commandOutput(await api.createClient('index.cgi', fixtures.createFixtureSend('default', { latency: 0 })).get('doctor'))
  const facts = platformFacts(doctor)
  assert.deepEqual([facts.os, facts.cpanel, facts.supported], ['AlmaLinux 9.8', '11.138', true])
  const outside = platformFacts({ ...doctor, platform: { ...doctor.platform, os: { ...doctor.platform.os, value: { ID: 'ubuntu', VERSION_ID: '22.04' } } } })
  assert.equal(outside.supported, false, 'an operating system outside the supported list is reported')
})

await test('php fixtures: status, OPcache install and restart jobs, tenant restart and the gateway rules', async () => {
  const send = fixtures.createFixtureSend('default', { latency: 0 })
  const client = api.createClient('index.cgi', send)
  const report = api.commandOutput(await client.get('php'))
  assert.equal(report.opcache.versions.length, 3)
  assert.equal(report.processes.totals.runaway, 1)
  assert.equal(report.limits.builtin.children, 5)
  await assert.rejects(client.get('php', { account: 'shopco' }), e => e.code === 'BAD_QUERY')
  const { digest } = await client.get('status')
  for (const [action, scope] of [['ols.opcache_install', 'account:x'], ['ols.opcache_install', 'version:ea-php8'], ['ols.opcache_install', 'version:alt-php81'],
    ['ols.php_restart', 'version:ea-php83'], ['ols.php_restart', 'account:'], ['ols.php_restart', 'domain:a.test']]) {
    await assert.rejects(client.act(action, { scope, digest }), e => e.code === 'BAD_BODY', `${action} ${scope}`)
  }
  const finished = async job => {
    let detail
    for (let i = 0; i < 10 && detail?.state !== 'done'; i++) detail = await client.get('job', { job })
    return detail
  }
  const install = await finished((await client.act('ols.opcache_install', { scope: 'version:ea-php74', digest })).job)
  assert.equal(install.output.changed, 1)
  const afterInstall = api.commandOutput(await client.get('php'))
  assert.equal(afterInstall.opcache.versions.find(v => v.version === 'ea-php74').tuned, true)
  assert.equal(afterInstall.opcache.versions.find(v => v.version === 'ea-php83').tuned, false)
  const before = api.commandOutput(await client.get('php')).environment
  assert.equal(before.versions[0].status, 'failed')
  assert.match(before.versions[0].error, /ea-php74-php-litespeed/)
  assert.equal(before.profile.present, true)
  await assert.rejects(client.act('ols.php_env_repair', { scope: 'version:ea-php74', digest }), e => e.code === 'BAD_BODY')
  const repair = await finished((await client.act('ols.php_env_repair', { scope: 'server', digest })).job)
  assert.equal(repair.output.result, 'repaired')
  const afterRepair = api.commandOutput(await client.get('php')).environment
  assert.deepEqual(afterRepair.versions.map(v => v.status), ['complete', 'complete', 'complete'])
  const restart = await finished((await client.act('ols.php_restart', { scope: 'account:shopco', digest })).job)
  assert.equal(restart.output.killed, 6)
  const afterRestart = api.commandOutput(await client.get('php'))
  assert.equal(afterRestart.processes.accounts.find(a => a.account === 'shopco').children, 0)
  assert.equal(afterRestart.processes.totals.runaway, 0)
  assert.equal(afterRestart.processes.accounts.find(a => a.account === 'legacy').children, 2)
  // The account's side: the header and body rules, one restart per interval, its own view.
  const cp = api.createClient('index.live.php', send)
  const mine = await cp.get('php')
  assert.equal(mine.user, 'legacy')
  assert.equal(mine.sites.length, 3)
  const raw = body => send({ method: 'POST', url: 'index.live.php?action=php_restart', headers: { 'X-OLS-cPanel-Request': '1' }, body })
  assert.equal((await send({ method: 'POST', url: 'index.live.php?action=php_restart', headers: {}, body: '{}' })).body.error.code, 'REQUEST_HEADER')
  for (const bad of ['{"user":"other"}', '{"domain":"a.test"}', '[]', 'nope']) assert.equal((await raw(bad)).body.error.code, 'BAD_BODY', bad)
  const done = await cp.post('php_restart', {})
  assert.equal(done.killed, 3)
  await assert.rejects(cp.post('php_restart', {}), e => e.code === 'RATE_LIMITED' && e.status === 429)
  assert.equal((await cp.get('php')).processes, null)
})

// ---- Components (server-side rendering) ---------------------------------------------------------------
const warnings = []
// A missing catalog key is a failure too (vue-i18n only warns on the console).
const consoleWarn = console.warn
console.warn = (...args) => {
  const text = args.map(String).join(' ')
  if (text.includes('[intlify]')) warnings.push(text)
  else consoleWarn(...args)
}
async function render(component, props = {}, slots = undefined, client = null) {
  const app = createSSRApp({ render: () => h(component, props, slots) })
  app.use(ElementPlus)
  app.use(i18n)
  app.provide(ID_INJECTION_KEY, { prefix: 1024, current: 0 })
  app.provide(ZINDEX_INJECTION_KEY, { current: 0 })
  app.provide(api.CLIENT_KEY, client || api.createClient('index.cgi', fixtures.createFixtureSend('default', { latency: 0 })))
  app.config.warnHandler = message => warnings.push(message)
  return renderToString(app)
}
function fakeResource({ data = null, error = null, loading = false, loadedAt = null } = {}) {
  return {
    name: 'x', data: shallowRef(data), error: shallowRef(error), loading: ref(loading), loadedAt: ref(loadedAt),
    observedAt: ref(loadedAt), source: ref('fixture-source'), staleAfter: 60000, load: async () => true,
  }
}
const StatusBadge = (await load('/src/shared/StatusBadge.vue')).default
const EngineBadge = (await load('/src/shared/EngineBadge.vue')).default
const StateView = (await load('/src/shared/StateView.vue')).default
const MetricCard = (await load('/src/shared/MetricCard.vue')).default
const FreshnessIndicator = (await load('/src/shared/FreshnessIndicator.vue')).default

await test('StatusBadge and EngineBadge', async () => {
  const html = await render(StatusBadge, { tone: 'bad', label: 'Failed' })
  assert.match(html, /olsc-tone-bad/)
  assert.match(html, /aria-hidden="true">✕<\/span><span>Failed/)
  assert.match(await render(EngineBadge, { engine: 'hybrid' }), /Served by Apache automatically/)
  assert.match(await render(EngineBadge, { status: { ports: { 80: ['httpd'], 443: ['httpd'] } } }), />Apache</)
  assert.match(await render(EngineBadge, { status: null }), /Unknown/)
  assert.match(await render(EngineBadge, { engine: 'bogus' }), /Unknown/)
})

await test('StateView states', async () => {
  const slot = { default: () => h('p', 'CONTENT') }
  assert.match(await render(StateView, { resource: fakeResource({ loading: true }) }, slot), /role="status".*Loading/s)
  let html = await render(StateView, { resource: fakeResource({ error: new api.ApiError('NETWORK', 'down') }) }, slot)
  assert.match(html, /Could not load this view/)
  assert.match(html, /Retry/)
  assert.doesNotMatch(html, /CONTENT/)
  html = await render(StateView, { resource: fakeResource({ error: new api.ApiError('SESSION', '', 0) }) }, slot)
  assert.match(html, /Your session has ended/)
  html = await render(StateView, { resource: fakeResource({ error: new api.ApiError('FORBIDDEN', 'Root access is required.', 403) }) }, slot)
  assert.match(html, /not allowed to see this view/)
  html = await render(StateView, { resource: fakeResource({ data: {}, loadedAt: Date.now() }), empty: true, emptyText: 'NOTHING' }, slot)
  assert.match(html, /NOTHING/)
  html = await render(StateView, { resource: fakeResource({ data: { a: 1 }, loadedAt: Date.now(), error: new api.ApiError('NETWORK', 'down') }) }, slot)
  assert.match(html, /CONTENT/)
  assert.match(html, /latest refresh failed/)
  assert.match(html, /Data may be out of date/)
  html = await render(StateView, { resource: fakeResource({ data: { a: 1 }, loadedAt: Date.now() }), degraded: 'DEG', pending: 'PEND' }, slot)
  assert.match(html, /DEG/)
  assert.match(html, /PEND/)
  assert.match(html, /source: fixture-source/)
})

await test('ConfirmDialog: typed confirmation, action disabled until it matches', async () => {
  const ConfirmDialog = (await load('/src/shared/ConfirmDialog.vue')).default
  // The dialog body renders in the browser only; on the server its accessible frame is checked.
  const html = await render(ConfirmDialog, { modelValue: true, title: 'Cut over', expected: 'p1', confirmLabel: 'GO' })
  assert.match(html, /role="dialog" aria-modal="true" aria-label="Cut over"/)
  const { confirmationMatches } = await load('/src/shared/confirm.js')
  assert.ok(confirmationMatches(' p20261022101500-a1b2c3 ', 'p20261022101500-a1b2c3'))
  for (const typed of ['', 'p2026', 'P20261022101500-A1B2C3', 'p20261022101500-a1b2c3x']) {
    assert.ok(!confirmationMatches(typed, 'p20261022101500-a1b2c3'), typed)
  }
  assert.ok(!confirmationMatches('', ''))
  assert.ok(!confirmationMatches(undefined, undefined))
})

await test('MetricCard and FreshnessIndicator', async () => {
  assert.match(await render(MetricCard, { label: 'Requests', value: null }), /Unknown/)
  assert.doesNotMatch(await render(MetricCard, { label: 'Requests', value: '0/s' }), /Unknown/)
  const html = await render(FreshnessIndicator, { resource: fakeResource({ data: {}, loadedAt: Date.now() - 5000 }) })
  assert.match(html, /Observed \d+ s ago/)
})

// Views render on the server after their initial load (useLoad/usePolling prefetch) against the fixture
// transport, so each assertion below is real data flowing through the view. Element Plus fills table cells
// only in the browser, so tables are checked by their row count (`rows`: at least that many rows).
const EXPECT = {
  'src/whm/views/OverviewView.vue': {
    default: [/Not switched \(Apache\)/, /Process: httpd/, /12,006/, /Live statistics are unavailable/, /Observed \d+ s ago/,
      /Traffic history/, /Last hour/, /olsc-history-vhost/, /Cache hits/, /PHP in use/, /<svg[^>]*role="img"/, /sampled every 10 seconds/],
    cutover: [/Busiest virtual hosts/, />\d+(\.\d)?\/s</, /Hybrid/, /Process: litespeed/, { rows: 5 }],
    'metrics-stale': [/has not updated its real-time report/],
    unauthorized: [/not allowed to see this view/],
    session: [/Your session has ended/],
    error: [/Could not load this view/, /service is not running/],
  },
  'src/whm/views/SwitchView.vue': {
    default: [/p20261022101500-a1b2c3/, /Prepare plan/, /Apache moved to 81\/444/,
      /Kept on Apache \(hybrid\)/, /7d3f0c2a9b8e/, { rows: 2 }],
    cutover: [/The server is already switched/],
    empty: [/No plan has been prepared yet/],
  },
  'src/whm/views/CompatView.vue': { default: [/423 in total/, /Export CSV/, { rows: 50 }], empty: [/No compatibility findings/] },
  'src/whm/views/AccountsView.vue': {
    default: [/12,006 in total/, /engines as planned by p20261022101500-a1b2c3/, { rows: 50 }],
    empty: [/No domains found/],
  },
  'src/whm/views/GenerationsView.vue': { default: [/Roll back/, { rows: 3 }], empty: [/No generation yet/] },
  'src/whm/views/JobsView.vue': {
    default: [/untranslatable \.htaccess/, /Finished with an error/, /Prepare a native cutover plan/, /exit code 1/, { rows: 2 }],
    empty: [/No jobs yet/],
  },
  'src/whm/views/CacheView.vue': {
    default: [/Purge all caches/, /Cached pages/, /2,308/, /Cache stores/, /Automatic cleanup/, /removed automatically every hour/,
      /allowed for the whole server/, /Most one site may store \(MB\)/, /1,840 cached pages removed/, /Save limits/, { rows: 6 }],
    empty: [/No cache stores yet/],
    unauthorized: [/not allowed to see this view/],
    error: [/Could not load this view/],
  },
  'src/whm/views/PhpView.vue': {
    default: [/Restart PHP for all accounts/, /With OPcache loaded/, /Runaway processes/, /Limits in force/, { rows: 7 }],
    empty: [/No EA4 PHP version and no PHP process were found/],
    unauthorized: [/not allowed to see this view/],
    error: [/Could not load this view/],
  },
  'src/whm/views/ObjectCacheView.vue': {
    default: [/Every account with WordPress and LiteSpeed Cache gets its own private object cache automatically\./, /Automatic object cache/, /Turn off/,
      { rows: 4 }],
    empty: [/No account has an object cache yet/],
    unauthorized: [/not allowed to see this view/],
    error: [/Could not load this view/],
  },
  'src/whm/views/ActivityView.vue': {
    default: [/Search activity/, /7 in total/, /Kind of activity/, /Result/, { rows: 7 }],
    empty: [/No activity has been recorded yet/],
    unauthorized: [/not allowed to see this view/],
    error: [/Could not load this view/],
  },
  'src/whm/views/NotificationsView.vue': {
    default: [/Where to send/, /Webhook address/, /E-mail addresses/, /0 of 20/, /Nothing sent yet/, /Send test/, /No messages have been sent yet/,
      /What to be told about/, /A scheduled job was missed or could not start/],
    unauthorized: [/not allowed to see this view/],
    error: [/Could not load this view/],
  },
  'src/whm/views/MaintenanceView.vue': {
    default: [/Schedule a job/, /Scheduled jobs/, /Start at/, /Window/, /same checks as the Switch center/, { rows: 1 }],
    cutover: [/Schedule a job/],
    empty: [/Nothing is scheduled/, /There is nothing to schedule yet/],
    unauthorized: [/not allowed to see this view/],
  },
  'src/whm/views/UpdatesView.vue': {
    default: [/Before you update/, /AlmaLinux 9\.8/, /11\.138/, /Supported/, /An update is available/, /Check now/, /nothing needs to be run by hand/, { rows: 2 }],
    unauthorized: [/not allowed to see this view/],
    error: [/Could not load this view/],
  },
  'src/whm/views/SupportView.vue': {
    default: [/Support bundle/, /Create bundle \(at most 20 MB\)/, /Anonymize/, /placeholders that stay the same/, /The last 3 bundles are kept/, /never included/, { rows: 1 }],
    empty: [/No bundle has been created yet/],
    unauthorized: [/not allowed to see this view/],
  },
  'src/whm/views/DiagnosticsView.vue': {
    default: [/Server health/, /Platform: AlmaLinux 9\.8, cPanel 11\.138 - supported/, /PHP is being repaired on 1 version/, /Supported platforms/, /Technical details/, /fixture observations/, /x86_64/, { rows: 4 }],
    cutover: [/OpenLiteSpeed is serving your sites/, /Configuration is up to date|Configuration is being updated/],
  },
  'src/cpanel/views/SitesView.vue': {
    default: [/This server still runs Apache/, /2 certificate\(s\) expired or expiring soon/, { rows: 4 }],
    cutover: [/OpenLiteSpeed/],
    empty: [/This account has no domains yet/],
    unauthorized: [/not allowed to see this view/, /not enabled for your account/],
  },
  'src/cpanel/views/PurgeNowView.vue': {
    default: [/Clear cache/, /Clearing the cache of all your sites/, /Back to cPanel/],
  },
  'src/cpanel/views/CacheView.vue': {
    default: [/LiteSpeed Cache for WordPress/, /233 cached pages/, /Old cached pages are removed automatically/, /Clear the cache of all my sites/, { rows: 2 }],
    empty: [/No cache store exists for your sites yet/],
    unauthorized: [/not allowed to see this view/, /not enabled for your account/],
  },
  'src/cpanel/views/PhpView.vue': {
    default: [/Restart my PHP/, /My PHP processes/, /2 workers/, /Limits for your account/, { rows: 6 }],
    empty: [/This account has no domains yet/],
    unauthorized: [/not allowed to see this view/, /not enabled for your account/],
  },
  'src/cpanel/views/ObjectCacheView.vue': {
    default: [/ready and configured for your WordPress sites/, /Connection values/, /\/home\/legacy\/\.ols-objcache\/valkey\.sock/, /None needed/, /Copy/, /configured automatically/, /Joomla, Drupal, Magento/, /My WordPress sites/, /tried again automatically/, { rows: 4 }],
    empty: [/starts by itself as soon as a WordPress site with LiteSpeed Cache is found/],
    unauthorized: [/not allowed to see this view/, /not enabled for your account/],
  },
  'src/cpanel/views/HistoryView.vue': {
    default: [/Traffic history/, /Last 7 days/, /Static files served/, /<svg[^>]*role="img"/, /highest/, /olsc-history-vhost/],
    empty: [/This account has no domains yet/],
    unauthorized: [/not allowed to see this view/, /not enabled for your account/],
  },
  'src/whm/views/RequestsView.vue': {
    default: [/1 open of 2/, /Please raise the PHP memory limit/, /Mark as done/, /Open again/],
    empty: [/No requests yet/],
    unauthorized: [/not allowed to see this view/],
    error: [/Could not load this view/],
  },
  'src/cpanel/views/LogsView.vue': {
    default: [/Download/, /Passwords, tokens and cookies are hidden/, /token=\[redacted\]/, /40 line\(s\) shown/, /Undefined variable \$total/, /31 time\(s\)/, /First seen 2026-10-27/],
    empty: [/This account has no domains yet/],
    unauthorized: [/not allowed to see this view/, /not enabled for your account/],
  },
  'src/cpanel/views/PerfView.vue': {
    default: [/Check this site/, /Press the button to check the site/],
    empty: [/This account has no domains yet/],
    unauthorized: [/not allowed to see this view/, /not enabled for your account/],
  },
  'src/cpanel/views/RequestsView.vue': {
    default: [/New message/, /Please raise the PHP memory limit/, /Your messages/, /Send/],
    unauthorized: [/not allowed to see this view/, /not enabled for your account/],
  },
  'src/cpanel/views/HtaccessView.vue': {
    default: [/A safe correction is available/, /invisible mark/, /Apply the correction/, /Recent corrections/, /No corrections were made yet/, /4 file\(s\) checked across 2 site folder\(s\)/, /Nothing needs to be done/, /Kept on Apache automatically/, /Handled automatically/],
    empty: [/No \.htaccess files were found/],
  },
}
await test('advisor explains automatic outcomes without customer tasks', async () => {
  const component = (await load('/src/cpanel/views/HtaccessView.vue')).default
  const client = api.createClient('index.live.php', fixtures.createFixtureSend('default', { latency: 0 }))
  const html = await render(component, {}, undefined, client)
  assert.equal((html.match(/olsc-tone-info/g) || []).length, 2)
  assert.equal((html.match(/olsc-tone-ok/g) || []).length, 2)
  assert.doesNotMatch(html, /olsc-tone-(?:warn|bad)|need attention|What to do|Explain|contact support/)
  // Reasons live in collapsed tables (Element Plus fills cells only in the browser): check the data the view
  // renders them from instead, through the shared catalog the gateway also uses.
  const catalog = JSON.parse(readFileSync(join(UI, 'src/shared/i18n.htaccess.en.json'), 'utf8'))
  const reasons = JSON.stringify(catalog)
  assert.match(reasons, /Apache preserves the conditions for sending this header/)
  assert.match(reasons, /Apache preserves who can access this folder/)
  assert.doesNotMatch(html, /el-collapse-item[^"<>]*is-active/)
})

await test('health statements: plain product state, supported-platform rules', async () => {
  const { healthStatements, platformFacts } = await load('/src/whm/health.js')
  const report = JSON.parse(JSON.stringify(fixtures.FIXTURES.whm.doctor.output))
  assert.equal(platformFacts(report).supported, true)
  assert.equal(platformFacts({ ...report, runtime: { ...report.runtime, architecture: 'aarch64' } }).supported, false)
  report.platform.os.value.VERSION_ID = '10.0'
  assert.equal(platformFacts(report).supported, false)
  const keys = healthStatements({ ports: { 80: ['litespeed'], 443: ['litespeed'] }, cut_over: true, profile: { hybrid_ports: [81] }, ols_active: true, pending_events: [], hybrid_vhosts: ['a.test'] },
    { environment: { versions: [{ status: 'complete' }] } }, fixtures.FIXTURES.whm.doctor.output).map(r => r.key)
  assert.deepEqual(keys, ['serving', 'configCurrent', 'hybrid', 'phpComplete', 'platformSupported'])
  assert.equal(JSON.stringify(healthStatements(null, null, null)), '[]')
})

await test('views render real fixture data in every scenario', async () => {
  const views = sources(join(UI, 'src')).filter(f => f.includes('/views/')).map(f => relative(UI, f))
  assert.deepEqual(views.filter(v => !EXPECT[v]), [], 'every view has expectations')
  for (const [view, scenarios] of Object.entries(EXPECT)) {
    const component = (await load(`/${view}`)).default
    for (const [scenario, checks] of Object.entries(scenarios)) {
      const endpoint = view.includes('/cpanel/') ? 'index.live.php' : 'index.cgi'
      const client = api.createClient(endpoint, fixtures.createFixtureSend(scenario, { latency: 0 }))
      const html = await render(component, { params: { id: 'j1792627900-0a1b2c3d' } }, undefined, client)
      if (process.env.DUMP) writeFileSync(join(process.env.DUMP, `${scenario}-${view.split('/').pop()}.html`), html)
      assert.match(html, /<h2/, `${view} has no heading`)
      for (const check of checks) {
        if (check instanceof RegExp) assert.match(html, check, `${view} (${scenario}): ${check}`)
        else assert.ok((html.match(/class="el-table__row/g) || []).length >= check.rows, `${view} (${scenario}): ${check.rows} rows`)
      }
    }
  }
  const shared = ['ConfirmDialog', 'DataTable', 'JobTimeline', 'HelpTip', 'PageHeader', 'AppShell', 'RoutedApp', 'ViewFallback']
  for (const name of shared) assert.ok((await load(`/src/shared/${name}.vue`)).default, name)
})

await test('no Vue warnings while rendering', () => {
  assert.deepEqual(warnings.filter(w => !/Hydration|ElementPlusError/.test(w)), [])
})

await server.close()
if (failures.length) {
  console.error(failures.join('\n\n'))
  console.error(`\n${failures.length} interface test(s) failed, ${passed} passed.`)
  process.exit(1)
}
console.log(`Interface unit and component tests passed (${passed}).`)
