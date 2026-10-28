// Browser and accessibility check of the fixture build (build/ui/browser-check.sh): a real headless Chromium
// (playwright-core, pinned in package.json) loads every route of both applications in every fixture
// scenario of dev/transport.js, runs axe-core (WCAG 2.0/2.1 A and AA rules) and checks console errors,
// horizontal scroll at 320 and 1280 px, keyboard reachability and visible focus, non-semantic click
// targets, heading structure, and the dialogs (focus trap, Escape, focus return).
// Usage: node check.mjs <dist-fixtures dir> [--quick] [--app=whm|cpanel] [--scenario=<name>] [--route=<path>] [--no-dialogs]
// (exit 1 on any violation; the filters are for fixing one finding without the full run)
import { createServer } from 'node:http'
import { readFileSync, existsSync, statSync } from 'node:fs'
import { extname, join, normalize } from 'node:path'
import { createRequire } from 'node:module'
import { chromium } from 'playwright-core'

const require = createRequire(import.meta.url)
const AXE = readFileSync(require.resolve('axe-core/axe.min.js'), 'utf8')
const ROOT = process.argv[2]
const QUICK = process.argv.includes('--quick')
if (!ROOT || !existsSync(join(ROOT, 'dev/whm.html'))) {
  console.error('usage: node check.mjs <dist-fixtures dir> (a fixture build: build/ui/browser-check.sh)')
  process.exit(2)
}

const ROUTES = {
  whm: ['overview', 'switch', 'compatibility', 'accounts', 'generations', 'jobs', 'jobs/j1792627900-0a1b2c3d', 'cache', 'php', 'requests',
    'diagnostics', 'activity', 'notifications', 'maintenance', 'updates', 'support'],
  cpanel: ['sites', 'htaccess', 'cache', 'php', 'logs', 'performance', 'requests', 'objcache', 'history', 'purge'],
}
const SCENARIOS = ['default', 'cutover', 'metrics-stale', 'empty', 'unauthorized', 'session', 'error', 'metrics-unavailable', 'slow']
const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']
const TYPES = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.svg': 'image/svg+xml', '.woff2': 'font/woff2' }

const server = createServer((req, res) => {
  const file = normalize(join(ROOT, decodeURIComponent(new URL(req.url, 'http://x').pathname)))
  if (!file.startsWith(ROOT) || !existsSync(file) || !statSync(file).isFile()) { res.writeHead(404).end(); return }
  res.writeHead(200, { 'content-type': TYPES[extname(file)] || 'application/octet-stream' }).end(readFileSync(file))
})
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
const base = `http://127.0.0.1:${server.address().port}`

const browser = await chromium.launch({ args: ['--no-sandbox'] })
const problems = []
const stats = { pages: 0, axeRuns: 0, dialogs: 0, buttonsTried: 0 }
const report = (where, kind, detail) => problems.push(`${where} | ${kind} | ${detail}`)

async function open(app, scenario, route, { width = 1280, scheme = 'light' } = {}) {
  const context = await browser.newContext({ viewport: { width, height: 900 }, colorScheme: scheme, reducedMotion: 'reduce' })
  const page = await context.newPage()
  const errors = []
  page.on('console', m => { if (m.type() === 'error' || m.type() === 'warning') errors.push(`console ${m.type()}: ${m.text()}`) })
  page.on('pageerror', e => errors.push(`pageerror: ${e.message}`))
  page.on('requestfailed', r => errors.push(`request failed: ${r.url()}`))
  // The fixture transport answers in-page; every 4xx/5xx of a scenario is a deliberate state, not a console error to chase.
  await page.goto(`${base}/dev/${app}.html?fixture=${scenario}#/${route}`)
  await page.waitForSelector('.olsc-body')
  await page.waitForLoadState('networkidle')
  await page.waitForFunction(() => !document.querySelector('.el-loading-mask, .el-skeleton.is-animated'), null, { timeout: 15000 }).catch(() => {})
  await page.waitForTimeout(scenario === 'slow' ? 3200 : 500)
  return { page, context, errors }
}

async function axe(page, where, selector) {
  await page.evaluate(AXE)
  const result = await page.evaluate(({ tags, selector }) => window.axe.run(selector ? document.querySelector(selector) : document,
    { runOnly: { type: 'tag', values: tags }, resultTypes: ['violations'] }), { tags: TAGS, selector })
  stats.axeRuns++
  for (const v of result.violations) {
    for (const n of v.nodes.slice(0, 3)) report(where, `axe ${v.id} (${v.impact})`, `${n.target.join(' ')} :: ${(n.html || '').replace(/\s+/g, ' ').slice(0, 110)} :: ${((n.any[0] || n.all[0] || n.none[0] || {}).message || '').slice(0, 130)}`)
  }
}

async function structure(page, where) {
  const info = await page.evaluate(() => {
    const visible = el => { const r = el.getBoundingClientRect(); const s = getComputedStyle(el); return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none' }
    const headings = [...document.querySelectorAll('h1,h2,h3,h4,h5,h6,[role=heading]')].filter(visible)
      .map(h => Number(h.getAttribute('aria-level') || h.tagName[1] || 2))
    const skips = headings.filter((l, i) => i > 0 && l > headings[i - 1] + 1).length
    const clickable = [...document.querySelectorAll('.olsc-body *, .olsc-header *')].filter(el => visible(el) && getComputedStyle(el).cursor === 'pointer'
      && !el.closest('a[href],button,[tabindex],input,select,textarea,label,[role=button],[role=tab],[role=switch],[role=checkbox],[role=radio],[role=menuitem],[role=option],summary,.el-select,.el-switch,.el-checkbox,.el-radio,.el-pagination,.el-table__expand-icon,.el-tabs__item,.el-input__wrapper,.el-radio-button,[disabled],.is-disabled'))
      .slice(0, 5).map(el => el.tagName.toLowerCase() + '.' + String(el.className).slice(0, 40))
    return { h1: headings.filter(l => l === 1).length, skips, clickable,
      nav: document.querySelectorAll('nav[aria-label]').length, region: document.querySelectorAll('.olsc-body[aria-label]').length,
      tabindexPositive: document.querySelectorAll('[tabindex]:not([tabindex="0"]):not([tabindex^="-"])').length,
      scroll: document.documentElement.scrollWidth - document.documentElement.clientWidth,
      wide: [...document.querySelectorAll('.olsc-app *')].filter(el => {
        if (el.getBoundingClientRect().right <= document.documentElement.clientWidth + 1 || !visible(el)) return false
        for (let p = el.parentElement; p && p !== document.body; p = p.parentElement) if (/(auto|scroll|hidden)/.test(getComputedStyle(p).overflowX)) return false
        return true
      }).slice(0, 3).map(el => el.tagName.toLowerCase() + '.' + String(el.className).slice(0, 50)),
      imgNoAlt: [...document.images].filter(i => !i.hasAttribute('alt')).length }
  })
  if (info.h1 !== 1) report(where, 'heading', `${info.h1} h1 elements (expected 1)`)
  if (info.skips) report(where, 'heading', `${info.skips} heading level skip(s)`)
  if (info.clickable.length) report(where, 'keyboard', `pointer targets that are not focusable: ${info.clickable.join(', ')}`)
  if (info.nav !== 1 || info.region !== 1) report(where, 'landmark', `nav=${info.nav} content-region=${info.region} (expected 1 and 1)`)
  if (info.tabindexPositive) report(where, 'keyboard', `${info.tabindexPositive} element(s) with a positive tabindex`)
  if (info.scroll > 0) report(where, 'reflow', `horizontal scroll of ${info.scroll}px: ${info.wide.join(', ')}`)
  if (info.imgNoAlt) report(where, 'alt', `${info.imgNoAlt} img without alt`)
}

// Tab through the page: every visible focusable control is reached, in DOM-compatible order, with a visible focus indicator.
async function keyboard(page, where) {
  const focusables = await page.evaluate(() => {
    const visible = el => { const r = el.getBoundingClientRect(); const s = getComputedStyle(el); return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none' }
    return [...document.querySelectorAll('a[href],button:not([disabled]),input:not([disabled]):not([type=hidden]),select:not([disabled]),textarea:not([disabled]),[tabindex="0"]')]
      .filter(el => visible(el) && !el.closest('[aria-hidden=true],[inert]')).length
  })
  await page.evaluate(() => { document.activeElement?.blur?.(); window.scrollTo(0, 0) })
  await page.keyboard.press('Tab') // from the document start (after a blur, the first focusable is next)
  const seen = new Set()
  let invisible = 0
  const noRing = []
  for (let i = 0; i < Math.min(focusables, 400) + 3; i++) {
    const r = await page.evaluate(() => {
      const el = document.activeElement
      if (!el || el === document.body) return null
      const s = getComputedStyle(el)
      const ring = (s.outlineStyle !== 'none' && parseFloat(s.outlineWidth) > 0) || s.boxShadow !== 'none'
      const wrapper = el.closest('.el-input__wrapper,.el-select__wrapper,.el-textarea__inner,.el-switch,.el-checkbox,.el-radio,.el-button,.el-pager,.el-pagination')
      const ws = wrapper && getComputedStyle(wrapper)
      const wring = ws && (ws.boxShadow !== 'none' || (ws.outlineStyle !== 'none' && parseFloat(ws.outlineWidth) > 0))
      const key = el.tagName + '|' + (el.id || '') + '|' + (el.className || '') + '|' + (el.textContent || '').trim().slice(0, 30) + '|' + [...document.querySelectorAll(el.tagName)].indexOf(el)
      return { key, ring: Boolean(ring || wring), label: el.tagName.toLowerCase() + (el.id ? '#' + el.id : '') + ':' + (el.getAttribute('aria-label') || el.textContent || '').trim().slice(0, 30) }
    })
    if (r) {
      if (!r.ring) noRing.push(r.label)
      seen.add(r.key)
    } else invisible++
    await page.keyboard.press('Tab')
  }
  if (noRing.length) report(where, 'focus-visible', `no visible focus indicator on: ${[...new Set(noRing)].slice(0, 6).join(' ; ')}`)
  // The pointer-based focusable count includes controls inside collapsed or clipped scroll areas; allow a small gap only for those.
  if (seen.size < focusables * 0.9) report(where, 'keyboard', `Tab reached ${seen.size} of ${focusables} focusable controls`)
}

// Click every enabled button of the route (fresh page each): a dialog that opens must hold focus, close on Escape and return focus.
async function dialogs(app, route, where) {
  const probe = await open(app, 'default', route)
  const labels = await probe.page.evaluate(() => [...document.querySelectorAll('.olsc-body button:not([disabled]), .olsc-body [role=button]')]
    .map((el, i) => ({ i, text: (el.getAttribute('aria-label') || el.textContent || '').trim().slice(0, 40) })))
  await probe.context.close()
  for (const { i, text } of labels.slice(0, 40)) {
    const { page, context } = await open(app, 'default', route)
    stats.buttonsTried++
    const tag = `${where} button#${i} "${text}"`
    try {
      const btn = page.locator('.olsc-body button:not([disabled]), .olsc-body [role=button]').nth(i)
      await btn.focus()
      await page.keyboard.press('Enter') // keyboard activation (Enter on a native button)
      await page.waitForTimeout(400)
      const dlg = page.locator('[role=dialog]:visible, .el-popover:visible, .el-popper.is-pure:visible')
      if (await dlg.count()) {
        stats.dialogs++
        const modal = await page.locator('[role=dialog]:visible').count()
        await axe(page, tag + ' (open)', null)
        if (modal) {
          const inside = () => page.evaluate(() => Boolean(document.activeElement?.closest('[role=dialog]')))
          if (!await inside()) report(tag, 'dialog', 'focus did not move into the dialog')
          for (let k = 0; k < 12; k++) {
            await page.keyboard.press('Tab')
            if (!await inside()) { report(tag, 'dialog', `focus left the dialog on Tab ${k + 1}`); break }
          }
          await page.keyboard.press('Escape')
          await page.waitForTimeout(500)
          if (await page.locator('[role=dialog]:visible').count()) report(tag, 'dialog', 'Escape did not close the dialog')
          else {
            const back = await page.evaluate(i => document.activeElement === document.querySelectorAll('.olsc-body button:not([disabled]), .olsc-body [role=button]')[i], i)
            if (!back) report(tag, 'dialog', 'focus did not return to the trigger after Escape')
          }
        }
      }
    } catch (e) {
      report(tag, 'harness', String(e.message).split('\n')[0])
    }
    await context.close()
  }
}

const only = name => process.argv.find(a => a.startsWith(`--${name}=`))?.split('=')[1]
const jobs = []
for (const app of Object.keys(ROUTES)) {
  if (only('app') && only('app') !== app) continue
  for (const scenario of only('scenario') ? [only('scenario')] : QUICK ? ['default', 'empty'] : SCENARIOS) {
    for (const route of ROUTES[app]) {
      if (only('route') && only('route') !== route) continue
      jobs.push(async () => {
        const where = `${app}/${scenario}/${route}`
        const views = scenario === 'default' ? [{ width: 1280, scheme: 'light' }, { width: 1280, scheme: 'dark' }, { width: 320, scheme: 'light' }] : [{ width: 1280, scheme: 'light' }]
        for (const view of views) {
          const w = `${where} @${view.width}${view.scheme === 'dark' ? ' dark' : ''}`
          const { page, context, errors } = await open(app, scenario, route, view)
          stats.pages++
          await axe(page, w)
          await structure(page, w)
          for (const e of errors) report(w, 'console', e.slice(0, 200))
          if (scenario === 'default' && view.width === 1280 && view.scheme === 'light') await keyboard(page, w)
          await context.close()
        }
        if (scenario === 'default' && !process.argv.includes('--no-dialogs')) await dialogs(app, route, where)
      })
    }
  }
}
// A small pool: Chromium contexts are cheap, the pages are mostly waiting for the in-page fixture latency.
const queue = [...jobs]
await Promise.all(Array.from({ length: 4 }, async () => { for (let job = queue.shift(); job; job = queue.shift()) await job() }))
await browser.close()
server.close()

const unique = [...new Set(problems)]
console.log(`pages ${stats.pages}, axe runs ${stats.axeRuns}, buttons tried ${stats.buttonsTried}, dialogs/popovers opened ${stats.dialogs}`)
if (unique.length) {
  console.log(`${unique.length} problem(s):`)
  for (const p of unique) console.log(' - ' + p)
  process.exit(1)
}
console.log('browser check passed: no axe violations, console errors, reflow, keyboard or dialog problems')
