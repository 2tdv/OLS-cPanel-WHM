// Checks a production interface build (artifacts/ui or a test build): both entries in the manifest with
// every referenced file present, views split into lazy chunks, no fixture code or data anywhere, and the
// first-view size budget (UIX-02). Usage: node tests/check_dist.mjs <build dir>
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { gzipSync } from 'node:zlib'

const dir = process.argv[2]
const fail = message => {
  console.error(`check_dist: ${message}`)
  process.exit(1)
}
if (!dir || !existsSync(join(dir, '.vite/manifest.json'))) fail('no .vite/manifest.json')
const manifest = JSON.parse(readFileSync(join(dir, '.vite/manifest.json'), 'utf8'))

// Markers of the fixture transport and fixture data (ui/dev): none may reach a production build.
const MARKERS = ['OLS_FIXTURE_TRANSPORT', 'fixture-domain.test', 'createFixtureSend', '__OLS_FIXTURES__', 'dev/fixtures']
const JS_BUDGET = 190 * 1024
const CSS_BUDGET = 40 * 1024

function files(root) {
  return readdirSync(root).flatMap(name => {
    const path = join(root, name)
    return statSync(path).isDirectory() ? files(path) : [path]
  })
}
for (const path of files(dir)) {
  if (path.endsWith('.html')) fail(`unexpected HTML file ${path}`)
  const text = readFileSync(path, 'utf8')
  for (const marker of MARKERS) if (text.includes(marker)) fail(`${path} contains fixture marker ${marker}`)
}

for (const entry of ['src/whm/main.js', 'src/cpanel/main.js']) {
  const chunk = manifest[entry]
  if (!chunk?.isEntry) fail(`${entry} is not an entry of the manifest`)
  if (!(chunk.dynamicImports || []).length) fail(`${entry} has no lazily loaded views`)
  const seen = new Set()
  let js = 0
  let css = 0
  const walk = key => {
    if (seen.has(key)) return
    seen.add(key)
    const c = manifest[key]
    if (!c) fail(`manifest key ${key} missing`)
    if (!existsSync(join(dir, c.file))) fail(`${c.file} missing`)
    js += gzipSync(readFileSync(join(dir, c.file))).length
    for (const file of c.css || []) {
      if (!existsSync(join(dir, file))) fail(`${file} missing`)
      css += gzipSync(readFileSync(join(dir, file))).length
    }
    for (const imported of c.imports || []) walk(imported)
  }
  walk(entry)
  for (const key of chunk.dynamicImports) if (!existsSync(join(dir, manifest[key]?.file || '-'))) fail(`lazy chunk ${key} missing`)
  if (js > JS_BUDGET) fail(`${entry}: first-view JavaScript ${js} B gzip exceeds ${JS_BUDGET}`)
  if (css > CSS_BUDGET) fail(`${entry}: first-view CSS ${css} B gzip exceeds ${CSS_BUDGET}`)
  console.log(`${entry}: first view ${Math.round(js / 1024)} KiB JS + ${Math.round(css / 1024)} KiB CSS (gzip), ${chunk.dynamicImports.length} lazy views`)
}
console.log('Production interface build: manifest complete, no fixture code, within the first-view budget.')
