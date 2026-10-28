import { fileURLToPath } from 'node:url'
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

const here = path => fileURLToPath(new URL(path, import.meta.url))

// Two applications from one design system. The host page (WHM CGI, cPanel LivePHP) reads the
// manifest and emits the tags; assets resolve relative to the session-prefixed page URL.
//
// Fixture mode (plan 21.3 "demo mode"): offline development against the JSON in dev/fixtures. It is a
// separate, explicitly labeled build: `OLS_UI_FIXTURES=1 vite --mode fixtures` (or `build --mode
// fixtures` into dist-fixtures/). Both switches are required, production refuses either one, and
// the fixture transport is only ever reached through the alias below, so it never enters the
// production module graph.
export default defineConfig(({ command, mode }) => {
  const flag = process.env.OLS_UI_FIXTURES === '1'
  const fixtures = mode === 'fixtures'
  if (flag !== fixtures) {
    throw new Error('Fixture mode needs both OLS_UI_FIXTURES=1 and --mode fixtures; production builds refuse either one.')
  }
  if (fixtures && command === 'build' && process.env.OLS_UI_OUT) {
    throw new Error('Fixture builds never write to the release artifact directory (OLS_UI_OUT).')
  }
  return {
    base: './',
    plugins: [vue()],
    define: { __OLS_FIXTURES__: JSON.stringify(fixtures) },
    resolve: {
      alias: {
        '@ols/transport': fixtures ? here('./dev/transport.js') : here('./src/shared/transport.js'),
      },
    },
    build: {
      outDir: fixtures ? 'dist-fixtures' : (process.env.OLS_UI_OUT || 'dist'),
      emptyOutDir: true,
      manifest: true,
      target: 'es2020',
      cssCodeSplit: true,
      rollupOptions: {
        input: fixtures
          ? { whm: here('./dev/whm.html'), cpanel: here('./dev/cpanel.html') }
          : { whm: 'src/whm/main.js', cpanel: 'src/cpanel/main.js' },
        output: {
          manualChunks(id) {
            if (id.includes('node_modules/element-plus') || id.includes('node_modules/@element-plus')) return 'element-plus'
            if (id.includes('node_modules')) return 'vendor'
          },
        },
      },
    },
  }
})
