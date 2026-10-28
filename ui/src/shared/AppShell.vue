<script setup>
import { nextTick, ref, watch, watchEffect } from 'vue'
import { useI18n } from 'vue-i18n'
import en from 'element-plus/es/locale/lang/en'
import { href } from './router.js'

// The frame of both applications (UIX-04): title, theme, navigation by hash links, one content region.
// Navigation items: { path, label }. Focus moves to the main region on every route
// change so keyboard and screen-reader users land on the new view (WCAG 2.4.3).
const props = defineProps({
  title: { type: String, required: true },
  nav: { type: Array, default: () => [] },
  active: { type: String, default: '' },
  routeKey: { type: String, default: '' },
})
const { t } = useI18n()
const fixtures = __OLS_FIXTURES__
const stored = (() => { try { return localStorage.getItem('ols-cpanel-theme') } catch { return null } })()
const dark = ref(stored ? stored === 'dark' : Boolean(globalThis.matchMedia?.('(prefers-color-scheme: dark)').matches))
const main = ref(null)

watchEffect(() => {
  try { localStorage.setItem('ols-cpanel-theme', dark.value ? 'dark' : 'light') } catch { /* per-session */ }
})
watch(() => props.routeKey, async (value, previous) => {
  if (previous === undefined) return
  await nextTick()
  main.value?.focus({ preventScroll: false })
})
function skip() {
  main.value?.focus()
}
</script>

<template>
  <el-config-provider :locale="en">
    <div class="olsc-app" :class="{ 'olsc-dark': dark }" dir="ltr" lang="en">
      <button type="button" class="olsc-skip" @click="skip">{{ t('shell.skip') }}</button>
      <header class="olsc-header">
        <h1 class="olsc-title">{{ props.title }}</h1>
        <el-switch v-model="dark" :active-text="t('theme.dark')" :inactive-text="t('theme.light')" inline-prompt
                   :aria-label="t('theme.toggle')" />
      </header>
      <div v-if="fixtures" class="olsc-fixture-banner" role="note">{{ t('dev.fixtureBanner') }}</div>
      <div class="olsc-layout">
        <nav v-if="props.nav.length" class="olsc-nav" :aria-label="t('shell.navigation')">
          <ul>
            <li v-for="item in props.nav" :key="item.path">
              <a :href="href(item.path)" :aria-current="item.path === props.active ? 'page' : undefined">{{ item.label }}</a>
            </li>
          </ul>
        </nav>
        <!-- A labelled region, not <main>: the WHM and cPanel chrome around the page owns the landmarks. -->
        <section ref="main" class="olsc-body" tabindex="-1" :aria-label="t('shell.content')">
          <slot />
        </section>
      </div>
    </div>
  </el-config-provider>
</template>
