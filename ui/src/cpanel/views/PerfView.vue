<script setup>
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import PageHeader from '../../shared/PageHeader.vue'
import StateView from '../../shared/StateView.vue'
import StatusBadge from '../../shared/StatusBadge.vue'
import { useClient, useResource } from '../../shared/api.js'
import { useLoad } from '../../shared/polling.js'

// Speed checks for one of the account's own sites (perf: tenant.perf). The server fetches the site's front page twice and
// reports compression, caching, HTTP/3 and the certificate. A check runs only when the button is pressed (it makes
// requests to the site, and the server allows one every few seconds).
const { t } = useI18n()
const client = useClient()
const sites = useResource(client, 'sites')
const domain = ref('')
const perf = useResource(client, 'perf', { params: () => ({ domain: domain.value }) })
const domains = computed(() => (Array.isArray(sites.data.value?.sites) ? sites.data.value.sites.map(s => String(s.domain)) : []))
async function init() {
  await sites.load()
  if (!domain.value && domains.value.length) domain.value = domains.value[0]
}
useLoad(init)
const result = computed(() => perf.data.value)
// A front page without the page cache is often not the site itself: the check then reports the WordPress folders it found.
function cacheRow(r, cache) {
  const subsites = Array.isArray(r.cache_subsites) ? r.cache_subsites : []
  const cached = subsites.filter(s => s.state === 'hit').map(s => s.path)
  if (cache === 'none' && subsites.length) {
    if (cached.length) return { key: 'cache', tone: 'ok', text: t('cpanel.perf.cache.subsiteHit', { paths: cached.join(', ') }) }
    return { key: 'cache', tone: 'warn', text: t('cpanel.perf.cache.subsiteNone', { paths: subsites.map(s => s.path).join(', ') }) }
  }
  return { key: 'cache', tone: cache === 'hit' ? 'ok' : 'warn', text: t(`cpanel.perf.cache.${['hit', 'miss', 'none'].includes(cache) ? cache : 'none'}`) }
}
const rows = computed(() => {
  const r = result.value
  if (!r || r.reachable !== true) return []
  const compression = r.compression?.state
  const cache = r.cache?.state
  return [
    { key: 'compression', tone: compression === 'on' ? 'ok' : compression === 'not_html' ? 'neutral' : 'warn',
      text: t(`cpanel.perf.compression.${['on', 'off', 'not_html'].includes(compression) ? compression : 'off'}`) },
    cacheRow(r, cache),
    { key: 'http3', tone: r.http3?.advertised ? 'ok' : 'neutral', text: t(r.http3?.advertised ? 'cpanel.perf.http3.yes' : 'cpanel.perf.http3.no') },
    { key: 'tls', tone: r.tls?.verified ? 'ok' : 'bad', text: t(r.tls?.verified ? 'cpanel.perf.tls.yes' : 'cpanel.perf.tls.no') },
  ]
})
</script>

<template>
  <div>
    <PageHeader :title="t('cpanel.perf.title')" :description="t('cpanel.perf.description')" />
    <StateView :resource="sites" :empty="sites.data.value !== null && !domains.length" :empty-text="t('cpanel.logs.noDomains')">
      <div class="olsc-toolbar olsc-gap-below">
        <el-select v-model="domain" :aria-label="t('cpanel.logs.domain')" style="width: 260px">
          <el-option v-for="d in domains" :key="d" :label="d" :value="d" />
        </el-select>
        <el-button type="primary" :loading="perf.loading.value" :disabled="!domain" @click="perf.load()">{{ t('cpanel.perf.run') }}</el-button>
      </div>
      <p v-if="!result && !perf.error.value" class="olsc-muted">{{ t('cpanel.perf.hint') }}</p>
      <el-alert v-if="perf.error.value" type="warning" show-icon :closable="false" class="olsc-gap-below"
                :title="t('cpanel.perf.failed')" :description="perf.error.value.code === 'RATE_LIMITED' ? t('cpanel.perf.wait') : perf.error.value.message" />
      <template v-if="result">
        <el-alert v-if="result.reachable === false" type="warning" show-icon :closable="false" :title="t('cpanel.perf.unreachable')" :description="result.error" />
        <ul v-else class="olsc-plain-list" role="status">
          <li v-for="r in rows" :key="r.key" class="olsc-gap-below"><StatusBadge :tone="r.tone" :label="t(`cpanel.perf.names.${r.key}`)" /> {{ r.text }}</li>
          <li class="olsc-muted">{{ t('cpanel.perf.timing', { first: result.time_first_ms, second: result.time_second_ms }) }}</li>
        </ul>
        <p class="olsc-muted olsc-small">{{ result.slow_urls?.available === true ? '' : t('cpanel.perf.noSlow') }}</p>
      </template>
    </StateView>
  </div>
</template>
