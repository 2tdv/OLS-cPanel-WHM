<script setup>
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import PageHeader from '../../shared/PageHeader.vue'
import StateView from '../../shared/StateView.vue'
import { buildUrl, useClient, useResource } from '../../shared/api.js'
import { formatDateTime, formatNumber } from '../../shared/format.js'
import { useLoad } from '../../shared/polling.js'

// The account's own logs (logs: tenant.logs, php_errors: tenant.php_errors). The server checks that the domain is one of
// this account's, shortens long lines, hides passwords, tokens and cookies and limits what it reads; the page only picks
// a domain, a log and how many lines. "Live" asks for the last lines again every five seconds while it is on.
const { t } = useI18n()
const client = useClient()
const sites = useResource(client, 'sites')
const domain = ref('')
const kind = ref('access')
const lines = ref(200)
const search = ref('')
const live = ref(false)
const query = () => ({ domain: domain.value, kind: kind.value, lines: lines.value, search: search.value.trim() })
const logs = useResource(client, 'logs', { params: query, staleAfter: 60 * 1000 })
const errors = useResource(client, 'php_errors', { params: () => ({ domain: domain.value }), staleAfter: 10 * 60 * 1000 })

const domains = computed(() => (Array.isArray(sites.data.value?.sites) ? sites.data.value.sites.map(s => String(s.domain)) : []))
const text = computed(() => (Array.isArray(logs.data.value?.lines) ? logs.data.value.lines.join('\n') : ''))
const groups = computed(() => (Array.isArray(errors.data.value?.groups) ? errors.data.value.groups : []))
const downloadUrl = computed(() => buildUrl(client.endpoint, { api: 'logs_download', domain: domain.value, kind: kind.value, search: search.value.trim() }))
const num = value => formatNumber(value) ?? t('state.unknown')

async function loadAll() {
  await sites.load()
  if (!domain.value && domains.value.length) domain.value = domains.value[0]
  if (domain.value) await Promise.all([logs.load(), errors.load()])
}
useLoad(loadAll)
const reload = () => domain.value && logs.load()
const reloadAll = () => domain.value && Promise.all([logs.load(), errors.load()])

let timer = null
watch(live, on => {
  clearInterval(timer)
  timer = on ? setInterval(() => { if (!globalThis.document?.hidden && !logs.loading.value) reload() }, 5000) : null
})
onBeforeUnmount(() => clearInterval(timer))
</script>

<template>
  <div>
    <PageHeader :title="t('cpanel.logs.title')" :description="t('cpanel.logs.description')" />
    <StateView :resource="sites" :empty="sites.data.value !== null && !domains.length" :empty-text="t('cpanel.logs.noDomains')">
      <div class="olsc-toolbar olsc-gap-below" role="group" :aria-label="t('cpanel.logs.controls')">
        <el-select v-model="domain" :aria-label="t('cpanel.logs.domain')" style="width: 240px" @change="reloadAll">
          <el-option v-for="d in domains" :key="d" :label="d" :value="d" />
        </el-select>
        <el-select v-model="kind" :aria-label="t('cpanel.logs.kind')" style="width: 200px" @change="reload">
          <el-option :label="t('cpanel.logs.kinds.access')" value="access" />
          <el-option :label="t('cpanel.logs.kinds.access_http')" value="access_http" />
          <el-option :label="t('cpanel.logs.kinds.error')" value="error" />
        </el-select>
        <el-select v-model="lines" :aria-label="t('cpanel.logs.lines')" style="width: 120px" @change="reload">
          <el-option v-for="n in [100, 200, 500]" :key="n" :label="t('cpanel.logs.lastLines', { n })" :value="n" />
        </el-select>
        <el-input v-model="search" maxlength="100" clearable :placeholder="t('cpanel.logs.search')" :aria-label="t('cpanel.logs.search')"
                  style="width: 220px" @keyup.enter="reload" @clear="reload" />
        <el-button :loading="logs.loading.value" @click="reload">{{ t('cpanel.logs.refresh') }}</el-button>
        <el-switch v-model="live" :active-text="t('cpanel.logs.live')" :aria-label="t('cpanel.logs.live')" />
        <a :href="downloadUrl" target="_blank" rel="noopener">{{ t('cpanel.logs.download') }}</a>
      </div>
      <p class="olsc-muted olsc-small">{{ t('cpanel.logs.privacy') }}</p>
      <StateView :resource="logs" :empty="logs.data.value !== null && logs.data.value.exists === false" :empty-text="t('cpanel.logs.noFile')">
        <p v-if="logs.data.value?.window_truncated" class="olsc-muted olsc-small">{{ t('cpanel.logs.truncated') }}</p>
        <p v-if="logs.data.value" class="olsc-muted" role="status">{{ t('cpanel.logs.shown', { n: num(logs.data.value.count) }) }}</p>
        <pre class="olsc-mono olsc-log" tabindex="0" :aria-label="t('cpanel.logs.title')">{{ text }}</pre>
      </StateView>
    </StateView>

    <section v-if="domains.length" class="olsc-card olsc-section" :aria-label="t('cpanel.logs.errorsTitle')">
      <h3 class="olsc-h3">{{ t('cpanel.logs.errorsTitle') }}</h3>
      <p class="olsc-muted">{{ t('cpanel.logs.errorsBody') }}</p>
      <StateView :resource="errors" :empty="errors.data.value !== null && !groups.length" :empty-text="t('cpanel.logs.noErrors')">
        <ul class="olsc-plain-list">
          <li v-for="(g, i) in groups" :key="i" class="olsc-gap-below">
            <strong>{{ g.level }}</strong> <span class="olsc-muted">{{ t('cpanel.logs.times', { n: num(g.count) }) }}</span>
            <div class="olsc-mono olsc-wrap">{{ g.message }}</div>
            <div class="olsc-muted olsc-small">{{ t('cpanel.logs.firstLast', { first: g.first_seen ?? t('state.unknown'), last: g.last_seen ?? t('state.unknown') }) }}</div>
          </li>
        </ul>
      </StateView>
      <p v-if="errors.data.value" class="olsc-muted olsc-small">{{ t('cpanel.logs.checkedAt', { time: formatDateTime(errors.data.value.observed_at) ?? t('state.unknown') }) }}</p>
    </section>
  </div>
</template>
