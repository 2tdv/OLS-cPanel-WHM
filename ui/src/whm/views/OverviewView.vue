<script setup>
import { computed, defineAsyncComponent, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import EngineBadge from '../../shared/EngineBadge.vue'
import HealthSummary from '../HealthSummary.vue'
import MetricCard from '../../shared/MetricCard.vue'
import PageHeader from '../../shared/PageHeader.vue'
import StateView from '../../shared/StateView.vue'
import StatusBadge from '../../shared/StatusBadge.vue'
import { href } from '../../shared/router.js'
import { useClient, useResource } from '../../shared/api.js'
import { cutOver, portOwner, portProcesses, profileName } from '../../shared/engine.js'
import { formatBytes, formatNumber } from '../../shared/format.js'
import { usePolling } from '../../shared/polling.js'

// The history charts are their own chunk: the first view stays inside its size budget (UIX-02).
const HistoryPanel = defineAsyncComponent(() => import('../../shared/HistoryPanel.vue'))

// Overview: server status (status), live statistics (metrics) and the domain count (inventory).
const { t } = useI18n()
const client = useClient()
const status = useResource(client, 'status', { staleAfter: 2 * 60 * 1000 })
const metrics = useResource(client, 'metrics', { staleAfter: 60 * 1000 })
const inventory = useResource(client, 'inventory', { params: { page: 1, size: 1 } })
const statusPoll = usePolling(() => status.load(), { interval: 30000, maxInterval: 5 * 60 * 1000 })
const metricsPoll = usePolling(() => metrics.load(), { interval: 10000, maxInterval: 2 * 60 * 1000 })
usePolling(() => inventory.load(), { interval: 5 * 60 * 1000, maxInterval: 30 * 60 * 1000 })
// Traffic history (history: admin.metrics): the whole server (vhost '') or one site, for an hour, a day or a week.
const resolution = ref('hour')
const historyVhost = ref('')
const history = useResource(client, 'history', {
  params: () => ({ resolution: resolution.value, vhost: historyVhost.value }),
  staleAfter: 5 * 60 * 1000,
})
const historyPoll = usePolling(() => history.load(), { interval: 60000, maxInterval: 10 * 60 * 1000 })
watch([resolution, historyVhost], () => historyPoll.refresh())

const s = computed(() => status.data.value || {})
const ownerLabel = port => t(`owner.${portOwner(status.data.value, port)}`)
const profile = computed(() => profileName(status.data.value ? s.value.profile : undefined))
const pendingEvents = computed(() => {
  const value = s.value.pending_events
  return Array.isArray(value) ? value.length : Number.isInteger(value) ? value : null
})
const hybridCount = computed(() => (Array.isArray(s.value.hybrid_vhosts) ? s.value.hybrid_vhosts.length : null))
const degraded = computed(() => (cutOver(status.data.value) && s.value.ols_active === false ? t('whm.overview.olsDown') : ''))

const m = computed(() => metrics.data.value || {})
const metricsState = computed(() => (['ok', 'stale', 'unavailable'].includes(m.value.status) ? m.value.status : 'unavailable'))
const server = computed(() => m.value.server || {})
const topVhosts = computed(() => (Array.isArray(m.value.vhosts) ? m.value.vhosts : [])
  .filter(v => typeof v?.requests_per_second === 'number')
  .sort((a, b) => b.requests_per_second - a.requests_per_second)
  .slice(0, 10))
const rate = value => (formatNumber(value) === null ? null : t('units.perSecond', { n: formatNumber(value) }))
const bandwidth = value => (formatBytes(value) === null ? null : t('units.perSecond', { n: formatBytes(value) }))
</script>

<template>
  <div>
    <PageHeader :title="t('whm.overview.title')" :description="t('whm.overview.description')" />

    <HealthSummary compact />

    <section :aria-label="t('whm.overview.serverSection')">
      <StateView :resource="status" :degraded="degraded" :refresh="statusPoll.refresh">
        <div class="olsc-grid">
          <div class="olsc-card" role="group" :aria-label="t('engine.serving')">
            <h3>{{ t('engine.serving') }}</h3>
            <div class="olsc-metric"><EngineBadge :status="status.data.value" /></div>
          </div>
          <MetricCard v-for="port in [80, 443]" :key="port" :label="t('whm.overview.port', { port })" :value="ownerLabel(port)"
                      :hint="portProcesses(status.data.value, port) ? t('whm.overview.processes', { names: portProcesses(status.data.value, port) }) : ''" />
          <MetricCard :label="t('whm.overview.profile')" :value="t(`profile.${profile}`)"
                      :hint="profile === 'hybrid' ? t('whm.overview.hybridPorts', { ports: s.profile.hybrid_ports.join(', ') }) : ''" />
          <MetricCard :label="t('whm.overview.generation')" mono
                      :value="s.active_generation === null ? t('whm.overview.noGeneration') : (s.active_generation ?? null)" />
          <MetricCard :label="t('whm.overview.epoch')" :value="Number.isInteger(s.epoch) ? String(s.epoch) : null"
                      :hint="t('whm.overview.epochHint')" />
          <MetricCard :label="t('whm.overview.pendingEvents')" :value="pendingEvents === null ? null : String(pendingEvents)"
                      :hint="t('whm.overview.pendingHint')" />
          <MetricCard :label="t('whm.overview.hybridVhosts')" :value="hybridCount === null ? null : String(hybridCount)" />
          <MetricCard :label="t('whm.overview.olsInstalled')"
                      :value="typeof s.ols_installed === 'boolean' ? t(s.ols_installed ? 'whm.overview.installed' : 'whm.overview.notInstalled') : null" />
          <MetricCard :label="t('whm.overview.domains')"
                      :value="Number.isInteger(inventory.data.value?.total) ? formatNumber(inventory.data.value.total) : null">
            <a :href="href('accounts')">{{ formatNumber(inventory.data.value?.total) }}</a>
          </MetricCard>
        </div>
      </StateView>
    </section>

    <section class="olsc-section" :aria-labelledby="'olsc-live'">
      <h3 id="olsc-live" class="olsc-h3">{{ t('whm.overview.live') }}</h3>
      <StateView :resource="metrics" :refresh="metricsPoll.refresh"
                 :degraded="metricsState === 'stale' ? t('whm.overview.metricsStale') : ''">
        <el-alert v-if="metricsState === 'unavailable'" type="info" :closable="false" show-icon
                  :title="t('whm.overview.metricsUnavailable')" :description="t('whm.overview.metricsUnavailableBody')" />
        <template v-else>
          <div class="olsc-grid">
            <MetricCard :label="t('metrics.requests')" :value="rate(server.requests_per_second)" />
            <MetricCard :label="t('metrics.connections')" :value="formatNumber(server.connections)" />
            <MetricCard :label="t('metrics.bandwidth')" :value="bandwidth(server.bytes_per_second)" />
            <MetricCard :label="t('metrics.processing')" :value="formatNumber(server.requests_processing)" />
            <MetricCard :label="t('metrics.tlsConnections')" :value="formatNumber(server.tls_connections)" />
            <MetricCard :label="t('metrics.cacheHits')" :value="rate(server.cache_hits_per_second)" />
            <MetricCard :label="t('metrics.phpInUse')" :value="formatNumber(server.extapp?.in_use)"
                        :hint="formatNumber(server.extapp?.waiting) === null ? '' : t('metrics.phpWaiting', { n: formatNumber(server.extapp.waiting) })" />
          </div>
          <h4 class="olsc-h4">{{ t('whm.overview.topVhosts') }}</h4>
          <el-table v-if="topVhosts.length" :data="topVhosts" size="small" stripe :aria-label="t('whm.overview.topVhosts')">
            <el-table-column :label="t('metrics.vhost')" min-width="220">
              <template #default="{ row }"><span class="olsc-mono">{{ row.vhost }}</span></template>
            </el-table-column>
            <el-table-column :label="t('metrics.requests')" width="170">
              <template #default="{ row }">{{ rate(row.requests_per_second) }}</template>
            </el-table-column>
            <el-table-column :label="t('metrics.cacheHits')" width="150">
              <template #default="{ row }">{{ rate(row.cache_hits_per_second) ?? t('state.unknown') }}</template>
            </el-table-column>
            <el-table-column :label="t('metrics.phpInUse')" width="150">
              <template #default="{ row }">{{ formatNumber(row.extapp?.in_use) ?? t('state.unknown') }}</template>
            </el-table-column>
          </el-table>
          <p v-else class="olsc-muted">{{ t('whm.overview.noVhostTraffic') }}</p>
        </template>
        <StatusBadge v-if="metricsState === 'ok'" tone="ok" :label="t('whm.overview.metricsLive')" />
      </StateView>
    </section>

    <section class="olsc-section" aria-labelledby="olsc-history">
      <h3 id="olsc-history" class="olsc-h3">{{ t('whm.overview.historyTitle') }}</h3>
      <p class="olsc-muted">{{ t('whm.overview.historyHint') }}</p>
      <StateView :resource="history" :refresh="historyPoll.refresh">
        <HistoryPanel v-if="history.data.value" :data="history.data.value" :resolution="resolution" :vhost="historyVhost" allow-server
                      @update:resolution="value => (resolution = value)" @update:vhost="value => (historyVhost = value)" />
      </StateView>
    </section>
  </div>
</template>
