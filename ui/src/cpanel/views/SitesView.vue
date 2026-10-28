<script setup>
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import EngineBadge from '../../shared/EngineBadge.vue'
import HelpTip from '../../shared/HelpTip.vue'
import PageHeader from '../../shared/PageHeader.vue'
import StateView from '../../shared/StateView.vue'
import StatusBadge from '../../shared/StatusBadge.vue'
import { useClient, useResource } from '../../shared/api.js'
import { serverEngine } from '../../shared/engine.js'
import { certificateState, formatDate } from '../../shared/format.js'
import { useLoad, useNow } from '../../shared/polling.js'

// My sites (sites: the account's own domains; status: the server's serving engine). While the server
// still runs Apache the engine column is labelled as the engine after the switch.
const { t, te } = useI18n()
const client = useClient()
const status = useResource(client, 'status', { staleAfter: 2 * 60 * 1000 })
const sites = useResource(client, 'sites')
useLoad(() => Promise.all([status.load(), sites.load()]))
const now = useNow()
const rows = computed(() => {
  const data = sites.data.value
  return Array.isArray(data) ? data : Array.isArray(data?.sites) ? data.sites : []
})
const server = computed(() => serverEngine(status.data.value))
const onApache = computed(() => server.value === 'apache')
const ENGINES = ['ols', 'hybrid', 'apache', 'unknown']
const engineOf = row => (ENGINES.includes(row.engine) ? row.engine : 'unknown')
const typeLabel = type => (te(`types.${type}`) ? t(`types.${type}`) : (type || t('state.unknown')))
const expiring = computed(() => rows.value.filter(r => r.tls?.present === true
  && ['soon', 'expired'].includes(certificateState(r.tls.not_after, now.value).state)).length)

function tls(row) {
  if (row.tls?.present === false) return { tone: 'warn', label: t('tls.absent') }
  if (row.tls?.present !== true) return { tone: 'neutral', label: t('state.unknown') }
  const cert = certificateState(row.tls.not_after, now.value)
  if (cert.state === 'expired') return { tone: 'bad', label: t('tls.expired', { date: formatDate(row.tls.not_after) }) }
  if (cert.state === 'soon') return { tone: 'warn', label: t('tls.expiresIn', { n: Math.max(cert.days, 0) }) }
  if (cert.state === 'ok') return { tone: 'ok', label: t('tls.validUntil', { date: formatDate(row.tls.not_after) }) }
  return { tone: 'neutral', label: t('tls.presentUnknownExpiry') }
}
</script>

<template>
  <div>
    <PageHeader :title="t('cpanel.sites.title')" :description="t('cpanel.sites.description')" />
    <div class="olsc-toolbar" role="status">
      <span class="olsc-muted">{{ t('engine.serving') }}:</span>
      <EngineBadge :status="status.data.value" />
    </div>
    <el-alert v-if="onApache" type="info" :closable="false" show-icon class="olsc-gap-below"
              :title="t('cpanel.sites.apacheTitle')" :description="t('cpanel.sites.apacheBody')" />
    <el-alert v-if="expiring" type="warning" :closable="false" show-icon class="olsc-gap-below"
              :title="t('cpanel.sites.expiring', { n: expiring })" :description="t('cpanel.sites.expiringBody')" />
    <StateView :resource="sites" :empty="sites.data.value !== null && !rows.length" :empty-text="t('cpanel.sites.none')">
      <el-table :data="rows" stripe size="small" :aria-label="t('cpanel.sites.title')">
        <el-table-column :label="t('fields.domain')" min-width="210">
          <template #default="{ row }">
            <span class="olsc-mono">{{ row.domain }}</span>
            <StatusBadge v-if="row.suspended === true" tone="bad" :label="t('account.suspended')" />
          </template>
        </el-table-column>
        <el-table-column :label="t('fields.type')" width="140">
          <template #default="{ row }">{{ typeLabel(row.type) }}</template>
        </el-table-column>
        <el-table-column :label="onApache ? t('cpanel.sites.engineAfter') : t('fields.engine')" width="210">
          <template #default="{ row }">
            <EngineBadge :engine="engineOf(row)" />
            <HelpTip v-if="engineOf(row) === 'hybrid'" topic="hybrid_vhost" />
          </template>
        </el-table-column>
        <el-table-column :label="t('fields.php')" width="150">
          <template #default="{ row }">
            <div>{{ row.php_version || t('state.unknown') }}</div>
            <div class="olsc-muted olsc-small">{{ row.php_handler || '' }}</div>
          </template>
        </el-table-column>
        <el-table-column :label="t('fields.certificate')" min-width="200">
          <template #default="{ row }"><StatusBadge :tone="tls(row).tone" :label="tls(row).label" /></template>
        </el-table-column>
        <el-table-column :label="t('fields.docroot')" min-width="220">
          <template #default="{ row }"><span class="olsc-mono olsc-wrap">{{ row.docroot }}</span></template>
        </el-table-column>
      </el-table>
    </StateView>
  </div>
</template>
