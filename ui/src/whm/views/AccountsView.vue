<script setup>
import { useI18n } from 'vue-i18n'
import DataTable from '../../shared/DataTable.vue'
import EngineBadge from '../../shared/EngineBadge.vue'
import HelpTip from '../../shared/HelpTip.vue'
import PageHeader from '../../shared/PageHeader.vue'
import StatusBadge from '../../shared/StatusBadge.vue'
import { computed } from 'vue'
import { useLoad } from '../../shared/polling.js'
import { useClient, usePaged } from '../../shared/api.js'

// Accounts and domains (inventory): server-side search and paging, one page in the browser, so
// 10,000+ domains stay usable (UIX-02).
const { t, te } = useI18n()
const client = useClient()
const paged = usePaged(client, 'inventory', { rowsKey: 'domains', size: 50 })
useLoad(() => paged.resource.load())
const ENGINES = ['ols', 'hybrid', 'apache', 'unknown']
const engineOf = row => (ENGINES.includes(row.engine) ? row.engine : 'unknown')
// Where the engine column comes from: the active generation's summary, else the latest plan, else nothing.
const engineSource = computed(() => {
  const source = paged.resource.data.value?.engine_source
  if (!paged.resource.data.value) return ''
  if (!source || typeof source !== 'object') return t('whm.accounts.engineNone')
  const key = source.source === 'plan' ? 'whm.accounts.enginePlan' : 'whm.accounts.engineActive'
  return t(key, { id: source.id ?? t('state.unknown') })
})
const typeLabel = type => (te(`types.${type}`) ? t(`types.${type}`) : (type || t('state.unknown')))
</script>

<template>
  <div>
    <PageHeader :title="t('whm.accounts.title')" :description="t('whm.accounts.description')" />
    <p v-if="engineSource" class="olsc-muted olsc-small">{{ engineSource }}</p>
    <p v-if="paged.resource.data.value?.rejected_rows" class="olsc-hint">
      {{ t('whm.accounts.rejected', { n: paged.resource.data.value.rejected_rows }) }}
    </p>
    <DataTable :paged="paged" :caption="t('whm.accounts.title')" :search-label="t('whm.accounts.search')"
               :empty-text="paged.query.value ? t('whm.accounts.noMatch') : t('whm.accounts.none')">
      <el-table-column :label="t('fields.domain')" min-width="210">
        <template #default="{ row }"><span class="olsc-mono">{{ row.domain }}</span></template>
      </el-table-column>
      <el-table-column :label="t('fields.account')" min-width="110">
        <template #default="{ row }"><span class="olsc-mono">{{ row.user }}</span></template>
      </el-table-column>
      <el-table-column :label="t('fields.type')" width="120">
        <template #default="{ row }">{{ typeLabel(row.type) }}</template>
      </el-table-column>
      <el-table-column :label="t('fields.engine')" width="190">
        <template #default="{ row }"><EngineBadge :engine="engineOf(row)" /><HelpTip v-if="engineOf(row) === 'hybrid'" topic="hybrid_vhost" /></template>
      </el-table-column>
      <el-table-column :label="t('fields.phpHandler')" width="120">
        <template #default="{ row }">{{ row.php_handler || t('state.unknown') }}</template>
      </el-table-column>
      <el-table-column :label="t('fields.tls')" width="120">
        <template #default="{ row }">
          <StatusBadge v-if="typeof row.tls === 'boolean'" :tone="row.tls ? 'ok' : 'warn'"
                       :label="row.tls ? t('tls.present') : t('tls.absent')" />
          <span v-else class="olsc-unknown">{{ t('state.unknown') }}</span>
        </template>
      </el-table-column>
      <el-table-column :label="t('fields.suspended')" width="130">
        <template #default="{ row }">
          <StatusBadge v-if="row.suspended === true" tone="bad" :label="t('account.suspended')" />
          <span v-else-if="row.suspended === false" class="olsc-muted">{{ t('account.active') }}</span>
          <span v-else class="olsc-unknown">{{ t('state.unknown') }}</span>
        </template>
      </el-table-column>
      <el-table-column :label="t('fields.docroot')" min-width="240">
        <template #default="{ row }"><span class="olsc-mono olsc-wrap">{{ row.docroot }}</span></template>
      </el-table-column>
    </DataTable>
  </div>
</template>
