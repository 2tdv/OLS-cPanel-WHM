<script setup>
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import DataTable from '../../shared/DataTable.vue'
import PageHeader from '../../shared/PageHeader.vue'
import StatusBadge from '../../shared/StatusBadge.vue'
import { useClient, usePaged } from '../../shared/api.js'
import { formatDateTime } from '../../shared/format.js'
import { actionLabel } from '../../shared/jobs.js'
import { useLoad } from '../../shared/polling.js'
import { href } from '../../shared/router.js'

// Activity (audit: the broker's audit log, newest first): who did what and when, with its result. Search, event and result
// filters and paging are applied by the server, so a long log stays fast (the last 4 MiB of it are read).
const { t, te } = useI18n()
const client = useClient()
const event = ref('')
const result = ref('')
const paged = usePaged(client, 'audit', {
  rowsKey: 'records', size: 50,
  extra: () => ({ event: event.value, result: result.value }),
})
useLoad(() => paged.resource.load())
const events = computed(() => (Array.isArray(paged.resource.data.value?.events) ? paged.resource.data.value.events : []))
const truncated = computed(() => paged.resource.data.value?.truncated === true)
const eventLabel = name => (te(`whm.activity.events.${name}`) ? t(`whm.activity.events.${name}`) : name)
const what = row => (row.action ? actionLabel(row.action) : eventLabel(row.event))
</script>

<template>
  <div>
    <PageHeader :title="t('whm.activity.title')" :description="t('whm.activity.description')" />
    <p v-if="truncated" class="olsc-hint">{{ t('whm.activity.truncated') }}</p>
    <DataTable :paged="paged" :caption="t('whm.activity.title')" :search-label="t('whm.activity.search')"
               :empty-text="paged.query.value || event || result ? t('whm.activity.noMatch') : t('whm.activity.none')">
      <template #toolbar>
        <label for="olsc-activity-event" class="olsc-sr-only">{{ t('whm.activity.eventFilter') }}</label>
        <el-select id="olsc-activity-event" v-model="event" clearable :placeholder="t('whm.activity.eventFilter')" class="olsc-select">
          <el-option v-for="name in events" :key="name" :label="eventLabel(name)" :value="name" />
        </el-select>
        <label for="olsc-activity-result" class="olsc-sr-only">{{ t('whm.activity.resultFilter') }}</label>
        <el-select id="olsc-activity-result" v-model="result" clearable :placeholder="t('whm.activity.resultFilter')" class="olsc-select">
          <el-option :label="t('whm.activity.resultOk')" value="ok" />
          <el-option :label="t('whm.activity.resultFailed')" value="failed" />
        </el-select>
      </template>
      <el-table-column :label="t('whm.activity.when')" min-width="180">
        <template #default="{ row }">{{ formatDateTime(row.time) ?? t('state.unknown') }}</template>
      </el-table-column>
      <el-table-column :label="t('whm.activity.who')" min-width="110">
        <template #default="{ row }"><span class="olsc-mono">{{ row.actor }}</span></template>
      </el-table-column>
      <el-table-column :label="t('whm.activity.what')" min-width="230">
        <template #default="{ row }">
          {{ what(row) }}
          <div v-if="row.scope && row.scope !== 'server'" class="olsc-muted olsc-small olsc-mono">{{ row.scope }}</div>
        </template>
      </el-table-column>
      <el-table-column :label="t('fields.job')" min-width="170">
        <template #default="{ row }">
          <a v-if="row.job" :href="href(`jobs/${row.job}`)" class="olsc-mono">{{ row.job }}</a>
        </template>
      </el-table-column>
      <el-table-column :label="t('whm.activity.result')" width="110">
        <template #default="{ row }">
          <StatusBadge :tone="row.result === 'failed' ? 'bad' : 'ok'" :label="row.result === 'failed' ? t('whm.activity.resultFailed') : t('whm.activity.resultOk')" />
        </template>
      </el-table-column>
      <el-table-column :label="t('whm.activity.detail')" min-width="220">
        <template #default="{ row }"><span class="olsc-muted olsc-small olsc-wrap">{{ row.detail }}</span></template>
      </el-table-column>
    </DataTable>
  </div>
</template>
