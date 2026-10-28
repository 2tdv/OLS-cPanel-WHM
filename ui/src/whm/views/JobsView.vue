<script setup>
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import JobTimeline from '../../shared/JobTimeline.vue'
import PageHeader from '../../shared/PageHeader.vue'
import StateView from '../../shared/StateView.vue'
import StatusBadge from '../../shared/StatusBadge.vue'
import { useClient, useResource } from '../../shared/api.js'
import { formatDateTime } from '../../shared/format.js'
import { actionLabel, jobRows, jobStateLabel, jobTone } from '../../shared/jobs.js'
import { usePolling } from '../../shared/polling.js'
import { href } from '../../shared/router.js'

// Jobs (jobs: the last 50) and one job in detail (job: state, progress lines, the command's output).
const props = defineProps({ params: { type: Object, default: () => ({}) } })
const { t } = useI18n()
const client = useClient()
const jobs = useResource(client, 'jobs')
const rows = computed(() => jobRows(jobs.data.value))
// One request in flight at most, backing off on failure; a followed job polls on its own.
const poller = usePolling(() => jobs.load(), { interval: 15000, maxInterval: 5 * 60 * 1000 })
const selected = computed(() => props.params.id || null)
</script>

<template>
  <div>
    <PageHeader :title="t('whm.jobs.title')" :description="t('whm.jobs.description')" />

    <section v-if="selected" class="olsc-card olsc-gap-below" :aria-label="t('whm.jobs.detail')">
      <p><a :href="href('jobs')">{{ t('whm.jobs.back') }}</a></p>
      <JobTimeline :key="selected" :job-id="selected" @finished="poller.refresh()" />
    </section>

    <StateView :resource="jobs" :empty="jobs.data.value !== null && !rows.length" :empty-text="t('whm.jobs.none')"
               :refresh="poller.refresh">
      <el-table :data="rows" size="small" stripe :aria-label="t('whm.jobs.title')">
        <el-table-column :label="t('fields.job')" min-width="160">
          <template #default="{ row }">
            <a :href="href(`jobs/${row.job}`)" class="olsc-mono"
               :aria-current="String(row.job) === selected ? 'true' : undefined">{{ row.job }}</a>
          </template>
        </el-table-column>
        <el-table-column :label="t('fields.action')" min-width="200">
          <template #default="{ row }">{{ actionLabel(row.action) }}</template>
        </el-table-column>
        <el-table-column :label="t('fields.state')" width="130">
          <template #default="{ row }"><StatusBadge :tone="jobTone(row.state)" :label="jobStateLabel(row.state)" /></template>
        </el-table-column>
        <el-table-column :label="t('jobs.started')" min-width="170">
          <template #default="{ row }">{{ formatDateTime(row.started) ?? t('state.unknown') }}</template>
        </el-table-column>
        <el-table-column :label="t('jobs.finished')" min-width="170">
          <template #default="{ row }">{{ row.state === 'running' ? '' : (formatDateTime(row.finished) ?? t('state.unknown')) }}</template>
        </el-table-column>
        <el-table-column :label="t('fields.exitCode')" width="100">
          <template #default="{ row }">{{ Number.isInteger(row.exit_code) ? row.exit_code : '' }}</template>
        </el-table-column>
      </el-table>
    </StateView>
  </div>
</template>
