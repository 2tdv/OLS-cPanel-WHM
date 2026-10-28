<script setup>
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import ConfirmDialog from '../../shared/ConfirmDialog.vue'
import JobTimeline from '../../shared/JobTimeline.vue'
import PageHeader from '../../shared/PageHeader.vue'
import StateView from '../../shared/StateView.vue'
import StatusBadge from '../../shared/StatusBadge.vue'
import { useLoad } from '../../shared/polling.js'
import { ACTIONS, commandOutput, useAction, useClient, useResource } from '../../shared/api.js'
import { errorMessage } from '../../shared/i18n.js'
import { runningJob } from '../../shared/jobs.js'
import { href } from '../../shared/router.js'

// Generations (generations: `ols-cpanel generation list`): the active one marked; rollback to the
// previous committed generation is a job (ols.rollback) confirmed by typing the active generation id.
const { t } = useI18n()
const client = useClient()
const generations = useResource(client, 'generations')
const status = useResource(client, 'status', { staleAfter: 2 * 60 * 1000 })
const jobs = useResource(client, 'jobs')
const action = useAction(client)
const confirm = ref(false)
const activeJob = ref(null)
const jobState = ref(null)

async function loadAll() {
  await Promise.all([generations.load(), status.load(), jobs.load()])
  const running = runningJob(jobs.data.value)
  if (running && !activeJob.value) {
    activeJob.value = String(running.job)
    jobState.value = 'running'
  }
}
useLoad(loadAll)

const list = computed(() => {
  const data = commandOutput(generations.data.value)
  const rows = Array.isArray(data) ? data : Array.isArray(data?.generations) ? data.generations : []
  return [...rows].reverse() // newest first
})
const active = computed(() => {
  const data = commandOutput(generations.data.value)
  return (typeof data?.active === 'string' && data.active) || list.value.find(g => g?.active)?.generation || null
})
const earlier = computed(() => list.value.some(g => g?.committed === true && g.generation !== active.value))
const digest = computed(() => (typeof status.data.value?.digest === 'string' && status.data.value.digest) || null)
const running = computed(() => activeJob.value !== null && jobState.value === 'running')
const blocked = computed(() => !active.value || !digest.value || running.value)

async function rollback() {
  const id = await action.run(ACTIONS.rollback, { scope: 'server', digest: digest.value })
  if (id) {
    confirm.value = false
    activeJob.value = id
    jobState.value = 'running'
  }
}
function onFinished(job) {
  jobState.value = job?.state || null
  loadAll()
}
const validTone = g => (g.valid === true ? 'ok' : g.valid === false ? 'bad' : 'neutral')
const validLabel = g => (g.valid === true ? t('whm.generations.valid') : g.valid === false ? t('whm.generations.invalid') : t('state.unknown'))
</script>

<template>
  <div>
    <PageHeader :title="t('whm.generations.title')" :description="t('whm.generations.description')" help="generations">
      <template #actions>
        <el-button type="danger" plain :disabled="blocked" @click="confirm = true">{{ t('whm.generations.rollback') }}</el-button>
      </template>
    </PageHeader>
    <p v-if="status.data.value && !digest" class="olsc-hint">{{ t('whm.switch.noDigestHint') }}</p>
    <el-alert v-if="action.error.value" type="error" show-icon class="olsc-gap-below" :title="t('whm.switch.actionFailed')"
              :description="errorMessage(action.error.value)" @close="action.error.value = null" />

    <section v-if="activeJob" class="olsc-card olsc-gap-below" :aria-label="t('whm.switch.currentJob')">
      <JobTimeline :key="activeJob" :job-id="activeJob" @finished="onFinished" />
      <p><a :href="href(`jobs/${activeJob}`)">{{ t('whm.switch.followInJobs') }}</a></p>
    </section>

    <StateView :resource="generations" :empty="generations.data.value !== null && !list.length"
               :empty-text="t('whm.generations.none')" :refresh="loadAll"
               :pending="running ? t('whm.switch.jobPending') : ''">
      <el-table :data="list" size="small" stripe :aria-label="t('whm.generations.title')">
        <el-table-column :label="t('fields.generation')" min-width="240">
          <template #default="{ row }">
            <span class="olsc-mono">{{ row.generation }}</span>
            <StatusBadge v-if="row.generation === active" tone="ok" :label="t('whm.generations.active')" />
          </template>
        </el-table-column>
        <el-table-column :label="t('whm.generations.committed')" width="140">
          <template #default="{ row }">
            {{ row.committed === true ? t('common.yes') : row.committed === false ? t('common.no') : t('state.unknown') }}
          </template>
        </el-table-column>
        <el-table-column :label="t('whm.generations.validation')" width="140">
          <template #default="{ row }"><StatusBadge :tone="validTone(row)" :label="validLabel(row)" /></template>
        </el-table-column>
        <el-table-column :label="t('whm.overview.epoch')" width="110">
          <template #default="{ row }">{{ Number.isInteger(row.epoch) ? row.epoch : t('state.unknown') }}</template>
        </el-table-column>
        <el-table-column :label="t('whm.generations.source')" min-width="160">
          <template #default="{ row }">
            <span class="olsc-mono">{{ typeof row.source_sha256 === 'string' ? row.source_sha256.slice(0, 16) : t('state.unknown') }}</span>
          </template>
        </el-table-column>
      </el-table>
    </StateView>

    <ConfirmDialog v-if="active" v-model="confirm" :title="t('whm.generations.confirmTitle')" :expected="active"
                   :confirm-label="t('whm.generations.rollback')" :busy="action.busy.value" :blocked="blocked" @confirm="rollback">
      <dl class="olsc-facts">
        <dt>{{ t('confirm.scope') }}</dt><dd>{{ t('whm.switch.scopeServer') }}</dd>
        <dt>{{ t('confirm.change') }}</dt><dd>{{ t('whm.generations.change', { active }) }}</dd>
        <dt>{{ t('confirm.affected') }}</dt><dd>{{ t('whm.generations.affected') }}</dd>
        <dt>{{ t('confirm.blockers') }}</dt>
        <dd>{{ earlier ? t('whm.switch.noBlockers') : t('whm.generations.noEarlier') }}</dd>
        <dt>{{ t('confirm.rollback') }}</dt><dd>{{ t('whm.generations.undo') }}</dd>
      </dl>
    </ConfirmDialog>
  </div>
</template>
