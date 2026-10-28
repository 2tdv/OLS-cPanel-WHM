<script setup>
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import JobTimeline from '../../shared/JobTimeline.vue'
import PageHeader from '../../shared/PageHeader.vue'
import StateView from '../../shared/StateView.vue'
import { useLoad } from '../../shared/polling.js'
import { ACTIONS, downloadUrl, useAction, useClient, useResource } from '../../shared/api.js'
import { formatBytes, formatDateTime } from '../../shared/format.js'
import { errorMessage } from '../../shared/i18n.js'
import { runningJob } from '../../shared/jobs.js'
import { href } from '../../shared/router.js'

// Support bundle (bundle: the archives that exist; ols.support_bundle and ols.support_bundle_raw make one as a job): product
// diagnostics for a support request, with private keys, passwords, tokens and e-mail addresses always removed and, by default,
// IP addresses, domain names and account names replaced by placeholders. The archive is downloaded from this page.
const { t } = useI18n()
const client = useClient()
const status = useResource(client, 'status', { staleAfter: 2 * 60 * 1000 })
const bundles = useResource(client, 'bundle', { staleAfter: 10 * 60 * 1000 })
const jobs = useResource(client, 'jobs')
const action = useAction(client)
const anonymize = ref(true)
const activeJob = ref(null)
const jobState = ref(null)

async function loadAll() {
  await Promise.all([status.load(), bundles.load(), jobs.load()])
  const running = runningJob(jobs.data.value)
  if (running && !activeJob.value) {
    activeJob.value = String(running.job)
    jobState.value = 'running'
  }
}
useLoad(loadAll)

const list = computed(() => (Array.isArray(bundles.data.value?.bundles) ? bundles.data.value.bundles : []))
const limitMb = computed(() => Math.round((bundles.data.value?.limit_bytes || 20 * 1024 * 1024) / (1024 * 1024)))
const statusDigest = computed(() => (typeof status.data.value?.digest === 'string' && status.data.value.digest ? status.data.value.digest : null))
const jobRunning = computed(() => activeJob.value !== null && jobState.value === 'running')
const blocked = computed(() => !statusDigest.value || jobRunning.value || action.busy.value)

async function create() {
  if (blocked.value) return
  const id = await action.run(anonymize.value ? ACTIONS.supportBundle : ACTIONS.supportBundleRaw, { scope: 'server', digest: statusDigest.value })
  if (id) {
    jobState.value = 'running'
    activeJob.value = id
  } else {
    loadAll()
  }
}
function onJobState(job) {
  jobState.value = job?.state || null
  loadAll()
}
</script>

<template>
  <div>
    <PageHeader :title="t('whm.support.title')" :description="t('whm.support.description')" />

    <section class="olsc-card olsc-gap-below" :aria-label="t('whm.support.createTitle')">
      <h3 class="olsc-h3">{{ t('whm.support.createTitle') }}</h3>
      <p class="olsc-muted">{{ t('whm.support.includes') }}</p>
      <p class="olsc-muted">{{ t('whm.support.neverIncludes') }}</p>
      <el-checkbox v-model="anonymize">{{ t('whm.support.anonymize') }}</el-checkbox>
      <p class="olsc-hint">{{ anonymize ? t('whm.support.anonymizeOn') : t('whm.support.anonymizeOff') }}</p>
      <el-button type="primary" :loading="action.busy.value" :disabled="blocked" @click="create">{{ t('whm.support.create', { mb: limitMb }) }}</el-button>
      <el-alert v-if="action.error.value" type="error" show-icon :closable="true" class="olsc-gap-above" :title="t('whm.support.createFailed')"
                :description="errorMessage(action.error.value)" @close="action.error.value = null" />
    </section>

    <section v-if="activeJob" class="olsc-card olsc-gap-below" :aria-label="t('whm.support.currentJob')">
      <h3 class="olsc-h3">{{ t('whm.support.currentJob') }}</h3>
      <JobTimeline :key="activeJob" :job-id="activeJob" @finished="onJobState" />
      <p class="olsc-muted">
        <a :href="href(`jobs/${activeJob}`)">{{ t('whm.switch.followInJobs') }}</a>
        <el-button v-if="!jobRunning" link type="primary" @click="activeJob = null">{{ t('whm.switch.dismissJob') }}</el-button>
      </p>
    </section>

    <StateView :resource="bundles" :empty="bundles.data.value !== null && !list.length" :empty-text="t('whm.support.none')" :refresh="loadAll">
      <h3 class="olsc-h3">{{ t('whm.support.listTitle') }}</h3>
      <p class="olsc-muted">{{ t('whm.support.keep', { n: bundles.data.value?.keep ?? 3 }) }}</p>
      <el-table :data="list" size="small" stripe :aria-label="t('whm.support.listTitle')">
        <el-table-column :label="t('whm.support.created')" min-width="200">
          <template #default="{ row }">{{ formatDateTime(row.created) ?? t('state.unknown') }}</template>
        </el-table-column>
        <el-table-column :label="t('whm.support.file')" min-width="260">
          <template #default="{ row }"><span class="olsc-mono">{{ row.name }}</span></template>
        </el-table-column>
        <el-table-column :label="t('whm.support.size')" width="130" align="right">
          <template #default="{ row }">{{ formatBytes(row.size) ?? t('state.unknown') }}</template>
        </el-table-column>
        <el-table-column :label="t('fields.action')" width="160">
          <template #default="{ row }">
            <a :href="downloadUrl(client.endpoint, row.name)" class="el-button el-button--small" download>{{ t('whm.support.download') }}</a>
          </template>
        </el-table-column>
      </el-table>
    </StateView>
  </div>
</template>
