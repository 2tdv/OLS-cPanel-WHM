<script setup>
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import JobTimeline from '../../shared/JobTimeline.vue'
import PageHeader from '../../shared/PageHeader.vue'
import StateView from '../../shared/StateView.vue'
import StatusBadge from '../../shared/StatusBadge.vue'
import { useLoad } from '../../shared/polling.js'
import { ACTIONS, commandOutput, useAction, useClient, useResource } from '../../shared/api.js'
import { formatDateTime } from '../../shared/format.js'
import { errorMessage } from '../../shared/i18n.js'
import { runningJob } from '../../shared/jobs.js'
import { href } from '../../shared/router.js'
import { platformFacts } from '../health.js'

// Updates (update: `ols-cpanel update check`, read-only): the installed OLS-cPanel version against the latest GitHub release of
// the project, per installed package its integrity (rpm signature, or a build the installer verified against the signed release),
// and whether this server's operating system and cPanel version are supported. "Update now" starts the job ols.update
// (`update install --latest`): the release's installer is verified with the project's signing key shipped in the product before
// it runs, upgrades the packages, and the product applies the upgrade by itself. The job is followed here and in Jobs.
const { t } = useI18n()
const client = useClient()
const force = ref(false)
const update = useResource(client, 'update', { params: () => (force.value ? { refresh: 1 } : {}), staleAfter: 30 * 60 * 1000 })
const doctor = useResource(client, 'doctor', { staleAfter: 10 * 60 * 1000 })
const status = useResource(client, 'status', { staleAfter: 2 * 60 * 1000 })
const jobs = useResource(client, 'jobs')
const action = useAction(client)
const confirmOpen = ref(false)
const activeJob = ref(null)
const jobState = ref(null)
const jobResult = ref(null)

async function loadAll() {
  await Promise.all([update.load(), doctor.load(), status.load(), jobs.load()])
  const running = runningJob(jobs.data.value)
  if (running && running.action === ACTIONS.update && !activeJob.value) {
    activeJob.value = String(running.job)
    jobState.value = 'running'
  }
}
useLoad(loadAll)

const report = computed(() => commandOutput(update.data.value) || {})
const packages = computed(() => (Array.isArray(report.value.packages) ? report.value.packages : []))
const release = computed(() => (report.value.update_available && report.value.available_release?.version ? report.value.available_release : null))
const facts = computed(() => platformFacts(commandOutput(doctor.data.value)))
const checking = computed(() => update.loading.value)
const statusDigest = computed(() => (typeof status.data.value?.digest === 'string' && status.data.value.digest ? status.data.value.digest : null))
const jobRunning = computed(() => activeJob.value !== null && jobState.value === 'running')
const blocked = computed(() => !release.value || !statusDigest.value || jobRunning.value || action.busy.value || runningJob(jobs.data.value) !== null)

async function checkNow() {
  force.value = true
  try {
    await update.load()
  } finally {
    force.value = false
  }
}
async function startUpdate() {
  if (blocked.value) return
  const id = await action.run(ACTIONS.update, { scope: 'server', digest: statusDigest.value })
  confirmOpen.value = false
  if (id) {
    jobResult.value = null
    jobState.value = 'running'
    activeJob.value = id
  } else {
    loadAll()
  }
}
function onJobState(job) {
  jobState.value = job?.state || null
  jobResult.value = job ? { state: job.state, version: job.output?.version ?? release.value?.version ?? null } : null
  // The update drops the cached check; asking again shows the new installed version.
  checkNow()
  jobs.load()
}

// Integrity of an installed package: its rpm signature when it has one, otherwise whether the installer verified exactly this
// build against the signed release manifest.
const INTEGRITY_TONES = { signed: 'ok', 'signed-key-missing': 'warn', verified: 'ok', unverified: 'neutral', unknown: 'neutral' }
function integrityKey(pkg) {
  const state = pkg.signature?.state
  if (state === 'signed' || state === 'signed-key-missing') return state
  if (pkg.release_verified === true) return 'verified'
  return state === 'unsigned' ? 'unverified' : 'unknown'
}
</script>

<template>
  <div>
    <PageHeader :title="t('whm.updates.title')" :description="t('whm.updates.description')">
      <template #actions>
        <el-button :loading="checking" @click="checkNow">{{ t('whm.updates.checkNow') }}</el-button>
      </template>
    </PageHeader>

    <section class="olsc-card olsc-gap-below" :aria-label="t('whm.updates.compatTitle')">
      <h3 class="olsc-h3">{{ t('whm.updates.compatTitle') }}</h3>
      <p class="olsc-muted">{{ t('whm.updates.compatText') }}</p>
      <dl v-if="facts" class="olsc-facts">
        <dt>{{ t('whm.updates.os') }}</dt><dd>{{ facts.os }}</dd>
        <dt>{{ t('whm.updates.cpanel') }}</dt><dd>{{ facts.cpanel }}</dd>
        <dt>{{ t('whm.updates.supportedList') }}</dt>
        <dd><StatusBadge :tone="facts.supported ? 'ok' : 'warn'" :label="facts.supported ? t('whm.updates.supported') : t('whm.updates.outside')" /></dd>
      </dl>
      <p v-else class="olsc-muted">{{ t('whm.updates.platformUnknown') }}</p>
      <p v-if="facts && !facts.supported" class="olsc-hint">{{ t('whm.updates.outsideHint') }}</p>
    </section>

    <section v-if="activeJob" class="olsc-card olsc-gap-below" :aria-label="t('whm.updates.currentJob')">
      <h3 class="olsc-h3">{{ t('whm.updates.currentJob') }}</h3>
      <JobTimeline :key="activeJob" :job-id="activeJob" @finished="onJobState" />
      <el-alert v-if="jobResult?.state === 'done'" type="success" show-icon :closable="false" class="olsc-gap-above"
                :title="t('whm.updates.resultDone', { version: jobResult.version ?? '' })" />
      <el-alert v-else-if="jobResult?.state === 'failed'" type="error" show-icon :closable="false" class="olsc-gap-above"
                :title="t('whm.updates.resultFailed')" />
      <p class="olsc-muted">
        <a :href="href(`jobs/${activeJob}`)">{{ t('whm.switch.followInJobs') }}</a>
        <el-button v-if="!jobRunning" link type="primary" @click="activeJob = null">{{ t('whm.switch.dismissJob') }}</el-button>
      </p>
    </section>

    <StateView :resource="update" :refresh="() => update.load()">
      <el-alert v-if="report.error" type="warning" show-icon :closable="false" class="olsc-gap-below" :title="t('whm.updates.queryFailed')"
                :description="report.error" />
      <section v-if="release" class="olsc-card olsc-gap-below" :aria-label="t('whm.updates.available', { version: release.version })">
        <p><StatusBadge tone="info" :label="t('whm.updates.available', { version: release.version })" /></p>
        <p class="olsc-muted">
          {{ t('whm.updates.installedVersion', { version: report.installed_version ?? t('state.unknown') }) }}
          · <a :href="release.url" target="_blank" rel="noopener noreferrer">{{ t('whm.updates.releaseNotes') }}</a>
        </p>
        <el-button type="primary" :disabled="blocked" :loading="action.busy.value || jobRunning" @click="confirmOpen = true">
          {{ jobRunning ? t('whm.updates.updating') : t('whm.updates.updateNow') }}
        </el-button>
        <el-alert v-if="action.error.value" type="error" show-icon :closable="true" class="olsc-gap-above" :title="t('whm.updates.updateFailed')"
                  :description="errorMessage(action.error.value)" @close="action.error.value = null" />
      </section>
      <p v-else-if="!report.error" class="olsc-gap-below">
        <StatusBadge tone="ok" :label="t('whm.updates.current')" />
        <span v-if="report.installed_version" class="olsc-muted"> {{ t('whm.updates.installedVersion', { version: report.installed_version }) }}</span>
      </p>
      <el-table :data="packages" size="small" stripe :aria-label="t('whm.updates.title')">
        <el-table-column :label="t('whm.updates.package')" min-width="220">
          <template #default="{ row }"><span class="olsc-mono">{{ row.package }}</span></template>
        </el-table-column>
        <el-table-column :label="t('whm.updates.installed')" min-width="220">
          <template #default="{ row }"><span class="olsc-mono">{{ row.installed ?? t('whm.updates.notInstalled') }}</span></template>
        </el-table-column>
        <el-table-column :label="t('whm.updates.signature')" min-width="260">
          <template #default="{ row }">
            <StatusBadge :tone="INTEGRITY_TONES[integrityKey(row)]" :label="t(`whm.updates.sig.${integrityKey(row)}`)" />
            <span v-if="row.signature?.key_id" class="olsc-muted olsc-small olsc-mono"> {{ row.signature.key_id }}</span>
          </template>
        </el-table-column>
      </el-table>
      <p class="olsc-hint">{{ t('whm.updates.sigHelp') }}</p>
      <dl class="olsc-facts olsc-gap-above">
        <dt>{{ t('whm.updates.latest') }}</dt><dd class="olsc-mono">{{ report.latest_release?.version ?? t('state.unknown') }}</dd>
        <dt>{{ t('whm.updates.cpanelVersion') }}</dt><dd>{{ report.cpanel_version ?? t('state.unknown') }}</dd>
        <dt>{{ t('whm.updates.checkedAt') }}</dt><dd>{{ formatDateTime(report.checked_at) ?? t('state.notObserved') }}</dd>
      </dl>
      <p class="olsc-muted">{{ t('whm.updates.howText') }}</p>
    </StateView>

    <el-dialog v-model="confirmOpen" :title="release ? t('whm.updates.confirmTitle', { version: release.version }) : ''" width="min(600px, 94vw)">
      <p>{{ t('whm.updates.confirmVerified') }}</p>
      <p>{{ t('whm.updates.confirmServing') }}</p>
      <p>{{ t('whm.updates.confirmApplies') }}</p>
      <template #footer>
        <el-button @click="confirmOpen = false">{{ t('whm.updates.confirmNo') }}</el-button>
        <el-button type="primary" :disabled="blocked" :loading="action.busy.value" @click="startUpdate">{{ t('whm.updates.confirmYes') }}</el-button>
      </template>
    </el-dialog>
  </div>
</template>
