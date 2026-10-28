<script setup>
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import ConfirmDialog from '../../shared/ConfirmDialog.vue'
import EngineBadge from '../../shared/EngineBadge.vue'
import HelpTip from '../../shared/HelpTip.vue'
import JobTimeline from '../../shared/JobTimeline.vue'
import PageHeader from '../../shared/PageHeader.vue'
import StateView from '../../shared/StateView.vue'
import StatusBadge from '../../shared/StatusBadge.vue'
import { useLoad } from '../../shared/polling.js'
import { ACTIONS, commandOutput, useAction, useClient, useResource } from '../../shared/api.js'
import { cutOver, profileName } from '../../shared/engine.js'
import { formatDateTime } from '../../shared/format.js'
import { errorMessage } from '../../shared/i18n.js'
import { runningJob } from '../../shared/jobs.js'
import { href } from '../../shared/router.js'
import { normalizePlan, planFromLatest } from '../plan.js'

// Switch center: readiness (doctor, plan), prepare (ols.plan / ols.plan_hybrid), review the plan,
// cut over (ols.cutover, typed plan id), return to Apache (ols.apache_return, typed phrase). Every
// action sends the scope and the digest of what is shown, so the broker refuses it if the server
// changed in between; progress is the job timeline (job), which survives closing the page (jobs).
const { t, te } = useI18n()
const client = useClient()
const status = useResource(client, 'status', { staleAfter: 2 * 60 * 1000 })
const plan = useResource(client, 'plan')
const doctor = useResource(client, 'doctor', { staleAfter: 10 * 60 * 1000 })
const jobs = useResource(client, 'jobs')
const action = useAction(client)
const activeJob = ref(null)
const jobState = ref(null)
const profileChoice = ref('hybrid') // the hybrid profile is the default of every installation (HR-D14)
const confirmCutover = ref(false)
const confirmReturn = ref(false)

async function loadAll() {
  await Promise.all([status.load(), plan.load(), doctor.load(), jobs.load()])
  const running = runningJob(jobs.data.value)
  if (running && !activeJob.value) {
    activeJob.value = String(running.job)
    jobState.value = 'running'
  }
}
useLoad(loadAll)

const s = computed(() => status.data.value || {})
const p = computed(() => normalizePlan(planFromLatest(plan.data.value)))
const isCutOver = computed(() => cutOver(status.data.value))
const statusDigest = computed(() => (typeof s.value.digest === 'string' && s.value.digest ? s.value.digest : null))
const jobRunning = computed(() => activeJob.value !== null && jobState.value === 'running')

const doctorReport = computed(() => commandOutput(doctor.data.value) || null)
const doctorBlockers = computed(() => (Array.isArray(doctorReport.value?.blockers) ? doctorReport.value.blockers : []))
// Plan blockers stop the cutover; doctor's certification blockers are shown as a warning (the broker
// and the CLI decide whether an uncertified platform may proceed).
const readiness = computed(() => {
  if (p.value?.blockers.length) return 'blocked'
  if (!doctorReport.value) return 'unknown'
  if (doctorReport.value.compatibility?.production_activation_allowed !== true || doctorBlockers.value.length) return 'uncertified'
  return p.value ? 'ready' : 'noPlan'
})
const READINESS_TONE = { ready: 'ok', blocked: 'bad', uncertified: 'warn', noPlan: 'info', unknown: 'neutral' }
const doctorText = code => (te(`doctor.blockers.${code}`) ? t(`doctor.blockers.${code}`) : '')

// The broker decides; the interface only refuses what it can see is wrong (no plan, no digest, plan
// blockers, already cut over, a job running). Readiness findings stay visible in the confirmation.
const cutoverBlocked = computed(() => !p.value || !p.value.valid || !p.value.digest || p.value.blockers.length > 0
  || isCutOver.value === true || jobRunning.value)
const prepareBlocked = computed(() => !statusDigest.value || jobRunning.value || isCutOver.value === true)
const returnBlocked = computed(() => !statusDigest.value || jobRunning.value || isCutOver.value !== true)

async function start(name, payload) {
  const id = await action.run(name, payload)
  if (id) {
    jobState.value = 'running'
    activeJob.value = id
  } else {
    loadAll() // a refused action (changed state, another job) shows the current state at once
  }
  return id
}
const prepare = () => start(ACTIONS.plan,
  { scope: 'server', digest: statusDigest.value })
async function cutover() {
  if (await start(ACTIONS.cutover, { scope: p.value.id, digest: p.value.digest })) confirmCutover.value = false
}
async function apacheReturn() {
  if (await start(ACTIONS.apacheReturn, { scope: 'server', digest: statusDigest.value })) confirmReturn.value = false
}
function onJobState(job) {
  jobState.value = job?.state || null
  loadAll()
}
</script>

<template>
  <div>
    <PageHeader :title="t('whm.switch.title')" :description="t('whm.switch.description')" help="cutover" />

    <el-alert v-if="action.error.value" type="error" show-icon :closable="true" class="olsc-gap-below"
              :title="t('whm.switch.actionFailed')" :description="errorMessage(action.error.value)"
              @close="action.error.value = null" />

    <section v-if="activeJob" class="olsc-card olsc-gap-below" :aria-label="t('whm.switch.currentJob')">
      <h3 class="olsc-h3">{{ t('whm.switch.currentJob') }}</h3>
      <JobTimeline :key="activeJob" :job-id="activeJob" @finished="onJobState" />
      <p class="olsc-muted">
        <a :href="href(`jobs/${activeJob}`)">{{ t('whm.switch.followInJobs') }}</a>
        <el-button v-if="!jobRunning" link type="primary" @click="activeJob = null">{{ t('whm.switch.dismissJob') }}</el-button>
      </p>
    </section>

    <!-- Current state and readiness -->
    <section class="olsc-section" :aria-labelledby="'olsc-sw-state'">
      <h3 id="olsc-sw-state" class="olsc-h3">{{ t('whm.switch.stateTitle') }}</h3>
      <StateView :resource="status" :refresh="loadAll"
                 :pending="jobRunning ? t('whm.switch.jobPending') : ''">
        <dl class="olsc-facts">
          <dt>{{ t('engine.serving') }}</dt><dd><EngineBadge :status="status.data.value" /></dd>
          <dt>{{ t('whm.overview.profile') }}</dt><dd>{{ t(`profile.${profileName(status.data.value ? s.profile : undefined)}`) }}</dd>
          <dt>{{ t('whm.overview.generation') }}</dt>
          <dd class="olsc-mono">{{ s.active_generation === null ? t('whm.overview.noGeneration') : (s.active_generation ?? t('state.unknown')) }}</dd>
          <dt>{{ t('whm.switch.statusDigest') }}</dt>
          <dd class="olsc-mono">{{ statusDigest ? statusDigest.slice(0, 16) : t('whm.switch.noDigest') }}</dd>
        </dl>
      </StateView>
    </section>

    <section class="olsc-section" :aria-labelledby="'olsc-sw-ready'">
      <h3 id="olsc-sw-ready" class="olsc-h3">
        {{ t('whm.switch.readiness') }}
        <StatusBadge :tone="READINESS_TONE[readiness]" :label="t(`whm.switch.ready.${readiness}`)" />
      </h3>
      <StateView :resource="doctor" :refresh="() => doctor.load()">
        <p>{{ t('whm.switch.doctorStatus', { status: doctorReport?.compatibility?.status ?? t('state.unknown') }) }}
          <a :href="href('diagnostics')">{{ t('whm.switch.openDiagnostics') }}</a></p>
        <ul v-if="doctorBlockers.length" class="olsc-list">
          <li v-for="code in doctorBlockers" :key="code">
            <StatusBadge tone="warn" :label="t('severity.warning')" /> <span class="olsc-mono">{{ code }}</span> {{ doctorText(code) }}
          </li>
        </ul>
        <p v-else class="olsc-muted">{{ t('whm.switch.noDoctorBlockers') }}</p>
      </StateView>
    </section>

    <!-- Step 1: prepare -->
    <section class="olsc-section olsc-card" :aria-labelledby="'olsc-sw-prepare'">
      <h3 id="olsc-sw-prepare" class="olsc-h3">{{ t('whm.switch.step1') }}</h3>
      <p class="olsc-muted">{{ t('whm.switch.prepareBody') }}</p>
      <p class="olsc-small">{{ t(`whm.switch.profileHelp.${profileChoice}`) }} <HelpTip topic="profile" /></p>
      <el-button type="primary" :disabled="prepareBlocked" :loading="action.busy.value" @click="prepare">
        {{ t('whm.switch.prepare') }}
      </el-button>
      <p v-if="!statusDigest && status.data.value" class="olsc-hint">{{ t('whm.switch.noDigestHint') }}</p>
      <p v-if="isCutOver === true" class="olsc-hint">{{ t('whm.switch.alreadyCutOver') }}</p>
    </section>

    <!-- Step 2: review -->
    <section class="olsc-section olsc-card" :aria-labelledby="'olsc-sw-review'">
      <h3 id="olsc-sw-review" class="olsc-h3">{{ t('whm.switch.step2') }}</h3>
      <StateView :resource="plan" :empty="plan.loadedAt.value !== null && !p" :empty-text="t('whm.switch.noPlan')"
                 :refresh="() => plan.load()">
        <template v-if="p">
          <el-alert v-if="!p.valid" type="error" :closable="false" show-icon class="olsc-gap-below" :title="t('whm.switch.planInvalid')" />
          <dl class="olsc-facts">
            <dt>{{ t('whm.switch.planId') }}</dt><dd class="olsc-mono">{{ p.id }}</dd>
            <dt>{{ t('whm.switch.planCreated') }}</dt><dd>{{ formatDateTime(p.createdAt) ?? t('state.unknown') }}</dd>
            <dt>{{ t('whm.overview.profile') }}</dt>
            <dd>{{ t(`profile.${p.profile}`) }}<span v-if="p.ports"> ({{ t('whm.overview.hybridPorts', { ports: p.ports.join(', ') }) }})</span></dd>
            <dt>{{ t('whm.switch.planDigest') }}</dt><dd class="olsc-mono">{{ p.digest ?? t('whm.switch.noDigest') }}</dd>
            <dt>{{ t('whm.switch.counts.vhosts') }}</dt><dd>{{ p.vhosts ?? t('state.unknown') }}</dd>
            <dt>{{ t('whm.switch.counts.ols') }}</dt><dd>{{ p.olsVhosts ?? t('state.unknown') }}</dd>
            <dt>{{ t('whm.switch.counts.hybrid') }}</dt><dd>{{ p.hybrid.length }}</dd>
            <dt>{{ t('whm.switch.counts.blockers') }}</dt><dd>{{ p.blockers.length }}</dd>
            <dt>{{ t('whm.switch.olsPackage') }}</dt><dd class="olsc-mono">{{ p.olsPackage ?? t('state.unknown') }}</dd>
            <dt>{{ t('whm.switch.backups') }}</dt>
            <dd>{{ p.backups === null ? t('state.unknown') : t('whm.switch.backupCount', { n: p.backups.length }) }}</dd>
          </dl>

          <template v-if="p.hostChanges.length">
            <h4 class="olsc-h4">{{ t('whm.switch.hostChanges') }}</h4>
            <ul class="olsc-list"><li v-for="(c, i) in p.hostChanges" :key="i">{{ c }}</li></ul>
          </template>
          <template v-if="p.checks.length">
            <h4 class="olsc-h4">{{ t('whm.switch.checks') }}</h4>
            <ul class="olsc-list">
              <li v-for="(c, i) in p.checks" :key="i">
                <StatusBadge :tone="c.ok === true ? 'ok' : c.ok === false ? 'bad' : 'neutral'"
                             :label="c.ok === true ? t('whm.switch.checkOk') : c.ok === false ? t('whm.switch.checkFailed') : t('state.unknown')" />
                <span class="olsc-mono">{{ c.name }}</span> {{ c.detail }}
              </li>
            </ul>
          </template>
          <template v-if="p.certification.length">
            <h4 class="olsc-h4">{{ t('whm.switch.certification') }}</h4>
            <ul class="olsc-list">
              <li v-for="code in p.certification" :key="code">
                <StatusBadge tone="warn" :label="t('severity.warning')" /> <span class="olsc-mono">{{ code }}</span> {{ doctorText(code) }}
              </li>
            </ul>
          </template>

          <h4 class="olsc-h4">{{ t('whm.switch.blockersTitle') }}</h4>
          <ul v-if="p.blockers.length" class="olsc-list">
            <li v-for="(b, i) in p.blockers" :key="i">
              <StatusBadge tone="bad" :label="t('severity.blocker')" />
              <span v-if="b.vhost" class="olsc-mono">{{ b.vhost }}</span> {{ b.detail }}
              <HelpTip :topic="b.explanation" />
            </li>
          </ul>
          <p v-else class="olsc-muted">{{ t('whm.switch.noBlockers') }}</p>

          <h4 class="olsc-h4">{{ t('whm.switch.hybridTitle') }} <HelpTip topic="hybrid_vhost" /></h4>
          <el-table v-if="p.hybrid.length" :data="p.hybrid" size="small" stripe :aria-label="t('whm.switch.hybridTitle')">
            <el-table-column :label="t('fields.vhost')" min-width="200">
              <template #default="{ row }"><span class="olsc-mono">{{ row.vhost }}</span></template>
            </el-table-column>
            <el-table-column :label="t('whm.switch.reasons')" min-width="320">
              <template #default="{ row }">
                <ul class="olsc-list olsc-tight">
                  <li v-for="(r, i) in row.reasons" :key="i">
                    <span class="olsc-mono">{{ r.location }}</span> {{ r.detail }} <HelpTip :topic="r.explanation" />
                  </li>
                  <li v-if="!row.reasons.length" class="olsc-muted">{{ t('whm.switch.noReasons') }}</li>
                </ul>
              </template>
            </el-table-column>
          </el-table>
          <p v-else class="olsc-muted">{{ t('whm.switch.noHybrid') }}</p>

          <template v-if="p.held.length">
            <h4 class="olsc-h4">{{ t('whm.switch.heldTitle') }} <HelpTip topic="php_dso" /></h4>
            <ul class="olsc-list">
              <li v-for="h in p.held" :key="h.vhost"><span class="olsc-mono">{{ h.vhost }}</span> {{ h.reasons.join('; ') }}</li>
            </ul>
          </template>
        </template>
      </StateView>
    </section>

    <!-- Step 3: cutover -->
    <section class="olsc-section olsc-card" :aria-labelledby="'olsc-sw-cutover'">
      <h3 id="olsc-sw-cutover" class="olsc-h3">{{ t('whm.switch.step3') }}</h3>
      <p class="olsc-muted">{{ t('whm.switch.cutoverBody') }} <HelpTip topic="cutover" /></p>
      <el-button type="danger" :disabled="cutoverBlocked" @click="confirmCutover = true">{{ t('whm.switch.cutover') }}</el-button>
      <p v-if="cutoverBlocked && !jobRunning && isCutOver !== true" class="olsc-hint">{{ t('whm.switch.cutoverBlockedHint') }}</p>
    </section>

    <!-- Return to Apache -->
    <section class="olsc-section olsc-card" :aria-labelledby="'olsc-sw-return'">
      <h3 id="olsc-sw-return" class="olsc-h3">{{ t('whm.switch.returnTitle') }}</h3>
      <p class="olsc-muted">{{ t('whm.switch.returnBody') }} <HelpTip topic="apache_return" /></p>
      <el-button type="danger" plain :disabled="returnBlocked" @click="confirmReturn = true">{{ t('whm.switch.return') }}</el-button>
      <p v-if="isCutOver === false" class="olsc-hint">{{ t('whm.switch.notCutOver') }}</p>
    </section>

    <ConfirmDialog v-if="p" v-model="confirmCutover" :title="t('whm.switch.confirmCutoverTitle')" :expected="p.id"
                   :confirm-label="t('whm.switch.cutover')" :busy="action.busy.value" :blocked="cutoverBlocked" @confirm="cutover">
      <dl class="olsc-facts">
        <dt>{{ t('confirm.scope') }}</dt><dd>{{ t('whm.switch.scopeServer') }}</dd>
        <dt>{{ t('confirm.change') }}</dt>
        <dd>{{ t('whm.switch.cutoverChange', { ols: p.olsVhosts ?? t('state.unknown'), hybrid: p.hybrid.length }) }}</dd>
        <dt>{{ t('confirm.affected') }}</dt>
        <dd>{{ t('whm.switch.cutoverAffected', { n: p.vhosts ?? t('state.unknown') }) }}</dd>
        <dt>{{ t('confirm.blockers') }}</dt><dd>{{ p.blockers.length ? p.blockers.length : t('whm.switch.noBlockers') }}</dd>
        <dt>{{ t('whm.switch.readiness') }}</dt>
        <dd><StatusBadge :tone="READINESS_TONE[readiness]" :label="t(`whm.switch.ready.${readiness}`)" /></dd>
        <dt v-if="p.hostChanges.length">{{ t('whm.switch.hostChanges') }}</dt>
        <dd v-if="p.hostChanges.length">{{ p.hostChanges.join('; ') }}</dd>
        <dt>{{ t('confirm.rollback') }}</dt><dd>{{ t('whm.switch.cutoverRollback') }}</dd>
        <dt>{{ t('whm.switch.planDigest') }}</dt><dd class="olsc-mono">{{ p.digest }}</dd>
      </dl>
    </ConfirmDialog>

    <ConfirmDialog v-model="confirmReturn" :title="t('whm.switch.confirmReturnTitle')" :expected="t('whm.switch.returnPhrase')"
                   :confirm-label="t('whm.switch.return')" :busy="action.busy.value" :blocked="returnBlocked" @confirm="apacheReturn">
      <dl class="olsc-facts">
        <dt>{{ t('confirm.scope') }}</dt><dd>{{ t('whm.switch.scopeServer') }}</dd>
        <dt>{{ t('confirm.change') }}</dt><dd>{{ t('whm.switch.returnChange') }}</dd>
        <dt>{{ t('confirm.affected') }}</dt><dd>{{ t('whm.switch.returnAffected') }}</dd>
        <dt>{{ t('confirm.rollback') }}</dt><dd>{{ t('whm.switch.returnRollback') }}</dd>
      </dl>
    </ConfirmDialog>
  </div>
</template>
