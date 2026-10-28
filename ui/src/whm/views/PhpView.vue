<script setup>
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import ConfirmDialog from '../../shared/ConfirmDialog.vue'
import JobTimeline from '../../shared/JobTimeline.vue'
import MetricCard from '../../shared/MetricCard.vue'
import PageHeader from '../../shared/PageHeader.vue'
import StateView from '../../shared/StateView.vue'
import StatusBadge from '../../shared/StatusBadge.vue'
import { useLoad } from '../../shared/polling.js'
import { ACTIONS, commandOutput, useAction, useClient, useResource } from '../../shared/api.js'
import { formatBytes, formatNumber } from '../../shared/format.js'
import { errorMessage } from '../../shared/i18n.js'
import { runningJob } from '../../shared/jobs.js'
import { href } from '../../shared/router.js'

// PHP manager (php: `ols-cpanel php status`): OPcache per installed EA4 PHP version with an install button, the
// lsphp processes per account with runaway detection, a restart per account or for the server, and the limits
// in force (read only; they come from /var/lib/ols-cpanel/php-limits.json). Installation and restart are product
// jobs (ols.opcache_install with the scope `version:ea-phpNN` or `server`, ols.php_restart with `account:<user>`
// or `server`) bound to the status digest of what is shown; restarting the whole server needs a typed phrase.
const { t } = useI18n()
const client = useClient()
const status = useResource(client, 'status', { staleAfter: 2 * 60 * 1000 })
const php = useResource(client, 'php', { staleAfter: 5 * 60 * 1000 })
const jobs = useResource(client, 'jobs')
const action = useAction(client)
const activeJob = ref(null)
const jobState = ref(null)
const confirmServer = ref(false)

async function loadAll() {
  await Promise.all([status.load(), php.load(), jobs.load()])
  const running = runningJob(jobs.data.value)
  if (running && !activeJob.value) {
    activeJob.value = String(running.job)
    jobState.value = 'running'
  }
}
useLoad(loadAll)

const report = computed(() => commandOutput(php.data.value) || {})
const versions = computed(() => (Array.isArray(report.value.opcache?.versions) ? report.value.opcache.versions : []))
const families = computed(() => (Array.isArray(report.value.processes?.accounts) ? report.value.processes.accounts : []))
const totals = computed(() => report.value.processes?.totals || {})
const thresholds = computed(() => report.value.processes?.thresholds || {})
const limits = computed(() => report.value.limits || {})
const limitRows = computed(() => Object.entries(limits.value.accounts || {}).map(([name, l]) => ({ name, ...l })))
const loadedCount = computed(() => versions.value.filter(v => v.loaded === true).length)
const statusDigest = computed(() => (typeof status.data.value?.digest === 'string' && status.data.value.digest ? status.data.value.digest : null))
const jobRunning = computed(() => activeJob.value !== null && jobState.value === 'running')
const blocked = computed(() => !statusDigest.value || jobRunning.value)

async function start(name, scope) {
  const id = await action.run(name, { scope, digest: statusDigest.value })
  if (id) {
    jobState.value = 'running'
    activeJob.value = id
  } else {
    loadAll() // a refused request (changed state, another job) shows the current state at once
  }
  return id
}
const install = scope => start(ACTIONS.opcacheInstall, scope)
const repairEnvironment = () => start(ACTIONS.phpEnvRepair, 'server')
const restart = scope => start(ACTIONS.phpRestart, scope)
async function restartServer() {
  if (await restart('server')) confirmServer.value = false
}
function onJobState(job) {
  jobState.value = job?.state || null
  loadAll()
}

const num = value => formatNumber(value) ?? t('state.unknown')
const kb = value => (Number.isFinite(value) ? formatBytes(value * 1024) : null) ?? t('state.unknown')
const bytes = value => (value === 0 ? t('whm.php.unlimited') : formatBytes(value) ?? t('state.unknown'))
const setting = (v, key) => v.settings?.[key] ?? t('state.unknown')
const needsWork = v => !(v.loaded === true && v.tuned === true)

// EasyApache compatibility (php env: the root applier that keeps lsphp, OPcache and redis complete per version).
const environment = computed(() => report.value.environment || null)
const envRows = computed(() => (Array.isArray(environment.value?.versions) ? environment.value.versions : []))
const envTone = status => ({ complete: 'ok', repairing: 'warn', failed: 'bad' })[status] || 'neutral'
const envLabel = status => t(`whm.php.env${{ complete: 'Complete', repairing: 'Repairing', failed: 'Failed' }[status] || 'Pending'}`)
const stepLabel = value => t(`whm.php.env${{ ok: 'Ok', repaired: 'Repaired', failed: 'Failed', off: 'Off', not_wanted: 'NotWanted', active: 'Active', pending: 'PendingStep', unsupported: 'Unsupported' }[value] || 'Ok'}`)
const when = seconds => (Number.isFinite(seconds) ? new Date(seconds * 1000).toLocaleString() : t('state.unknown'))
const unitsOff = computed(() => environment.value !== null && !(environment.value.units?.watcher && environment.value.units?.timer))
</script>

<template>
  <div>
    <PageHeader :title="t('whm.php.title')" :description="t('whm.php.description')">
      <template #actions>
        <el-button type="danger" :disabled="blocked" @click="confirmServer = true">{{ t('whm.php.restartServer') }}</el-button>
      </template>
    </PageHeader>

    <el-alert v-if="action.error.value" type="error" show-icon :closable="true" class="olsc-gap-below"
              :title="t('whm.php.notStarted')" :description="errorMessage(action.error.value)" @close="action.error.value = null" />

    <section v-if="activeJob" class="olsc-card olsc-gap-below" :aria-label="t('whm.php.currentJob')">
      <h3 class="olsc-h3">{{ t('whm.php.currentJob') }}</h3>
      <JobTimeline :key="activeJob" :job-id="activeJob" @finished="onJobState" />
      <p class="olsc-muted">
        <a :href="href(`jobs/${activeJob}`)">{{ t('whm.switch.followInJobs') }}</a>
        <el-button v-if="!jobRunning" link type="primary" @click="activeJob = null">{{ t('whm.switch.dismissJob') }}</el-button>
      </p>
    </section>

    <p v-if="!statusDigest && status.data.value" class="olsc-hint">{{ t('whm.php.stateFingerprint') }}</p>

    <StateView :resource="php" :refresh="loadAll" :empty="php.data.value !== null && !versions.length && !families.length"
               :empty-text="t('whm.php.none')" :pending="jobRunning ? t('whm.switch.jobPending') : ''">
      <div class="olsc-grid olsc-gap-below">
        <MetricCard :label="t('whm.php.versions')" :value="formatNumber(versions.length)" />
        <MetricCard :label="t('whm.php.opcacheLoaded')" :value="`${formatNumber(loadedCount)} / ${formatNumber(versions.length)}`" />
        <MetricCard :label="t('whm.php.processes')" :value="formatNumber(totals.processes)" />
        <MetricCard :label="t('whm.php.runaway')" :value="formatNumber(totals.runaway)" :hint="t('whm.php.runawayHint', thresholds)" />
      </div>

      <section class="olsc-section" :aria-label="t('whm.php.opcacheTitle')">
        <h3 class="olsc-h3">{{ t('whm.php.opcacheTitle') }}</h3>
        <p class="olsc-muted">
          {{ report.opcache?.auto === false ? t('whm.php.autoOff') : t('whm.php.autoOn') }}
        </p>
        <div role="region" :aria-label="t('whm.php.opcacheTitle')" class="olsc-table-wrap">
          <el-table :data="versions" stripe size="small" :aria-label="t('whm.php.opcacheTitle')">
            <el-table-column :label="t('whm.php.version')" width="130">
              <template #default="{ row }"><span class="olsc-mono">{{ row.version }}</span><div class="olsc-muted olsc-small">{{ t('whm.php.phpLabel', { v: row.php }) }}</div></template>
            </el-table-column>
            <el-table-column :label="t('fields.state')" min-width="190">
              <template #default="{ row }">
                <StatusBadge v-if="row.loaded && row.tuned" tone="ok" :label="t('whm.php.ready')" />
                <StatusBadge v-else-if="row.loaded" tone="warn" :label="t('whm.php.notTuned')" />
                <StatusBadge v-else-if="row.package_installed" tone="warn" :label="t('whm.php.notLoaded')" />
                <StatusBadge v-else tone="neutral" :label="t('whm.php.notInstalled')" />
              </template>
            </el-table-column>
            <el-table-column :label="t('whm.php.memory')" width="110" align="right">
              <template #default="{ row }">{{ setting(row, 'memory_consumption') }}</template>
            </el-table-column>
            <el-table-column :label="t('whm.php.files')" width="110" align="right">
              <template #default="{ row }">{{ setting(row, 'max_accelerated_files') }}</template>
            </el-table-column>
            <el-table-column :label="t('whm.php.revalidate')" width="120" align="right">
              <template #default="{ row }">{{ setting(row, 'revalidate_freq') }}</template>
            </el-table-column>
            <el-table-column :label="t('whm.php.validateRoot')" width="120">
              <template #default="{ row }">{{ setting(row, 'validate_root') }}</template>
            </el-table-column>
            <el-table-column :label="t('whm.php.validatePermission')" width="130">
              <template #default="{ row }">{{ setting(row, 'validate_permission') }}</template>
            </el-table-column>
            <el-table-column :label="t('whm.php.accounts')" width="100" align="right">
              <template #default="{ row }">{{ num(row.accounts) }}</template>
            </el-table-column>
            <el-table-column :label="t('fields.action')" min-width="190">
              <template #default="{ row }">
                <el-popconfirm :title="t('whm.php.confirmInstall', { name: row.version })" :confirm-button-text="t('whm.php.confirmInstallYes')"
                               :cancel-button-text="t('whm.php.confirmNo')" @confirm="install(`version:${row.version}`)">
                  <template #reference>
                    <el-button size="small" :disabled="blocked || !needsWork(row)">{{ row.loaded ? t('whm.php.repair') : t('whm.php.install') }}</el-button>
                  </template>
                </el-popconfirm>
              </template>
            </el-table-column>
          </el-table>
        </div>
        <p class="olsc-hint">{{ t('whm.php.opcacheNote') }}</p>
      </section>

      <section v-if="environment" class="olsc-section" :aria-label="t('whm.php.envTitle')">
        <h3 class="olsc-h3">{{ t('whm.php.envTitle') }}</h3>
        <p class="olsc-muted">{{ t('whm.php.envNote', { minutes: 15 }) }}</p>
        <p class="olsc-muted">{{ environment.checked_at ? t('whm.php.envChecked', { time: when(environment.checked_at) }) : t('whm.php.envNeverChecked') }}</p>
        <el-alert v-if="unitsOff" type="warning" show-icon :closable="false" class="olsc-gap-below" :title="t('whm.php.envUnitsOff')" />
        <p v-if="!envRows.length" class="olsc-muted">{{ t('whm.php.envNone') }}</p>
        <div v-else role="region" :aria-label="t('whm.php.envTitle')" class="olsc-table-wrap">
          <el-table :data="envRows" stripe size="small" :aria-label="t('whm.php.envTitle')">
            <el-table-column :label="t('whm.php.version')" width="130">
              <template #default="{ row }"><span class="olsc-mono">{{ row.version }}</span><div class="olsc-muted olsc-small">{{ t('whm.php.phpLabel', { v: row.php }) }}</div></template>
            </el-table-column>
            <el-table-column :label="t('fields.state')" width="190">
              <template #default="{ row }"><StatusBadge :tone="envTone(row.status)" :label="envLabel(row.status)" /></template>
            </el-table-column>
            <el-table-column :label="t('whm.php.envLsphp')" width="140">
              <template #default="{ row }">{{ row.lsphp ? t('whm.php.envPresent') : t('whm.php.envMissing') }}</template>
            </el-table-column>
            <el-table-column :label="t('whm.php.envOpcache')" width="130">
              <template #default="{ row }">{{ row.opcache ? stepLabel(row.opcache) : t('state.unknown') }}</template>
            </el-table-column>
            <el-table-column :label="t('whm.php.envRedis')" width="190">
              <template #default="{ row }">{{ row.redis ? stepLabel(row.redis) : t('state.unknown') }}</template>
            </el-table-column>
            <el-table-column :label="t('whm.php.envReason')" min-width="260">
              <template #default="{ row }">
                <span v-if="row.error">{{ row.error }}</span>
                <div v-if="row.status === 'failed' && row.retry_at" class="olsc-muted olsc-small">{{ t('whm.php.envRetry', { time: when(row.retry_at) }) }}</div>
              </template>
            </el-table-column>
          </el-table>
        </div>
        <p class="olsc-gap-below">
          <el-popconfirm :title="t('whm.php.envRepairConfirm')" :confirm-button-text="t('whm.php.envRepairYes')" :cancel-button-text="t('whm.php.confirmNo')"
                         @confirm="repairEnvironment">
            <template #reference>
              <el-button type="primary" :disabled="blocked">{{ t('whm.php.envRepair') }}</el-button>
            </template>
          </el-popconfirm>
        </p>
        <p class="olsc-hint">{{ t('whm.php.envRepairNote') }}</p>
        <h4 class="olsc-h3">{{ t('whm.php.profileTitle') }}</h4>
        <p class="olsc-muted">{{ t('whm.php.profileText') }}</p>
        <dl class="olsc-facts">
          <dt>{{ t('whm.php.profileFile') }}</dt><dd><span class="olsc-mono">{{ environment.profile?.file || t('state.unknown') }}</span></dd>
          <dt>{{ t('fields.state') }}</dt>
          <dd>{{ environment.profile?.error ? `${t('whm.php.profileError')}: ${environment.profile.error}` : environment.profile?.present ? t('whm.php.profilePresent') : t('whm.php.profileAbsent') }}</dd>
        </dl>
      </section>

      <section class="olsc-section" :aria-label="t('whm.php.processesTitle')">
        <h3 class="olsc-h3">{{ t('whm.php.processesTitle') }}</h3>
        <p v-if="!families.length" class="olsc-muted">{{ t('whm.php.noProcesses') }}</p>
        <div v-else role="region" :aria-label="t('whm.php.processesTitle')" class="olsc-table-wrap">
          <el-table :data="families" stripe size="small" :aria-label="t('whm.php.processesTitle')">
            <el-table-column :label="t('whm.php.account')" min-width="140">
              <template #default="{ row }"><span class="olsc-mono">{{ row.account }}</span></template>
            </el-table-column>
            <el-table-column :label="t('whm.php.parents')" width="100" align="right">
              <template #default="{ row }">{{ num(row.parents) }}</template>
            </el-table-column>
            <el-table-column :label="t('whm.php.children')" width="100" align="right">
              <template #default="{ row }">{{ num(row.children) }}</template>
            </el-table-column>
            <el-table-column :label="t('whm.php.cpu')" width="100" align="right">
              <template #default="{ row }">{{ Number.isFinite(row.cpu_percent) ? `${row.cpu_percent}%` : t('state.unknown') }}</template>
            </el-table-column>
            <el-table-column :label="t('whm.php.rss')" width="120" align="right">
              <template #default="{ row }">{{ kb(row.rss_kb) }}</template>
            </el-table-column>
            <el-table-column :label="t('fields.state')" width="170">
              <template #default="{ row }">
                <StatusBadge v-if="row.runaway > 0" tone="bad" :label="t('whm.php.runawayCount', { n: row.runaway })" />
                <StatusBadge v-else tone="ok" :label="t('whm.php.normal')" />
              </template>
            </el-table-column>
            <el-table-column :label="t('fields.action')" width="170">
              <template #default="{ row }">
                <el-popconfirm :title="t('whm.php.confirmRestart', { name: row.account })" :confirm-button-text="t('whm.php.confirmRestartYes')"
                               :cancel-button-text="t('whm.php.confirmNo')" @confirm="restart(`account:${row.account}`)">
                  <template #reference>
                    <el-button size="small" :disabled="blocked">{{ t('whm.php.restart') }}</el-button>
                  </template>
                </el-popconfirm>
              </template>
            </el-table-column>
          </el-table>
        </div>
      </section>

      <section class="olsc-section" :aria-label="t('whm.php.limitsTitle')">
        <h3 class="olsc-h3">{{ t('whm.php.limitsTitle') }}</h3>
        <el-alert v-if="limits.error" type="error" show-icon :closable="false" class="olsc-gap-below"
                  :title="t('whm.php.limitsError')" :description="limits.error" />
        <p class="olsc-muted">{{ t('whm.php.limitsNote', { file: limits.file || '' }) }}</p>
        <dl class="olsc-facts">
          <dt>{{ t('whm.php.limitChildren') }}</dt><dd>{{ num(limits.builtin?.children) }}</dd>
          <dt>{{ t('whm.php.limitConns') }}</dt><dd>{{ num(limits.builtin?.max_conns) }}</dd>
          <dt>{{ t('whm.php.limitMem') }}</dt><dd>{{ bytes(limits.builtin?.mem_soft) }} / {{ bytes(limits.builtin?.mem_hard) }}</dd>
          <dt>{{ t('whm.php.limitProc') }}</dt><dd>{{ num(limits.builtin?.proc_soft) }} / {{ num(limits.builtin?.proc_hard) }}</dd>
          <dt>{{ t('whm.php.limitRunaway') }}</dt>
          <dd>{{ t('whm.php.runawayHint', limits.runaway || thresholds) }}</dd>
        </dl>
        <p v-if="!limitRows.length" class="olsc-muted">{{ t('whm.php.noOverrides') }}</p>
        <div v-else role="region" :aria-label="t('whm.php.overrides')" class="olsc-table-wrap">
          <el-table :data="limitRows" stripe size="small" :aria-label="t('whm.php.overrides')">
            <el-table-column :label="t('whm.php.account')" min-width="140">
              <template #default="{ row }"><span class="olsc-mono">{{ row.name }}</span></template>
            </el-table-column>
            <el-table-column :label="t('whm.php.limitChildren')" width="130" align="right">
              <template #default="{ row }">{{ num(row.children) }}</template>
            </el-table-column>
            <el-table-column :label="t('whm.php.limitConns')" width="150" align="right">
              <template #default="{ row }">{{ num(row.max_conns) }}</template>
            </el-table-column>
            <el-table-column :label="t('whm.php.limitMem')" min-width="190">
              <template #default="{ row }">{{ bytes(row.mem_soft) }} / {{ bytes(row.mem_hard) }}</template>
            </el-table-column>
            <el-table-column :label="t('whm.php.limitProc')" width="150">
              <template #default="{ row }">{{ num(row.proc_soft) }} / {{ num(row.proc_hard) }}</template>
            </el-table-column>
          </el-table>
        </div>
      </section>
    </StateView>

    <ConfirmDialog v-model="confirmServer" :title="t('whm.php.serverTitle')" :expected="t('whm.php.serverPhrase')"
                   :confirm-label="t('whm.php.restartServer')" :busy="action.busy.value" :blocked="blocked" @confirm="restartServer">
      <dl class="olsc-facts">
        <dt>{{ t('confirm.scope') }}</dt><dd>{{ t('whm.switch.scopeServer') }}</dd>
        <dt>{{ t('confirm.change') }}</dt><dd>{{ t('whm.php.serverChange') }}</dd>
        <dt>{{ t('confirm.affected') }}</dt><dd>{{ t('whm.php.serverAffected', { n: num(totals.processes), accounts: num(totals.accounts) }) }}</dd>
        <dt>{{ t('confirm.rollback') }}</dt><dd>{{ t('whm.php.serverUndo') }}</dd>
      </dl>
    </ConfirmDialog>
  </div>
</template>
