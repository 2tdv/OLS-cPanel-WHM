<script setup>
import { computed, reactive, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import ConfirmDialog from '../../shared/ConfirmDialog.vue'
import JobTimeline from '../../shared/JobTimeline.vue'
import MetricCard from '../../shared/MetricCard.vue'
import PageHeader from '../../shared/PageHeader.vue'
import StateView from '../../shared/StateView.vue'
import StatusBadge from '../../shared/StatusBadge.vue'
import { useLoad } from '../../shared/polling.js'
import { ACTIONS, WHM_SETTINGS, commandOutput, useAction, useClient, useMutation, useResource } from '../../shared/api.js'
import { formatBytes, formatDateTime, formatNumber } from '../../shared/format.js'
import { errorMessage } from '../../shared/i18n.js'
import { runningJob } from '../../shared/jobs.js'
import { href } from '../../shared/router.js'

// LiteSpeed page cache (cache: `ols-cpanel cache stats`, one row per store). Purges are product jobs
// (ols.cache_purge) with the scope `server`, `account:<user>` or `domain:<vhost>` and the status digest of
// what is shown; the server-wide purge needs a typed phrase, a site or an account a short confirmation.
// The account filter is applied by the server (the full report walks every store).
const SHOWN = 200
const ACCOUNT = /^[a-z0-9][a-z0-9_-]{0,31}$/
const { t } = useI18n()
const client = useClient()
const filter = ref('')
const draft = ref('')
const draftInvalid = computed(() => draft.value !== '' && !ACCOUNT.test(draft.value))
const status = useResource(client, 'status', { staleAfter: 2 * 60 * 1000 })
const cache = useResource(client, 'cache', { params: () => ({ account: filter.value }), staleAfter: 10 * 60 * 1000 })
const jobs = useResource(client, 'jobs')
const limits = useResource(client, 'cache_limits', { staleAfter: 10 * 60 * 1000 })
const saving = useMutation(client)
const action = useAction(client)
const activeJob = ref(null)
const jobState = ref(null)
const confirmServer = ref(false)

async function loadAll() {
  await Promise.all([status.load(), cache.load(), jobs.load(), limits.load()])
  const running = runningJob(jobs.data.value)
  if (running && !activeJob.value) {
    activeJob.value = String(running.job)
    jobState.value = 'running'
  }
}
useLoad(loadAll)

// The automatic cleanup (ols-cpanel cache limits): the caps in force, the last cleanup and the form that changes the limits.
// Bounds come from the server's report; the engine and the broker check them again.
const LIMIT_KEYS = ['per_site_mb', 'server_percent', 'server_max_gb']
const FALLBACK_BOUNDS = { per_site_mb: [16, 102400], server_percent: [1, 50], server_max_gb: [1, 2048] }
const cleanup = computed(() => commandOutput(limits.data.value) || {})
const bounds = key => (Array.isArray(cleanup.value.bounds?.[key]) ? cleanup.value.bounds[key] : FALLBACK_BOUNDS[key])
const form = reactive({ per_site_mb: '', server_percent: '', server_max_gb: '' })
const dirty = ref(false)
const saved = ref(false)
watch(() => cleanup.value.limits, value => {
  if (!value || dirty.value) return
  for (const key of LIMIT_KEYS) form[key] = String(value[key] ?? '')
}, { immediate: true })
const fieldInvalid = key => {
  const text = String(form[key]).trim()
  const [min, max] = bounds(key)
  return !/^[0-9]{1,9}$/.test(text) || Number(text) < min || Number(text) > max
}
const formInvalid = computed(() => LIMIT_KEYS.some(fieldInvalid))
const touch = () => {
  dirty.value = true
  saved.value = false
}
async function saveLimits() {
  if (formInvalid.value) return
  const body = Object.fromEntries(LIMIT_KEYS.map(key => [key, Number(String(form[key]).trim())]))
  const reply = await saving.run(WHM_SETTINGS.cacheLimits, body)
  if (reply) {
    limits.data.value = reply
    dirty.value = false
    saved.value = true
  }
}
function resetLimits() {
  const defaults = cleanup.value.defaults || {}
  for (const key of LIMIT_KEYS) form[key] = String(defaults[key] ?? form[key])
  touch()
}
const lastClean = computed(() => cleanup.value.last_clean || null)
const percentOfLimit = row => (cleanup.value.per_site_bytes > 0 && typeof row.bytes === 'number' ? Math.round((row.bytes * 100) / cleanup.value.per_site_bytes) : null)

const report = computed(() => commandOutput(cache.data.value) || {})
const stores = computed(() => (Array.isArray(report.value.stores) ? report.value.stores : []))
const shown = computed(() => stores.value.slice(0, SHOWN))
const totals = computed(() => report.value.totals || {})
const statusDigest = computed(() => (typeof status.data.value?.digest === 'string' && status.data.value.digest ? status.data.value.digest : null))
const jobRunning = computed(() => activeJob.value !== null && jobState.value === 'running')
const purgeBlocked = computed(() => !statusDigest.value || jobRunning.value)
const emptyText = computed(() => (filter.value ? t('whm.cache.noMatch') : t('whm.cache.noStores')))

function apply() {
  if (draftInvalid.value) return
  filter.value = draft.value.trim()
  cache.load()
}
function clear() {
  draft.value = ''
  filter.value = ''
  cache.load()
}

async function purge(scope) {
  const id = await action.run(ACTIONS.cachePurge, { scope, digest: statusDigest.value })
  if (id) {
    jobState.value = 'running'
    activeJob.value = id
  } else {
    loadAll() // a refused purge (changed state, another job) shows the current state at once
  }
  return id
}
async function purgeServer() {
  if (await purge('server')) confirmServer.value = false
}
function onJobState(job) {
  jobState.value = job?.state || null
  loadAll()
}

const siteName = row => row.vhost || row.store
const alsoServes = row => (Array.isArray(row.domains) ? row.domains.filter(d => d !== row.vhost) : [])
const num = value => formatNumber(value) ?? t('state.unknown')
const size = value => formatBytes(value) ?? t('state.unknown')
</script>

<template>
  <div>
    <PageHeader :title="t('whm.cache.title')" :description="t('whm.cache.description')">
      <template #actions>
        <el-button type="danger" :disabled="purgeBlocked || !stores.length" @click="confirmServer = true">
          {{ t('whm.cache.purgeServer') }}
        </el-button>
      </template>
    </PageHeader>

    <el-alert v-if="action.error.value" type="error" show-icon :closable="true" class="olsc-gap-below"
              :title="t('whm.cache.purgeFailed')" :description="errorMessage(action.error.value)"
              @close="action.error.value = null" />

    <section v-if="activeJob" class="olsc-card olsc-gap-below" :aria-label="t('whm.cache.currentJob')">
      <h3 class="olsc-h3">{{ t('whm.cache.currentJob') }}</h3>
      <JobTimeline :key="activeJob" :job-id="activeJob" @finished="onJobState" />
      <p class="olsc-muted">
        <a :href="href(`jobs/${activeJob}`)">{{ t('whm.switch.followInJobs') }}</a>
        <el-button v-if="!jobRunning" link type="primary" @click="activeJob = null">{{ t('whm.switch.dismissJob') }}</el-button>
      </p>
    </section>

    <section class="olsc-card olsc-gap-below" :aria-label="t('whm.cache.cleanupTitle')">
      <h3 class="olsc-h3">{{ t('whm.cache.cleanupTitle') }}</h3>
      <p class="olsc-muted">{{ t('whm.cache.cleanupText') }}</p>
      <el-alert v-if="cleanup.emergency" type="warning" show-icon :closable="false" class="olsc-gap-below"
                :title="t('whm.cache.emergency')" />
      <el-alert v-if="cleanup.problem" type="warning" show-icon :closable="false" class="olsc-gap-below"
                :title="t('whm.cache.limitsProblem')" :description="cleanup.problem" />
      <dl v-if="limits.data.value" class="olsc-facts">
        <dt>{{ t('whm.cache.usage') }}</dt>
        <dd>{{ t('whm.cache.usageOf', { used: size(totals.bytes), cap: size(cleanup.server_bytes) }) }}</dd>
        <dt>{{ t('whm.cache.siteCap') }}</dt><dd>{{ size(cleanup.per_site_bytes) }}</dd>
        <dt>{{ t('whm.cache.diskFree') }}</dt>
        <dd>{{ typeof cleanup.filesystem?.free_percent === 'number' ? `${cleanup.filesystem.free_percent}%` : t('state.unknown') }}</dd>
        <dt>{{ t('whm.cache.lastCleanup') }}</dt>
        <dd v-if="lastClean">
          {{ t('whm.cache.lastCleanupDone', { time: formatDateTime(lastClean.last_run) ?? t('state.unknown'), pages: num(lastClean.totals?.files),
                                              size: size(lastClean.totals?.bytes) }) }}
        </dd>
        <dd v-else>{{ t('whm.cache.neverCleaned') }}</dd>
      </dl>
      <form class="olsc-toolbar" @submit.prevent="saveLimits">
        <div v-for="key in LIMIT_KEYS" :key="key">
          <label :for="`olsc-limit-${key}`">{{ t(`whm.cache.limit.${key}`) }}</label>
          <el-input :id="`olsc-limit-${key}`" v-model="form[key]" type="number" :min="bounds(key)[0]" :max="bounds(key)[1]"
                    :aria-invalid="fieldInvalid(key) ? 'true' : 'false'" @input="touch" />
          <p class="olsc-hint">{{ t(`whm.cache.limitHelp.${key}`, { min: formatNumber(bounds(key)[0]), max: formatNumber(bounds(key)[1]) }) }}</p>
        </div>
        <el-button native-type="submit" type="primary" :loading="saving.busy.value" :disabled="formInvalid || !dirty">{{ t('whm.cache.limitsSave') }}</el-button>
        <el-button :disabled="saving.busy.value" @click="resetLimits">{{ t('whm.cache.limitsDefaults') }}</el-button>
      </form>
      <el-alert v-if="saving.error.value" type="error" show-icon :closable="true" :title="t('whm.cache.limitsFailed')"
                :description="errorMessage(saving.error.value)" @close="saving.error.value = null" />
      <p v-if="saved" class="olsc-hint" role="status">{{ t('whm.cache.limitsSaved') }}</p>
    </section>

    <form class="olsc-toolbar" role="search" @submit.prevent="apply">
      <label for="olsc-cache-filter" class="olsc-sr-only">{{ t('whm.cache.filter') }}</label>
      <el-input id="olsc-cache-filter" v-model="draft" :placeholder="t('whm.cache.filter')" clearable class="olsc-search"
                autocomplete="off" spellcheck="false" :aria-label="t('whm.cache.filter')"
                :aria-invalid="draftInvalid ? 'true' : 'false'" />
      <el-button native-type="submit" :disabled="draftInvalid">{{ t('whm.cache.filterApply') }}</el-button>
      <el-button v-if="filter" link type="primary" @click="clear">{{ t('whm.cache.filterClear') }}</el-button>
    </form>
    <p v-if="draftInvalid" class="olsc-hint" role="status">{{ t('whm.cache.filterHint') }}</p>
    <p v-if="!statusDigest && status.data.value" class="olsc-hint">{{ t('whm.cache.stateFingerprint') }}</p>

    <StateView :resource="cache" :refresh="loadAll" :empty="cache.data.value !== null && !stores.length" :empty-text="emptyText"
               :pending="jobRunning ? t('whm.switch.jobPending') : ''">
      <div class="olsc-grid olsc-gap-below">
        <MetricCard :label="t('whm.cache.entries')" :value="formatNumber(totals.entries)" />
        <MetricCard :label="t('whm.cache.size')" :value="formatBytes(totals.bytes)" />
        <MetricCard :label="t('whm.cache.private')" :value="formatNumber(totals.private_entries)" />
        <MetricCard :label="t('whm.cache.stores')" :value="formatNumber(totals.stores)" />
      </div>
      <p v-if="stores.length > SHOWN" class="olsc-hint">{{ t('whm.cache.shown', { shown: SHOWN, n: stores.length }) }}</p>
      <div role="region" :aria-label="t('whm.cache.title')" class="olsc-table-wrap">
        <el-table :data="shown" stripe size="small" :aria-label="t('whm.cache.title')">
          <el-table-column :label="t('whm.cache.site')" min-width="260">
            <template #default="{ row }">
              <span v-if="row.account === null || row.account === undefined">{{ t('whm.cache.serverStore') }}</span>
              <span v-else class="olsc-mono">{{ siteName(row) }}</span>
              <div v-if="alsoServes(row).length" class="olsc-muted olsc-small olsc-wrap">
                {{ t('whm.cache.alsoServes', { names: alsoServes(row).join(', ') }) }}
              </div>
            </template>
          </el-table-column>
          <el-table-column :label="t('whm.cache.account')" min-width="110">
            <template #default="{ row }"><span class="olsc-mono">{{ row.account ?? '' }}</span></template>
          </el-table-column>
          <el-table-column :label="t('fields.state')" width="170">
            <template #default="{ row }">
              <StatusBadge v-if="row.enabled === true" tone="ok" :label="t('whm.cache.serving')" />
              <StatusBadge v-else-if="row.enabled === false" tone="neutral" :label="t('whm.cache.off')" />
              <span v-else class="olsc-unknown">{{ row.vhost ? t('state.unknown') : t('whm.cache.unmapped') }}</span>
            </template>
          </el-table-column>
          <el-table-column :label="t('whm.cache.pages')" width="120" align="right">
            <template #default="{ row }">{{ num(row.entries) }}</template>
          </el-table-column>
          <el-table-column :label="t('whm.cache.size')" width="120" align="right">
            <template #default="{ row }">{{ size(row.bytes) }}</template>
          </el-table-column>
          <el-table-column :label="t('whm.cache.ofLimit')" width="110" align="right">
            <template #default="{ row }">{{ percentOfLimit(row) === null ? '' : `${percentOfLimit(row)}%` }}</template>
          </el-table-column>
          <el-table-column :label="t('whm.cache.lastPurge')" width="190">
            <template #default="{ row }">{{ formatDateTime(row.last_purge) ?? t('whm.cache.never') }}</template>
          </el-table-column>
          <el-table-column :label="t('fields.action')" min-width="250">
            <template #default="{ row }">
              <el-popconfirm v-if="row.vhost && row.account" :title="t('whm.cache.confirmSite', { name: row.vhost })"
                             :confirm-button-text="t('whm.cache.confirmYes')" :cancel-button-text="t('whm.cache.confirmNo')"
                             @confirm="purge(`domain:${row.vhost}`)">
                <template #reference>
                  <el-button size="small" :disabled="purgeBlocked">{{ t('whm.cache.purgeSite') }}</el-button>
                </template>
              </el-popconfirm>
              <el-popconfirm v-if="row.account" :title="t('whm.cache.confirmAccount', { name: row.account })"
                             :confirm-button-text="t('whm.cache.confirmYes')" :cancel-button-text="t('whm.cache.confirmNo')"
                             @confirm="purge(`account:${row.account}`)">
                <template #reference>
                  <el-button size="small" :disabled="purgeBlocked">{{ t('whm.cache.purgeAccount') }}</el-button>
                </template>
              </el-popconfirm>
            </template>
          </el-table-column>
        </el-table>
      </div>
    </StateView>

    <ConfirmDialog v-model="confirmServer" :title="t('whm.cache.serverTitle')" :expected="t('whm.cache.serverPhrase')"
                   :confirm-label="t('whm.cache.purgeServer')" :busy="action.busy.value" :blocked="purgeBlocked" @confirm="purgeServer">
      <dl class="olsc-facts">
        <dt>{{ t('confirm.scope') }}</dt><dd>{{ t('whm.switch.scopeServer') }}</dd>
        <dt>{{ t('confirm.change') }}</dt><dd>{{ t('whm.cache.serverChange') }}</dd>
        <dt>{{ t('confirm.affected') }}</dt><dd>{{ t('whm.cache.serverAffected', { n: num(totals.stores) }) }}</dd>
        <dt>{{ t('confirm.rollback') }}</dt><dd>{{ t('whm.cache.serverUndo') }}</dd>
      </dl>
    </ConfirmDialog>
  </div>
</template>
