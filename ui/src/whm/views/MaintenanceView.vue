<script setup>
import { computed, reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import PageHeader from '../../shared/PageHeader.vue'
import StateView from '../../shared/StateView.vue'
import StatusBadge from '../../shared/StatusBadge.vue'
import { usePolling } from '../../shared/polling.js'
import { ACTIONS, WHM_SETTINGS, commandOutput, useClient, useMutation, useResource } from '../../shared/api.js'
import { formatDateTime } from '../../shared/format.js'
import { errorMessage } from '../../shared/i18n.js'
import { actionLabel } from '../../shared/jobs.js'
import { href } from '../../shared/router.js'

// Maintenance windows (schedule: the scheduled jobs; schedule_add and schedule_cancel change them). The switch and the return can be
// scheduled for a time and a window; at that time the server starts the job through the same checked path as the Switch center. A
// switch runs only on the plan approved here: if the plan changed by then, it is refused and never run.
const WINDOWS = [30, 60, 120, 240, 480, 720]
const { t } = useI18n()
const client = useClient()
const schedule = useResource(client, 'schedule', { staleAfter: 5 * 60 * 1000 })
const plan = useResource(client, 'plan', { staleAfter: 5 * 60 * 1000 })
const status = useResource(client, 'status', { staleAfter: 5 * 60 * 1000 })
const adding = useMutation(client)
const cancelling = useMutation(client)

async function loadAll() {
  await Promise.all([schedule.load(), plan.load(), status.load()])
}
// One request in flight at most, backing off on failure; a window passing changes the states without any click.
const poller = usePolling(async () => {
  await loadAll()
  return !schedule.error.value
}, { interval: 30000, maxInterval: 5 * 60 * 1000 })

const report = computed(() => commandOutput(schedule.data.value) || {})
const entries = computed(() => (Array.isArray(report.value.entries) ? report.value.entries : []))
const limits = computed(() => report.value.limits || {})
const latestPlan = computed(() => (plan.data.value?.plan && plan.data.value.plan.valid !== false ? plan.data.value.plan : null))
const cutOver = computed(() => status.data.value?.cut_over === true)
const statusDigest = computed(() => (typeof status.data.value?.digest === 'string' && status.data.value.digest ? status.data.value.digest : null))

const form = reactive({ action: '', when: '', window: limits.value.default_window || 60 })
const added = ref(false)
const options = computed(() => [
  ...(latestPlan.value ? [{ value: ACTIONS.cutover, label: t('whm.maintenance.optSwitch', { id: latestPlan.value.id }) }] : []),
  ...(cutOver.value ? [{ value: ACTIONS.apacheReturn, label: t('whm.maintenance.optReturn') }] : []),
])
// The browser's local date and time (yyyy-mm-ddThh:mm), read as local time.
const whenMs = computed(() => {
  const ms = form.when ? Date.parse(form.when) : Number.NaN
  return Number.isNaN(ms) ? null : ms
})
const minMs = () => Date.now() + 2 * 60 * 1000
const whenInvalid = computed(() => whenMs.value === null || whenMs.value < minMs()
  || whenMs.value > Date.now() + (limits.value.max_days_ahead || 90) * 86400000)
const pending = computed(() => entries.value.filter(e => e.state === 'scheduled').length)
const full = computed(() => pending.value >= (limits.value.max_pending || 10))
const blocked = computed(() => !form.action || whenInvalid.value || full.value || adding.busy.value
  || (form.action === ACTIONS.cutover ? !latestPlan.value : !statusDigest.value))

async function add() {
  if (blocked.value) return
  const cutover = form.action === ACTIONS.cutover
  const body = { action: form.action, scope: cutover ? latestPlan.value.id : 'server', digest: cutover ? latestPlan.value.digest : statusDigest.value,
    at: Math.floor(whenMs.value / 1000), window: form.window }
  const reply = await adding.run(WHM_SETTINGS.scheduleAdd, body)
  if (reply) {
    added.value = true
    form.when = ''
    schedule.data.value = reply
    schedule.loadedAt.value = Date.now()
  } else {
    loadAll() // a changed plan or state shows the current one at once
  }
}
async function cancel(id) {
  const reply = await cancelling.run(WHM_SETTINGS.scheduleCancel, { id })
  if (reply) {
    schedule.data.value = reply
  } else {
    loadAll()
  }
}
const stateTone = state => ({ scheduled: 'info', running: 'pending', done: 'ok', failed: 'bad', missed: 'warn', refused: 'bad', cancelled: 'neutral' }[state] || 'neutral')
const stateLabel = state => t(`whm.maintenance.state.${['scheduled', 'running', 'done', 'failed', 'missed', 'refused', 'cancelled'].includes(state) ? state : 'unknown'}`)
const until = entry => formatDateTime(entry.at + (entry.window_minutes || 0) * 60) ?? t('state.unknown')
</script>

<template>
  <div>
    <PageHeader :title="t('whm.maintenance.title')" :description="t('whm.maintenance.description')" />
    <StateView :resource="schedule" :refresh="poller.refresh">
      <section class="olsc-card olsc-gap-below" :aria-label="t('whm.maintenance.addTitle')">
        <h3 class="olsc-h3">{{ t('whm.maintenance.addTitle') }}</h3>
        <p class="olsc-muted">{{ t('whm.maintenance.addText') }}</p>
        <p v-if="!options.length" class="olsc-hint">{{ t('whm.maintenance.nothingToSchedule') }}</p>
        <form class="olsc-toolbar" @submit.prevent="add">
          <div>
            <label for="olsc-maint-action">{{ t('whm.maintenance.what') }}</label>
            <el-select id="olsc-maint-action" v-model="form.action" :placeholder="t('whm.maintenance.what')" :disabled="!options.length">
              <el-option v-for="o in options" :key="o.value" :label="o.label" :value="o.value" />
            </el-select>
          </div>
          <div>
            <label for="olsc-maint-when">{{ t('whm.maintenance.when') }}</label>
            <el-input id="olsc-maint-when" v-model="form.when" type="datetime-local" :aria-label="t('whm.maintenance.when')" />
          </div>
          <div>
            <label for="olsc-maint-window">{{ t('whm.maintenance.window') }}</label>
            <el-select id="olsc-maint-window" v-model="form.window" :placeholder="t('whm.maintenance.window')">
              <el-option v-for="m in WINDOWS" :key="m" :label="t('whm.maintenance.windowMinutes', { n: m })" :value="m" />
            </el-select>
          </div>
          <el-button native-type="submit" type="primary" :loading="adding.busy.value" :disabled="blocked">{{ t('whm.maintenance.add') }}</el-button>
        </form>
        <p v-if="form.when && whenInvalid" class="olsc-hint olsc-error">{{ t('whm.maintenance.whenInvalid', { days: limits.max_days_ahead || 90 }) }}</p>
        <p v-if="full" class="olsc-hint olsc-error">{{ t('whm.maintenance.full', { n: limits.max_pending || 10 }) }}</p>
        <p class="olsc-hint">{{ t('whm.maintenance.windowHelp') }}</p>
        <el-alert v-if="adding.error.value" type="error" show-icon :closable="true" :title="t('whm.maintenance.addFailed')"
                  :description="errorMessage(adding.error.value)" @close="adding.error.value = null" />
        <p v-if="added" class="olsc-hint" role="status">{{ t('whm.maintenance.added') }}</p>
      </section>

      <section class="olsc-card" :aria-label="t('whm.maintenance.listTitle')">
        <h3 class="olsc-h3">{{ t('whm.maintenance.listTitle') }}</h3>
        <el-alert v-if="cancelling.error.value" type="error" show-icon :closable="true" :title="t('whm.maintenance.cancelFailed')"
                  :description="errorMessage(cancelling.error.value)" @close="cancelling.error.value = null" />
        <p v-if="!entries.length" class="olsc-muted">{{ t('whm.maintenance.none') }}</p>
        <el-table v-else :data="entries" size="small" stripe :aria-label="t('whm.maintenance.listTitle')">
          <el-table-column :label="t('fields.action')" min-width="220">
            <template #default="{ row }">
              {{ actionLabel(row.action) }}
              <div v-if="row.scope !== 'server'" class="olsc-muted olsc-small olsc-mono">{{ row.scope }}</div>
            </template>
          </el-table-column>
          <el-table-column :label="t('whm.maintenance.startsAt')" min-width="190">
            <template #default="{ row }">{{ formatDateTime(row.at) ?? t('state.unknown') }}</template>
          </el-table-column>
          <el-table-column :label="t('whm.maintenance.until')" min-width="190">
            <template #default="{ row }">{{ until(row) }}</template>
          </el-table-column>
          <el-table-column :label="t('fields.state')" width="130">
            <template #default="{ row }"><StatusBadge :tone="stateTone(row.state)" :label="stateLabel(row.state)" /></template>
          </el-table-column>
          <el-table-column :label="t('whm.maintenance.note')" min-width="240">
            <template #default="{ row }">
              <span class="olsc-muted olsc-small olsc-wrap">{{ row.note }}</span>
              <a v-if="row.job" :href="href(`jobs/${row.job}`)" class="olsc-mono olsc-small">{{ row.job }}</a>
            </template>
          </el-table-column>
          <el-table-column :label="t('fields.action')" width="140">
            <template #default="{ row }">
              <el-popconfirm v-if="row.state === 'scheduled'" :title="t('whm.maintenance.cancelConfirm')"
                             :confirm-button-text="t('whm.maintenance.cancelYes')" :cancel-button-text="t('whm.maintenance.cancelNo')"
                             @confirm="cancel(row.id)">
                <template #reference>
                  <el-button size="small" :loading="cancelling.busy.value">{{ t('whm.maintenance.cancel') }}</el-button>
                </template>
              </el-popconfirm>
            </template>
          </el-table-column>
        </el-table>
      </section>
    </StateView>
  </div>
</template>
