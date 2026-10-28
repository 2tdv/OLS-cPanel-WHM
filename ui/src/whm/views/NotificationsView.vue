<script setup>
import { computed, reactive, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import PageHeader from '../../shared/PageHeader.vue'
import StateView from '../../shared/StateView.vue'
import StatusBadge from '../../shared/StatusBadge.vue'
import { useLoad } from '../../shared/polling.js'
import { WHM_SETTINGS, commandOutput, useClient, useMutation, useResource } from '../../shared/api.js'
import { formatDateTime } from '../../shared/format.js'
import { errorMessage } from '../../shared/i18n.js'

// Notifications (notify: the settings and what was sent; notify_settings and notify_test change and try them). Opt-in: nothing is
// sent until an address or a webhook is set. The webhook URL may hold a secret, so it is never shown again: leave the field empty to
// keep the stored one, type a new one to replace it, or remove it.
const MAX_EMAILS = 5
const EMAIL = /^[A-Za-z0-9][A-Za-z0-9._%+-]{0,63}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/
const { t, te } = useI18n()
const client = useClient()
const notify = useResource(client, 'notify', { staleAfter: 10 * 60 * 1000 })
const saving = useMutation(client)
const testing = useMutation(client)
useLoad(() => notify.load())

const report = computed(() => commandOutput(notify.data.value) || {})
const settings = computed(() => report.value.settings || {})
const known = computed(() => Object.keys(settings.value.available_events || {}))
const form = reactive({ emails: '', webhook: '', removeWebhook: false, events: [] })
const dirty = ref(false)
const saved = ref(false)
const testResult = ref(null)
watch(settings, value => {
  if (!value || dirty.value || !Array.isArray(value.emails)) return
  form.emails = value.emails.join('\n')
  form.events = Array.isArray(value.events) ? [...value.events] : []
}, { immediate: true })
const touch = () => {
  dirty.value = true
  saved.value = false
}

const emailList = computed(() => [...new Set(form.emails.split(/[\s,;]+/).map(e => e.trim().toLowerCase()).filter(Boolean))])
const emailsInvalid = computed(() => emailList.value.length > MAX_EMAILS || emailList.value.some(e => e.length > 254 || !EMAIL.test(e)))
const webhookText = computed(() => form.webhook.trim())
const webhookInvalid = computed(() => {
  if (!webhookText.value) return false
  if (webhookText.value.length > 512 || !/^https:\/\/[^\s'"<>\\]+$/.test(webhookText.value)) return true
  try {
    const url = new URL(webhookText.value)
    return url.username !== '' || url.password !== ''
  } catch {
    return true
  }
})
const formInvalid = computed(() => emailsInvalid.value || webhookInvalid.value || form.events.length === 0)
const willBeOn = computed(() => emailList.value.length > 0 || (webhookText.value !== '' || (settings.value.webhook?.set === true && !form.removeWebhook)))

async function save() {
  if (formInvalid.value) return
  const body = { emails: emailList.value, events: form.events }
  if (webhookText.value) body.webhook = webhookText.value
  else if (form.removeWebhook) body.webhook = ''
  const reply = await saving.run(WHM_SETTINGS.notifySettings, body)
  if (reply) {
    notify.data.value = reply
    form.webhook = ''
    form.removeWebhook = false
    dirty.value = false
    saved.value = true
    testResult.value = null
  }
}
async function sendTest() {
  testResult.value = null
  const reply = await testing.run(WHM_SETTINGS.notifyTest, {})
  if (reply) testResult.value = commandOutput(reply)
  notify.load()
}
const eventLabel = name => (te(`whm.notify.events.${name}`) ? t(`whm.notify.events.${name}`) : name)
const channelLabel = name => (te(`whm.notify.channels.${name}`) ? t(`whm.notify.channels.${name}`) : name)
const recent = computed(() => (Array.isArray(report.value.recent) ? report.value.recent : []))
const lastError = computed(() => report.value.last_error || null)
</script>

<template>
  <div>
    <PageHeader :title="t('whm.notify.title')" :description="t('whm.notify.description')" />
    <StateView :resource="notify" :refresh="() => notify.load()">
      <section class="olsc-card olsc-gap-below" :aria-label="t('whm.notify.statusTitle')">
        <h3 class="olsc-h3">{{ t('whm.notify.statusTitle') }}</h3>
        <dl class="olsc-facts">
          <dt>{{ t('whm.notify.state') }}</dt>
          <dd>
            <StatusBadge v-if="settings.enabled" tone="ok" :label="t('whm.notify.on')" />
            <StatusBadge v-else tone="neutral" :label="t('whm.notify.off')" />
          </dd>
          <dt>{{ t('whm.notify.sentToday') }}</dt>
          <dd>{{ t('whm.notify.sentOf', { n: report.sent_last_24h ?? 0, max: report.limits?.per_day ?? 20 }) }}</dd>
          <dt>{{ t('whm.notify.lastSent') }}</dt>
          <dd>{{ formatDateTime(report.last_sent) ?? t('whm.notify.neverSent') }}</dd>
          <dt>{{ t('whm.notify.lastRun') }}</dt>
          <dd>{{ formatDateTime(report.last_run) ?? t('state.notObserved') }}</dd>
        </dl>
        <el-alert v-if="lastError" type="warning" show-icon :closable="false" :title="t('whm.notify.lastError', { time: formatDateTime(lastError.time) ?? t('state.unknown') })"
                  :description="lastError.message" />
        <p class="olsc-muted">{{ t('whm.notify.limitsText', { hours: report.limits?.dedupe_hours ?? 6, max: report.limits?.per_day ?? 20 }) }}</p>
      </section>

      <section class="olsc-card olsc-gap-below" :aria-label="t('whm.notify.formTitle')">
        <h3 class="olsc-h3">{{ t('whm.notify.formTitle') }}</h3>
        <form @submit.prevent="save">
          <div class="olsc-field">
            <label for="olsc-notify-emails">{{ t('whm.notify.emails') }}</label>
            <el-input id="olsc-notify-emails" v-model="form.emails" type="textarea" :rows="3" autocomplete="off" spellcheck="false"
                      :aria-invalid="emailsInvalid ? 'true' : 'false'" @input="touch" />
            <p class="olsc-hint" :class="{ 'olsc-error': emailsInvalid }">{{ t('whm.notify.emailsHelp', { max: MAX_EMAILS }) }}</p>
          </div>
          <div class="olsc-field">
            <label for="olsc-notify-webhook">{{ t('whm.notify.webhook') }}</label>
            <el-input id="olsc-notify-webhook" v-model="form.webhook" autocomplete="off" spellcheck="false" :disabled="form.removeWebhook"
                      :placeholder="settings.webhook?.set ? t('whm.notify.webhookSet', { host: settings.webhook.host ?? '' }) : t('whm.notify.webhookPlaceholder')"
                      :aria-invalid="webhookInvalid ? 'true' : 'false'" @input="touch" />
            <p class="olsc-hint" :class="{ 'olsc-error': webhookInvalid }">{{ t('whm.notify.webhookHelp') }}</p>
            <el-checkbox v-if="settings.webhook?.set" v-model="form.removeWebhook" @change="touch">{{ t('whm.notify.webhookRemove') }}</el-checkbox>
          </div>
          <fieldset class="olsc-field">
            <legend>{{ t('whm.notify.eventsTitle') }}</legend>
            <el-checkbox-group v-model="form.events" :aria-label="t('whm.notify.eventsTitle')" @change="touch">
              <el-checkbox v-for="name in known" :key="name" :value="name" :label="eventLabel(name)" class="olsc-block" />
            </el-checkbox-group>
            <p v-if="form.events.length === 0" class="olsc-hint olsc-error">{{ t('whm.notify.eventsNone') }}</p>
          </fieldset>
          <p v-if="!willBeOn" class="olsc-hint">{{ t('whm.notify.willBeOff') }}</p>
          <div class="olsc-toolbar">
            <el-button native-type="submit" type="primary" :loading="saving.busy.value" :disabled="formInvalid || !dirty">{{ t('whm.notify.save') }}</el-button>
            <el-button :loading="testing.busy.value" :disabled="!settings.enabled || dirty" @click="sendTest">{{ t('whm.notify.sendTest') }}</el-button>
          </div>
        </form>
        <el-alert v-if="saving.error.value" type="error" show-icon :closable="true" :title="t('whm.notify.saveFailed')"
                  :description="errorMessage(saving.error.value)" @close="saving.error.value = null" />
        <p v-if="saved" class="olsc-hint" role="status">{{ t('whm.notify.saved') }}</p>
        <el-alert v-if="testing.error.value" type="error" show-icon :closable="true" :title="t('whm.notify.testFailed')"
                  :description="errorMessage(testing.error.value)" @close="testing.error.value = null" />
        <div v-if="testResult" role="status" class="olsc-gap-above">
          <p><strong>{{ testResult.result === 'sent' ? t('whm.notify.testSent') : t('whm.notify.testNotSent') }}</strong></p>
          <ul class="olsc-list">
            <li v-for="c in testResult.channels || []" :key="c.channel">
              <StatusBadge :tone="c.ok ? 'ok' : 'bad'" :label="channelLabel(c.channel)" />
              <span class="olsc-muted"> {{ c.ok ? t('whm.notify.delivered') : c.error }}</span>
            </li>
          </ul>
        </div>
      </section>

      <section class="olsc-card" :aria-label="t('whm.notify.recentTitle')">
        <h3 class="olsc-h3">{{ t('whm.notify.recentTitle') }}</h3>
        <p v-if="!recent.length" class="olsc-muted">{{ t('whm.notify.recentNone') }}</p>
        <el-table v-else :data="recent" size="small" stripe :aria-label="t('whm.notify.recentTitle')">
          <el-table-column :label="t('whm.activity.when')" min-width="180">
            <template #default="{ row }">{{ formatDateTime(row.time) ?? t('state.unknown') }}</template>
          </el-table-column>
          <el-table-column :label="t('whm.notify.eventColumn')" min-width="260">
            <template #default="{ row }">{{ row.title }}</template>
          </el-table-column>
          <el-table-column :label="t('whm.activity.result')" width="130">
            <template #default="{ row }">
              <StatusBadge :tone="row.ok ? 'ok' : 'bad'" :label="row.ok ? t('whm.notify.delivered') : t('whm.notify.notDelivered')" />
            </template>
          </el-table-column>
        </el-table>
      </section>
    </StateView>
  </div>
</template>
