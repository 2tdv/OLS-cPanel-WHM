<script setup>
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import PageHeader from '../../shared/PageHeader.vue'
import StateView from '../../shared/StateView.vue'
import StatusBadge from '../../shared/StatusBadge.vue'
import { CPANEL_ACTIONS, useClient, useMutation, useResource } from '../../shared/api.js'
import { formatDateTime } from '../../shared/format.js'
import { errorMessage } from '../../shared/i18n.js'
import { useLoad } from '../../shared/polling.js'

// A message to the hosting provider (requests: tenant.requests, POST request): a subject from a fixed list and up to
// 1000 characters. The server knows the account; one message can be sent per minute and ten can be open at once.
const { t } = useI18n()
const client = useClient()
const list = useResource(client, 'requests')
const mutation = useMutation(client)
const subject = ref('other')
const text = ref('')
const sent = ref(false)
useLoad(() => list.load())
const subjects = computed(() => (Array.isArray(list.data.value?.subjects) ? list.data.value.subjects : []))
const requests = computed(() => (Array.isArray(list.data.value?.requests) ? list.data.value.requests : []))
const max = computed(() => (Number.isInteger(list.data.value?.max_text) ? list.data.value.max_text : 1000))
const known = value => (subjects.value.includes(value) ? t(`cpanel.requests.subjects.${value}`) : t('state.unknown'))

async function send() {
  sent.value = false
  if (!text.value.trim()) return
  const reply = await mutation.run(CPANEL_ACTIONS.request, { subject: subject.value, text: text.value })
  if (reply) {
    text.value = ''
    sent.value = true
    await list.load()
  }
}
</script>

<template>
  <div>
    <PageHeader :title="t('cpanel.requests.title')" :description="t('cpanel.requests.description')" />
    <el-alert v-if="mutation.error.value" type="error" show-icon :closable="true" class="olsc-gap-below"
              :title="t('cpanel.requests.failed')" :description="errorMessage(mutation.error.value)" @close="mutation.error.value = null" />
    <el-alert v-if="sent" type="success" show-icon :closable="true" class="olsc-gap-below" :title="t('cpanel.requests.sent')" @close="sent = false" />
    <section class="olsc-card olsc-section" :aria-label="t('cpanel.requests.formTitle')">
      <h3 class="olsc-h3">{{ t('cpanel.requests.formTitle') }}</h3>
      <el-select v-model="subject" :aria-label="t('cpanel.requests.subject')" style="width: 260px" class="olsc-gap-below">
        <el-option v-for="s in (subjects.length ? subjects : ['other'])" :key="s" :label="t(`cpanel.requests.subjects.${s}`)" :value="s" />
      </el-select>
      <el-input v-model="text" type="textarea" :rows="5" :maxlength="max" show-word-limit :aria-label="t('cpanel.requests.text')"
                :placeholder="t('cpanel.requests.placeholder')" />
      <el-button type="primary" class="olsc-gap-above" :loading="mutation.busy.value" :disabled="!text.trim()" @click="send">{{ t('cpanel.requests.send') }}</el-button>
    </section>
    <StateView :resource="list" :empty="list.data.value !== null && !requests.length" :empty-text="t('cpanel.requests.none')">
      <h3 class="olsc-h3">{{ t('cpanel.requests.yours') }}</h3>
      <ul class="olsc-plain-list">
        <li v-for="r in requests" :key="r.id" class="olsc-gap-below">
          <StatusBadge :tone="r.status === 'done' ? 'ok' : 'info'" :label="r.status === 'done' ? t('cpanel.requests.done') : t('cpanel.requests.open')" />
          <strong> {{ known(r.subject) }}</strong>
          <span class="olsc-muted olsc-small"> {{ formatDateTime(r.created_at) ?? t('state.unknown') }}</span>
          <div class="olsc-wrap" style="white-space: pre-wrap">{{ r.text }}</div>
        </li>
      </ul>
    </StateView>
  </div>
</template>
