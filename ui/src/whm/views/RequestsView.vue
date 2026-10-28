<script setup>
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import PageHeader from '../../shared/PageHeader.vue'
import StateView from '../../shared/StateView.vue'
import StatusBadge from '../../shared/StatusBadge.vue'
import { WHM_SETTINGS, useClient, useMutation, useResource } from '../../shared/api.js'
import { formatDateTime } from '../../shared/format.js'
import { errorMessage } from '../../shared/i18n.js'
import { useLoad } from '../../shared/polling.js'

// Requests from accounts (requests: admin.requests): newest first with the account, subject, text and status; the
// administrator marks a request done or open again (POST request_status, a settings change, no job).
const { t } = useI18n()
const client = useClient()
const list = useResource(client, 'requests', { staleAfter: 5 * 60 * 1000 })
const mutation = useMutation(client)
useLoad(() => list.load())
const requests = computed(() => (Array.isArray(list.data.value?.requests) ? list.data.value.requests : []))
const SUBJECTS = ['cache', 'php', 'htaccess', 'ssl', 'performance', 'logs', 'domains', 'other']
const subject = value => (SUBJECTS.includes(value) ? t(`whm.requests.subjects.${value}`) : t('state.unknown'))

async function mark(r, status) {
  const reply = await mutation.run(WHM_SETTINGS.requestStatus, { id: r.id, status })
  if (reply) await list.load()
}
</script>

<template>
  <div>
    <PageHeader :title="t('whm.requests.title')" :description="t('whm.requests.description')">
      <template #actions>
        <el-button :loading="list.loading.value" @click="list.load()">{{ t('whm.requests.refresh') }}</el-button>
      </template>
    </PageHeader>
    <el-alert v-if="mutation.error.value" type="error" show-icon :closable="true" class="olsc-gap-below"
              :title="t('whm.requests.failed')" :description="errorMessage(mutation.error.value)" @close="mutation.error.value = null" />
    <StateView :resource="list" :empty="list.data.value !== null && !requests.length" :empty-text="t('whm.requests.none')">
      <p class="olsc-muted" role="status">{{ t('whm.requests.summary', { open: list.data.value?.open ?? 0, total: list.data.value?.total ?? 0 }) }}</p>
      <ul class="olsc-plain-list">
        <li v-for="r in requests" :key="r.id" class="olsc-card olsc-gap-below">
          <StatusBadge :tone="r.status === 'done' ? 'ok' : 'info'" :label="r.status === 'done' ? t('whm.requests.done') : t('whm.requests.open')" />
          <strong class="olsc-mono"> {{ r.user }}</strong> - {{ subject(r.subject) }}
          <span class="olsc-muted olsc-small"> {{ formatDateTime(r.created_at) ?? t('state.unknown') }}</span>
          <div class="olsc-wrap" style="white-space: pre-wrap">{{ r.text }}</div>
          <el-button v-if="r.status !== 'done'" size="small" :disabled="mutation.busy.value" @click="mark(r, 'done')">{{ t('whm.requests.markDone') }}</el-button>
          <el-button v-else size="small" :disabled="mutation.busy.value" @click="mark(r, 'open')">{{ t('whm.requests.reopen') }}</el-button>
        </li>
      </ul>
    </StateView>
  </div>
</template>
