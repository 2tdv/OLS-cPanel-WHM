<script setup>
import { computed, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import StatusBadge from './StatusBadge.vue'
import StateView from './StateView.vue'
import { useClient, useResource } from './api.js'
import { formatDateTime } from './format.js'
import { usePolling } from './polling.js'
import { actionLabel, jobStateLabel, jobTone } from './jobs.js'

// Follows one product job (job.status) until it ends: state, progress lines, exit code and the
// command's JSON output. Long work is never tied to this page: the job runs in the broker and can be
// followed again from the Jobs view after closing the page (UIX-03).
const props = defineProps({ jobId: { type: String, required: true } })
const emit = defineEmits(['finished'])
const { t } = useI18n()
const client = useClient()
const job = useResource(client, 'job', { params: () => ({ job: props.jobId }) })
const poller = usePolling(async () => {
  const ok = await job.load()
  if (ok && job.data.value?.state && job.data.value.state !== 'running') poller.stop()
  return ok
}, { interval: 2000, maxInterval: 15000 })

const data = computed(() => job.data.value)
const lines = computed(() => (Array.isArray(data.value?.log) ? data.value.log : []).map(line =>
  typeof line === 'string' ? { message: line, time: null } : { message: String(line?.message ?? ''), time: line?.time ?? null }))
const reason = computed(() => {
  const output = data.value?.output && typeof data.value.output === 'object' ? data.value.output : {}
  return [data.value?.reason, output.reason, output.message, output.error?.message].find(v => typeof v === 'string' && v) || null
})
const output = computed(() => (data.value?.output === undefined || data.value?.output === null)
  ? null : JSON.stringify(data.value.output, null, 2))
watch(() => data.value?.state, (state, previous) => {
  if (state && state !== 'running' && previous !== state) emit('finished', data.value)
})
</script>

<template>
  <section class="olsc-job" :aria-label="t('jobs.timelineLabel', { id: props.jobId })">
    <StateView :resource="job" :refresh="poller.refresh">
      <header class="olsc-job-head">
        <strong>{{ actionLabel(data.action) }}</strong>
        <span class="olsc-mono olsc-muted">{{ props.jobId }}</span>
        <span aria-live="polite">
          <StatusBadge :tone="jobTone(data.state)" :label="jobStateLabel(data.state)" />
        </span>
      </header>
      <ol class="olsc-timeline">
        <li class="olsc-timeline-item">
          <span class="olsc-timeline-dot" aria-hidden="true" />
          <span>{{ t('jobs.started') }}</span>
          <time class="olsc-muted">{{ formatDateTime(data.started) || t('state.unknown') }}</time>
        </li>
        <li v-for="(line, i) in lines" :key="i" class="olsc-timeline-item">
          <span class="olsc-timeline-dot" aria-hidden="true" />
          <span class="olsc-mono">{{ line.message }}</span>
          <time v-if="line.time" class="olsc-muted">{{ formatDateTime(line.time) }}</time>
        </li>
        <li v-if="data.state === 'running'" class="olsc-timeline-item olsc-timeline-live">
          <span class="olsc-timeline-dot" aria-hidden="true" />
          <span>{{ t('jobs.running') }}</span>
        </li>
        <li v-else class="olsc-timeline-item" :class="`olsc-tone-text-${jobTone(data.state)}`">
          <span class="olsc-timeline-dot" aria-hidden="true" />
          <span>{{ data.state === 'done' ? t('jobs.finishedOk') : t('jobs.finishedFailed') }}</span>
          <span class="olsc-muted">{{ t('jobs.exitCode', { code: data.exit_code ?? t('state.unknown') }) }}</span>
          <time class="olsc-muted">{{ formatDateTime(data.finished) || '' }}</time>
        </li>
      </ol>
      <el-alert v-if="reason && data.state !== 'running'" :type="data.state === 'done' ? 'info' : 'error'"
                :closable="false" :title="reason" class="olsc-gap-below" />
      <details v-if="output" class="olsc-details">
        <summary>{{ t('jobs.output') }}</summary>
        <pre class="olsc-pre">{{ output }}</pre>
      </details>
    </StateView>
  </section>
</template>
