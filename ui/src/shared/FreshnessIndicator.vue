<script setup>
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import StatusBadge from './StatusBadge.vue'
import { freshness } from './api.js'
import { age, formatDateTime } from './format.js'
import { useNow } from './polling.js'

// "Observed 12 seconds ago · source" with a stale marker (UIX-01: every value carries its time and source).
const props = defineProps({
  resource: { type: Object, required: true },
  refreshable: { type: Boolean, default: true },
  // A polled view passes its poller's refresh so a manual refresh also resets the schedule.
  refresh: { type: Function, default: null },
})
const { t } = useI18n()
const now = useNow()
const observed = computed(() => props.resource.observedAt.value)
const ago = computed(() => age(observed.value, now.value))
const state = computed(() => freshness(props.resource, now.value))
function refresh() {
  if (props.refresh) props.refresh()
  else props.resource.load()
}
</script>

<template>
  <p class="olsc-freshness">
    <StatusBadge v-if="state === 'stale'" tone="warn" :label="t('state.stale')" />
    <span v-if="observed">
      <time :datetime="new Date(observed).toISOString()" :title="formatDateTime(observed)">
        {{ ago ? t(`time.ago.${ago.unit}`, { n: ago.n }) : formatDateTime(observed) }}
      </time>
    </span>
    <span v-else>{{ t('state.notObserved') }}</span>
    <span v-if="props.resource.source.value" class="olsc-muted">· {{ t('state.source', { source: props.resource.source.value }) }}</span>
    <el-button v-if="props.refreshable" link type="primary" :loading="props.resource.loading.value" @click="refresh">
      {{ t('state.refresh') }}
    </el-button>
  </p>
</template>
