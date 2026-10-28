<script setup>
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import FreshnessIndicator from './FreshnessIndicator.vue'
import { errorMessage } from './i18n.js'

// The states every view supports (plan 21.3): loading, empty, unauthorized, error, stale, degraded
// and pending. Unknown is never shown as healthy; a failed refresh keeps the last data, marked stale.
const props = defineProps({
  resource: { type: Object, required: true },
  empty: { type: Boolean, default: false },
  emptyText: { type: String, default: '' },
  degraded: { type: String, default: '' },
  pending: { type: String, default: '' },
  refresh: { type: Function, default: null },
  freshness: { type: Boolean, default: true },
})
const { t } = useI18n()
const error = computed(() => props.resource.error.value)
// Loaded at least once (a reply may legitimately be null, e.g. no plan yet).
const hasData = computed(() => props.resource.loadedAt.value !== null)
const state = computed(() => {
  if (error.value?.unauthorized) return 'unauthorized'
  if (!hasData.value) return error.value ? 'error' : 'loading'
  return props.empty ? 'empty' : 'ready'
})
function retry() {
  if (props.refresh) props.refresh()
  else props.resource.load()
}
function reload() {
  globalThis.location.reload()
}
</script>

<template>
  <div class="olsc-state" :aria-busy="props.resource.loading.value ? 'true' : 'false'">
    <div v-if="state === 'loading'" role="status">
      <span class="olsc-sr-only">{{ t('state.loading') }}</span>
      <el-skeleton :rows="4" animated />
    </div>

    <el-result v-else-if="state === 'unauthorized'" icon="warning"
               :title="error.code === 'SESSION' ? t('state.sessionTitle') : t('state.unauthorizedTitle')"
               :sub-title="error.code === 'SESSION' ? t('state.sessionBody') : errorMessage(error)">
      <template #extra><el-button type="primary" @click="reload">{{ t('state.reload') }}</el-button></template>
    </el-result>

    <el-result v-else-if="state === 'error'" icon="error" :title="t('state.error')" :sub-title="errorMessage(error)">
      <template #extra>
        <el-button type="primary" :loading="props.resource.loading.value" @click="retry">{{ t('state.retry') }}</el-button>
      </template>
    </el-result>

    <template v-else>
      <el-alert v-if="error" type="warning" :closable="false" show-icon class="olsc-gap-below"
                :title="t('state.refreshFailed')" :description="errorMessage(error)" />
      <el-alert v-if="props.degraded" type="warning" :closable="false" show-icon class="olsc-gap-below"
                :title="t('state.degraded')" :description="props.degraded" />
      <el-alert v-if="props.pending" type="info" :closable="false" show-icon class="olsc-gap-below"
                :title="t('state.pending')" :description="props.pending" />
      <el-empty v-if="state === 'empty'" :description="props.emptyText || t('state.empty')" />
      <slot v-else />
      <FreshnessIndicator v-if="props.freshness" :resource="props.resource" :refresh="props.refresh" />
    </template>
  </div>
</template>
