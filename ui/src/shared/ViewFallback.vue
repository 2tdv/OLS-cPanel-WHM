<script setup>
import { useI18n } from 'vue-i18n'

// Shown while a lazily loaded view arrives, or when its code could not be loaded (for example after
// an upgrade replaced the hashed assets under an open page).
const props = defineProps({ failed: { type: Boolean, default: false } })
const { t } = useI18n()
const reload = () => globalThis.location.reload()
</script>

<template>
  <el-result v-if="props.failed" icon="error" :title="t('state.viewFailed')" :sub-title="t('state.viewFailedBody')">
    <template #extra><el-button type="primary" @click="reload">{{ t('state.reload') }}</el-button></template>
  </el-result>
  <div v-else role="status">
    <span class="olsc-sr-only">{{ t('state.loading') }}</span>
    <el-skeleton :rows="5" animated />
  </div>
</template>
