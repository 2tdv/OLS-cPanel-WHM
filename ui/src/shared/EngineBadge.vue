<script setup>
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import StatusBadge from './StatusBadge.vue'
import { serverEngine } from './engine.js'

// Either the server's serving engine (`status`: the status operation) or one domain's engine
// (`engine`: "ols" | "hybrid" | "apache" | "unknown"). Anything unrecognised is shown as unknown.
const props = defineProps({
  status: { type: Object, default: null },
  engine: { type: String, default: null },
})
const { t } = useI18n()
const TONE = { ols: 'ok', hybrid: 'info', apache: 'warn', none: 'bad', unknown: 'neutral' }
const key = computed(() => {
  const value = props.engine !== null ? props.engine : serverEngine(props.status)
  return value in TONE ? value : 'unknown'
})
</script>

<template>
  <StatusBadge :tone="TONE[key]" :label="t(`engine.${key}`)" />
</template>
