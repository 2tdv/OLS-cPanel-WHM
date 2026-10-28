<script setup>
import { useI18n } from 'vue-i18n'

// One labelled value. A missing value reads "Unknown", never 0 (UIX-01, INV-11).
const props = defineProps({
  label: { type: String, required: true },
  value: { type: [String, Number], default: null },
  hint: { type: String, default: '' },
  mono: { type: Boolean, default: false },
})
const { t } = useI18n()
</script>

<template>
  <div class="olsc-card" role="group" :aria-label="props.label">
    <h3>{{ props.label }}</h3>
    <div v-if="props.value === null || props.value === ''" class="olsc-metric olsc-unknown">{{ t('state.unknown') }}</div>
    <div v-else class="olsc-metric" :class="{ 'olsc-mono': props.mono }"><slot>{{ props.value }}</slot></div>
    <div v-if="props.hint" class="olsc-muted olsc-small">{{ props.hint }}</div>
  </div>
</template>
