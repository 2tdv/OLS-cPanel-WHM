<script setup>
import HelpTip from './HelpTip.vue'

// View heading: one h2 per view, a one-line purpose, optional help topic and actions.
const props = defineProps({
  title: { type: String, required: true },
  description: { type: String, default: '' },
  help: { type: String, default: '' },
})
</script>

<template>
  <div class="olsc-page-header">
    <div class="olsc-page-title">
      <h2 class="olsc-h2">{{ props.title }}</h2>
      <p v-if="props.description" class="olsc-muted">
        {{ props.description }}
        <HelpTip v-if="props.help" :topic="props.help" />
      </p>
    </div>
    <div class="olsc-page-actions"><slot name="actions" /></div>
  </div>
</template>
