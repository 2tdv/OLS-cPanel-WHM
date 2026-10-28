<script setup>
// A status label that never relies on colour alone (WCAG 1.4.1): a glyph and the text, with AA
// contrast in light and dark themes (theme.css, --olsc-tone-*).
const props = defineProps({
  tone: { type: String, default: 'neutral', validator: v => ['ok', 'warn', 'bad', 'info', 'neutral', 'pending'].includes(v) },
  label: { type: String, required: true },
  title: { type: String, default: undefined },
})
const GLYPH = { ok: '✓', warn: '!', bad: '✕', info: 'i', neutral: '•', pending: '…' }
</script>

<template>
  <span class="olsc-badge" :class="`olsc-tone-${props.tone}`" :title="props.title">
    <span class="olsc-badge-glyph" aria-hidden="true">{{ GLYPH[props.tone] }}</span>
    <span>{{ props.label }}</span>
  </span>
</template>
