<script setup>
import { ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { HELP_DOCS } from './findings.js'

// Help in context (UIX-07): every finding, setting and error can be expanded into a plain-language
// explanation, what OpenLiteSpeed does, what to do, and the document that covers it. A disclosure
// button (aria-expanded), so it works with keyboard and screen readers and never leaves the page.
const props = defineProps({ topic: { type: String, required: true } })
const { t, te } = useI18n()
const open = ref(false)
const id = `olsc-help-${Math.random().toString(36).slice(2, 10)}`
const key = topic => (te(`help.${topic}.title`) ? topic : 'unknown')
</script>

<template>
  <span class="olsc-help">
    <el-button link type="primary" size="small" :aria-expanded="open ? 'true' : 'false'" :aria-controls="id"
               @click="open = !open">
      {{ open ? t('help.hide') : t('help.show') }}
      <span class="olsc-sr-only">: {{ t(`help.${key(props.topic)}.title`) }}</span>
    </el-button>
    <div v-show="open" :id="id" class="olsc-help-body" role="note">
      <strong>{{ t(`help.${key(props.topic)}.title`) }}</strong>
      <p>{{ t(`help.${key(props.topic)}.body`) }}</p>
      <p v-if="te(`help.${key(props.topic)}.ols`)"><em>{{ t('help.olsDoes') }}</em> {{ t(`help.${key(props.topic)}.ols`) }}</p>
      <p v-if="te(`help.${key(props.topic)}.fix`)"><em>{{ t('help.whatToDo') }}</em> {{ t(`help.${key(props.topic)}.fix`) }}</p>
      <p class="olsc-muted">{{ t('help.reference') }} <code class="olsc-mono">{{ HELP_DOCS[props.topic] || HELP_DOCS.default }}</code></p>
    </div>
  </span>
</template>
