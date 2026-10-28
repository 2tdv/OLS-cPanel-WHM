<script setup>
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { confirmationMatches } from './confirm.js'

// Typed confirmation for dangerous actions (UIX-03): the slot shows scope, expected change, blockers
// and rollback; the action stays disabled until the operator types the exact text (a plan id, a
// generation id). The dialog traps focus, Escape cancels, Enter confirms only when the text matches.
const props = defineProps({
  title: { type: String, required: true },
  expected: { type: String, required: true },
  confirmLabel: { type: String, required: true },
  busy: { type: Boolean, default: false },
  blocked: { type: Boolean, default: false },
})
const open = defineModel({ type: Boolean, default: false })
const emit = defineEmits(['confirm'])
const { t } = useI18n()
const typed = ref('')
const inputId = `olsc-confirm-${Math.random().toString(36).slice(2, 10)}`
const matches = computed(() => confirmationMatches(typed.value, props.expected))
watch(open, value => { if (value) typed.value = '' })
function confirm() {
  if (matches.value && !props.busy && !props.blocked) emit('confirm')
}
</script>

<template>
  <el-dialog v-model="open" :title="props.title" width="min(640px, 94vw)" :close-on-click-modal="false">
    <div class="olsc-confirm">
      <slot />
      <label :for="inputId" class="olsc-confirm-label">
        {{ t('confirm.typeToConfirm') }} <code class="olsc-mono">{{ props.expected }}</code>
      </label>
      <el-input :id="inputId" v-model="typed" autocomplete="off" spellcheck="false" class="olsc-mono"
                :aria-invalid="typed !== '' && !matches ? 'true' : 'false'" @keyup.enter="confirm" />
      <p v-if="typed !== '' && !matches" class="olsc-hint" role="status">{{ t('confirm.mismatch') }}</p>
    </div>
    <template #footer>
      <el-button @click="open = false">{{ t('confirm.cancel') }}</el-button>
      <el-button type="danger" :disabled="!matches || props.blocked" :loading="props.busy" @click="confirm">
        {{ props.confirmLabel }}
      </el-button>
    </template>
  </el-dialog>
</template>
