<script setup>
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import StatusBadge from '../shared/StatusBadge.vue'
import { href } from '../shared/router.js'
import { useLoad } from '../shared/polling.js'
import { commandOutput, useClient, useResource } from '../shared/api.js'
import { healthStatements } from './health.js'

// Product-state summary in plain words (Diagnostics and, compact, Overview).
defineProps({ compact: { type: Boolean, default: false } })
const { t } = useI18n()
const client = useClient()
const status = useResource(client, 'status', { staleAfter: 2 * 60 * 1000 })
const php = useResource(client, 'php', { staleAfter: 5 * 60 * 1000 })
const doctor = useResource(client, 'doctor', { staleAfter: 10 * 60 * 1000 })
useLoad(() => Promise.all([status.load(), php.load(), doctor.load()]))
const rows = computed(() => healthStatements(status.data.value, commandOutput(php.data.value), commandOutput(doctor.data.value)))
</script>

<template>
  <section class="olsc-card olsc-gap-below" :aria-label="t('whm.health.title')">
    <h3 class="olsc-h3">{{ t('whm.health.title') }}</h3>
    <ul v-if="rows.length" class="olsc-list">
      <li v-for="row in rows" :key="row.key">
        <StatusBadge :tone="row.tone" :label="t(`whm.health.badge.${row.tone}`)" />
        {{ t(`whm.health.${row.key}`, row.params || {}) }}
        <a v-if="row.link && !compact" :href="href(row.link)">{{ t(`whm.health.link.${row.link}`) }}</a>
      </li>
    </ul>
    <p v-else class="olsc-muted">{{ t('whm.health.none') }}</p>
  </section>
</template>
