<script setup>
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import HistoryPanel from '../../shared/HistoryPanel.vue'
import PageHeader from '../../shared/PageHeader.vue'
import StateView from '../../shared/StateView.vue'
import { useClient, useResource } from '../../shared/api.js'
import { usePolling } from '../../shared/polling.js'

// The account's own traffic history (history: tenant.metrics): requests, cache hits, static files and PHP use of one
// of its sites for the last hour, day or week. The broker only ever answers for the account's own sites.
const { t } = useI18n()
const client = useClient()
const resolution = ref('hour')
const vhost = ref('')
const history = useResource(client, 'history', {
  params: () => ({ resolution: resolution.value, vhost: vhost.value }),
  staleAfter: 5 * 60 * 1000,
})
const poll = usePolling(() => history.load(), { interval: 60000, maxInterval: 10 * 60 * 1000 })
watch([resolution, vhost], () => poll.refresh())

const data = computed(() => history.data.value)
const noSites = computed(() => data.value !== null && !(Array.isArray(data.value.vhosts) && data.value.vhosts.length))
const chosen = computed(() => vhost.value || data.value?.vhost || '')
</script>

<template>
  <div>
    <PageHeader :title="t('cpanel.history.title')" :description="t('cpanel.history.description')" />
    <StateView :resource="history" :empty="noSites" :empty-text="t('cpanel.history.none')" :refresh="poll.refresh">
      <HistoryPanel v-if="data" :data="data" :resolution="resolution" :vhost="chosen"
                    @update:resolution="value => (resolution = value)" @update:vhost="value => (vhost = value)" />
    </StateView>
  </div>
</template>
