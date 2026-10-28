<script setup>
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import PageHeader from '../../shared/PageHeader.vue'
import StateView from '../../shared/StateView.vue'
import StatusBadge from '../../shared/StatusBadge.vue'
import { CPANEL_ACTIONS, useClient, useMutation, useResource } from '../../shared/api.js'
import { formatBytes, formatDateTime, formatNumber } from '../../shared/format.js'
import { errorMessage } from '../../shared/i18n.js'
import { useLoad } from '../../shared/polling.js'

// The account's own page cache (cache: tenant.cache_stats). Clearing is synchronous (POST cache_purge with
// the site, or with nothing for every site); the server checks that the site is this account's and allows one
// clear every few seconds. No account or path is ever sent.
const { t } = useI18n()
const client = useClient()
const cache = useResource(client, 'cache', { staleAfter: 10 * 60 * 1000 })
const mutation = useMutation(client)
const removed = ref(null)
useLoad(() => cache.load())

const stores = computed(() => (Array.isArray(cache.data.value?.stores) ? cache.data.value.stores : []))
const totals = computed(() => cache.data.value?.totals || {})
const alsoServes = row => (Array.isArray(row.domains) ? row.domains.filter(d => d !== row.vhost) : [])
const num = value => formatNumber(value) ?? t('state.unknown')
const size = value => formatBytes(value) ?? t('state.unknown')

async function purge(domain) {
  removed.value = null
  const reply = await mutation.run(CPANEL_ACTIONS.cachePurge, domain ? { domain } : {})
  if (reply) {
    removed.value = Number.isInteger(reply.totals?.entries) ? reply.totals.entries : null
    await cache.load()
  }
}
</script>

<template>
  <div>
    <PageHeader :title="t('cpanel.cache.title')" :description="t('cpanel.cache.description')">
      <template #actions>
        <el-popconfirm :title="t('cpanel.cache.confirmAll')" :confirm-button-text="t('cpanel.cache.confirmYes')"
                       :cancel-button-text="t('cpanel.cache.confirmNo')" @confirm="purge(null)">
          <template #reference>
            <el-button type="primary" :loading="mutation.busy.value" :disabled="!stores.length">{{ t('cpanel.cache.purgeAll') }}</el-button>
          </template>
        </el-popconfirm>
      </template>
    </PageHeader>

    <el-alert v-if="mutation.error.value" type="error" show-icon :closable="true" class="olsc-gap-below"
              :title="t('cpanel.cache.failed')" :description="errorMessage(mutation.error.value)"
              @close="mutation.error.value = null" />
    <el-alert v-if="removed !== null" type="success" show-icon :closable="true" class="olsc-gap-below"
              :title="t('cpanel.cache.done', { n: formatNumber(removed) ?? t('state.unknown') })" @close="removed = null" />

    <StateView :resource="cache" :empty="cache.data.value !== null && !stores.length" :empty-text="t('cpanel.cache.none')">
      <p class="olsc-muted" role="status">{{ t('cpanel.cache.total', { pages: num(totals.entries), size: size(totals.bytes) }) }}</p>
      <div role="region" :aria-label="t('cpanel.cache.title')" class="olsc-table-wrap">
        <el-table :data="stores" stripe size="small" :aria-label="t('cpanel.cache.title')">
          <el-table-column :label="t('cpanel.cache.site')" min-width="260">
            <template #default="{ row }">
              <span class="olsc-mono">{{ row.vhost || row.store }}</span>
              <div v-if="alsoServes(row).length" class="olsc-muted olsc-small olsc-wrap">
                {{ t('cpanel.cache.alsoServes', { names: alsoServes(row).join(', ') }) }}
              </div>
            </template>
          </el-table-column>
          <el-table-column :label="t('fields.state')" width="130">
            <template #default="{ row }">
              <StatusBadge v-if="row.enabled === true" tone="ok" :label="t('cpanel.cache.serving')" />
              <StatusBadge v-else-if="row.enabled === false" tone="neutral" :label="t('cpanel.cache.off')" />
              <span v-else class="olsc-unknown">{{ t('state.unknown') }}</span>
            </template>
          </el-table-column>
          <el-table-column :label="t('cpanel.cache.pages')" width="130" align="right">
            <template #default="{ row }">{{ num(row.entries) }}</template>
          </el-table-column>
          <el-table-column :label="t('cpanel.cache.size')" width="120" align="right">
            <template #default="{ row }">{{ size(row.bytes) }}</template>
          </el-table-column>
          <el-table-column :label="t('cpanel.cache.lastPurge')" width="190">
            <template #default="{ row }">{{ formatDateTime(row.last_purge) ?? t('cpanel.cache.never') }}</template>
          </el-table-column>
          <el-table-column :label="t('fields.action')" width="160">
            <template #default="{ row }">
              <el-popconfirm v-if="row.vhost" :title="t('cpanel.cache.confirmOne', { name: row.vhost })"
                             :confirm-button-text="t('cpanel.cache.confirmYes')" :cancel-button-text="t('cpanel.cache.confirmNo')"
                             @confirm="purge(row.vhost)">
                <template #reference>
                  <el-button size="small" :disabled="mutation.busy.value">{{ t('cpanel.cache.purge') }}</el-button>
                </template>
              </el-popconfirm>
            </template>
          </el-table-column>
        </el-table>
      </div>
    </StateView>

    <section class="olsc-card olsc-section" :aria-label="t('cpanel.cache.wpTitle')">
      <h3 class="olsc-h3">{{ t('cpanel.cache.wpTitle') }}</h3>
      <p>{{ t('cpanel.cache.wpBody') }}</p>
      <p class="olsc-muted">{{ t('cpanel.cache.wpPurge') }}</p>
    </section>
  </div>
</template>
