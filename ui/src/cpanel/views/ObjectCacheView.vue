<script setup>
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import PageHeader from '../../shared/PageHeader.vue'
import StateView from '../../shared/StateView.vue'
import StatusBadge from '../../shared/StatusBadge.vue'
import { useClient, useResource } from '../../shared/api.js'
import { formatBytes, formatDateTime, formatNumber } from '../../shared/format.js'
import { useLoad } from '../../shared/polling.js'

// The account's own object cache (objcache: tenant.objcache): the connection values to enter in applications, and
// the WordPress sites the product found with the state of their LiteSpeed Cache object cache. Nothing is sent and
// nothing has to be done for WordPress sites with LiteSpeed Cache: they are set up automatically.
const { t } = useI18n()
const client = useClient()
const objcache = useResource(client, 'objcache', { staleAfter: 10 * 60 * 1000 })
useLoad(() => objcache.load())

const copied = ref(false)
const copyFailed = ref(false)
const enabled = computed(() => objcache.data.value?.enabled === true)
const connection = computed(() => objcache.data.value?.connection || null)
const sites = computed(() => (Array.isArray(objcache.data.value?.wordpress) ? objcache.data.value.wordpress : []))
const usage = computed(() => objcache.data.value?.usage || null)
const running = computed(() => objcache.data.value?.state === 'active')
// Off: either the hosting provider decided so (the account or its package turned off, or the automatic mode switched off),
// or nothing was decided yet and the cache starts by itself once WordPress with LiteSpeed Cache is found.
const providerOff = computed(() => ['disabled', 'package_off'].includes(objcache.data.value?.origin) || objcache.data.value?.automatic === false)
const offText = computed(() => (providerOff.value ? t('cpanel.objcache.providerOff') : t('cpanel.objcache.off')))
const num = value => formatNumber(value) ?? t('state.unknown')
const size = value => formatBytes(value) ?? t('state.unknown')
const percent = value => (Number.isFinite(value) ? `${Math.round(value * 100)}%` : t('state.unknown'))
const TONES = { automatic: 'ok', owner: 'neutral', inactive: 'neutral', error: 'bad' }
const tone = row => TONES[row.state] || 'neutral'
const label = row => (['automatic', 'owner', 'inactive', 'error'].includes(row.state) ? t(`cpanel.objcache.site.${row.state}`) : t('state.unknown'))

async function copy(text) {
  copied.value = false
  copyFailed.value = false
  try {
    await globalThis.navigator.clipboard.writeText(text)
    copied.value = true
  } catch {
    copyFailed.value = true
  }
}
</script>

<template>
  <div>
    <PageHeader :title="t('cpanel.objcache.title')" :description="t('cpanel.objcache.description')" />

    <StateView :resource="objcache" :empty="objcache.data.value !== null && !enabled" :empty-text="offText">
      <el-alert v-if="objcache.data.value?.suspended" type="warning" show-icon :closable="false" class="olsc-gap-below"
                :title="t('cpanel.objcache.suspended')" />
      <el-alert v-else-if="!running" type="warning" show-icon :closable="false" class="olsc-gap-below"
                :title="t('cpanel.objcache.notRunning')" :description="t('cpanel.objcache.notRunningBody')" />
      <el-alert v-else type="success" show-icon :closable="false" class="olsc-gap-below" :title="t('cpanel.objcache.ready')" />

      <section v-if="connection" class="olsc-card olsc-section" :aria-label="t('cpanel.objcache.connectionTitle')">
        <h3 class="olsc-h3">{{ t('cpanel.objcache.connectionTitle') }}</h3>
        <dl class="olsc-facts">
          <dt>{{ t('cpanel.objcache.host') }}</dt>
          <dd>
            <span class="olsc-mono">{{ connection.host }}</span>
            <el-button size="small" class="olsc-copy" :aria-label="t('cpanel.objcache.copyHost')" @click="copy(connection.host)">
              {{ t('cpanel.objcache.copy') }}
            </el-button>
          </dd>
          <dt>{{ t('cpanel.objcache.port') }}</dt>
          <dd>
            <span class="olsc-mono">{{ connection.port }}</span>
            <el-button size="small" class="olsc-copy" :aria-label="t('cpanel.objcache.copyPort')" @click="copy(String(connection.port))">
              {{ t('cpanel.objcache.copy') }}
            </el-button>
          </dd>
          <dt>{{ t('cpanel.objcache.password') }}</dt>
          <dd>{{ t('cpanel.objcache.noPassword') }}</dd>
        </dl>
        <p v-if="copied" class="olsc-muted" role="status">{{ t('cpanel.objcache.copied') }}</p>
        <p v-if="copyFailed" class="olsc-muted" role="status">{{ t('cpanel.objcache.copyFailed') }}</p>
        <p class="olsc-muted">{{ t('cpanel.objcache.explain') }}</p>
      </section>

      <section class="olsc-card olsc-section" :aria-label="t('cpanel.objcache.sitesTitle')">
        <h3 class="olsc-h3">{{ t('cpanel.objcache.sitesTitle') }}</h3>
        <p v-if="!sites.length" class="olsc-muted">{{ t('cpanel.objcache.noSites') }}</p>
        <div v-else role="region" :aria-label="t('cpanel.objcache.sitesTitle')" class="olsc-table-wrap">
          <el-table :data="sites" stripe size="small" :aria-label="t('cpanel.objcache.sitesTitle')">
            <el-table-column :label="t('cpanel.objcache.folder')" min-width="260">
              <template #default="{ row }"><span class="olsc-mono">{{ row.path }}</span></template>
            </el-table-column>
            <el-table-column :label="t('fields.state')" min-width="260">
              <template #default="{ row }"><StatusBadge :tone="tone(row)" :label="label(row)" /></template>
            </el-table-column>
            <el-table-column :label="t('cpanel.objcache.checked')" width="190">
              <template #default="{ row }">{{ formatDateTime(row.checked_at) ?? t('state.unknown') }}</template>
            </el-table-column>
          </el-table>
        </div>
        <p v-if="sites.some(s => s.state === 'error')" class="olsc-muted">{{ t('cpanel.objcache.retry') }}</p>
      </section>

      <section v-if="usage" class="olsc-card olsc-section" :aria-label="t('cpanel.objcache.usageTitle')">
        <h3 class="olsc-h3">{{ t('cpanel.objcache.usageTitle') }}</h3>
        <dl class="olsc-facts">
          <dt>{{ t('cpanel.objcache.memory') }}</dt><dd>{{ size(usage.used_memory) }} / {{ size(usage.maxmemory) }}</dd>
          <dt>{{ t('cpanel.objcache.keys') }}</dt><dd>{{ num(usage.keys) }}</dd>
          <dt>{{ t('cpanel.objcache.hitRate') }}</dt><dd>{{ percent(usage.hit_rate) }}</dd>
        </dl>
      </section>
    </StateView>
  </div>
</template>
