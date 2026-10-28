<script setup>
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import PageHeader from '../../shared/PageHeader.vue'
import StateView from '../../shared/StateView.vue'
import StatusBadge from '../../shared/StatusBadge.vue'
import { WHM_SETTINGS, commandOutput, useClient, useMutation, useResource } from '../../shared/api.js'
import { errorMessage } from '../../shared/i18n.js'
import { useLoad } from '../../shared/polling.js'

// The object cache of the server (objcache: admin.objcache, `ols-cpanel objcache status`): the automatic mode, which gives
// every account with WordPress and LiteSpeed Cache its own private cache, and the accounts with a cache or a decision, each
// with who decided it. The mode is switched with POST objcache_automatic (a settings change, no job); turning it off removes
// only the caches the automatic mode set up, so it asks first.
const { t } = useI18n()
const client = useClient()
const objcache = useResource(client, 'objcache', { staleAfter: 5 * 60 * 1000 })
const saving = useMutation(client)
useLoad(() => objcache.load())

const report = computed(() => commandOutput(objcache.data.value) || null)
const automatic = computed(() => report.value?.automatic !== false)
const accounts = computed(() => (Array.isArray(report.value?.accounts) ? report.value.accounts : []))
const ORIGINS = ['automatic', 'administrator', 'package', 'disabled', 'package_off']
const origin = row => t(`whm.objcache.origins.${ORIGINS.includes(row.origin) ? row.origin : 'none'}`)
const ORIGIN_TONES = { automatic: 'ok', administrator: 'info', package: 'info', disabled: 'neutral', package_off: 'neutral' }
const STATES = ['active', 'inactive', 'failed', 'activating']
const stateLabel = row => (STATES.includes(row.state) ? t(`whm.objcache.states.${row.state}`) : t('state.unknown'))
const stateTone = row => ({ active: 'ok', failed: 'bad' })[row.state] || 'neutral'
const memory = row => (Number.isInteger(row.memory_mb) ? `${row.memory_mb} MB` : '-')
const sites = row => (Array.isArray(row.wordpress) ? row.wordpress.length : 0)

async function setAutomatic(on) {
  const reply = await saving.run(WHM_SETTINGS.objcacheAutomatic, { automatic: on })
  if (reply) await objcache.load()
}
</script>

<template>
  <div>
    <PageHeader :title="t('whm.objcache.title')" :description="t('whm.objcache.description')" />
    <StateView :resource="objcache">
      <section class="olsc-card olsc-section" :aria-label="t('whm.objcache.autoTitle')">
        <h3 class="olsc-h3">
          {{ t('whm.objcache.autoTitle') }}
          <StatusBadge :tone="automatic ? 'ok' : 'neutral'" :label="automatic ? t('whm.objcache.autoOn') : t('whm.objcache.autoOff')" />
        </h3>
        <p>{{ t('whm.objcache.autoLead') }}</p>
        <p class="olsc-muted">{{ t('whm.objcache.autoDetail') }}</p>
        <el-popconfirm v-if="automatic" :title="t('whm.objcache.confirmOff')" :confirm-button-text="t('whm.objcache.confirmYes')"
                       :cancel-button-text="t('whm.objcache.confirmNo')" width="320" @confirm="setAutomatic(false)">
          <template #reference>
            <el-button :loading="saving.busy.value">{{ t('whm.objcache.turnOff') }}</el-button>
          </template>
        </el-popconfirm>
        <el-button v-else type="primary" :loading="saving.busy.value" @click="setAutomatic(true)">{{ t('whm.objcache.turnOn') }}</el-button>
        <el-alert v-if="saving.error.value" type="error" show-icon :closable="true" class="olsc-gap-below" :title="t('whm.objcache.failed')"
                  :description="errorMessage(saving.error.value)" @close="saving.error.value = null" />
      </section>

      <section class="olsc-card olsc-section" :aria-label="t('whm.objcache.accountsTitle')">
        <h3 class="olsc-h3">{{ t('whm.objcache.accountsTitle') }}</h3>
        <p v-if="!accounts.length" class="olsc-muted">{{ t('whm.objcache.none') }}</p>
        <div v-else role="region" :aria-label="t('whm.objcache.accountsTitle')" class="olsc-table-wrap">
          <el-table :data="accounts" stripe size="small" :aria-label="t('whm.objcache.accountsTitle')">
            <el-table-column :label="t('whm.objcache.account')" min-width="160">
              <template #default="{ row }"><span class="olsc-mono">{{ row.account }}</span></template>
            </el-table-column>
            <el-table-column :label="t('whm.objcache.origin')" min-width="230">
              <template #default="{ row }"><StatusBadge :tone="ORIGIN_TONES[row.origin] || 'neutral'" :label="origin(row)" /></template>
            </el-table-column>
            <el-table-column :label="t('whm.objcache.running')" width="140">
              <template #default="{ row }"><StatusBadge :tone="stateTone(row)" :label="stateLabel(row)" /></template>
            </el-table-column>
            <el-table-column :label="t('whm.objcache.memory')" width="140">
              <template #default="{ row }">{{ memory(row) }}</template>
            </el-table-column>
            <el-table-column :label="t('whm.objcache.sites')" width="150">
              <template #default="{ row }">{{ sites(row) }}</template>
            </el-table-column>
          </el-table>
        </div>
      </section>
    </StateView>
  </div>
</template>
