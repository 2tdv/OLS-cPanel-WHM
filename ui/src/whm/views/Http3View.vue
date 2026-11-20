<script setup>
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import PageHeader from '../../shared/PageHeader.vue'
import StateView from '../../shared/StateView.vue'
import StatusBadge from '../../shared/StatusBadge.vue'
import { WHM_SETTINGS, commandOutput, useClient, useMutation, useResource } from '../../shared/api.js'
import { errorMessage } from '../../shared/i18n.js'
import { useLoad } from '../../shared/polling.js'

// HTTP/3 (http3: admin.http3, `ols-cpanel http3 status`): the server-wide state (the operator input and the UDP 443 firewall) and,
// per site, whether OLS offers HTTP/3 (Alt-Svc) with the share of the last requests that used it. The per-site switch is
// POST http3_domain {domain, enabled} (a settings change, no job); the reconciler compiles it within a minute, so the page
// shows the wanted state at once and says so.
const { t } = useI18n()
const client = useClient()
const http3 = useResource(client, 'http3', { staleAfter: 5 * 60 * 1000 })
const saving = useMutation(client)
const changed = ref(false)
const working = ref(null)
useLoad(() => http3.load())

const report = computed(() => commandOutput(http3.data.value) || null)
const serverState = computed(() => (report.value?.enabled === true ? 'on' : report.value?.enabled === false ? 'off' : 'invalid'))
const switchable = computed(() => serverState.value === 'on')
const sites = computed(() => (Array.isArray(report.value?.protocol_share) ? report.value.protocol_share : []))
const stale = computed(() => (Array.isArray(report.value?.input?.off_unknown) ? report.value.input.off_unknown : []))
const firewall = computed(() => (typeof report.value?.firewall?.detail === 'string' ? report.value.firewall.detail : null))
const offered = row => row.http3_off !== true && serverState.value === 'on'
const share = row => {
  const bp = row.share_bp?.h3
  return row.lines > 0 && Number.isInteger(bp) ? `${(bp / 100).toFixed(1)} %` : t('whm.http3.shareNone')
}

async function setSite(row, on) {
  working.value = row.vhost
  changed.value = false
  const reply = await saving.run(WHM_SETTINGS.http3Domain, { domain: row.vhost, enabled: on })
  working.value = null
  if (reply) {
    changed.value = true
    await http3.load()
  }
}
</script>

<template>
  <div>
    <PageHeader :title="t('whm.http3.title')" :description="t('whm.http3.description')" />
    <StateView :resource="http3">
      <section class="olsc-card olsc-section" :aria-label="t('whm.http3.serverTitle')">
        <h3 class="olsc-h3">
          {{ t('whm.http3.serverTitle') }}
          <StatusBadge :tone="serverState === 'on' ? 'ok' : serverState === 'off' ? 'neutral' : 'bad'"
                       :label="serverState === 'on' ? t('whm.http3.serverOn') : serverState === 'off' ? t('whm.http3.serverOff') : t('whm.http3.serverInvalid')" />
        </h3>
        <p v-if="serverState === 'off'" class="olsc-muted">{{ t('whm.http3.serverOffDetail') }}</p>
        <p v-else-if="serverState === 'invalid'" class="olsc-muted">{{ t('whm.http3.serverInvalidDetail', { error: report?.input?.error || '' }) }}</p>
        <p v-else class="olsc-muted">{{ firewall ? t('whm.http3.firewall', { detail: firewall }) : t('whm.http3.firewallNone') }}</p>
      </section>

      <section class="olsc-card olsc-section" :aria-label="t('whm.http3.sitesTitle')">
        <h3 class="olsc-h3">{{ t('whm.http3.sitesTitle') }}</h3>
        <el-alert v-if="saving.error.value" type="error" show-icon :closable="true" class="olsc-gap-below" :title="t('whm.http3.failed')"
                  :description="errorMessage(saving.error.value)" @close="saving.error.value = null" />
        <el-alert v-if="changed" type="info" show-icon :closable="true" class="olsc-gap-below" :title="t('whm.http3.pending')" @close="changed = false" />
        <p v-if="!sites.length" class="olsc-muted">{{ t('whm.http3.none') }}</p>
        <div v-else role="region" :aria-label="t('whm.http3.sitesTitle')" class="olsc-table-wrap">
          <el-table :data="sites" stripe size="small" :aria-label="t('whm.http3.sitesTitle')">
            <el-table-column :label="t('whm.http3.site')" min-width="220">
              <template #default="{ row }"><span class="olsc-mono">{{ row.vhost }}</span></template>
            </el-table-column>
            <el-table-column :label="t('whm.http3.offered')" width="160">
              <template #default="{ row }"><StatusBadge :tone="offered(row) ? 'ok' : 'neutral'" :label="offered(row) ? t('whm.http3.yes') : t('whm.http3.no')" /></template>
            </el-table-column>
            <el-table-column :label="t('whm.http3.share')" width="200">
              <template #default="{ row }">{{ share(row) }}</template>
            </el-table-column>
            <el-table-column width="120">
              <template #default="{ row }">
                <el-switch :model-value="row.http3_off !== true" :disabled="!switchable || saving.busy.value" :loading="working === row.vhost"
                           :aria-label="t('whm.http3.switchLabel', { site: row.vhost })" @change="on => setSite(row, on)" />
              </template>
            </el-table-column>
          </el-table>
        </div>
        <p v-if="stale.length" class="olsc-muted">{{ t('whm.http3.stale', { names: stale.join(', ') }) }}</p>
      </section>
    </StateView>
  </div>
</template>
