<script setup>
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import PageHeader from '../../shared/PageHeader.vue'
import StateView from '../../shared/StateView.vue'
import StatusBadge from '../../shared/StatusBadge.vue'
import { useLoad } from '../../shared/polling.js'
import { commandOutput, useClient, useResource } from '../../shared/api.js'
import { formatDateTime } from '../../shared/format.js'
import { platformFacts } from '../health.js'

// Updates (update: `ols-cpanel update check`, read-only): installed and available versions of the product packages, the package
// signature state, and whether this server's operating system and cPanel version are supported, so it can be seen before updating.
// The update itself is done by the server's package manager and cPanel's own update schedule; the product applies it by itself.
const { t } = useI18n()
const client = useClient()
const force = ref(false)
const update = useResource(client, 'update', { params: () => (force.value ? { refresh: 1 } : {}), staleAfter: 30 * 60 * 1000 })
const doctor = useResource(client, 'doctor', { staleAfter: 10 * 60 * 1000 })
useLoad(() => Promise.all([update.load(), doctor.load()]))

const report = computed(() => commandOutput(update.data.value) || {})
const packages = computed(() => (Array.isArray(report.value.packages) ? report.value.packages : []))
const facts = computed(() => platformFacts(commandOutput(doctor.data.value)))
const checking = computed(() => update.loading.value)
async function checkNow() {
  force.value = true
  try {
    await update.load()
  } finally {
    force.value = false
  }
}
const SIGNATURES = ['signed', 'signed-key-missing', 'unsigned']
const signatureKey = pkg => (SIGNATURES.includes(pkg.signature?.state) ? pkg.signature.state : 'unknown')
const signatureTone = pkg => ({ signed: 'ok', 'signed-key-missing': 'warn', unsigned: 'neutral' }[pkg.signature?.state] || 'neutral')
</script>

<template>
  <div>
    <PageHeader :title="t('whm.updates.title')" :description="t('whm.updates.description')">
      <template #actions>
        <el-button :loading="checking" @click="checkNow">{{ t('whm.updates.checkNow') }}</el-button>
      </template>
    </PageHeader>

    <section class="olsc-card olsc-gap-below" :aria-label="t('whm.updates.compatTitle')">
      <h3 class="olsc-h3">{{ t('whm.updates.compatTitle') }}</h3>
      <p class="olsc-muted">{{ t('whm.updates.compatText') }}</p>
      <dl v-if="facts" class="olsc-facts">
        <dt>{{ t('whm.updates.os') }}</dt><dd>{{ facts.os }}</dd>
        <dt>{{ t('whm.updates.cpanel') }}</dt><dd>{{ facts.cpanel }}</dd>
        <dt>{{ t('whm.updates.supportedList') }}</dt>
        <dd><StatusBadge :tone="facts.supported ? 'ok' : 'warn'" :label="facts.supported ? t('whm.updates.supported') : t('whm.updates.outside')" /></dd>
      </dl>
      <p v-else class="olsc-muted">{{ t('whm.updates.platformUnknown') }}</p>
      <p v-if="facts && !facts.supported" class="olsc-hint">{{ t('whm.updates.outsideHint') }}</p>
    </section>

    <StateView :resource="update" :refresh="() => update.load()">
      <el-alert v-if="report.error" type="warning" show-icon :closable="false" class="olsc-gap-below" :title="t('whm.updates.queryFailed')"
                :description="report.error" />
      <p v-else-if="report.update_available" class="olsc-gap-below"><StatusBadge tone="info" :label="t('whm.updates.available')" /></p>
      <p v-else class="olsc-gap-below"><StatusBadge tone="ok" :label="t('whm.updates.current')" /></p>
      <el-table :data="packages" size="small" stripe :aria-label="t('whm.updates.title')">
        <el-table-column :label="t('whm.updates.package')" min-width="220">
          <template #default="{ row }"><span class="olsc-mono">{{ row.package }}</span></template>
        </el-table-column>
        <el-table-column :label="t('whm.updates.installed')" min-width="200">
          <template #default="{ row }"><span class="olsc-mono">{{ row.installed ?? t('whm.updates.notInstalled') }}</span></template>
        </el-table-column>
        <el-table-column :label="t('whm.updates.availableVersion')" min-width="200">
          <template #default="{ row }">
            <span v-if="row.available" class="olsc-mono">{{ row.available }}</span>
            <span v-else class="olsc-muted">{{ t('whm.updates.noNewer') }}</span>
          </template>
        </el-table-column>
        <el-table-column :label="t('whm.updates.signature')" min-width="260">
          <template #default="{ row }">
            <StatusBadge :tone="signatureTone(row)" :label="t(`whm.updates.sig.${signatureKey(row)}`)" />
            <span v-if="row.signature?.key_id" class="olsc-muted olsc-small olsc-mono"> {{ row.signature.key_id }}</span>
          </template>
        </el-table-column>
      </el-table>
      <dl class="olsc-facts olsc-gap-above">
        <dt>{{ t('whm.updates.cpanelVersion') }}</dt><dd>{{ report.cpanel_version ?? t('state.unknown') }}</dd>
        <dt>{{ t('whm.updates.checkedAt') }}</dt><dd>{{ formatDateTime(report.checked_at) ?? t('state.notObserved') }}</dd>
      </dl>
      <p class="olsc-muted">{{ t('whm.updates.howText') }}</p>
    </StateView>
  </div>
</template>
