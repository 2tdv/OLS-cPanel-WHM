<script setup>
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import PageHeader from '../../shared/PageHeader.vue'
import StateView from '../../shared/StateView.vue'
import StatusBadge from '../../shared/StatusBadge.vue'
import { WHM_SETTINGS, commandOutput, useClient, useMutation, useResource } from '../../shared/api.js'
import { formatDateTime, formatNumber } from '../../shared/format.js'
import { errorMessage } from '../../shared/i18n.js'
import { useLoad } from '../../shared/polling.js'

// The WordPress login guard (RV-64; login_guard: admin.login_guard, `ols-cpanel login-guard status`): the switch (on by default),
// whether the log watcher runs, the addresses blocked now with their counts, and the recent blocks. The switch is POST login_guard
// (a settings change, no job); turning it off lets every blocked address through at once, so it asks first.
const { t } = useI18n()
const client = useClient()
const guard = useResource(client, 'login_guard', { staleAfter: 60 * 1000 })
const saving = useMutation(client)
useLoad(() => guard.load())

const report = computed(() => commandOutput(guard.data.value) || null)
const enabled = computed(() => report.value?.enabled !== false)
const blocked = computed(() => (Array.isArray(report.value?.blocked) ? report.value.blocked : []))
const recent = computed(() => (Array.isArray(report.value?.recent) ? report.value.recent.slice(0, 20) : []))
const limits = computed(() => report.value?.limits || {})
const lead = computed(() => t('whm.guard.lead', {
  login: limits.value['wp-login'] ?? 20, xmlrpc: limits.value.xmlrpc ?? 30, minutes: Math.round((report.value?.block_seconds ?? 900) / 60),
}))
const seen = computed(() => report.value?.seen || {})
const REASONS = ['expired', 'unblocked', 'guard_off']
const reason = row => (REASONS.includes(row.reason) ? t(`whm.guard.reasons.${row.reason}`) : '-')
const time = value => (Number.isInteger(value) && value > 0 ? formatDateTime(value) : '-')

async function setEnabled(on) {
  const reply = await saving.run(WHM_SETTINGS.loginGuard, { enabled: on })
  if (reply) await guard.load()
}
</script>

<template>
  <div>
    <PageHeader :title="t('whm.guard.title')" :description="t('whm.guard.description')" />
    <StateView :resource="guard">
      <section class="olsc-card olsc-section" :aria-label="t('whm.guard.switchTitle')">
        <h3 class="olsc-h3">
          {{ t('whm.guard.switchTitle') }}
          <StatusBadge :tone="enabled ? 'ok' : 'neutral'" :label="enabled ? t('whm.guard.on') : t('whm.guard.off')" />
        </h3>
        <p>{{ lead }}</p>
        <p class="olsc-muted">{{ t('whm.guard.detail') }}</p>
        <p v-if="enabled">
          {{ t('whm.guard.watcher') }}:
          <StatusBadge :tone="report?.watching ? 'ok' : 'warn'" :label="report?.watching ? t('whm.guard.watcherOk') : t('whm.guard.watcherStale')" />
          <span class="olsc-muted">{{ report?.checked_at ? t('whm.guard.lastCheck', { time: time(report.checked_at) }) : t('whm.guard.never') }}</span>
        </p>
        <p v-if="seen.since" class="olsc-muted">
          {{ t('whm.guard.seenTitle', { time: time(seen.since) }) }}:
          {{ t('whm.guard.seen', { posts: formatNumber(seen.posts ?? 0), refused: formatNumber(seen.refused ?? 0) }) }}
        </p>
        <el-popconfirm v-if="enabled" :title="t('whm.guard.confirmOff')" :confirm-button-text="t('whm.guard.confirmYes')"
                       :cancel-button-text="t('whm.guard.confirmNo')" width="320" @confirm="setEnabled(false)">
          <template #reference>
            <el-button :loading="saving.busy.value">{{ t('whm.guard.turnOff') }}</el-button>
          </template>
        </el-popconfirm>
        <el-button v-else type="primary" :loading="saving.busy.value" @click="setEnabled(true)">{{ t('whm.guard.turnOn') }}</el-button>
        <el-alert v-if="saving.error.value" type="error" show-icon :closable="true" class="olsc-gap-below" :title="t('whm.guard.failed')"
                  :description="errorMessage(saving.error.value)" @close="saving.error.value = null" />
      </section>

      <section class="olsc-card olsc-section" :aria-label="t('whm.guard.blockedTitle')">
        <h3 class="olsc-h3">{{ t('whm.guard.blockedTitle') }}</h3>
        <p v-if="!blocked.length" class="olsc-muted">{{ t('whm.guard.none') }}</p>
        <div v-else role="region" :aria-label="t('whm.guard.blockedTitle')" class="olsc-table-wrap">
          <el-table :data="blocked" stripe size="small" :aria-label="t('whm.guard.blockedTitle')">
            <el-table-column :label="t('whm.guard.site')" min-width="200">
              <template #default="{ row }"><span class="olsc-mono">{{ row.domain }}</span></template>
            </el-table-column>
            <el-table-column :label="t('whm.guard.address')" min-width="160">
              <template #default="{ row }"><span class="olsc-mono">{{ row.address }}</span></template>
            </el-table-column>
            <el-table-column :label="t('whm.guard.endpoint')" width="130">
              <template #default="{ row }"><span class="olsc-mono">{{ row.endpoint }}</span></template>
            </el-table-column>
            <el-table-column :label="t('whm.guard.requests')" width="120">
              <template #default="{ row }">{{ formatNumber(row.requests ?? 0) }}</template>
            </el-table-column>
            <el-table-column :label="t('whm.guard.refused')" width="120">
              <template #default="{ row }">{{ formatNumber(row.refused ?? 0) }}</template>
            </el-table-column>
            <el-table-column :label="t('whm.guard.since')" min-width="160">
              <template #default="{ row }">{{ time(row.since) }}</template>
            </el-table-column>
            <el-table-column :label="t('whm.guard.until')" min-width="160">
              <template #default="{ row }">{{ time(row.until) }}</template>
            </el-table-column>
            <el-table-column :label="t('whm.guard.repeat')" width="90">
              <template #default="{ row }">{{ row.strike ?? 1 }}</template>
            </el-table-column>
          </el-table>
        </div>
      </section>

      <section v-if="recent.length" class="olsc-card olsc-section" :aria-label="t('whm.guard.recentTitle')">
        <h3 class="olsc-h3">{{ t('whm.guard.recentTitle') }}</h3>
        <div role="region" :aria-label="t('whm.guard.recentTitle')" class="olsc-table-wrap">
          <el-table :data="recent" stripe size="small" :aria-label="t('whm.guard.recentTitle')">
            <el-table-column :label="t('whm.guard.site')" min-width="200">
              <template #default="{ row }"><span class="olsc-mono">{{ row.domain }}</span></template>
            </el-table-column>
            <el-table-column :label="t('whm.guard.address')" min-width="160">
              <template #default="{ row }"><span class="olsc-mono">{{ row.address }}</span></template>
            </el-table-column>
            <el-table-column :label="t('whm.guard.refused')" width="120">
              <template #default="{ row }">{{ formatNumber(row.refused ?? 0) }}</template>
            </el-table-column>
            <el-table-column :label="t('whm.guard.since')" min-width="160">
              <template #default="{ row }">{{ time(row.since) }}</template>
            </el-table-column>
            <el-table-column :label="t('whm.guard.ended')" min-width="160">
              <template #default="{ row }">{{ time(row.ended) }}</template>
            </el-table-column>
            <el-table-column :label="t('whm.guard.reason')" min-width="160">
              <template #default="{ row }">{{ reason(row) }}</template>
            </el-table-column>
          </el-table>
        </div>
      </section>
    </StateView>
  </div>
</template>
