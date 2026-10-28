<script setup>
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import PageHeader from '../../shared/PageHeader.vue'
import StateView from '../../shared/StateView.vue'
import StatusBadge from '../../shared/StatusBadge.vue'
import { CPANEL_ACTIONS, useClient, useMutation, useResource } from '../../shared/api.js'
import { formatBytes, formatNumber } from '../../shared/format.js'
import { errorMessage } from '../../shared/i18n.js'
import { useLoad } from '../../shared/polling.js'

// The account's own PHP view (php: tenant.php): the PHP version and handler of each site, whether OPcache is
// active for the versions in use, this account's PHP worker processes, and the limits that apply. Restarting
// (POST php_restart) ends the account's own PHP processes; new ones start with the next request. The server
// allows one restart every half minute. No account is ever sent.
const { t } = useI18n()
const client = useClient()
const php = useResource(client, 'php', { staleAfter: 5 * 60 * 1000 })
const mutation = useMutation(client)
const done = ref(null)
useLoad(() => php.load())

const sites = computed(() => (Array.isArray(php.data.value?.sites) ? php.data.value.sites : []))
const opcache = computed(() => (Array.isArray(php.data.value?.opcache) ? php.data.value.opcache : []))
const family = computed(() => php.data.value?.processes || null)
const rows = computed(() => (Array.isArray(family.value?.processes) ? family.value.processes : []))
const limits = computed(() => php.data.value?.limits || {})
const num = value => formatNumber(value) ?? t('state.unknown')
const kb = value => (Number.isFinite(value) ? formatBytes(value * 1024) : null) ?? t('state.unknown')
const bytes = value => (value === 0 ? t('cpanel.php.unlimited') : formatBytes(value) ?? t('state.unknown'))
const opcacheOf = version => opcache.value.find(v => v.version === version)
const age = seconds => {
  if (!Number.isFinite(seconds)) return t('state.unknown')
  if (seconds < 3600) return t('cpanel.php.minutes', { n: Math.floor(seconds / 60) })
  if (seconds < 172800) return t('cpanel.php.hours', { n: Math.floor(seconds / 3600) })
  return t('cpanel.php.days', { n: Math.floor(seconds / 86400) })
}

async function restart() {
  done.value = null
  const reply = await mutation.run(CPANEL_ACTIONS.phpRestart, {})
  if (reply) {
    done.value = Number.isInteger(reply.killed) ? reply.killed : 0
    await php.load()
  }
}
</script>

<template>
  <div>
    <PageHeader :title="t('cpanel.php.title')" :description="t('cpanel.php.description')">
      <template #actions>
        <el-popconfirm :title="t('cpanel.php.confirm')" :confirm-button-text="t('cpanel.php.confirmYes')"
                       :cancel-button-text="t('cpanel.php.confirmNo')" @confirm="restart">
          <template #reference>
            <el-button type="primary" :loading="mutation.busy.value" :disabled="!sites.length">{{ t('cpanel.php.restart') }}</el-button>
          </template>
        </el-popconfirm>
      </template>
    </PageHeader>

    <el-alert v-if="mutation.error.value" type="error" show-icon :closable="true" class="olsc-gap-below"
              :title="t('cpanel.php.failed')" :description="errorMessage(mutation.error.value)" @close="mutation.error.value = null" />
    <el-alert v-if="done !== null" type="success" show-icon :closable="true" class="olsc-gap-below"
              :title="t('cpanel.php.done', { n: formatNumber(done) ?? t('state.unknown') })" @close="done = null" />

    <StateView :resource="php" :empty="php.data.value !== null && !sites.length" :empty-text="t('cpanel.php.none')">
      <div role="region" :aria-label="t('cpanel.php.sitesTitle')" class="olsc-table-wrap">
        <el-table :data="sites" stripe size="small" :aria-label="t('cpanel.php.sitesTitle')">
          <el-table-column :label="t('cpanel.php.site')" min-width="240">
            <template #default="{ row }"><span class="olsc-mono">{{ row.domain }}</span></template>
          </el-table-column>
          <el-table-column :label="t('cpanel.php.version')" width="140">
            <template #default="{ row }"><span class="olsc-mono">{{ row.php_version || t('state.unknown') }}</span></template>
          </el-table-column>
          <el-table-column :label="t('fields.phpHandler')" width="130">
            <template #default="{ row }"><span class="olsc-mono">{{ row.php_handler || t('state.unknown') }}</span></template>
          </el-table-column>
          <el-table-column :label="t('cpanel.php.opcache')" width="190">
            <template #default="{ row }">
              <StatusBadge v-if="opcacheOf(row.php_version)?.loaded && opcacheOf(row.php_version)?.tuned" tone="ok" :label="t('cpanel.php.opcacheOn')" />
              <StatusBadge v-else-if="opcacheOf(row.php_version)?.loaded" tone="warn" :label="t('cpanel.php.opcachePartial')" />
              <StatusBadge v-else-if="opcacheOf(row.php_version)" tone="neutral" :label="t('cpanel.php.opcacheOff')" />
              <span v-else class="olsc-unknown">{{ t('state.unknown') }}</span>
            </template>
          </el-table-column>
        </el-table>
      </div>

      <section class="olsc-card olsc-section" :aria-label="t('cpanel.php.processesTitle')">
        <h3 class="olsc-h3">{{ t('cpanel.php.processesTitle') }}</h3>
        <p v-if="!family" class="olsc-muted">{{ t('cpanel.php.noProcesses') }}</p>
        <template v-else>
          <p class="olsc-muted" role="status">
            {{ t('cpanel.php.summary', { workers: num(family.children), memory: kb(family.rss_kb), cpu: Number.isFinite(family.cpu_percent) ? family.cpu_percent : 0 }) }}
          </p>
          <el-alert v-if="family.runaway > 0" type="warning" show-icon :closable="false" class="olsc-gap-below"
                    :title="t('cpanel.php.runaway', { n: family.runaway })" :description="t('cpanel.php.runawayBody')" />
          <div v-if="rows.length" role="region" :aria-label="t('cpanel.php.processesTitle')" class="olsc-table-wrap">
            <el-table :data="rows" stripe size="small" :aria-label="t('cpanel.php.processesTitle')">
              <el-table-column :label="t('cpanel.php.process')" width="110">
                <template #default="{ row }"><span class="olsc-mono">{{ row.pid }}</span></template>
              </el-table-column>
              <el-table-column :label="t('cpanel.php.role')" width="120">
                <template #default="{ row }">{{ row.role === 'parent' ? t('cpanel.php.parent') : t('cpanel.php.worker') }}</template>
              </el-table-column>
              <el-table-column :label="t('cpanel.php.cpu')" width="90" align="right">
                <template #default="{ row }">{{ Number.isFinite(row.cpu_percent) ? `${row.cpu_percent}%` : t('state.unknown') }}</template>
              </el-table-column>
              <el-table-column :label="t('cpanel.php.memory')" width="120" align="right">
                <template #default="{ row }">{{ kb(row.rss_kb) }}</template>
              </el-table-column>
              <el-table-column :label="t('cpanel.php.age')" width="120" align="right">
                <template #default="{ row }">{{ age(row.elapsed_seconds) }}</template>
              </el-table-column>
              <el-table-column :label="t('fields.state')" width="150">
                <template #default="{ row }">
                  <StatusBadge v-if="row.runaway?.length" tone="bad" :label="t('cpanel.php.runawayRow')" />
                  <StatusBadge v-else tone="ok" :label="t('cpanel.php.normal')" />
                </template>
              </el-table-column>
            </el-table>
          </div>
        </template>
      </section>

      <section class="olsc-card olsc-section" :aria-label="t('cpanel.php.limitsTitle')">
        <h3 class="olsc-h3">{{ t('cpanel.php.limitsTitle') }}</h3>
        <dl class="olsc-facts">
          <dt>{{ t('cpanel.php.limitChildren') }}</dt><dd>{{ num(limits.children) }}</dd>
          <dt>{{ t('cpanel.php.limitMem') }}</dt><dd>{{ bytes(limits.mem_soft) }} / {{ bytes(limits.mem_hard) }}</dd>
          <dt>{{ t('cpanel.php.limitProc') }}</dt><dd>{{ num(limits.proc_soft) }} / {{ num(limits.proc_hard) }}</dd>
        </dl>
        <p class="olsc-muted">{{ t('cpanel.php.limitsNote') }}</p>
      </section>
    </StateView>
  </div>
</template>
