<script setup>
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import PageHeader from '../../shared/PageHeader.vue'
import StateView from '../../shared/StateView.vue'
import StatusBadge from '../../shared/StatusBadge.vue'
import HealthSummary from '../HealthSummary.vue'
import { useLoad } from '../../shared/polling.js'
import { commandOutput, useClient, useResource } from '../../shared/api.js'

// Diagnostics (doctor: `ols-cpanel doctor --read-only`, cached 60 s by the broker): compatibility,
// supported platforms, blockers, platform observations with their source, runtime, and the full report.
const { t, te } = useI18n()
const client = useClient()
const doctor = useResource(client, 'doctor', { staleAfter: 10 * 60 * 1000 })
useLoad(() => doctor.load())
const r = computed(() => commandOutput(doctor.data.value) || {})
const platforms = computed(() => (Array.isArray(r.value.compatibility?.supported_platforms) ? r.value.compatibility.supported_platforms : []))
const blockers = computed(() => (Array.isArray(r.value.blockers) ? r.value.blockers : []))
const observations = computed(() => Object.entries(r.value.platform || {}).map(([name, o]) => ({
  name, status: o?.status ?? null, source: o?.source ?? null,
  value: typeof o?.value === 'string' ? o.value : JSON.stringify(o?.value ?? null),
})))
const runtime = computed(() => Object.entries(r.value.runtime || {}))
const raw = computed(() => JSON.stringify(commandOutput(doctor.data.value), null, 2))
const flag = value => (value === true ? t('common.yes') : value === false ? t('common.no') : t('state.unknown'))
</script>

<template>
  <div>
    <PageHeader :title="t('whm.diagnostics.title')" :description="t('whm.diagnostics.description')" help="doctor" />
    <HealthSummary />
    <StateView :resource="doctor">
      <el-alert v-if="r.synthetic" type="warning" :closable="false" show-icon class="olsc-gap-below"
                :title="t('whm.diagnostics.synthetic')" />
      <details class="olsc-details">
        <summary>{{ t('whm.diagnostics.technical') }}</summary>
        <p class="olsc-muted">{{ t('whm.diagnostics.technicalNote') }}</p>
      <dl class="olsc-facts">
        <dt>{{ t('whm.diagnostics.mode') }}</dt><dd>{{ r.mode ?? t('state.unknown') }}</dd>
        <dt>{{ t('fields.exitCode') }}</dt><dd>{{ doctor.data.value?.exit_code ?? t('state.unknown') }}</dd>
        <dt>{{ t('whm.diagnostics.compatibility') }}</dt><dd>{{ r.compatibility?.status ?? t('state.unknown') }}</dd>
        <dt>{{ t('whm.diagnostics.supported') }}</dt><dd>{{ flag(r.compatibility?.supported) }}</dd>
        <dt>{{ t('whm.diagnostics.activation') }}</dt><dd>{{ flag(r.compatibility?.production_activation_allowed) }}</dd>
        <dt>{{ t('whm.diagnostics.complete') }}</dt><dd>{{ flag(r.observation_complete) }}</dd>
      </dl>

      <h3 class="olsc-h3">{{ t('whm.diagnostics.blockers') }}</h3>
      <ul v-if="blockers.length" class="olsc-list">
        <li v-for="code in blockers" :key="code">
          <StatusBadge tone="bad" :label="t('severity.blocker')" /> <span class="olsc-mono">{{ code }}</span>
          {{ te(`doctor.blockers.${code}`) ? t(`doctor.blockers.${code}`) : '' }}
        </li>
      </ul>
      <p v-else class="olsc-muted">{{ t('whm.switch.noDoctorBlockers') }}</p>

      <h3 class="olsc-h3">{{ t('whm.diagnostics.platforms') }}</h3>
      <ul class="olsc-list">
        <li v-for="p in platforms" :key="p">{{ p }}</li>
      </ul>

      <h3 class="olsc-h3">{{ t('whm.diagnostics.observations') }}</h3>
      <el-table :data="observations" size="small" :aria-label="t('whm.diagnostics.observations')">
        <el-table-column :label="t('whm.diagnostics.item')" width="160">
          <template #default="{ row }"><span class="olsc-mono">{{ row.name }}</span></template>
        </el-table-column>
        <el-table-column :label="t('fields.state')" width="120">
          <template #default="{ row }">{{ row.status ?? t('state.unknown') }}</template>
        </el-table-column>
        <el-table-column :label="t('fields.source')" width="160">
          <template #default="{ row }">{{ row.source ?? t('state.unknown') }}</template>
        </el-table-column>
        <el-table-column :label="t('fields.value')" min-width="300">
          <template #default="{ row }"><span class="olsc-mono olsc-wrap">{{ row.value }}</span></template>
        </el-table-column>
      </el-table>

      <h3 class="olsc-h3">{{ t('whm.diagnostics.runtime') }}</h3>
      <dl class="olsc-facts">
        <template v-for="[key, value] in runtime" :key="key">
          <dt class="olsc-mono">{{ key }}</dt><dd class="olsc-mono">{{ value }}</dd>
        </template>
      </dl>

      <details class="olsc-details">
        <summary>{{ t('whm.diagnostics.raw') }}</summary>
        <pre class="olsc-pre">{{ raw }}</pre>
      </details>
      </details>
    </StateView>
  </div>
</template>
