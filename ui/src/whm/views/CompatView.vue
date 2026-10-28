<script setup>
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import DataTable from '../../shared/DataTable.vue'
import EngineBadge from '../../shared/EngineBadge.vue'
import HelpTip from '../../shared/HelpTip.vue'
import PageHeader from '../../shared/PageHeader.vue'
import StatusBadge from '../../shared/StatusBadge.vue'
import { useLoad } from '../../shared/polling.js'
import { fetchAllPages, toApiError, useClient, usePaged } from '../../shared/api.js'
import { downloadText, toCsv } from '../../shared/csv.js'
import { SEVERITIES, normalizeBlocker, severityTone } from '../../shared/findings.js'
import { errorMessage } from '../../shared/i18n.js'

// Compatibility center (compat: server-side search and paging over the virtual hosts that have findings
// or stay on Apache): each finding with severity, file and line where known, explanation and help; the
// engine of the vhost; CSV export of the current search and filter.
const { t } = useI18n()
const client = useClient()
const paged = usePaged(client, 'compat', { rowsKey: 'vhosts', size: 50 })
useLoad(() => paged.resource.load())
const severity = ref('')
const exporting = ref(false)
const exportError = ref(null)
const ENGINES = ['ols', 'hybrid', 'apache', 'unknown']

function normalize(row) {
  return {
    vhost: String(row?.vhost ?? ''),
    user: row?.user ?? null,
    domains: Array.isArray(row?.domains) ? row.domains : null,
    engine: ENGINES.includes(row?.engine) ? row.engine : 'unknown',
    hybrid: row?.hybrid === true,
    findings: (Array.isArray(row?.findings) ? row.findings : []).map(f => ({ ...normalizeBlocker(f), file: f?.file ?? null })),
  }
}
const shownFindings = row => row.findings.filter(f => !severity.value || f.severity === severity.value)
// The severity filter applies to the page the server returned; the search runs on the server.
const rows = computed(() => paged.rows.value.map(normalize).filter(r => !severity.value || shownFindings(r).length))
const where = f => [f.file || f.location, f.line !== null ? t('cpanel.htaccess.line', { n: f.line }) : null].filter(Boolean).join(' · ')

async function exportCsv() {
  exporting.value = true
  exportError.value = null
  try {
    const { rows: all, complete } = await fetchAllPages(client, 'compat', 'vhosts', { query: paged.query.value.trim() })
    const lines = all.map(normalize).flatMap(r => {
      const findings = shownFindings(r)
      if (findings.length) return findings.map(f => ({ r, f }))
      return severity.value ? [] : [{ r, f: null }]
    })
    const csv = toCsv(lines, [
      { label: t('fields.vhost'), value: ({ r }) => r.vhost },
      { label: t('fields.account'), value: ({ r }) => r.user },
      { label: t('fields.engine'), value: ({ r }) => t(`engine.${r.engine}`) },
      { label: t('fields.severity'), value: ({ f }) => (f?.severity ? t(`severity.${f.severity}`) : '') },
      { label: t('fields.location'), value: ({ f }) => (f ? where(f) : '') },
      { label: t('fields.finding'), value: ({ f }) => (f ? f.detail : t('help.hybrid_vhost.title')) },
      { label: t('fields.explanation'), value: ({ f }) => t(`help.${f ? f.explanation : 'hybrid_vhost'}.title`) },
    ])
    downloadText(`ols-cpanel-findings${complete ? '' : '-partial'}.csv`, csv)
    if (!complete) exportError.value = { code: 'PARTIAL', message: t('whm.compat.exportPartial') }
  } catch (e) {
    exportError.value = toApiError(e)
  } finally {
    exporting.value = false
  }
}
</script>

<template>
  <div>
    <PageHeader :title="t('whm.compat.title')" :description="t('whm.compat.description')">
      <template #actions>
        <el-button :loading="exporting" :disabled="!paged.total.value || paged.queryInvalid.value" @click="exportCsv">
          {{ t('whm.compat.export') }}
        </el-button>
      </template>
    </PageHeader>
    <el-alert v-if="exportError" type="warning" show-icon class="olsc-gap-below" :title="t('whm.compat.exportFailed')"
              :description="exportError.code === 'PARTIAL' ? exportError.message : errorMessage(exportError)"
              @close="exportError = null" />
    <DataTable :paged="paged" :rows="rows" :caption="t('whm.compat.title')" :search-label="t('whm.compat.search')"
               :empty-text="severity ? t('whm.compat.noneForFilter') : t('whm.compat.none')">
      <template #toolbar>
        <label for="olsc-compat-severity" class="olsc-sr-only">{{ t('fields.severity') }}</label>
        <el-select id="olsc-compat-severity" v-model="severity" :placeholder="t('whm.compat.allSeverities')" clearable
                   class="olsc-filter" :aria-label="t('fields.severity')">
          <el-option v-for="s in SEVERITIES" :key="s" :label="t(`severity.${s}`)" :value="s" />
        </el-select>
        <span v-if="severity" class="olsc-muted olsc-small">{{ t('whm.compat.filterScope') }}</span>
      </template>
      <el-table-column :label="t('fields.vhost')" min-width="200">
        <template #default="{ row }">
          <div class="olsc-mono">{{ row.vhost }}</div>
          <div v-if="row.user" class="olsc-muted olsc-small">{{ t('fields.accountValue', { user: row.user }) }}</div>
          <div v-if="row.domains" class="olsc-muted olsc-small olsc-mono">{{ row.domains.join(', ') }}</div>
        </template>
      </el-table-column>
      <el-table-column :label="t('fields.engine')" width="200">
        <template #default="{ row }">
          <EngineBadge :engine="row.engine" />
          <HelpTip v-if="row.hybrid" topic="hybrid_vhost" />
        </template>
      </el-table-column>
      <el-table-column :label="t('fields.finding')" min-width="420">
        <template #default="{ row }">
          <ul class="olsc-list olsc-tight">
            <li v-for="(f, i) in shownFindings(row)" :key="i">
              <StatusBadge :tone="severityTone(f.severity)" :label="f.severity ? t(`severity.${f.severity}`) : t('state.unknown')" />
              <span v-if="where(f)" class="olsc-mono olsc-muted"> {{ where(f) }}</span>
              <div class="olsc-mono olsc-wrap">{{ f.detail }}</div>
              <HelpTip :topic="f.explanation" />
            </li>
            <li v-if="!row.findings.length" class="olsc-muted">{{ t('whm.compat.hybridOnly') }}</li>
          </ul>
        </template>
      </el-table-column>
    </DataTable>
  </div>
</template>
