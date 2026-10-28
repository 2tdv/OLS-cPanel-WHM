<script setup>
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import PageHeader from '../../shared/PageHeader.vue'
import StateView from '../../shared/StateView.vue'
import StatusBadge from '../../shared/StatusBadge.vue'
import { useLoad } from '../../shared/polling.js'
import { CPANEL_ACTIONS, useClient, useMutation, useResource } from '../../shared/api.js'
import { formatDateTime } from '../../shared/format.js'
import { errorMessage } from '../../shared/i18n.js'
import { normalizeBlocker } from '../../shared/findings.js'

// Account-local translation outcomes; details are optional and collapsed on first load.
const { t } = useI18n()
const client = useClient()
const report = useResource(client, 'htaccess')
const changes = useResource(client, 'htaccess_backups')
const mutation = useMutation(client)
const notice = ref(null)
useLoad(() => Promise.all([report.load(), changes.load()]))
const data = computed(() => report.data.value || {})
const files = computed(() => (Array.isArray(data.value.files) ? data.value.files : []).map(f => ({
  path: String(f?.path ?? ''),
  docroot: f?.docroot ?? null,
  outcome: f?.outcome === 'translated' ? 'translated' : 'kept_on_apache',
  digest: typeof f?.digest === 'string' ? f.digest : null,
  fixes: (Array.isArray(f?.fixes) ? f.fixes : []).filter(k => ['bom', 'cr_line_endings'].includes(k)),
  findings: (Array.isArray(f?.reasons) ? f.reasons : []).map(r => ({
    ...normalizeBlocker(r.directive), reasonKey: r.reason_key,
  })),
})))
const truncatedText = computed(() => {
  if (!data.value.truncated) return ''
  return data.value.stopped === 'files' ? t('cpanel.htaccess.truncated', { n: data.value.limit }) : t('cpanel.htaccess.partial')
})
const recent = computed(() => (Array.isArray(changes.data.value?.backups) ? changes.data.value.backups : []))

// The correction is written by the account's own page (never by the server's root), after a copy of the file is kept;
// the file's digest is sent so a file edited in the meantime is refused (it is checked again right before the swap;
// the copy kept first holds the original in any case).
async function apply(file) {
  notice.value = null
  const reply = await mutation.run(CPANEL_ACTIONS.htaccessApply, { path: file.path, digest: file.digest })
  if (reply) notice.value = 'applied'
  await Promise.all([report.load(), changes.load()])
}
async function undo(change) {
  notice.value = null
  const reply = await mutation.run(CPANEL_ACTIONS.htaccessUndo, { id: change.id })
  if (reply) notice.value = 'undone'
  await Promise.all([report.load(), changes.load()])
}
const where = (finding) => [finding.location, finding.line !== null ? t('cpanel.htaccess.line', { n: finding.line }) : null]
  .filter(Boolean).join(' · ')
</script>

<template>
  <div>
    <PageHeader :title="t('cpanel.htaccess.title')" :description="t('cpanel.htaccess.intro')">
      <template #actions>
        <el-button :loading="report.loading.value" @click="report.load()">{{ t('cpanel.htaccess.recheck') }}</el-button>
      </template>
    </PageHeader>
    <el-alert v-if="mutation.error.value" type="error" show-icon :closable="true" class="olsc-gap-below"
              :title="t('cpanel.htaccess.applyFailed')"
              :description="mutation.error.value.code === 'STALE' ? t('cpanel.htaccess.stale') : errorMessage(mutation.error.value)"
              @close="mutation.error.value = null" />
    <el-alert v-if="notice" type="success" show-icon :closable="true" class="olsc-gap-below"
              :title="notice === 'applied' ? t('cpanel.htaccess.applied') : t('cpanel.htaccess.undoDone')" @close="notice = null" />
    <StateView :resource="report" :empty="report.data.value !== null && !files.length" :empty-text="t('cpanel.htaccess.noFiles')"
               :degraded="truncatedText">
      <p>{{ t('cpanel.htaccess.scanned', { files: files.length, roots: Number.isInteger(data.roots) ? data.roots : 0 }) }}</p>
      <el-collapse class="olsc-gap-below">
        <el-collapse-item v-for="f in files" :key="f.path" :name="f.path">
          <template #title>
            <span class="olsc-mono">{{ f.path }}</span>&nbsp;
            <StatusBadge :tone="f.outcome === 'translated' ? 'ok' : 'info'"
                         :label="f.outcome === 'translated' ? t('cpanel.htaccess.translated') : t('cpanel.htaccess.keptOnApache')" />
          </template>
          <p v-if="f.docroot" class="olsc-muted olsc-small">{{ t('cpanel.htaccess.site', { docroot: f.docroot }) }}</p>
          <div v-if="f.fixes.length && f.digest" class="olsc-gap-below">
            <strong>{{ t('cpanel.htaccess.fixTitle') }}</strong>
            <ul class="olsc-plain-list"><li v-for="k in f.fixes" :key="k">{{ t(`cpanel.htaccess.fixes.${k}`) }}</li></ul>
            <el-popconfirm :title="t('cpanel.htaccess.applyConfirm')" :confirm-button-text="t('cpanel.htaccess.applyYes')"
                           :cancel-button-text="t('cpanel.htaccess.applyNo')" @confirm="apply(f)">
              <template #reference>
                <el-button size="small" type="primary" :loading="mutation.busy.value">{{ t('cpanel.htaccess.apply') }}</el-button>
              </template>
            </el-popconfirm>
          </div>
          <el-table v-if="f.findings.length" :data="f.findings" size="small" :aria-label="t('cpanel.htaccess.findingsFor', { file: f.path })">
            <el-table-column :label="t('cpanel.htaccess.where')" min-width="130">
              <template #default="{ row }"><span class="olsc-mono">{{ where(row) || t('state.unknown') }}</span></template>
            </el-table-column>
            <el-table-column :label="t('cpanel.htaccess.directive')" min-width="230">
              <template #default="{ row }"><span class="olsc-mono olsc-wrap">{{ row.detail }}</span></template>
            </el-table-column>
            <el-table-column :label="t('cpanel.htaccess.reason')" min-width="260">
              <template #default="{ row }">{{ t(`cpanel.htaccess.reasons.${row.reasonKey || 'directive'}`) }}</template>
            </el-table-column>
          </el-table>
        </el-collapse-item>
      </el-collapse>
    </StateView>
    <section class="olsc-card olsc-section" :aria-label="t('cpanel.htaccess.changesTitle')">
      <h3 class="olsc-h3">{{ t('cpanel.htaccess.changesTitle') }}</h3>
      <p v-if="!recent.length" class="olsc-muted">{{ t('cpanel.htaccess.noChanges') }}</p>
      <ul v-else class="olsc-plain-list">
        <li v-for="c in recent" :key="c.id" class="olsc-gap-below">
          <span class="olsc-mono">{{ c.path }}</span>
          <span class="olsc-muted olsc-small"> {{ formatDateTime(c.applied_at) ?? t('state.unknown') }}</span>
          <span v-if="c.undone" class="olsc-muted"> - {{ t('cpanel.htaccess.undone') }}</span>
          <el-popconfirm v-else :title="t('cpanel.htaccess.undoConfirm')" :confirm-button-text="t('cpanel.htaccess.undo')"
                         :cancel-button-text="t('cpanel.htaccess.applyNo')" @confirm="undo(c)">
            <template #reference>
              <el-button size="small" :disabled="mutation.busy.value">{{ t('cpanel.htaccess.undo') }}</el-button>
            </template>
          </el-popconfirm>
        </li>
      </ul>
    </section>
  </div>
</template>
