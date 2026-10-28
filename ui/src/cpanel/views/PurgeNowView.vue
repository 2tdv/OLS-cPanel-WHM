<script setup>
import { onBeforeUnmount, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import PageHeader from '../../shared/PageHeader.vue'
import { CPANEL_ACTIONS, useClient, useMutation } from '../../shared/api.js'
import { formatNumber } from '../../shared/format.js'
import { errorMessage } from '../../shared/i18n.js'
import { recentPurge, rememberPurge, sessionStore } from '../purgeMemory.js'

// The cPanel dashboard's "Clear cache" icon (install.json, ?view=purge): clears the page cache of every site of this
// account at once (the same cache_purge action as the Page cache view, with no site) and returns to the cPanel home.
// A reload or a back-navigation within a minute shows the result of that purge instead of clearing again (purgeMemory.js),
// and does not return to the cPanel home by itself (the visitor came back to this page on purpose).
const { t } = useI18n()
const mutation = useMutation(useClient())
const removed = ref(null)
const done = ref(false)
const repeated = ref(false)
const HOME = '../index.html'
const RETURN_AFTER = 4000
let timer = null

onMounted(async () => {
  const store = sessionStore()
  const last = recentPurge(store)
  if (last) {
    removed.value = last.removed
    repeated.value = true
    done.value = true
    return
  }
  const reply = await mutation.run(CPANEL_ACTIONS.cachePurge, {})
  if (reply) {
    removed.value = Number.isInteger(reply.totals?.entries) ? reply.totals.entries : null
    rememberPurge(store, removed.value)
    done.value = true
    timer = setTimeout(() => { globalThis.location.href = HOME }, RETURN_AFTER)
  }
})
onBeforeUnmount(() => clearTimeout(timer))
</script>

<template>
  <div>
    <PageHeader :title="t('cpanel.purgeNow.title')" :description="t('cpanel.purgeNow.description')" />
    <el-alert v-if="mutation.error.value" type="error" show-icon :closable="false" class="olsc-gap-below"
              :title="t('cpanel.purgeNow.failed')" :description="errorMessage(mutation.error.value)" />
    <el-alert v-else-if="done" type="success" show-icon :closable="false" class="olsc-gap-below"
              :title="removed === null ? t('cpanel.purgeNow.doneUnknown') : t('cpanel.purgeNow.done', { n: formatNumber(removed) })"
              :description="repeated ? t('cpanel.purgeNow.recent') : t('cpanel.purgeNow.returning')" />
    <p v-else class="olsc-muted" role="status">{{ t('cpanel.purgeNow.working') }}</p>
    <p class="olsc-gap-above">
      <a :href="HOME" class="el-button el-button--primary">{{ t('cpanel.purgeNow.back') }}</a>
      <a href="#/cache" class="el-button">{{ t('cpanel.purgeNow.details') }}</a>
    </p>
  </div>
</template>
