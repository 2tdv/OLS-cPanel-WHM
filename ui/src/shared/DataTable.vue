<script setup>
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import StateView from './StateView.vue'
import { formatNumber } from './format.js'

// Server-side search and paging over a paged operation (usePaged): only one page is in the browser,
// so 10,000+ domains stay fast (UIX-02). Columns come from the default slot (el-table-column).
const props = defineProps({
  paged: { type: Object, required: true },
  caption: { type: String, required: true },
  searchLabel: { type: String, required: true },
  emptyText: { type: String, default: '' },
  rows: { type: Array, default: null },
  rowKey: { type: String, default: undefined },
  pageSizes: { type: Array, default: () => [25, 50, 100, 200] },
})
const { t } = useI18n()
const searchId = `olsc-search-${Math.random().toString(36).slice(2, 10)}`
const hintId = `${searchId}-hint`
const shown = computed(() => props.rows ?? props.paged.rows.value)
const total = computed(() => props.paged.total.value)
</script>

<template>
  <div class="olsc-datatable">
    <div class="olsc-toolbar" role="search">
      <label :for="searchId" class="olsc-sr-only">{{ props.searchLabel }}</label>
      <el-input :id="searchId" v-model="props.paged.query.value" :placeholder="props.searchLabel" clearable
                class="olsc-search" :aria-invalid="props.paged.queryInvalid.value ? 'true' : 'false'"
                :aria-describedby="hintId" />
      <slot name="toolbar" />
      <span class="olsc-muted olsc-count" aria-live="polite">
        {{ total === null ? t('table.totalUnknown') : t('table.total', { n: formatNumber(total) }) }}
      </span>
    </div>
    <p :id="hintId" class="olsc-hint" :class="{ 'olsc-sr-only': !props.paged.queryInvalid.value }" role="status">
      {{ t('table.queryHint') }}
    </p>
    <StateView :resource="props.paged.resource" :empty="props.paged.resource.data.value !== null && !shown.length"
               :empty-text="props.emptyText">
      <div role="region" :aria-label="props.caption" class="olsc-table-wrap">
        <el-table :data="shown" :row-key="props.rowKey" stripe size="small" :empty-text="props.emptyText || t('state.empty')">
          <slot />
        </el-table>
      </div>
      <el-pagination v-if="total !== null && total > 0" v-model:current-page="props.paged.page.value"
                     v-model:page-size="props.paged.pageSize.value" :total="total" :page-sizes="props.pageSizes"
                     layout="total, sizes, prev, pager, next" :pager-count="5" class="olsc-pagination" background />
    </StateView>
  </div>
</template>
