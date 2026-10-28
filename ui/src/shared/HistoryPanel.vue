<script setup>
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import HistoryChart from './HistoryChart.vue'
import { RESOLUTIONS, SERVER_CHARTS, VHOST_CHARTS } from './history.js'
import { formatNumber } from './format.js'

// The charts of one history reply (admin.metrics or tenant.metrics) with the time range picker and, when the reply
// lists vhosts, a picker for the site; the parent owns the request and passes the choices back through v-model.
// `allowServer` adds the whole server as the first choice (WHM only).
const props = defineProps({
  data: { type: Object, required: true },
  resolution: { type: String, default: 'hour' },
  vhost: { type: String, default: '' },
  allowServer: { type: Boolean, default: false },
})
const emit = defineEmits(['update:resolution', 'update:vhost'])
const { t } = useI18n()
const vhosts = computed(() => (Array.isArray(props.data.vhosts) ? props.data.vhosts : []))
const charts = computed(() => (props.data.scope === 'server' ? SERVER_CHARTS : VHOST_CHARTS))
const showPicker = computed(() => vhosts.value.length > (props.allowServer ? 0 : 1))
</script>

<template>
  <div>
    <div class="olsc-toolbar">
      <el-radio-group :model-value="props.resolution" :aria-label="t('history.range')"
                      @update:model-value="value => emit('update:resolution', value)">
        <el-radio-button v-for="r in RESOLUTIONS" :key="r" :value="r" :label="t(`history.resolution.${r}`)" />
      </el-radio-group>
      <template v-if="showPicker">
        <label for="olsc-history-vhost" class="olsc-sr-only">{{ t('history.site') }}</label>
        <el-select id="olsc-history-vhost" :model-value="props.vhost" class="olsc-filter" :aria-label="t('history.site')"
                   @update:model-value="value => emit('update:vhost', value)">
          <el-option v-if="props.allowServer" value="" :label="t('history.wholeServer')" />
          <el-option v-for="v in vhosts" :key="v" :value="v" :label="v" />
        </el-select>
      </template>
    </div>
    <div class="olsc-grid olsc-chart-grid-wide">
      <HistoryChart v-for="chart in charts" :key="`${props.data.scope}-${props.data.vhost}-${chart.id}`" :title="t(chart.title)"
                    :data="props.data" :channels="chart.series" :unit="chart.unit" :resolution="props.data.resolution" />
    </div>
    <p class="olsc-muted olsc-small">{{ t('history.explain', { seconds: formatNumber(props.data.interval) ?? '10' }) }}</p>
  </div>
</template>
