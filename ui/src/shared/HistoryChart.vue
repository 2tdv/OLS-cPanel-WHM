<script setup>
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { chartPaths, scaleMax, seriesOf, summarize, timeLabel } from './history.js'
import { formatBytes, formatNumber } from './format.js'

// One line chart (inline SVG, no chart library). Several series share one scale; gaps stay gaps. Every value is also
// given as text below the chart, so the numbers do not depend on reading the drawing.
const props = defineProps({
  title: { type: String, required: true },
  data: { type: Object, required: true },
  channels: { type: Array, required: true },
  unit: { type: String, default: 'count' },
  resolution: { type: String, default: 'hour' },
})
const { t } = useI18n()
const W = 600
const H = 150
const box = { left: 44, top: 8, width: W - 44 - 8, height: H - 8 - 22 }

const series = computed(() => props.channels.map((key, index) => ({ key, index, values: seriesOf(props.data, key) })))
const max = computed(() => scaleMax(series.value.map(s => s.values)))
const lines = computed(() => series.value.map(s => ({ ...s, ...chartPaths(s.values, { ...box, max: max.value }), summary: summarize(s.values) })))
const empty = computed(() => lines.value.every(s => s.summary === null))
const startLabel = computed(() => timeLabel(props.data.start, props.resolution))
const endLabel = computed(() => timeLabel(props.data.start + (props.data.count - 1) * props.data.step, props.resolution))

function show(value) {
  if (props.unit === 'bytes') return t('units.perSecond', { n: formatBytes(value) ?? t('state.unknown') })
  if (props.unit === 'rate') return t('units.perSecond', { n: formatNumber(value) ?? t('state.unknown') })
  return formatNumber(value) ?? t('state.unknown')
}
const topLabel = computed(() => show(max.value))
const description = computed(() => (empty.value
  ? t('history.noSamplesShort', { title: props.title })
  : t('history.chartLabel', { title: props.title, from: startLabel.value, to: endLabel.value, max: topLabel.value })))
</script>

<template>
  <figure class="olsc-card olsc-chart">
    <figcaption class="olsc-h3">{{ props.title }}</figcaption>
    <p v-if="empty" class="olsc-muted">{{ t('history.noSamples') }}</p>
    <template v-else>
      <svg :viewBox="`0 0 ${W} ${H}`" role="img" :aria-label="description" class="olsc-chart-svg" focusable="false">
        <line v-for="g in [0, 0.5, 1]" :key="g" class="olsc-chart-grid" :x1="box.left" :x2="box.left + box.width"
              :y1="box.top + box.height * g" :y2="box.top + box.height * g" />
        <text class="olsc-chart-axis" :x="box.left - 6" :y="box.top + 4" text-anchor="end">{{ topLabel }}</text>
        <text class="olsc-chart-axis" :x="box.left - 6" :y="box.top + box.height + 4" text-anchor="end">0</text>
        <text class="olsc-chart-axis" :x="box.left" :y="H - 6" text-anchor="start">{{ startLabel }}</text>
        <text class="olsc-chart-axis" :x="box.left + box.width" :y="H - 6" text-anchor="end">{{ endLabel }}</text>
        <g v-for="line in lines" :key="line.key" :class="`olsc-chart-line olsc-chart-s${line.index}`">
          <path v-for="(d, i) in line.segments" :key="i" :d="d" fill="none" />
          <circle v-for="(dot, i) in line.dots" :key="`d${i}`" :cx="dot[0]" :cy="dot[1]" r="2" />
        </g>
      </svg>
      <ul class="olsc-chart-legend">
        <li v-for="line in lines" :key="line.key" :class="`olsc-chart-s${line.index}`">
          <span class="olsc-chart-swatch" aria-hidden="true" />
          <span>{{ t(`history.series.${line.key}`) }}</span>
          <span v-if="line.summary" class="olsc-muted">
            {{ t('history.values', { latest: show(line.summary.latest), peak: show(line.summary.peak), average: show(line.summary.average) }) }}
          </span>
        </li>
      </ul>
    </template>
  </figure>
</template>
