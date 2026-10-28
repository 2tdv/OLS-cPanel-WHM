// Metrics history (FV-05): the pure parts of the charts. The broker returns, per resolution, `count` buckets of `step`
// seconds starting at `start`, one array per channel with null for a bucket without samples (docs/product-interfaces.md,
// "Metrics history"). Nothing here guesses: a gap stays a gap in the line.

export const RESOLUTIONS = Object.freeze(['hour', 'day', 'week'])

// Chart definitions: the channels of one chart share a scale. `unit` picks the value format.
export const SERVER_CHARTS = Object.freeze([
  { id: 'requests', title: 'metrics.requests', unit: 'rate', series: ['requests_per_second'] },
  { id: 'connections', title: 'metrics.connections', unit: 'count', series: ['connections', 'tls_connections'] },
  { id: 'bandwidth', title: 'metrics.bandwidth', unit: 'bytes', series: ['bytes_in_per_second', 'bytes_out_per_second'] },
  { id: 'processing', title: 'metrics.processing', unit: 'count', series: ['requests_processing'] },
  { id: 'cache', title: 'metrics.cacheHits', unit: 'rate', series: ['cache_hits_per_second'] },
  { id: 'php', title: 'metrics.phpInUse', unit: 'count', series: ['php_in_use'] },
])
export const VHOST_CHARTS = Object.freeze([
  { id: 'requests', title: 'metrics.requests', unit: 'rate', series: ['requests_per_second'] },
  { id: 'cache', title: 'metrics.cacheHits', unit: 'rate', series: ['cache_hits_per_second'] },
  { id: 'static', title: 'metrics.staticHits', unit: 'rate', series: ['static_hits_per_second'] },
  { id: 'php', title: 'metrics.phpInUse', unit: 'count', series: ['php_in_use'] },
])

/** The next "nice" number (1, 2, 5 x 10^n) at or above a positive value; 1 for zero or nothing. */
export function niceMax(max) {
  if (!Number.isFinite(max) || max <= 0) return 1
  const power = 10 ** Math.floor(Math.log10(max))
  const unit = max / power
  return (unit <= 1 ? 1 : unit <= 2 ? 2 : unit <= 5 ? 5 : 10) * power
}

const numbers = values => (Array.isArray(values) ? values : []).filter(v => typeof v === 'number' && Number.isFinite(v))

/** Shared scale of several series: the nice maximum of all their values. */
export function scaleMax(seriesValues) {
  return niceMax(Math.max(0, ...seriesValues.flatMap(numbers)))
}

/**
 * The drawing of one series: `segments` are runs of consecutive samples ("M x y L x y ..."), `dots` the isolated
 * samples (a run of one has no line). x spans [left, left + width], y is 0 at the top.
 */
export function chartPaths(values, { left, top, width, height, max }) {
  const list = Array.isArray(values) ? values : []
  const n = list.length
  const x = i => left + (n > 1 ? (i * width) / (n - 1) : width)
  const y = v => top + height - (Math.min(Math.max(v, 0), max) / max) * height
  const round = v => Math.round(v * 10) / 10
  const segments = []
  const dots = []
  let run = []
  const flush = () => {
    if (run.length === 1) dots.push(run[0])
    else if (run.length > 1) segments.push(run.map(([px, py], k) => `${k ? 'L' : 'M'}${px} ${py}`).join(' '))
    run = []
  }
  list.forEach((v, i) => {
    if (typeof v === 'number' && Number.isFinite(v)) run.push([round(x(i)), round(y(v))])
    else flush()
  })
  flush()
  return { segments, dots }
}

/** Latest, peak and mean of the samples that exist; null when there are none. */
export function summarize(values) {
  const list = numbers(values)
  if (!list.length) return null
  return { latest: list[list.length - 1], peak: Math.max(...list), average: list.reduce((a, b) => a + b, 0) / list.length, samples: list.length }
}

/** Clock label of an x-axis end: the time of day for an hour or a day, the date and hour for a week. */
export function timeLabel(seconds, resolution) {
  if (!Number.isFinite(seconds)) return ''
  const d = new Date(seconds * 1000)
  const pad = v => String(v).padStart(2, '0')
  const clock = `${pad(d.getHours())}:${pad(d.getMinutes())}`
  return resolution === 'week' ? `${d.toLocaleDateString('en', { month: 'short', day: 'numeric' })} ${clock}` : clock
}

/** One channel of a reply as an array (empty when the reply does not carry it). */
export function seriesOf(data, key) {
  const values = data?.channels?.[key]
  return Array.isArray(values) ? values : []
}
