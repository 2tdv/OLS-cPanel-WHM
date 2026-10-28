// Development fixture of the metrics history (admin.metrics, tenant.metrics): deterministic series in the reply
// shape of docs/product-interfaces.md, "Metrics history" (buckets of `step` seconds from `start`, null for a gap).
// Never part of a production build (ui/dev is only reachable through the fixture transport alias).

const LEVELS = { hour: [10, 360], day: [60, 1440], week: [600, 1008] }
const SERVER = ['requests_per_second', 'requests_processing', 'connections', 'tls_connections', 'bytes_in_per_second',
  'bytes_out_per_second', 'cache_hits_per_second', 'php_in_use']
const VHOST = ['requests_per_second', 'cache_hits_per_second', 'static_hits_per_second', 'php_in_use']
const SCALE = {
  requests_per_second: 40, requests_processing: 6, connections: 120, tls_connections: 90, bytes_in_per_second: 40000,
  bytes_out_per_second: 1800000, cache_hits_per_second: 22, static_hits_per_second: 15, php_in_use: 5,
}

/** A reply for the server (vhost null) or one vhost; `vhosts` is the list the picker offers. `gap` leaves a hole. */
export function historyReply({ resolution = 'hour', vhost = null, vhosts = [], user = null, now = Math.floor(Date.now() / 1000), gap = true }) {
  const [step, count] = LEVELS[resolution]
  const end = Math.floor(now / step) * step
  const start = end - (count - 1) * step
  const names = vhost === null && user === null ? SERVER : VHOST
  const seed = [...(vhost || 'server')].reduce((a, c) => a + c.charCodeAt(0), 0)
  const channels = {}
  names.forEach((name, c) => {
    channels[name] = Array.from({ length: count }, (_, i) => {
      if (gap && i > count * 0.4 && i < count * 0.4 + Math.max(2, count * 0.03)) return null
      const wave = 0.55 + 0.35 * Math.sin((i + seed) / (count / 7)) + 0.1 * Math.sin((i * (c + 3)) / 5)
      const v = SCALE[name] * Math.max(0.02, wave) * (name === 'tls_connections' ? 0.75 : 1) * (vhost ? 0.3 : 1)
      return Math.round(v * 1000) / 1000
    })
  })
  const samples = channels[names[0]].filter(v => v !== null).length
  const reply = { observed_at: now, source: user ? 'OpenLiteSpeed real-time reports' : '/var/lib/ols-cpanel/metrics', vhost,
    vhosts, resolution, start, step, count, samples, interval: 10, channels }
  return user ? { ...reply, user } : { ...reply, scope: vhost === null ? 'server' : 'vhost' }
}
