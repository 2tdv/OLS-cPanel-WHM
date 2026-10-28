import { onBeforeUnmount, onMounted, onServerPrefetch, ref } from 'vue'

// Live views without polling storms (UIX-02): one request at a time per view, the next one scheduled
// only after the previous finished, exponential backoff on failure, nothing while the tab is hidden
// (one refresh when it becomes visible again).

export function nextDelay(interval, failures, maxInterval) {
  return Math.min(maxInterval, interval * 2 ** Math.min(failures, 16))
}

export function createPoller(task, { interval, maxInterval = interval * 8, timers = globalThis, doc = globalThis.document } = {}) {
  let timer = null
  let failures = 0
  let running = false
  let stopped = true

  const schedule = ms => {
    timers.clearTimeout(timer)
    timer = timers.setTimeout(tick, ms)
  }

  async function tick() {
    timer = null
    if (stopped || running) return
    if (doc?.hidden) return // resumed by the visibility listener
    running = true
    let ok = false
    try {
      ok = (await task()) !== false
    } catch {
      ok = false
    }
    running = false
    failures = ok ? 0 : failures + 1
    if (!stopped) schedule(nextDelay(interval, failures, maxInterval))
  }

  function onVisibility() {
    if (!doc.hidden && !stopped && !running && timer === null) tick()
  }

  return {
    get failures() { return failures },
    get delay() { return nextDelay(interval, failures, maxInterval) },
    start({ immediate = true } = {}) {
      if (!stopped) return
      stopped = false
      doc?.addEventListener?.('visibilitychange', onVisibility)
      if (immediate) tick()
      else schedule(interval)
    },
    stop() {
      stopped = true
      timers.clearTimeout(timer)
      timer = null
      doc?.removeEventListener?.('visibilitychange', onVisibility)
    },
    refresh() {
      timers.clearTimeout(timer)
      timer = null
      return tick()
    },
  }
}

/** A view's initial load: on mount in the browser, before rendering when rendered on a server (tests). */
export function useLoad(task) {
  onMounted(task)
  onServerPrefetch(task)
}

/** A poller bound to the component lifetime (started on mount; a server rendering loads once, never polls). */
export function usePolling(task, options) {
  const poller = createPoller(task, options)
  onMounted(() => poller.start())
  onServerPrefetch(task)
  onBeforeUnmount(() => poller.stop())
  return poller
}

// One shared clock for relative times ("observed 12 s ago"), ticking only while something shows it.
const now = ref(Date.now())
let subscribers = 0
let clock = null

export function useNow() {
  onMounted(() => {
    subscribers++
    now.value = Date.now()
    if (clock === null) clock = setInterval(() => { if (!globalThis.document?.hidden) now.value = Date.now() }, 5000)
  })
  onBeforeUnmount(() => {
    subscribers--
    if (subscribers === 0 && clock !== null) {
      clearInterval(clock)
      clock = null
    }
  })
  return now
}
