import { computed, inject, ref, shallowRef, watch } from 'vue'
import { send as defaultSend } from '@ols/transport'
import { toMillis } from './format.js'

// One request layer for both hosts (docs/product-interfaces.md, "Gateways"): reads are
// GET <page>?api=<name>&<args>, mutations POST <page>?action=<name> with {scope, digest} and the
// X-OLS-cPanel-Request header. The endpoint is the host page itself, so every URL stays inside the
// authenticated WHM/cPanel session path. The transport is the only part fixture mode replaces.

// Mutations of the WHM gateway: the capability actions of "Admin socket: jobs for WHM".
export const ACTIONS = Object.freeze({
  sync: 'ols.sync',
  rollback: 'ols.rollback',
  plan: 'ols.plan',
  planHybrid: 'ols.plan_hybrid',
  cutover: 'ols.cutover',
  apacheReturn: 'ols.apache_return',
  cachePurge: 'ols.cache_purge',
  phpRestart: 'ols.php_restart',
  opcacheInstall: 'ols.opcache_install',
  phpEnvRepair: 'ols.php_env_repair',
  supportBundle: 'ols.support_bundle',
  supportBundleRaw: 'ols.support_bundle_raw',
})

// Mutations of the cPanel gateway: synchronous, no job (plugins/cpanel/index.live.php).
export const CPANEL_ACTIONS = Object.freeze({
  cachePurge: 'cache_purge',
  phpRestart: 'php_restart',
  htaccessApply: 'htaccess_apply',
  htaccessUndo: 'htaccess_undo',
  request: 'request',
})

// Settings changes and small operations of the WHM gateway: synchronous, no job, no digest (the limits of the automatic page cache
// cleanup, the notification settings and test, maintenance windows).
export const WHM_SETTINGS = Object.freeze({
  cacheLimits: 'cache_limits',
  requestStatus: 'request_status',
  notifySettings: 'notify_settings',
  notifyTest: 'notify_test',
  scheduleAdd: 'schedule_add',
  scheduleCancel: 'schedule_cancel',
})

export const REQUEST_HEADER = 'X-OLS-cPanel-Request'

export class ApiError extends Error {
  constructor(code, message, status = 0) {
    super(message || code)
    this.code = code
    this.status = status
  }

  // Session expired, feature disabled or not root: the view shows the unauthorized state.
  get unauthorized() {
    return this.code === 'SESSION' || this.status === 401 || this.status === 403
  }
}

/** The address of a support bundle download (the gateway serves the file as an attachment). */
export function downloadUrl(endpoint, name) {
  return `${endpoint}?${new URLSearchParams({ download: String(name) }).toString()}`
}

export function buildUrl(endpoint, params) {
  const search = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== '') search.set(key, String(value))
  }
  return `${endpoint}?${search.toString()}`
}

function unwrap({ status, body }) {
  if (status === 0 || (body === null && (status === 200 || status === 401 || status === 403))) {
    throw new ApiError('SESSION', '', status)
  }
  if (body && body.ok === true) return body.result
  const code = body?.error?.code || (status === 401 || status === 403 ? 'FORBIDDEN' : 'BAD_REPLY')
  throw new ApiError(code, body?.error?.message || `HTTP ${status}`, status)
}

export function createClient(endpoint, send = defaultSend) {
  async function call(request) {
    let reply
    try {
      reply = await send(request)
    } catch (e) {
      throw new ApiError('NETWORK', e?.message || String(e))
    }
    return unwrap(reply)
  }
  return {
    endpoint,
    get(name, args = {}) {
      return call({ method: 'GET', url: buildUrl(endpoint, { api: name, ...args }), headers: { Accept: 'application/json' } })
    },
    act(action, { scope, digest }) {
      if (!Object.values(ACTIONS).includes(action)) throw new ApiError('BAD_ACTION', action)
      return call({
        method: 'POST',
        url: buildUrl(endpoint, { action }),
        headers: { Accept: 'application/json', 'Content-Type': 'application/json', [REQUEST_HEADER]: '1' },
        body: JSON.stringify({ scope, digest }),
      })
    },
    // A cPanel account's own mutation: POST <page>?action=<name> with a small JSON object, same header.
    post(action, body = {}) {
      if (!Object.values(CPANEL_ACTIONS).includes(action) && !Object.values(WHM_SETTINGS).includes(action)) throw new ApiError('BAD_ACTION', action)
      return call({
        method: 'POST',
        url: buildUrl(endpoint, { action }),
        headers: { Accept: 'application/json', 'Content-Type': 'application/json', [REQUEST_HEADER]: '1' },
        body: JSON.stringify(body),
      })
    },
  }
}

export const CLIENT_KEY = Symbol('ols-cpanel-client')

export function useClient() {
  return inject(CLIENT_KEY)
}

export function toApiError(e) {
  return e instanceof ApiError ? e : new ApiError('CLIENT', e?.message || String(e))
}

/**
 * A read operation with its loading, error and freshness state. Responses that arrive after a newer
 * request was started are dropped (fast typing in a search box never shows an older page). A failed
 * refresh keeps the previous data, which the views then show as stale. `load()` resolves to true on
 * success so pollers can back off on failure.
 */
export function useResource(client, name, options = {}) {
  const data = shallowRef(null)
  const error = shallowRef(null)
  const loading = ref(false)
  const loadedAt = ref(null)
  let sequence = 0

  async function load() {
    const mine = ++sequence
    loading.value = true
    try {
      const args = typeof options.params === 'function' ? options.params() : options.params
      const result = await client.get(name, args || {})
      if (mine !== sequence) return true
      data.value = result
      error.value = null
      loadedAt.value = Date.now()
      return true
    } catch (e) {
      if (mine !== sequence) return false
      error.value = toApiError(e)
      if (error.value.unauthorized) {
        data.value = null
        loadedAt.value = null
      }
      return false
    } finally {
      if (mine === sequence) loading.value = false
    }
  }

  // The time of the observation itself when the operation reports it (every value carries
  // observed_at), otherwise the time this page received it.
  const observedAt = computed(() => toMillis(data.value?.observed_at) ?? loadedAt.value)
  const source = computed(() => data.value?.source ?? null)
  return { name, data, error, loading, loadedAt, observedAt, source, staleAfter: options.staleAfter ?? 5 * 60 * 1000, load }
}

/**
 * The report inside a reply that wraps a product command (`doctor`, `generations`: {observed_at, source,
 * exit_code, output}); other replies are returned as they are.
 */
export function commandOutput(reply) {
  return reply && typeof reply === 'object' && 'exit_code' in reply && 'output' in reply ? reply.output : reply
}

/** A mutation that starts a product job: run() resolves to the job id, or null with `error` set. */
export function useAction(client) {
  const busy = ref(false)
  const error = shallowRef(null)
  async function run(action, payload) {
    busy.value = true
    error.value = null
    try {
      const result = await client.act(action, payload)
      if (result?.job === undefined || result?.job === null || result?.job === '') throw new ApiError('BAD_REPLY', 'no job id')
      return String(result.job)
    } catch (e) {
      error.value = toApiError(e)
      return null
    } finally {
      busy.value = false
    }
  }
  return { busy, error, run }
}

/** A synchronous mutation (cPanel `post`): run() resolves to the reply, or null with `error` set. */
export function useMutation(client) {
  const busy = ref(false)
  const error = shallowRef(null)
  async function run(action, body) {
    busy.value = true
    error.value = null
    try {
      return await client.post(action, body)
    } catch (e) {
      error.value = toApiError(e)
      return null
    } finally {
      busy.value = false
    }
  }
  return { busy, error, run }
}

/**
 * 'none' (nothing loaded), 'stale' (the last refresh failed, the operation itself reports stale data,
 * or the data is older than the resource's limit) or 'fresh'.
 */
export function freshness(resource, now) {
  const data = resource.data.value
  if (resource.loadedAt.value === null) return 'none'
  if (resource.error.value) return 'stale'
  if (data?.status === 'stale') return 'stale'
  if (resource.loadedAt.value !== null && now - resource.loadedAt.value > resource.staleAfter) return 'stale'
  return 'fresh'
}

// The gateways' search grammar (plugins/whm/index.cgi PARAMS.query): anything else is refused as BAD_QUERY.
export const QUERY_PATTERN = /^[A-Za-z0-9._-]{0,253}$/

/** Server-side search and paging (inventory, compat): only one page is ever held in the browser. */
export function usePaged(client, name, { size = 50, rowsKey, debounce = 300, extra = null } = {}) {
  const query = ref('')
  const queryInvalid = computed(() => !QUERY_PATTERN.test(query.value.trim()))
  const page = ref(1)
  const pageSize = ref(size)
  const resource = useResource(client, name, {
    params: () => ({ query: query.value.trim(), page: page.value, size: pageSize.value, ...(extra ? extra() : {}) }),
  })
  const rows = computed(() => resource.data.value?.[rowsKey] || [])
  const total = computed(() => (Number.isInteger(resource.data.value?.total) ? resource.data.value.total : null))
  let timer = null
  watch(query, () => {
    clearTimeout(timer)
    if (queryInvalid.value) return // the field explains the grammar; nothing is sent
    timer = setTimeout(() => {
      if (page.value !== 1) page.value = 1
      else resource.load()
    }, debounce)
  })
  watch([page, pageSize], () => resource.load())
  // Further filters (the Activity view's event and result): a change starts again from the first page.
  if (extra) {
    watch(extra, () => {
      if (page.value !== 1) page.value = 1
      else resource.load()
    }, { deep: true })
  }
  return { query, queryInvalid, page, pageSize, resource, rows, total }
}

/** Every page of a paged operation for one query (CSV export), bounded so it never runs away. */
export async function fetchAllPages(client, name, rowsKey, args = {}, maxPages = 50) {
  const rows = []
  for (let page = 1; page <= maxPages; page++) {
    const result = await client.get(name, { ...args, page, size: 200 })
    const chunk = result?.[rowsKey] || []
    rows.push(...chunk)
    if (!chunk.length || rows.length >= (result?.total ?? 0)) return { rows, complete: true }
  }
  return { rows, complete: false }
}
