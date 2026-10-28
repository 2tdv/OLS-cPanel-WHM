import { computed, onBeforeUnmount, onMounted, ref } from 'vue'

// Hash routing (plan 21.3: CGI simplicity; a browser refresh or a bookmarked nested route never
// leaves the session-prefixed page). Routes: [{ name, path: 'jobs/:id', view }].

export function parseHash(hash) {
  const path = String(hash || '').replace(/^#\/?/, '').split('?')[0]
  return path.split('/').filter(Boolean).map(segment => {
    try {
      return decodeURIComponent(segment)
    } catch {
      return segment
    }
  })
}

export function matchRoute(routes, segments, fallback) {
  for (const route of routes) {
    const parts = route.path.split('/').filter(Boolean)
    if (parts.length !== segments.length) continue
    const params = {}
    const matched = parts.every((part, i) => {
      if (part.startsWith(':')) {
        params[part.slice(1)] = segments[i]
        return true
      }
      return part === segments[i]
    })
    if (matched) return { route, params }
  }
  return { route: routes.find(r => r.name === fallback), params: {} }
}

export function href(path) {
  return `#/${path.split('/').map(encodeURIComponent).join('/')}`
}

/**
 * The view a dashboard link asks for: `?view=<route name>` (cPanel's dashboard icons link to the plugin page with a query
 * string; the fragment is the router's own). Only a known route name without parameters is used.
 */
export function initialHash(routes, location = globalThis.location) {
  if (!location || (location.hash && location.hash !== '#')) return location?.hash || ''
  const view = new URLSearchParams(location.search || '').get('view')
  const route = routes.find(r => r.name === view && !r.path.includes(':'))
  return route ? href(route.path) : ''
}

export function useHashRouter(routes, fallback) {
  const start = initialHash(routes)
  if (start && globalThis.location && globalThis.location.hash !== start) {
    globalThis.history?.replaceState?.(null, '', start)
  }
  const hash = ref(start || globalThis.location?.hash || '')
  const update = () => { hash.value = globalThis.location.hash }
  onMounted(() => window.addEventListener('hashchange', update))
  onBeforeUnmount(() => window.removeEventListener('hashchange', update))
  const current = computed(() => matchRoute(routes, parseHash(hash.value), fallback))
  return {
    current,
    navigate(path) {
      globalThis.location.hash = href(path)
    },
  }
}
