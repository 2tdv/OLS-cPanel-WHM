import { lazyView } from '../shared/mount.js'

// The cPanel application's one route and navigation registry (same rules as src/whm/routes.js): a
// feature vertical (plan 21.6) adds its view with one entry here plus `cpanel.nav.<name>` in i18n.js.
export const routes = [
  { name: 'sites', path: 'sites', view: lazyView(() => import('./views/SitesView.vue')) },
  { name: 'htaccess', path: 'htaccess', view: lazyView(() => import('./views/HtaccessView.vue')) },
  { name: 'cache', path: 'cache', view: lazyView(() => import('./views/CacheView.vue')) },
  { name: 'php', path: 'php', view: lazyView(() => import('./views/PhpView.vue')) },
  { name: 'logs', path: 'logs', view: lazyView(() => import('./views/LogsView.vue')) },
  { name: 'perf', path: 'performance', view: lazyView(() => import('./views/PerfView.vue')) },
  { name: 'requests', path: 'requests', view: lazyView(() => import('./views/RequestsView.vue')) },
  { name: 'objcache', path: 'objcache', view: lazyView(() => import('./views/ObjectCacheView.vue')) },
  { name: 'history', path: 'history', view: lazyView(() => import('./views/HistoryView.vue')) },
  // The dashboard's one-click "Clear cache" icon; not in the menu (it belongs to the Page cache view).
  { name: 'purge', path: 'purge', nav: 'cache', view: lazyView(() => import('./views/PurgeNowView.vue')) },
]

export const fallback = 'sites'
