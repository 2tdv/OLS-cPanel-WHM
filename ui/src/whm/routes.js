import { lazyView } from '../shared/mount.js'

// The WHM application's one route and navigation registry. A feature vertical (plan 21.6, FV-01..FV-08)
// adds its view with one entry here plus its catalog strings (whm.nav.<name>, i18n.js), as `cache` does below:
// `path` is the hash route (segments starting with ':' are parameters passed to the view as
// `params`); `nav: '<name>'` marks a nested route that highlights another entry instead of having its
// own navigation item. Order is navigation order. Each view is its own chunk, loaded on first use.
export const routes = [
  { name: 'overview', path: 'overview', view: lazyView(() => import('./views/OverviewView.vue')) },
  { name: 'switch', path: 'switch', view: lazyView(() => import('./views/SwitchView.vue')) },
  { name: 'compat', path: 'compatibility', view: lazyView(() => import('./views/CompatView.vue')) },
  { name: 'accounts', path: 'accounts', view: lazyView(() => import('./views/AccountsView.vue')) },
  { name: 'generations', path: 'generations', view: lazyView(() => import('./views/GenerationsView.vue')) },
  { name: 'jobs', path: 'jobs', view: lazyView(() => import('./views/JobsView.vue')) },
  { name: 'job', path: 'jobs/:id', nav: 'jobs', view: lazyView(() => import('./views/JobsView.vue')) },
  { name: 'cache', path: 'cache', view: lazyView(() => import('./views/CacheView.vue')) },
  { name: 'php', path: 'php', view: lazyView(() => import('./views/PhpView.vue')) },
  { name: 'objcache', path: 'objcache', view: lazyView(() => import('./views/ObjectCacheView.vue')) },
  { name: 'requests', path: 'requests', view: lazyView(() => import('./views/RequestsView.vue')) },
  { name: 'diagnostics', path: 'diagnostics', view: lazyView(() => import('./views/DiagnosticsView.vue')) },
  // FV-07 operations.
  { name: 'activity', path: 'activity', view: lazyView(() => import('./views/ActivityView.vue')) },
  { name: 'notifications', path: 'notifications', view: lazyView(() => import('./views/NotificationsView.vue')) },
  { name: 'maintenance', path: 'maintenance', view: lazyView(() => import('./views/MaintenanceView.vue')) },
  { name: 'updates', path: 'updates', view: lazyView(() => import('./views/UpdatesView.vue')) },
  { name: 'support', path: 'support', view: lazyView(() => import('./views/SupportView.vue')) },
]

export const fallback = 'overview'
