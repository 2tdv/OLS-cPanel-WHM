// Which web server answers on 80/443. The status operation (`ols-cpanel status`) reports `ports` as
// {"80": [process names], "443": [...]} ("unknown" when a listener's process is not visible, [] when free;
// a single name is accepted too).
const OLS_PROCESSES = ['litespeed', 'lshttpd', 'openlitespeed']
const APACHE_PROCESSES = ['httpd', 'apache2']

/** 'ols' | 'apache' | 'none' | 'other' (some other or several processes) | 'unknown' (not reported). */
function processes(status, port) {
  const value = status?.ports?.[String(port)]
  return Array.isArray(value) ? value.map(String) : typeof value === 'string' && value ? [value] : null
}

export function portOwner(status, port) {
  const names = processes(status, port)
  if (names === null) return 'unknown'
  if (names.length === 0) return 'none'
  if (names.every(n => OLS_PROCESSES.includes(n))) return 'ols'
  if (names.every(n => APACHE_PROCESSES.includes(n))) return 'apache'
  return names.every(n => n === 'unknown') ? 'unknown' : 'other'
}

export function portProcesses(status, port) {
  return (processes(status, port) || []).join(', ')
}

/** The server's serving engine: the owner of both 80 and 443, else derived from the unit states. */
export function serverEngine(status) {
  if (!status || typeof status !== 'object') return 'unknown'
  if (status.ports && typeof status.ports === 'object') {
    const http = portOwner(status, 80)
    if (http === portOwner(status, 443) && ['ols', 'apache', 'none'].includes(http)) return http
    return 'unknown'
  }
  if (status.ols_active === true) return 'ols'
  if (status.apache_active === true) return 'apache'
  if (status.ols_active === false && status.apache_active === false) return 'none'
  return 'unknown'
}

/** True when the server is cut over (a deployment profile exists). Null when not reported. */
export function cutOver(status) {
  if (typeof status?.cut_over === 'boolean') return status.cut_over
  if (!status || !('profile' in status)) return null
  return status.profile !== null && typeof status.profile === 'object'
}

/** 'native' | 'hybrid' | 'none' (not cut over) | 'invalid' (unreadable profile.json) | 'unknown'. */
export function profileName(profile) {
  if (profile === undefined) return 'unknown'
  if (profile === null) return 'none'
  if (typeof profile !== 'object' || 'error' in profile) return 'invalid'
  return Array.isArray(profile.hybrid_ports) && profile.hybrid_ports.length ? 'hybrid' : 'native'
}
