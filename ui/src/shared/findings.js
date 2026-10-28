// Compatibility findings: the explanation key of a translator blocker and its help entry (UIX-07).
// Blockers come from the .htaccess translator ("<uri>: unsupported ..."); the compat operation names
// the key itself, older replies are classified from the message.

const RULES = [
  [/unsupported PHP handler/, 'php_handler'],
  [/\.htaccess scan incomplete/, 'scan_incomplete'],
  [/\.htaccess is a symlink/, 'symlink'],
  [/\.htaccess unreadable/, 'unreadable'],
  [/unsafe path/, 'unsafe_path'],
  [/Directory Privacy/, 'privacy'],
  [/<Files|<FilesMatch|Files>/, 'files_block'],
  [/access rule combination/, 'access_rules'],
  [/unsupported Options/, 'options'],
  [/conditional Header/, 'conditional_header'],
  [/[Rr]ewrite/, 'rewrite'],
]

// The broker's explanation keys (compat.findings `key`, docs/product-interfaces.md) to the help topics below.
export const BROKER_KEYS = {
  'php.handler': 'php_handler', 'htaccess.scan_incomplete': 'scan_incomplete', 'htaccess.symlink': 'symlink',
  'htaccess.unreadable': 'unreadable', 'htaccess.unsafe_path': 'unsafe_path', 'htaccess.directory_privacy': 'privacy',
  'htaccess.section_body': 'files_block', 'htaccess.section_pattern': 'files_block', 'htaccess.access_rules': 'access_rules',
  'htaccess.options': 'options', 'htaccess.conditional_header': 'conditional_header', 'htaccess.rewrite': 'rewrite',
  'htaccess.directive': 'directive', 'htaccess.other': 'directive',
}

export const EXPLANATION_KEYS = [
  'php_handler', 'scan_incomplete', 'symlink', 'unreadable', 'unsafe_path', 'privacy', 'files_block', 'access_rules', 'options', 'conditional_header', 'rewrite', 'directive',
  'hybrid_vhost', 'php_dso', 'missing_alias_dir', 'tls_missing', 'suspended', 'unknown',
]

// Where each explanation is documented in the repository (and the installed documentation).
const ENGINE_DOC = 'docs/product-architecture.md#configuration-engine'
const HYBRID_DOC = 'docs/product-interfaces.md#hybrid-profile-constraints'
export const HELP_DOCS = {
  php_handler: HYBRID_DOC, scan_incomplete: ENGINE_DOC, symlink: ENGINE_DOC, unreadable: ENGINE_DOC, unsafe_path: ENGINE_DOC, privacy: ENGINE_DOC, files_block: ENGINE_DOC, access_rules: ENGINE_DOC, options: ENGINE_DOC,
  conditional_header: ENGINE_DOC, rewrite: ENGINE_DOC, directive: ENGINE_DOC, missing_alias_dir: ENGINE_DOC,
  tls_missing: ENGINE_DOC, suspended: ENGINE_DOC,
  hybrid_vhost: HYBRID_DOC, php_dso: HYBRID_DOC, profile: HYBRID_DOC,
  cutover: 'docs/product-architecture.md#installation-and-cutover-18',
  apache_return: 'docs/product-architecture.md#return-to-apache-and-uninstall-19',
  generations: 'docs/product-architecture.md#generations-and-activation',
  doctor: 'docs/product-interfaces.md#command-line-interface-ols-cpanel-root-unless-noted',
  default: 'docs/product-architecture.md',
}

export function classifyBlocker(message) {
  const text = String(message || '')
  for (const [pattern, key] of RULES) if (pattern.test(text)) return key
  return 'directive'
}

/**
 * One blocker as a displayable finding: translator text, or an object (the broker's compat finding
 * {kind, severity, directory, file, line, key, message}, or {message, line, file}).
 */
export function normalizeBlocker(blocker) {
  const item = typeof blocker === 'string' ? { message: blocker } : { ...(blocker || {}) }
  const message = String(item.message ?? '')
  const split = message.indexOf(': ')
  return {
    message,
    location: item.location ?? item.directory ?? (split > 0 ? message.slice(0, split) : null),
    detail: split > 0 ? message.slice(split + 2) : message,
    line: Number.isInteger(item.line) ? item.line : null,
    file: item.file ?? null,
    severity: SEVERITIES.includes(item.severity) ? item.severity : null,
    explanation: BROKER_KEYS[item.key] ?? (EXPLANATION_KEYS.includes(item.explanation) ? item.explanation : classifyBlocker(message)),
  }
}

export const SEVERITIES = ['blocker', 'warning', 'info']

export function severityTone(severity) {
  return { blocker: 'bad', warning: 'warn', info: 'info' }[severity] || 'neutral'
}
