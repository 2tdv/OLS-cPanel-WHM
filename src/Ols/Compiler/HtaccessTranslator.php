<?php
declare(strict_types=1);

namespace OlsCpanel\Ols\Compiler;

/**
 * Translates the certified .htaccess subset into OLS vhost realms/contexts (plan §9, R-03, OLS-16).
 * Unknown directives become blockers and are never dropped. mod_rewrite directives become the
 * directory context's own per-directory rules (owner decision HR-D07: OLS never reads .htaccess);
 * proxying, handler flags, targets naming an internal backend (loopback, WebSocket/socket schemes,
 * dotless names such as the cpsrvdNNNN proxy backends), quoted or continued arguments, control
 * characters, heredoc terminators, unknown Rewrite* directives and rules without RewriteEngine are
 * blockers. LiteSpeed Cache sections (<IfModule LiteSpeed>, FV-01) are applied as LiteSpeed applies them:
 * their RewriteEngine, RewriteCond, RewriteRule and CacheKeyModify lines join the directory's rules in
 * document order and "CacheLookup on" is honoured by the vhost cache policy (CachePolicy); "CacheLookup
 * off", ESI and other directives there are blockers, as is a "cache-..." environment flag outside such a
 * section (Apache only sets a variable; OLS would start caching, plan §9.4). <IfModule mod_authz_core.c>,
 * <IfModule mod_expires.c> and <IfModule mod_headers.c> (modules always loaded on cPanel's EasyApache 4) keep their
 * bodies and the negated forms are dropped; ExpiresActive/ExpiresDefault/ExpiresByType become the context's
 * enableExpires/expiresDefault/expiresByType; a lone directory-level "Require all denied" plus <Files>/<FilesMatch>
 * blocks holding only "Require all granted" becomes one regex context with a negative lookahead exempting the
 * allowed basenames. Output is kept byte-identical to the lab-proven
 * build/vm-qualification/htaccess_translate.py (checked by tests/compiler_equivalence.py).
 */
final class HtaccessTranslator
{
    private const PPD = '/#-+cp:ppd.*?# End section managed by cPanel: Password Protected Directories[^\n]*\n#-+cp:ppd/s';
    private const PHP_INI = '/# BEGIN cPanel-generated php ini directives.*?# END cPanel-generated php ini directives[^\n]*/s';
    private const HANDLER = '/# php -- BEGIN cPanel-generated handler.*?# php -- END cPanel-generated handler[^\n]*/s';
    private const REWRITE_BLOCK = '/<IfModule\s+mod_rewrite\.c\s*>(.*?)<\/IfModule>/si';
    private const REWRITE_DIRECTIVE = '/^Rewrite(Engine|Base|Cond|Rule|Options)\b/i';
    private const FILES = '/<(Files|FilesMatch)\s+"?([^">]+)"?\s*>(.*?)<\/\1>/si';
    private const SAFE_PATH = '/^\/[A-Za-z0-9._\/@+-]*$/';
    private const HEADER = '/^Header\s+(?:(?:always|onsuccess)\s+)?(set|append|merge|add|unset)\s+([A-Za-z0-9-]+)(?:\s+(.+))?$/i';
    /**
     * OLS parses a trailing env= but never evaluates it; expr= and early have no OLS equivalent. A quoted condition
     * ("expr=...") is a condition too (soak test 2026-10-30: it was read as part of the value).
     */
    private const HEADER_CONDITION = '/(^|\s)["\']?(env|expr)=|(^|\s)early$/i';
    private const ERROR_DOCUMENT = '/^ErrorDocument\s+([45]\d\d)\s+(\/[A-Za-z0-9._\/-]*)$/';
    // RV-46 (soak test 2026-10-30), what the stock .htaccess of Joomla, Drupal and Laravel need.
    private const DIRECTORY_INDEX = '/^DirectoryIndex((?:[ \t]+[A-Za-z0-9._-]+)+)$/i';
    private const ADD_TYPE = '/^AddType[ \t]+([A-Za-z0-9.+\/_-]+)((?:[ \t]+\.?[A-Za-z0-9]+)+)$/i';
    private const ADD_ENCODING = '/^AddEncoding[ \t]+(gzip|x-gzip)((?:[ \t]+\.?[A-Za-z0-9]+)+)$/i';
    private const INDEX_IGNORE = '/^IndexIgnore\b/i';
    /** OLS answers a request carrying a Proxy header with 400, so Drupal's httpoxy mitigation is already in effect. */
    private const PROXY_UNSET = '/^RequestHeader[ \t]+unset[ \t]+Proxy$/i';
    /** The MIME types OLS 1.9.3 maps these extensions to by default: an AddType naming the same type changes nothing. */
    private const OLS_DEFAULT_MIME = ['svg' => 'image/svg+xml', 'svgz' => 'image/svg+xml', 'webp' => 'image/webp'];
    /** Static file types a header-only <FilesMatch> or AddEncoding may target with its own regex context. */
    private const STATIC_EXTENSION = '/^\\\\\.([A-Za-z0-9]+)\$$/D';
    /**
     * Drupal's "no scripts in uploads" idiom (SA-2006-006, SA-2013-003): a handler name that does not exist, so Apache
     * sends every file of the directory as it is and never runs a script. OLS: the script suffixes of that directory
     * are mapped to a static type (context addMIMEType), so nothing there reaches lsphp.
     */
    private const DRUPAL_NO_SCRIPTS = '/^SetHandler[ \t]+Drupal_Security_Do_Not_Remove_See_SA_[0-9]{4}_[0-9]{3}$/';
    private const NO_SCRIPTS_MIME = 'application/octet-stream php php3 php4 php5 php7 php8 phtml pht phar inc cgi pl py sh shtml';
    private const SCRIPT_EXTENSIONS = ['php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'phar', 'cgi', 'pl', 'py', 'sh',
        'shtml', 'asp', 'aspx', 'jsp'];
    private const IFMODULE_OPEN = '/^<IfModule[ \t]+(!?)([^\s>]+)[ \t]*>$/i';
    private const MODULE_SOURCE = '/^mod_([A-Za-z0-9_]+)\.c$/Di';
    /**
     * Pre-compressed assets (Joomla's and Drupal's stock .htaccess): inside <IfModule mod_headers.c>, .css/.js requests
     * are rewritten to an existing .gz/.br copy, typed with [T=...] and sent with "Content-Encoding". OLS compresses
     * static and dynamic responses itself (gzip and brotli, compressed static copies kept up to date), so the client
     * gets the same resource compressed either way. Only this exact idiom is recognised; the section is left to OLS.
     */
    private const PRECOMPRESSED_SECTION = '/<IfModule[ \t]+mod_headers\.c[ \t]*>((?:(?!<\/?IfModule\b).)*?)<\/IfModule[ \t]*>/si';
    private const PRECOMPRESSED_LINES = [
        '/^RewriteCond[ \t]+"?%\{HTTP:Accept-encoding\}"?[ \t]+"?(gzip|br)"?$/i',
        '/^RewriteCond[ \t]+"?%\{REQUEST_FILENAME\}\\\\\.(gz|br)"?[ \t]+"?-s"?$/i',
        '/^RewriteRule[ \t]+"?\^\(\.\*(?:(css|js)_\[a-zA-Z0-9-_\]\+)?\)\\\\\.(css|js)\$?"?[ \t]+"?\$1\\\\\.(css|js)\\\\\.(gz|br)"?[ \t]+\[QSA\]$/',
        '/^RewriteRule[ \t]+"?\\\\\.(css|js)\\\\\.(gz|br)\$"?[ \t]+"?-"?[ \t]+\[T=(text\/css|text\/javascript|application\/javascript),E=no-gzip:1,E=no-brotli:1\]$/',
    ];
    private const PRECOMPRESSED_FILES = '/^\(\\\\\.js\\\\\.(gz|br)\|\\\\\.css\\\\\.\1\)\$$/D';
    /**
     * Double-quoted rewrite arguments outside <IfModule LiteSpeed> (Drupal's stock rules): Apache and OLS split them the
     * same way and keep inner backslashes, as long as a quoted argument holds no escaped quote and no escaped blank.
     */
    private const APACHE_ARGUMENT = '"(?:[^"\\\\\n]|\\\\[^"\s])*"|[^\s"\']+';
    private const SEARCH_CHARS = '/^[A-Za-z0-9._@\\\\^$|()?*+\[\]#!=<>,~:%-]+$/D';
    private const LOOKAROUND = '/\G\(\?(?:[:=!]|<[=!])/';
    /** Directive names and arguments are separated by any run of blanks; OLS accepts tabs as well as spaces. */
    private const REWRITE_SPACE = '/[ \t]+/';
    private const REWRITE_CONTROL = '/[\x00-\x08\x0a-\x1f\x7f]/';
    /** The complete flag expression: everything after the second argument, which may contain blanks. */
    private const REWRITE_FLAGS = '/^\[([^\[\]]*)\]$/';
    /**
     * Backslash-escaped blanks and line continuations (any rewrite line) and quotes (RewriteRule) would
     * split the arguments differently from the blank-separated reading below.
     */
    private const REWRITE_ESCAPED = '/\\\\([ \t]|$)/';
    private const REWRITE_QUOTE = '/["\']/';
    /**
     * A tenant must never reach the server's own services through a rewrite (review F-13): loopback and
     * socket targets, and any literal host without a dot, which names a configured extProcessor (for
     * example the cpsrvdNNNN proxy backends). A host taken from a variable or back-reference is a redirect.
     */
    /** LiteSpeed Cache sections (OLS source references in build/vm-qualification/htaccess_translate.py). */
    private const LITESPEED_BLOCK = '/<IfModule\s+LiteSpeed\s*>(.*?)<\/IfModule>/si';
    private const CACHE_DIRECTIVE = '/^Cache(Lookup|KeyModify)\b/i';
    private const CACHE_LOOKUP_ON = '/^CacheLookup[ \t]+((public|private)[ \t]+)?on$/Di';
    private const CACHE_KEY_MODIFY = '/^CacheKeyModify[ \t]+(-qs:[A-Za-z0-9_.-]+\*?|clear)$/Di';
    private const LITESPEED_QUOTED_ENV = '/^\[E="cache-(vary|control):[A-Za-z0-9_,.:=+-]*"\]$/Di';
    private const ESI_ON = '/esi[ \t]*=[ \t]*"?on/i';
    private const REWRITE_INTERNAL = '/^(ws|wss|unix|proxy):|^[a-z][a-z0-9+.-]*:\/\/([^\/?#]*@|127\.|localhost|\[|0\.0\.0\.0'
        . '|(?![%$])[^\/?#.]*([\/?#]|$))/i';
    private const AUTHZ_OPEN = '/^<IfModule\s+(!?)mod_(?:authz_core|expires|headers)\.c\s*>$/i';
    private const ANY_IFMODULE_OPEN = '/^<IfModule\b[^>]*>$/i';
    private const IFMODULE_CLOSE = '/^<\/IfModule\s*>$/i';
    private const LITESPEED_OPEN = '/^<IfModule\s+LiteSpeed\s*>$/i';
    private const EXPIRES_ACTIVE = '/^ExpiresActive[ \t]+(on|off)$/Di';
    private const EXPIRES_DEFAULT = '/^ExpiresDefault[ \t]+(.+)$/Di';
    private const EXPIRES_BY_TYPE = '/^ExpiresByType[ \t]+([A-Za-z0-9][A-Za-z0-9.+_-]*\/[A-Za-z0-9][A-Za-z0-9.+_-]*)[ \t]+(.+)$/Di';
    private const EXPIRES_SHORT = '/^([AaMm])([0-9]{1,9})$/D';
    private const EXPIRES_LONG = '/^(access|now|modification)(?:[ \t]+plus)?((?:[ \t]+[0-9]{1,9}[ \t]+(?:years?|months?|weeks?|days?|hours?|minutes?|seconds?))+)$/Di';
    private const EXPIRES_UNIT = ['y' => 31536000, 'mo' => 2592000, 'w' => 604800, 'd' => 86400, 'h' => 3600, 'mi' => 60, 's' => 1];
    private const EXPIRES_BY_TYPE_LIMIT = 3500;
    private const DENY_ALL = [['require all denied'], ['deny from all'], ['order deny,allow', 'deny from all'],
        ['order allow,deny', 'deny from all']];
    private const DENY_LINES = ['require all denied', 'deny from all', 'order deny,allow', 'order allow,deny'];
    private const NOOP_OPTIONS = ['followsymlinks', 'symlinksifownermatch', '-multiviews'];
    private const CONTEXT_KEYS = ['allowBrowse', 'autoIndex', 'realm', 'authName', 'required', 'enableExpires',
        'expiresDefault', 'expiresByType', 'indexFiles', 'addMIMEType'];

    /**
     * @param array<string,string> $files relative directory ("" or "sub/dir") => .htaccess text
     * @param list<string>|null $modules the identifiers of the modules Apache has loaded (`httpd -M`, e.g. "rewrite_module"),
     *   or null when unknown (then only the modules EasyApache 4 always loads are assumed)
     * @return array{0:list<string>,1:list<string>,2:list<string>} [realms, blocks, blockers]
     */
    public function translate(array $files, string $docroot, ?array $modules = null, array $rootHeaders = []): array
    {
        $loaded = $modules === null ? null : array_fill_keys(array_map('strtolower', $modules), true);
        $realms = $regexContexts = $errorPages = $blockers = [];
        $contexts = [];
        // Headers the virtual host itself sets on every response (RV-44: cPanel's technical domains): they lead the
        // "/" context's own, and the static file contexts copy them with the rest of it.
        if ($rootHeaders !== [] && preg_match(self::SAFE_PATH, rtrim($docroot, '/') . '/')) {
            $contexts['/'] = ['location' => rtrim($docroot, '/') . '/', 'headers' => $rootHeaders];
        }
        ksort($files, SORT_STRING);
        foreach ($files as $rel => $text) {
            $rel = trim((string) $rel, '/');
            $uri = '/' . ($rel !== '' ? $rel . '/' : '');
            $location = rtrim($docroot, '/') . $uri;
            if (!preg_match(self::SAFE_PATH, $location)) {
                $blockers[] = "$uri: unsafe path";
                continue;
            }
            $contexts[$uri] ??= ['location' => $location];
            $remaining = preg_replace(self::PHP_INI, '', preg_replace(self::HANDLER, '', $text));
            preg_match_all(self::PPD, $remaining, $sections);
            foreach ($sections[0] as $sectionText) {
                $section = [];
                foreach ($this->directives($sectionText) as $line) {
                    [$key, $value] = array_pad(explode(' ', $line, 2), 2, '');
                    $section[strtolower($key)] = trim(trim($value), '"');
                }
                $userFile = $section['authuserfile'] ?? '';
                // The password file must be the account's own (review F-03): /<home-root>/<user>/.htpasswds/...
                $home = implode('/', array_slice(explode('/', rtrim($docroot, '/')), 0, 3));
                if (strtolower($section['authtype'] ?? '') !== 'basic' || ($section['require'] ?? null) !== 'valid-user'
                    || !preg_match(self::SAFE_PATH, $userFile) || !str_starts_with($userFile, $home . '/.htpasswds/')
                    || str_contains($userFile, '/../') || str_contains($userFile, '/./')) {
                    $blockers[] = "$uri: unsupported Directory Privacy section";
                    continue;
                }
                $realm = 'ppd_' . substr(hash('sha256', "$uri\0$userFile"), 0, 12);
                $name = preg_replace('/[^A-Za-z0-9 _.-]/', '', $section['authname'] ?? 'Restricted');
                $name = $name !== '' ? $name : 'Restricted';
                $realms[] = "realm $realm {\n  userDB {\n    location              $userFile\n  }\n}\n";
                $contexts[$uri]['realm'] = $realm;
                $contexts[$uri]['authName'] = $name;
                $contexts[$uri]['required'] = 'valid-user';
            }
            $remaining = preg_replace(self::PPD, '', $remaining);
            $remaining = $loaded === null ? $this->resolveModules($remaining)
                : $this->resolveAllModules($this->stripPrecompressed($remaining), $loaded);
            $grants = [];
            $fileDenies = 0;
            $staticHeaders = [];
            preg_match_all(self::FILES, $remaining, $blocks, PREG_SET_ORDER);
            foreach ($blocks as [, $kind, $pattern, $body]) {
                if (array_map('strtolower', $this->directives($body)) === ['require all granted']) {
                    $grants[] = [$kind, $pattern];
                    continue;
                }
                if ($loaded !== null && strtolower($kind) === 'filesmatch' && $pattern === '\\.php$'
                    && array_map('strtolower', $this->directives($body)) === ['expiresactive off']) {
                    // OLS sets Expires on dynamic responses from the virtual host's own setting (httpcgitool.cpp
                    // processExpires uses the root context), never from these directory contexts: already off.
                    continue;
                }
                $headerLines = $this->directives($body);
                $headers = array_map(fn(string $l): ?array => preg_match(self::HEADER, $l, $h) ? $h : null, $headerLines);
                if ($loaded !== null && strtolower($kind) === 'filesmatch' && $headers !== [] && !in_array(null, $headers, true)
                    && preg_match(self::STATIC_EXTENSION, $pattern, $static)
                    && !in_array(strtolower($static[1]), self::SCRIPT_EXTENSIONS, true)) {
                    $conditional = array_filter($headers, fn(array $h): bool => preg_match(self::HEADER_CONDITION, $h[3] ?? '') === 1);
                    if ($uri !== '/' || $conditional !== []) {
                        $blockers[] = "$uri: <$kind $pattern> with unsupported body";
                    } else {
                        $staticHeaders[] = [$static[1], array_map(static fn(array $h): string => 'Header '
                            . implode(' ', array_filter(array_slice($h, 1), static fn(string $p): bool => $p !== '')), $headers)];
                    }
                    continue;
                }
                $bodyLines = $this->directives($body);
                if ($loaded !== null && strtolower($kind) === 'files' && $pattern === '*' && $bodyLines !== []
                    && !array_filter($bodyLines, fn(string $l): bool => !preg_match(self::DRUPAL_NO_SCRIPTS, $l))) {
                    $contexts[$uri]['addMIMEType'] = self::NO_SCRIPTS_MIME;
                    continue;
                }
                if (!$this->isDenyAll($this->directives($body))) {
                    $blockers[] = "$uri: <$kind $pattern> with unsupported body";
                    continue;
                }
                // Validate what the tenant wrote; the translation below only adds "[^/]*" around it.
                // "@" is a literal in a regex (WordPress plugin files such as Akismet's logo@2x.png, lab 2026-10-28).
                // The structure is checked too (soak test 2026-10-30): a back-reference or a stray quantifier ("*a") made
                // an invalid OLS regex, and one tenant's file would have failed the whole server's configuration test.
                if (!preg_match('/^[A-Za-z0-9._@\\\\^$|()?*+\[\]-]+$/D', $pattern) || str_contains($pattern, '/')
                    || (strtolower($kind) === 'filesmatch' && !$this->regexSupported($pattern))) {
                    $search = $loaded !== null && strtolower($kind) === 'filesmatch' ? $this->basenameSearch($pattern) : null;
                    if ($search === null) {
                        $blockers[] = "$uri: unsupported <$kind> pattern " . $this->pyRepr($pattern);
                        continue;
                    }
                    // The path reaches the start of the last segment, then the basename is searched (Drupal's pattern).
                    $regexContexts[] = 'context exp:^' . $this->pyEscape($uri) . '(?:.*/)?(?=[^/]*$)[^/]*?(?:' . $search
                        . ") {\n  allowBrowse             0\n}\n";
                    ++$fileDenies;
                    continue;
                }
                if (strtolower($kind) === 'files') {
                    // <Files> takes a wildcard string, not a regex.
                    $regex = '';
                    foreach (str_split($pattern) as $char) {
                        $regex .= $char === '*' ? '[^/]*' : ($char === '?' ? '[^/]' : $this->pyEscape($char));
                    }
                } else {
                    // FilesMatch is an unanchored search on the basename; keep that inside one segment.
                    $regex = (str_starts_with($pattern, '^') ? '' : '[^/]*') . ltrim($pattern, '^');
                    $regex = str_ends_with($regex, '$') ? $regex : $regex . '[^/]*';
                }
                // <Files> matches the basename in this directory and below.
                $regexContexts[] = 'context exp:^' . $this->pyEscape($uri) . '(.*/)?' . ltrim($regex, '^')
                    . (str_ends_with($regex, '$') ? '' : '$') . " {\n  allowBrowse             0\n}\n";
                ++$fileDenies;
            }
            $remaining = preg_replace(self::FILES, '', $remaining);
            $remaining = preg_replace_callback(self::REWRITE_BLOCK, static fn(array $m): string => $m[1], $remaining);
            $tagged = $this->taggedDirectives($remaining);
            $rewriteLines = array_values(array_filter($tagged, fn(array $t): bool => $this->isRewrite($t[0], $t[1])));
            if ($rewriteLines !== []) {
                $rewrite = $this->rewrite($uri, $rewriteLines, $blockers);
                if ($rewrite !== null) {
                    $contexts[$uri]['rewrite'] = $rewrite;
                }
            }
            $lines = array_values(array_map(static fn(array $t): string => $t[0],
                array_filter($tagged, fn(array $t): bool => !$this->isRewrite($t[0], $t[1]))));
            $denyLines = array_values(array_filter($lines,
                static fn(string $l): bool => in_array(strtolower($l), self::DENY_LINES, true)));
            $allowList = false;
            if ($grants !== []) {
                // Apache merges <Files> sections after the directory's own rules, so a granted name is open
                // whatever the directory says. Only "the directory is denied, these names are not" is translated.
                if (array_map('strtolower', $denyLines) !== ['require all denied'] || $fileDenies > 0 || $rewriteLines !== []) {
                    foreach ($grants as [$kind, $pattern]) {
                        $blockers[] = "$uri: <$kind $pattern> grants access without a lone directory-level \"Require all denied\"";
                    }
                } else {
                    $alternatives = array_map(fn(array $g): ?string => $this->grantRegex($g[0], $g[1]), $grants);
                    foreach ($grants as $index => [$kind, $pattern]) {
                        if ($alternatives[$index] === null) {
                            $blockers[] = "$uri: unsupported <$kind> pattern " . $this->pyRepr($pattern);
                        }
                    }
                    if (!in_array(null, $alternatives, true)) {
                        $allowList = true;
                        // Earlier path segments must not contain a dot: "x.php/allowed.js" is the script x.php
                        // with path info for Apache, which names the file by its real basename.
                        $regexContexts[] = 'context exp:^' . $this->pyEscape($uri) . '(?!(?:[^/.]*/)*(?=[^/]*$)(?:'
                            . implode('|', $alternatives) . ")$) {\n  allowBrowse             0\n}\n";
                    }
                }
            }
            if ($denyLines !== []) {
                if ($allowList) {
                    // The lookahead context above replaces the plain directory denial.
                } elseif ($this->isDenyAll($denyLines)) {
                    $contexts[$uri]['allowBrowse'] = '0';
                } else {
                    $blockers[] = "$uri: unsupported access rule combination " . $this->pyList($denyLines);
                }
            }
            $expiresTypes = [];
            $indexIgnore = false;
            foreach ($lines as $line) {
                if (in_array($line, $denyLines, true)) {
                    continue;
                }
                if (preg_match(self::EXPIRES_ACTIVE, $line, $active)) {
                    $contexts[$uri]['enableExpires'] = strtolower($active[1]) === 'on' ? '1' : '0';
                } elseif (preg_match(self::EXPIRES_DEFAULT, $line, $default)) {
                    $value = $this->expiresValue($default[1]);
                    if ($value === null) {
                        $blockers[] = "$uri: unsupported expiry " . $this->pyRepr($line);
                    } else {
                        $contexts[$uri]['expiresDefault'] = $value;
                    }
                } elseif (preg_match(self::EXPIRES_BY_TYPE, $line, $byType)) {
                    $value = $this->expiresValue($byType[2]);
                    if ($value === null) {
                        $blockers[] = "$uri: unsupported expiry " . $this->pyRepr($line);
                    } else {
                        unset($expiresTypes[strtolower($byType[1])]);
                        $expiresTypes[strtolower($byType[1])] = $value;
                    }
                } elseif (str_starts_with(strtolower($line), 'options ')) {
                    foreach (array_slice(preg_split('/\s+/', trim($line)), 1) as $option) {
                        $lowered = strtolower($option);
                        if ($lowered === '-indexes') {
                            $contexts[$uri]['autoIndex'] = '0';
                        } elseif ($lowered === '+indexes' || $lowered === 'indexes') {
                            $contexts[$uri]['autoIndex'] = '1';
                        } elseif ($loaded !== null && ($lowered === '-includes' || ($lowered === '-execcgi' && !str_starts_with($uri, '/cgi-bin/')))) {
                            // OLS has no server-side includes, and runs CGI only in its cgi-bin context: both are off already.
                        } elseif (!in_array(ltrim($lowered, '+'), self::NOOP_OPTIONS, true)
                            && !in_array($lowered, self::NOOP_OPTIONS, true)) {
                            $blockers[] = "$uri: unsupported Options " . $this->pyRepr($option);
                        }
                    }
                } elseif (preg_match(self::HEADER, $line, $header)
                    && preg_match(self::HEADER_CONDITION, $header[3] ?? '')) {
                    $blockers[] = "$uri: unsupported conditional Header " . $this->pyRepr($line);
                } elseif (preg_match(self::HEADER, $line, $header)) {
                    $parts = array_filter(array_slice($header, 1), static fn(string $p): bool => $p !== '');
                    $contexts[$uri]['headers'][] = 'Header ' . implode(' ', $parts);
                } elseif ($loaded !== null && preg_match(self::DIRECTORY_INDEX, $line, $index)) {
                    $contexts[$uri]['indexFiles'] = implode(', ', preg_split('/[ \t]+/', trim($index[1])));
                } elseif ($loaded !== null && preg_match(self::ADD_TYPE, $line, $added)) {
                    foreach (preg_split('/[ \t]+/', trim($added[2])) as $extension) {
                        if ((self::OLS_DEFAULT_MIME[strtolower(ltrim($extension, '.'))] ?? null) !== strtolower($added[1])) {
                            $blockers[] = "$uri: unsupported directive " . $this->pyRepr($line);
                            break;
                        }
                    }
                } elseif ($loaded !== null && preg_match(self::ADD_ENCODING, $line, $encoding)) {
                    $extensions = array_map(static fn(string $e): string => ltrim($e, '.'), preg_split('/[ \t]+/', trim($encoding[2])));
                    $scripts = array_filter($extensions, static fn(string $e): bool => in_array(strtolower($e), self::SCRIPT_EXTENSIONS, true));
                    if ($uri !== '/' || $scripts !== []) {
                        $blockers[] = "$uri: unsupported directive " . $this->pyRepr($line);
                    } else {
                        foreach ($extensions as $extension) {
                            $staticHeaders[] = [$extension, ['Header set Content-Encoding gzip']];
                        }
                    }
                } elseif ($loaded !== null && preg_match(self::DRUPAL_NO_SCRIPTS, $line)) {
                    $contexts[$uri]['addMIMEType'] = self::NO_SCRIPTS_MIME;
                } elseif ($loaded !== null && preg_match(self::PROXY_UNSET, $line)) {
                    // OLS refuses requests carrying a Proxy header (400): nothing to translate.
                } elseif ($loaded !== null && preg_match(self::INDEX_IGNORE, $line)) {
                    $indexIgnore = true;
                } elseif ($uri === '/' && preg_match(self::ERROR_DOCUMENT, $line, $error)) {
                    // A later ErrorDocument for the same status wins, as in Apache.
                    unset($errorPages[$error[1]]);
                    $errorPages[$error[1]] = "errorPage {$error[1]} {\n  url                     {$error[2]}\n}\n";
                } else {
                    $blockers[] = "$uri: unsupported directive " . $this->pyRepr($line);
                }
            }
            // After the directory's own lines: the static file contexts carry its final settings.
            foreach ($staticHeaders as [$extension, $headers]) {
                $regexContexts[] = $this->staticHeaderContext($docroot, $extension, $headers, $contexts[$uri]);
            }
            if ($indexIgnore && ($contexts[$uri]['autoIndex'] ?? null) !== '0') {
                $blockers[] = "$uri: IndexIgnore while directory listings are not turned off";
            }
            if ($expiresTypes !== []) {
                $listing = implode(',', array_map(static fn(string $name, string $v): string => "$name=$v",
                    array_keys($expiresTypes), $expiresTypes));
                if (strlen($listing) > self::EXPIRES_BY_TYPE_LIMIT) {
                    $blockers[] = "$uri: too many ExpiresByType entries";
                } else {
                    $contexts[$uri]['expiresByType'] = $listing;
                }
            }
        }
        ksort($contexts, SORT_STRING);
        $rendered = [];
        foreach ($contexts as $uri => $props) {
            $location = $props['location'];
            unset($props['location']);
            if ($props !== []) {
                $rendered[] = $this->renderContext($uri, $location, $props);
            }
        }
        return [$realms, [...$rendered, ...$regexContexts, ...array_values($errorPages)], $blockers];
    }

    /**
     * Header names the translated "/" context sets (set/append/merge/add), first spelling kept.
     * @param list<string> $blocks
     * @return list<string>
     */
    public function rootHeaderNames(array $blocks): array
    {
        $names = [];
        foreach ($blocks as $block) {
            if (!str_starts_with($block, "context / {\n")) {
                continue;
            }
            foreach (preg_split('/\R/', $block) as $line) {
                if (preg_match('/^Header (set|append|merge|add) ([A-Za-z0-9-]+)/i', $line, $m)
                    && !in_array(strtolower($m[2]), array_map('strtolower', $names), true)) {
                    $names[] = $m[2];
                }
            }
        }
        return $names;
    }

    /**
     * Context rewrite settings for one directory's rewrite lines ([line, inside <IfModule LiteSpeed>]
     * pairs), or null after a blocker or when nothing remains.
     * @param list<array{0:string,1:bool}> $lines
     * @param list<string> $blockers
     * @return array<string,mixed>|null
     */
    private function rewrite(string $uri, array $lines, array &$blockers): ?array
    {
        $settings = $rules = [];
        $engine = null;
        $lookups = 0;
        foreach ($lines as [$line, $litespeed]) {
            if (str_contains($line, 'END_')) {
                $blockers[] = "$uri: unsupported rewrite line " . $this->pyRepr($line);
                return null;
            }
            if (preg_match(self::REWRITE_CONTROL, $line)) {
                $blockers[] = "$uri: rewrite line with control characters";
                return null;
            }
            [$word, $rest] = array_pad(preg_split(self::REWRITE_SPACE, $line, 2), 2, '');
            $word = strtolower($word);
            if ($word === 'rewriteengine') {
                if (!in_array(strtolower($rest), ['on', 'off'], true)) {
                    $blockers[] = "$uri: unsupported RewriteEngine " . $this->pyRepr($rest);
                    return null;
                }
                $engine = strtolower($rest) === 'on';
            } elseif ($word === 'rewritebase') {
                if (!preg_match(self::SAFE_PATH, $rest)) {
                    $blockers[] = "$uri: unsupported RewriteBase " . $this->pyRepr($rest);
                    return null;
                }
                $settings['base'] = $rest;
            } elseif ($word === 'rewriteoptions') {
                if (strtolower($rest) !== 'inherit') {
                    $blockers[] = "$uri: unsupported RewriteOptions " . $this->pyRepr($rest);
                    return null;
                }
                $settings['inherit'] = '1';
            } elseif ($word === 'cachelookup') {
                // Honoured by the vhost's cache policy; "off" cannot be expressed per directory in OLS.
                if (!preg_match(self::CACHE_LOOKUP_ON, $line)) {
                    $blockers[] = "$uri: unsupported CacheLookup " . $this->pyRepr($line);
                    return null;
                }
                ++$lookups;
            } elseif ($word === 'cachekeymodify') {
                if (!preg_match(self::CACHE_KEY_MODIFY, $line)) {
                    $blockers[] = "$uri: unsupported CacheKeyModify " . $this->pyRepr($line);
                    return null;
                }
                $rules[] = $line;
            } elseif ($word === 'rewritecond' || $word === 'rewriterule') {
                if (!$this->rewriteArgumentsSafe($word, $rest, $litespeed)) {
                    $blockers[] = "$uri: unsupported " . ($word === 'rewriterule' ? 'RewriteRule' : 'RewriteCond') . ' '
                        . $this->pyRepr($line);
                    return null;
                }
                $rules[] = $line;
            } else {
                $blockers[] = "$uri: unsupported rewrite directive " . $this->pyRepr($line);
                return null;
            }
        }
        if ($engine === null && $lookups === count($lines)) {
            return null;
        }
        if ($engine === null) {
            $blockers[] = "$uri: rewrite directives without RewriteEngine";
            return null;
        }
        return ['enable' => $engine ? '1' : '0', ...$settings, 'rules' => $engine ? $rules : []];
    }

    /**
     * Whether a RewriteCond/RewriteRule argument list is fully understood and names no internal backend.
     * ESI is not supported by OLS (plan §20.3): a LiteSpeed rule turning it on is refused.
     */
    private function rewriteArgumentsSafe(string $word, string $rest, bool $litespeed = false): bool
    {
        if ($litespeed && preg_match(self::ESI_ON, $rest)) {
            return false;
        }
        if ($litespeed && (preg_match(self::REWRITE_ESCAPED, $rest) || preg_match(self::REWRITE_QUOTE, $rest))) {
            return $this->litespeedQuotedSafe($word, $rest);
        }
        if (preg_match(self::REWRITE_QUOTE, $rest) && !preg_match(self::REWRITE_ESCAPED, $rest)) {
            $argument = self::APACHE_ARGUMENT;
            if (!preg_match("/^($argument)[ \t]+($argument)(?:[ \t]+(\[[^\[\]]*\]))?$/", $rest, $quoted)) {
                return false;
            }
            $args = array_map(static fn(string $a): string => str_starts_with($a, '"') ? substr($a, 1, -1) : $a, [$quoted[1], $quoted[2]]);
            if (($quoted[3] ?? '') !== '') {
                $args[] = $quoted[3];
            }
            if (str_starts_with($args[0], '|') || str_starts_with($args[1], '|')
                || ($word === 'rewriterule' && (str_starts_with($args[1], '[') || preg_match(self::REWRITE_INTERNAL, $args[1])))) {
                return false;
            }
            return count($args) < 3 || $this->flagsSafe($args[2], $litespeed);
        }
        $args = preg_split(self::REWRITE_SPACE, $rest, 3);
        if (count($args) < 2 || preg_match(self::REWRITE_ESCAPED, $rest)
            || str_starts_with($args[0], '|') || str_starts_with($args[1], '|')
            || ($word === 'rewriterule' && (preg_match(self::REWRITE_QUOTE, $rest) || str_starts_with($args[1], '[')
                || preg_match(self::REWRITE_INTERNAL, $args[1])))) {
            return false;
        }
        return count($args) < 3 || $this->flagsSafe($args[2], $litespeed);
    }

    /**
     * A complete "[...]" flag list without proxy/handler flags or internal targets; a "cache-..." environment
     * flag drives the OLS cache module and is accepted only inside <IfModule LiteSpeed>.
     */
    private function flagsSafe(string $text, bool $litespeed): bool
    {
        if (!preg_match(self::REWRITE_FLAGS, $text, $flags)) {
            return false;
        }
        foreach (preg_split('/[ \t,]+/', $flags[1]) as $flag) {
            [$name, $value] = array_pad(explode('=', $flag, 2), 2, '');
            $name = strtolower($name);
            if (in_array($name, ['p', 'proxy', 'h', 'handler'], true) || preg_match(self::REWRITE_INTERNAL, $value)) {
                return false;
            }
            if (in_array($name, ['e', 'env'], true) && str_starts_with(strtolower(ltrim($value, "\"'")), 'cache-') && !$litespeed) {
                return false;
            }
        }
        return true;
    }

    /**
     * The first two arguments of a rewrite line split as OLS 1.9.3 does (a leading quote delimits, a
     * backslash escapes the next character), then the rest of the line when present; null when unterminated.
     * @return list<string>|null
     */
    private function olsArguments(string $text): ?array
    {
        $args = [];
        $i = 0;
        $n = strlen($text);
        while (count($args) < 2) {
            while ($i < $n && ($text[$i] === ' ' || $text[$i] === "\t")) {
                ++$i;
            }
            if ($i >= $n) {
                return $args;
            }
            $quote = ($text[$i] === '"' || $text[$i] === "'") ? $text[$i] : '';
            $i += $quote !== '' ? 1 : 0;
            $start = $i;
            while ($i < $n && !(($quote !== '' && $text[$i] === $quote) || ($quote === '' && ($text[$i] === ' ' || $text[$i] === "\t")))) {
                $i += $text[$i] === '\\' ? 2 : 1;
            }
            if ($i > $n || ($quote !== '' && $i >= $n)) {
                return null;
            }
            $args[] = substr($text, $start, $i - $start);
            ++$i;
        }
        $rest = $i < $n ? trim(substr($text, $i), " \t") : '';
        return $rest !== '' ? [...$args, $rest] : $args;
    }

    /**
     * Inside <IfModule LiteSpeed> only OLS reads the line: a RewriteCond with quoted or escaped arguments, and
     * a RewriteRule "<pattern> - [E="Cache-Vary|Cache-Control:<value>"]".
     */
    private function litespeedQuotedSafe(string $word, string $rest): bool
    {
        $args = $this->olsArguments($rest);
        if ($args === null || count($args) < 2 || str_starts_with($args[0], '|') || str_starts_with($args[1], '|')) {
            return false;
        }
        if ($word === 'rewriterule') {
            $lead = ltrim($rest, " \t");
            return count($args) === 3 && !str_starts_with($lead, '"') && !str_starts_with($lead, "'") && $args[1] === '-'
                && preg_match(self::LITESPEED_QUOTED_ENV, $args[2]) === 1;
        }
        return count($args) === 2 || $this->flagsSafe($args[2], true);
    }

    /**
     * Directives in document order with whether they lie inside <IfModule LiteSpeed>.
     * @return list<array{0:string,1:bool}>
     */
    private function taggedDirectives(string $text): array
    {
        $out = [];
        $position = 0;
        preg_match_all(self::LITESPEED_BLOCK, $text, $matches, PREG_SET_ORDER | PREG_OFFSET_CAPTURE);
        foreach ($matches as $match) {
            foreach ($this->directives(substr($text, $position, $match[0][1] - $position)) as $line) {
                $out[] = [$line, false];
            }
            foreach ($this->directives($match[1][0]) as $line) {
                $out[] = [$line, true];
            }
            $position = $match[0][1] + strlen($match[0][0]);
        }
        foreach ($this->directives(substr($text, $position)) as $line) {
            $out[] = [$line, false];
        }
        return $out;
    }

    private function isRewrite(string $line, bool $litespeed): bool
    {
        return preg_match(self::REWRITE_DIRECTIVE, $line) === 1 || ($litespeed && preg_match(self::CACHE_DIRECTIVE, $line) === 1);
    }

    /** @return list<string> */
    private function directives(string $text): array
    {
        $out = [];
        foreach (preg_split('/\R/', $text) as $line) {
            $line = trim($line);
            if ($line !== '' && !str_starts_with($line, '#')) {
                $out[] = $line;
            }
        }
        return $out;
    }

    /** "A<seconds>" or "M<seconds>" for an Apache expiry (short or long syntax, optionally quoted), or null. */
    private function expiresValue(string $text): ?string
    {
        $text = trim($text, " \t");
        if (strlen($text) >= 2 && $text[0] === $text[strlen($text) - 1] && ($text[0] === '"' || $text[0] === "'")) {
            $text = trim(substr($text, 1, -1), " \t");
        }
        if (preg_match(self::EXPIRES_SHORT, $text, $short)) {
            return strtoupper($short[1]) . (string) (int) $short[2];
        }
        if (!preg_match(self::EXPIRES_LONG, $text, $long)) {
            return null;
        }
        $seconds = 0;
        preg_match_all('/([0-9]+)[ \t]+([A-Za-z]+)/', $long[2], $pairs, PREG_SET_ORDER);
        foreach ($pairs as [, $count, $unit]) {
            $unit = strtolower($unit);
            $key = in_array(substr($unit, 0, 2), ['mo', 'mi'], true) ? substr($unit, 0, 2) : $unit[0];
            $seconds += (int) $count * self::EXPIRES_UNIT[$key];
        }
        if ($seconds > 2147483647) {
            return null;
        }
        return (strtolower($long[1]) === 'modification' ? 'M' : 'A') . $seconds;
    }

    /**
     * Apache evaluates <IfModule mod_X.c> at parse time; mod_authz_core, mod_expires and mod_headers are always
     * loaded on cPanel's EasyApache 4, so the body of <IfModule mod_X.c> is kept (wrapper removed) and the body of
     * <IfModule !mod_X.c> is dropped. Other <IfModule> lines stay (also inside <IfModule LiteSpeed>); unbalanced
     * sections leave the text unchanged (blockers follow).
     */
    private function resolveModules(string $text): string
    {
        if (!preg_match('/<IfModule\s+!?mod_(?:authz_core|expires|headers)\.c\s*>/i', $text)) {
            return $text;
        }
        $out = [];
        $stack = [];
        foreach (preg_split('/\r\n|\n|\r/', $text) as $line) {
            $stripped = trim($line);
            if (preg_match(self::AUTHZ_OPEN, $stripped, $known) && !in_array('ls', $stack, true)) {
                $stack[] = $known[1] !== '' ? 'drop' : 'keep';
            } elseif (preg_match(self::ANY_IFMODULE_OPEN, $stripped)) {
                if (!in_array('drop', $stack, true)) {
                    $out[] = $line;
                }
                $stack[] = preg_match(self::LITESPEED_OPEN, $stripped) ? 'ls' : 'other';
            } elseif (preg_match(self::IFMODULE_CLOSE, $stripped)) {
                if ($stack === []) {
                    return $text;
                }
                if (in_array(array_pop($stack), ['other', 'ls'], true) && !in_array('drop', $stack, true)) {
                    $out[] = $line;
                }
            } elseif (!in_array('drop', $stack, true)) {
                $out[] = $line;
            }
        }
        return $stack !== [] ? $text : implode("\n", $out) . "\n";
    }

    /** @param array<string,true> $modules */
    private function moduleLoaded(string $name, array $modules): bool
    {
        $name = trim($name, '"\'');
        return isset($modules[strtolower(preg_match(self::MODULE_SOURCE, $name, $source) ? $source[1] . '_module' : $name)]);
    }

    /**
     * RV-46 (soak test 2026-10-30): with the server's own module list (`httpd -M`) every <IfModule [!]name> outside
     * <IfModule LiteSpeed> is decided as Apache decides it at parse time: the body of a true section is kept (wrapper
     * removed), a false one is dropped with everything nested in it. <IfModule LiteSpeed>, anything inside it and
     * <IfModule !LiteSpeed> stay as written. Unbalanced sections leave the text unchanged (blockers follow).
     * @param array<string,true> $modules
     */
    private function resolveAllModules(string $text, array $modules): string
    {
        $out = [];
        $stack = [];
        foreach (preg_split('/\r\n|\n|\r/', $text) as $line) {
            $stripped = trim($line);
            if (preg_match(self::IFMODULE_OPEN, $stripped, $section) && !in_array('ls', $stack, true)
                && strtolower(trim($section[2], '"\'')) !== 'litespeed') {
                $stack[] = $this->moduleLoaded($section[2], $modules) !== ($section[1] !== '') ? 'keep' : 'drop';
            } elseif (preg_match(self::ANY_IFMODULE_OPEN, $stripped)) {
                if (!in_array('drop', $stack, true)) {
                    $out[] = $line;
                }
                $stack[] = preg_match(self::LITESPEED_OPEN, $stripped) ? 'ls' : 'other';
            } elseif (preg_match(self::IFMODULE_CLOSE, $stripped)) {
                if ($stack === []) {
                    return $text;
                }
                if (in_array(array_pop($stack), ['other', 'ls'], true) && !in_array('drop', $stack, true)) {
                    $out[] = $line;
                }
            } elseif (!in_array('drop', $stack, true)) {
                $out[] = $line;
            }
        }
        return $stack !== [] ? $text : implode("\n", $out) . "\n";
    }

    private function precompressedSection(string $body): bool
    {
        if (!preg_match_all(self::FILES, $body, $files, PREG_SET_ORDER)) {
            return false;
        }
        foreach ($files as [, $kind, $pattern, $inner]) {
            if (strtolower($kind) !== 'filesmatch' || !preg_match(self::PRECOMPRESSED_FILES, $pattern, $encoding)
                || array_map('strtolower', $this->directives($inner)) !== [
                    'header set content-encoding ' . ($encoding[1] === 'gz' ? 'gzip' : 'br'), 'header append vary accept-encoding']) {
                return false;
            }
        }
        $rest = $this->directives(preg_replace(self::FILES, '', $body));
        foreach ($rest as $line) {
            if (!array_filter(self::PRECOMPRESSED_LINES, static fn(string $rx): bool => preg_match($rx, $line) === 1)) {
                return false;
            }
        }
        return $rest !== [];
    }

    private function stripPrecompressed(string $text): string
    {
        return preg_replace_callback(self::PRECOMPRESSED_SECTION,
            fn(array $m): string => $this->precompressedSection($m[1]) ? '' : $m[0], $text);
    }

    /**
     * A <FilesMatch> regex (an unanchored search on the basename) rewritten to run inside a path regex that has reached
     * the start of the last segment: "^" becomes "(?<=/)", "#" is written \x23 (it would start a comment in the OLS
     * configuration). Groups, lookarounds, classes and alternations are kept; back-references, other "(?" constructs,
     * braces, a "<<<" sequence and stacked or leading quantifiers are refused (null).
     */
    private function basenameSearch(string $pattern): ?string
    {
        if (!preg_match(self::SEARCH_CHARS, $pattern) || str_contains($pattern, '<<<')) {
            return null;
        }
        $out = '';
        $i = 0;
        $n = strlen($pattern);
        $depth = 0;
        $quantifiable = false;
        while ($i < $n) {
            $c = $pattern[$i];
            if ($c === '\\') {
                if ($i + 1 >= $n || (ctype_alnum($pattern[$i + 1]) && !str_contains('dwsDWS', $pattern[$i + 1]))) {
                    return null;
                }
                $out .= substr($pattern, $i, 2);
                $quantifiable = true;
                $i += 2;
            } elseif ($c === '[') {
                $j = $i + 1 + (substr($pattern, $i + 1, 1) === '^' ? 1 : 0);
                $start = $j;
                while ($j < $n && !str_contains(']\\[', $pattern[$j])) {
                    ++$j;
                }
                if ($j >= $n || $pattern[$j] !== ']' || $j === $start) {
                    return null;
                }
                $out .= str_replace('#', '\\x23', substr($pattern, $i, $j + 1 - $i));
                $quantifiable = true;
                $i = $j + 1;
            } elseif ($c === '(') {
                $look = null;
                if (substr($pattern, $i + 1, 1) === '?') {
                    if (!preg_match(self::LOOKAROUND, $pattern, $match, 0, $i)) {
                        return null;
                    }
                    $look = $match[0];
                }
                $token = $look ?? '(';
                $out .= $token;
                ++$depth;
                $quantifiable = false;
                $i += strlen($token);
            } elseif ($c === ')') {
                if (--$depth < 0) {
                    return null;
                }
                $out .= ')';
                $quantifiable = true;
                ++$i;
            } elseif ($c === '|' || $c === '$') {
                $out .= $c;
                $quantifiable = false;
                ++$i;
            } elseif ($c === '^') {
                $out .= '(?<=/)';
                $quantifiable = false;
                ++$i;
            } elseif ($c === '*' || $c === '+' || $c === '?') {
                if (!$quantifiable) {
                    return null;
                }
                $out .= $c;
                $quantifiable = false;
                ++$i;
            } else {
                $out .= $c === '#' ? '\\x23' : $c;
                $quantifiable = true;
                ++$i;
            }
        }
        return $depth === 0 ? $out : null;
    }

    /**
     * Headers for one static file type of the document root: a regex context serving the file itself. It carries the
     * "/" context's access denial, authentication, expiry and headers (its own headers after them): the lab showed that
     * such a context does not take the root context's headers by itself (soak test 2026-10-30).
     * @param list<string> $headers
     * @param array<string,mixed> $root
     */
    private function staticHeaderContext(string $docroot, string $extension, array $headers, array $root): string
    {
        $lines = ['context exp:^/((?:.*/)?[^/]*\\.' . $extension . ')$ {', '  location                ' . rtrim($docroot, '/') . '/$1',
            '  allowBrowse             ' . ($root['allowBrowse'] ?? '1')];
        foreach (['realm', 'authName', 'required', 'enableExpires', 'expiresDefault', 'expiresByType'] as $key) {
            if (isset($root[$key])) {
                $lines[] = '  ' . str_pad($key, 23) . ' ' . $root[$key];
            }
        }
        $lines = [...$lines, '  extraHeaders            <<<END_extraHeaders', ...($root['headers'] ?? []), ...$headers, 'END_extraHeaders', "}\n"];
        return implode("\n", $lines);
    }

    /**
     * A FilesMatch pattern that is balanced and simple enough to embed in a group: escapes are punctuation or
     * d/w/s/D/W/S (no back-references), classes hold no escapes, "(?" constructs and stacked or leading
     * quantifiers are refused.
     */
    private function regexSupported(string $pattern): bool
    {
        $depth = 0;
        $i = 0;
        $n = strlen($pattern);
        $quantifiable = false;
        while ($i < $n) {
            $c = $pattern[$i];
            if ($c === '\\') {
                if ($i + 1 >= $n || (ctype_alnum($pattern[$i + 1]) && !str_contains('dwsDWS', $pattern[$i + 1]))) {
                    return false;
                }
                $quantifiable = true;
                $i += 2;
            } elseif ($c === '[') {
                $j = $i + 1 + (substr($pattern, $i + 1, 1) === '^' ? 1 : 0);
                $start = $j;
                while ($j < $n && !str_contains(']\\[', $pattern[$j])) {
                    ++$j;
                }
                if ($j >= $n || $pattern[$j] !== ']' || $j === $start) {
                    return false;
                }
                $quantifiable = true;
                $i = $j + 1;
            } elseif ($c === '(') {
                if (substr($pattern, $i + 1, 1) === '?') {
                    return false;
                }
                ++$depth;
                $quantifiable = false;
                ++$i;
            } elseif ($c === ')') {
                if (--$depth < 0) {
                    return false;
                }
                $quantifiable = true;
                ++$i;
            } elseif ($c === '|' || $c === '^' || $c === '$') {
                $quantifiable = false;
                ++$i;
            } elseif ($c === '*' || $c === '+' || $c === '?') {
                if (!$quantifiable) {
                    return false;
                }
                $quantifiable = false;
                ++$i;
            } else {
                $quantifiable = true;
                ++$i;
            }
        }
        return $depth === 0;
    }

    /**
     * Basename regex (no trailing anchor) of one <Files>/<FilesMatch> pattern that grants access, or null when the
     * pattern is not understood well enough. It never matches a name containing "/". What it accepts is a subset of
     * what Apache accepts, because everything else stays denied.
     */
    private function grantRegex(string $kind, string $pattern): ?string
    {
        if (strtolower($kind) === 'files') {
            if (!preg_match('/^[A-Za-z0-9._@*?-]+$/D', $pattern)) {
                return null;
            }
            $regex = '';
            foreach (str_split($pattern) as $char) {
                $regex .= $char === '*' ? '[^/]*' : ($char === '?' ? '[^/]' : $this->pyEscape($char));
            }
            return $regex;
        }
        if (!preg_match('/^[A-Za-z0-9._@\\\\^$|()?*+\[\]-]+$/D', $pattern) || str_contains($pattern, '/')
            || !$this->regexSupported($pattern)) {
            return null;
        }
        $body = ltrim($pattern, '^');
        $anchored = preg_match('/(\\\\*)\$$/D', $body, $tail) === 1 && strlen($tail[1]) % 2 === 0;
        return (str_starts_with($pattern, '^') ? '' : '[^/]*') . '(?:' . $body . ')' . ($anchored ? '' : '[^/]*');
    }

    /** @param list<string> $lines */
    private function isDenyAll(array $lines): bool
    {
        return in_array(array_map('strtolower', $lines), self::DENY_ALL, true);
    }

    /** @param array<string,mixed> $props */
    private function renderContext(string $uri, string $location, array $props): string
    {
        $lines = ["context $uri {", "  location                $location"];
        foreach (self::CONTEXT_KEYS as $key) {
            if (isset($props[$key])) {
                $lines[] = '  ' . str_pad($key, 23) . ' ' . $props[$key];
            }
        }
        if (!empty($props['headers'])) {
            $lines[] = '  extraHeaders            <<<END_extraHeaders';
            array_push($lines, ...$props['headers']);
            $lines[] = 'END_extraHeaders';
        }
        if (isset($props['rewrite'])) {
            $rewrite = $props['rewrite'];
            $lines[] = '  rewrite  {';
            foreach (['enable', 'inherit', 'base'] as $key) {
                if (isset($rewrite[$key])) {
                    $lines[] = '    ' . str_pad($key, 21) . ' ' . $rewrite[$key];
                }
            }
            if ($rewrite['rules'] !== []) {
                $lines[] = '    rules                 <<<END_rules';
                array_push($lines, ...$rewrite['rules']);
                $lines[] = 'END_rules';
            }
            $lines[] = '  }';
        }
        $lines[] = "}\n";
        return implode("\n", $lines);
    }

    /** Same characters as Python's re.escape, so generated regexes match the lab tool exactly. */
    private function pyEscape(string $text): string
    {
        return preg_replace('/([()\[\]{}?*+\-|^$\\\\.&~# \t\n\r\x0b\x0c])/', '\\\\$1', $text);
    }

    /** Python repr() of a string (ASCII escapes included), for blocker messages identical to the lab tool. */
    private function pyRepr(string $text): string
    {
        $quote = str_contains($text, "'") && !str_contains($text, '"') ? '"' : "'";
        $escaped = preg_replace_callback('/[\\\\\x00-\x1f\x7f' . ($quote === "'" ? "'" : '') . ']/',
            static fn(array $m): string => match ($m[0]) {
                '\\' => '\\\\', "'" => "\\'", "\t" => '\t', "\n" => '\n', "\r" => '\r',
                default => sprintf('\x%02x', ord($m[0])),
            }, $text);
        return $quote . $escaped . $quote;
    }

    /** @param list<string> $items */
    private function pyList(array $items): string
    {
        return '[' . implode(', ', array_map(fn(string $i): string => $this->pyRepr($i), $items)) . ']';
    }
}
