<?php
declare(strict_types=1);

namespace OlsCpanel\Operations;

/**
 * Redaction of the support bundle (FV-07). Always, whatever the operator chose: private keys and certificates (PEM blocks),
 * passwords, tokens, API keys, authorization and cookie headers (the value of any `password`, `secret`, `token`, `key`... setting),
 * credentials inside URLs, query strings (they carry tokens and customer data), long token-like strings, and e-mail addresses
 * (also with a quoted local part). Headers are found anywhere in a line, whatever prefix or case, and lose their whole value.
 * With `anonymize` (the default): IP addresses, domain names and account names become stable placeholders
 * (`ip-<hex>`, `domain-<hex>.invalid`, `acct-<hex>`): the first characters of an HMAC-SHA256 of the value under a per-server salt,
 * so the same value reads the same in every file and in every bundle of this server and cannot be recovered or matched
 * across servers. Domains and accounts that this server hosts are given to the constructor and replaced exactly (longest first).
 * Journals and audit records also hold names this server no longer hosts, so any other host name is replaced too (a general rule,
 * not a list of top-level domains), also when a file name continues it with a hyphen (OpenLiteSpeed's `<domain>-error.log`,
 * `<domain>-php.sock`), and so is the account of any `/home*` path and of the account fields of structured records. File names
 * (an explicit list of extensions) and the product's own dotted words (ols.sync, job.status, opcache.enable) are left alone.
 */
final class Redactor
{
    private const SECRET_NAMES = 'password|passwd|passphrase|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|auth|authorization|credential|session|cookie|bearer';
    /**
     * Final labels that make a dotted word a file name, not a host name: the general host name rule never ends a name on one of
     * these (error.log, php-env.json, ols-cpanel-notify.timer, wp-config.php, archive.tar.gz stay; <domain>-error.log loses only
     * the domain). Any other final label of 2 to 63 letters is a host name: there are over a thousand top-level domains.
     */
    private const FILE_LABELS = ['log', 'logs', 'conf', 'cnf', 'cfg', 'config', 'ini', 'json', 'yaml', 'yml', 'toml', 'xml', 'php', 'phtml', 'inc', 'html', 'htm',
        'js', 'mjs', 'cjs', 'ts', 'vue', 'css', 'scss', 'map', 'txt', 'rst', 'csv', 'tsv', 'sql', 'rb', 'lua', 'sock', 'socket', 'pid', 'lock', 'tmp', 'temp',
        'bak', 'old', 'orig', 'swp', 'gz', 'tgz', 'tar', 'xz', 'bz', 'zst', 'rpm', 'deb', 'repo', 'spec', 'service', 'timer', 'target', 'mount', 'slice', 'path',
        'scope', 'key', 'crt', 'pem', 'csr', 'cert', 'db', 'sqlite', 'dat', 'bin', 'out', 'err', 'png', 'jpg', 'jpeg', 'gif', 'svg', 'ico', 'webp', 'ttf',
        'otf', 'woff', 'pdf', 'htaccess', 'htpasswd', 'tpl', 'twig', 'env', 'list', 'cache', 'sync', 'status', 'rules', 'tmpl', 'dist', 'sample'];
    /**
     * Extensions that are also country or generic top-level domains (script.pl, run.sh, README.md, lib.so; but example.pl is in
     * Poland): a file name when the name has two labels, a host name when it has three or more (shop.example.pl).
     */
    private const AMBIGUOUS_LABELS = ['pl', 'sh', 'py', 'md', 'so', 'rs', 'ps', 'zip', 'new', 'run'];
    /**
     * First labels of the product's own dotted words (broker operations such as ols.sync, job.status, cap.issue; PHP settings such
     * as opcache.enable, date.timezone): a name of exactly two labels that starts with one of these is left alone.
     */
    private const WORD_LABELS = ['ols', 'job', 'jobs', 'cap', 'server', 'engine', 'tenant', 'admin', 'htaccess', 'plan', 'epoch', 'notify', 'schedule',
        'support', 'update', 'request', 'requests', 'cache', 'objcache', 'lscache', 'opcache', 'php', 'lsphp', 'lsapi', 'apc', 'session', 'date', 'zend',
        'mbstring', 'pcre', 'mysqli', 'mysqlnd', 'pdo', 'xdebug', 'curl', 'openssl', 'intl', 'assert', 'phar', 'zlib', 'mail', 'lab', 'generation', 'metrics'];
    /** Field names whose value is an account name in the product's own records (audit, journal, state files). */
    private const ACCOUNT_FIELDS = 'user|username|account|actor|owner|principal|cpuser';
    /** Field values that are not account names. */
    private const NOT_ACCOUNTS = ['root', 'nobody', 'server', 'all', 'none', 'null', 'true', 'false', 'system', 'admin', 'unknown', 'self'];

    /** Header names whose value is a credential (X-Api-Key, X-Auth-Token, X-CSRF-Token, X-Session-Id...). */
    private const HEADERS = '(?:Proxy-Authorization|Authorization|Set-Cookie|Cookie|Api-Key|X-[A-Za-z0-9-]*(?:Token|Key|Secret|Auth|Session)[A-Za-z0-9-]*)';

    /** @var array<string,int> category => replacements */
    private array $counts = [];
    private string $domainPattern = '';
    private string $accountPattern = '';

    /**
     * @param list<string> $domains the domain names this server hosts (and its own host name)
     * @param list<string> $accounts the cPanel account names
     */
    public function __construct(private readonly bool $anonymize, array $domains, array $accounts, private readonly string $salt)
    {
        $domains = array_values(array_unique(array_filter(array_map('strtolower', $domains), static fn(string $d): bool => strlen($d) >= 4 && str_contains($d, '.'))));
        usort($domains, static fn(string $a, string $b): int => strlen($b) <=> strlen($a));
        $accounts = array_values(array_unique(array_filter($accounts, static fn(string $a): bool => strlen($a) >= 3)));
        usort($accounts, static fn(string $a, string $b): int => strlen($b) <=> strlen($a));
        if ($domains !== []) {
            $this->domainPattern = '/(?<![A-Za-z0-9-])(?:' . implode('|', array_map(static fn(string $d): string => preg_quote($d, '/'), $domains)) . ')(?![A-Za-z0-9])/i';
        }
        if ($accounts !== []) {
            $this->accountPattern = '/(?<![A-Za-z0-9])(?:' . implode('|', array_map(static fn(string $a): string => preg_quote($a, '/'), $accounts)) . ')(?![A-Za-z0-9])/';
        }
    }

    /** @return array<string,int> */
    public function counts(): array
    {
        return $this->counts;
    }

    public function anonymizing(): bool
    {
        return $this->anonymize;
    }

    private function count(string $category, int $n = 1): void
    {
        $this->counts[$category] = ($this->counts[$category] ?? 0) + $n;
    }

    private function token(string $prefix, string $value, string $suffix = ''): string
    {
        return $prefix . substr(hash_hmac('sha256', $prefix . strtolower($value), $this->salt), 0, 8) . $suffix;
    }

    /**
     * Sensitive headers wherever they are written: after a log prefix (`[ERROR] Authorization: Bearer x`), in any case, as a quoted
     * or JSON-escaped key (`"Authorization": "..."`, `\"Cookie\": \"...\"`) or inside a JSON string (`{"msg":"Cookie: a=b"}`). The
     * whole value goes: to the end of the line, or to the closing quote when the value is quoted or the header sits inside a quoted
     * string (an odd number of unescaped double quotes before it on its line), so the record around it stays readable.
     */
    private function headers(string $text): string
    {
        if (preg_match_all('/(?<![A-Za-z0-9_-])' . self::HEADERS . '(\\\\?["\']?)[ \t]*:[ \t]*/i', $text, $all, PREG_OFFSET_CAPTURE | PREG_SET_ORDER) < 1) {
            return $text;
        }
        $out = '';
        $at = 0;
        foreach ($all as $m) {
            [$match, $offset] = $m[0];
            if ($offset < $at) {
                continue; // inside a value already removed
            }
            $start = $offset + strlen($match);
            $eol = $start + strcspn($text, "\r\n", $start);
            $line = strrpos(substr($text, 0, $offset), "\n");
            $prefix = substr($text, $line === false ? 0 : $line + 1, $offset - ($line === false ? 0 : $line + 1));
            $quoted = preg_match('/\G\\\\?(["\'])/', $text, $q, 0, $start) === 1;
            $value = $quoted ? $start + strlen($q[0]) : $start;
            $end = $eol;
            if ($quoted || $m[1][0] !== '' || preg_match_all('/(?<!\\\\)"/', $prefix) % 2 === 1) {
                $segment = substr($text, $value, $eol - $value);
                $close = ($quoted && $q[1] === "'") || (!$quoted && str_ends_with($m[1][0], "'")) ? strpos($segment, "'") : strpos($segment, '"');
                if ($close !== false) {
                    $end = $value + ($close > 0 && $segment[$close - 1] === '\\' ? $close - 1 : $close);
                }
            }
            $old = substr($text, $value, $end - $value);
            if (trim($old) === '' || str_starts_with($old, '[REDACTED')) {
                continue;
            }
            $this->count('header');
            $out .= substr($text, $at, $value - $at) . '[REDACTED]';
            $at = $end;
        }
        return $out . substr($text, $at);
    }

    /** The placeholder of an account name; system names, numbers and placeholders already made stay as they are. */
    private function accountToken(string $name): string
    {
        if (in_array(strtolower($name), self::NOT_ACCOUNTS, true) || ctype_digit($name) || preg_match('/^(?:acct|domain|ip6?|email)-[0-9a-f]{8}$/D', $name) === 1) {
            return $name;
        }
        $this->count('account');
        return $this->token('acct-', $name);
    }

    public function text(string $text): string
    {
        // PEM blocks (keys of every kind, certificates, requests): the whole block goes, also an unterminated one.
        $text = preg_replace_callback('/-----BEGIN ([A-Z0-9 ]+)-----.*?(?:-----END \1-----|\z)/s', function (array $m): string {
            $this->count('pem');
            return str_contains($m[1], 'PRIVATE KEY') ? '[REDACTED PRIVATE KEY]' : '[REDACTED PEM BLOCK]';
        }, $text) ?? '';
        // Credentials and query strings of URLs.
        $text = preg_replace_callback('~\b([a-z][a-z0-9+.-]*://)[^\s/@:]*:[^\s/@]*@~i', function (array $m): string {
            $this->count('url_credentials');
            return $m[1] . '[REDACTED]@';
        }, $text) ?? '';
        // The path and query of a full URL: webhooks and API endpoints carry their token there. The host stays.
        $text = preg_replace_callback('~(\bhttps?://[^\s/?#"\'<>]+)[/?#][^\s"\'<>]*~i', function (array $m): string {
            $this->count('url_path');
            return $m[1] . '/[REDACTED]';
        }, $text) ?? '';
        $text = $this->headers($text);
        // Bearer and Basic credentials anywhere (a header the rule above did not see, a message quoting one): the token goes.
        // Basic needs a base64-looking token (a digit, + / =, or a capital after the first letter), so "Basic setup" stays.
        $text = preg_replace_callback('~\b(Bearer)(\s+)(?!\[REDACTED)[A-Za-z0-9._\~+/=-]+|\b(Basic)(\s+)(?!\[REDACTED)(?=[A-Za-z0-9+/]{4,}={0,2}(?![A-Za-z0-9+/=]))'
            . '(?-i:(?=[A-Za-z0-9+/]*[0-9+/=]|[A-Za-z0-9+/][a-z0-9+/]*[A-Z]))[A-Za-z0-9+/]+={0,2}~i', function (array $m): string {
            $this->count('header');
            return ($m[1] !== '' ? $m[1] . $m[2] : $m[3] . $m[4]) . '[REDACTED]';
        }, $text) ?? '';
        // name=value and "name": "value" where the name says it is a secret.
        $name = '(?:[A-Za-z0-9_.-]*(?:' . self::SECRET_NAMES . ')[A-Za-z0-9_.-]*)';
        $text = preg_replace_callback('/(["\']?)(' . $name . ')\1(\s*[:=]\s*)("[^"\r\n]*"|\'[^\'\r\n]*\'|[^\s,;&}\]]+)/im', function (array $m): string {
            if (in_array(strtolower(trim($m[4], '"\'')), ['', 'true', 'false', 'null', 'none', '[redacted]'], true) || str_starts_with(ltrim($m[4], '"\''), '[REDACTED')) {
                return $m[0];
            }
            $this->count('secret');
            return $m[1] . $m[2] . $m[1] . $m[3] . ($m[4][0] === '"' ? '"[REDACTED]"' : '[REDACTED]');
        }, $text) ?? '';
        // Long token-like strings (never a path component or a word: they carry a letter and a digit).
        $text = preg_replace_callback('/(?<![A-Za-z0-9\/._-])(?=[A-Za-z0-9+_-]*[0-9])(?=[A-Za-z0-9+_-]*[A-Za-z])[A-Za-z0-9+_-]{32,}={0,2}(?![A-Za-z0-9\/._-])/', function (): string {
            $this->count('token');
            return '[REDACTED TOKEN]';
        }, $text) ?? '';
        // E-mail addresses always: personal data of customers and of the operator. A quoted local part ("first.last"@, also
        // JSON-escaped \"first.last\"@) goes with its quotes.
        $text = preg_replace_callback('/(?:\\\\?"[^"\r\n]{1,64}?\\\\?"|[A-Za-z0-9._%+-]+)@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+/', function (array $m): string {
            $this->count('email');
            return $this->token('email-', $m[0], '@example.invalid');
        }, $text) ?? '';
        return $this->anonymize ? $this->anonymized($text) : $text;
    }

    private function anonymized(string $text): string
    {
        if ($this->domainPattern !== '') {
            $text = preg_replace_callback($this->domainPattern, function (array $m): string {
                $this->count('domain');
                return $this->token('domain-', $m[0], '.invalid');
            }, $text) ?? '';
        }
        // Any other host name (one this server no longer hosts appears in journals and audit records): labels of letters, digits
        // and hyphens, at least one dot, a final label of 2 to 63 letters that is not a file extension. A hyphen may continue it
        // (<domain>-error.log); a further dotted part may not (so jquery.min.js and archive.backup.gz are not names).
        $files = implode('|', self::FILE_LABELS);
        $text = preg_replace_callback('/(?<![A-Za-z0-9.@_-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+(?!(?:' . $files . ')(?![A-Za-z0-9]))'
            . '[A-Za-z]{2,63}(?![A-Za-z0-9_])(?!\.[A-Za-z0-9])/i', function (array $m): string {
            $labels = explode('.', strtolower($m[0]));
            if (end($labels) === 'invalid' || (count($labels) === 2 && (in_array($labels[0], self::WORD_LABELS, true)
                || in_array($labels[1], self::AMBIGUOUS_LABELS, true)))) {
                return $m[0]; // a placeholder already, a product word (ols.sync, opcache.enable) or a two-label file name (run.sh)
            }
            $this->count('domain');
            return $this->token('domain-', $m[0], '.invalid');
        }, $text) ?? '';
        // Account names in home directory paths (/home/<name>/, /home2/<name>/, /home/virtfs/<name>/) and in the account fields of
        // the product's records (user=, "account": "...", actor, principal, --account=, scope account:<name>), also of accounts
        // that were removed and so are not in the list this server gives.
        $text = preg_replace_callback('~(/home[A-Za-z0-9_]*/(?:virtfs/)?)([A-Za-z0-9_][A-Za-z0-9_-]{0,31})(?![A-Za-z0-9_.+-])~', function (array $m): string {
            return $m[1] . $this->accountToken($m[2]);
        }, $text) ?? '';
        $text = preg_replace_callback('/(?<![A-Za-z0-9_])((\\\\?["\']?)(?:' . self::ACCOUNT_FIELDS . ')\2\s*[:=]\s*(\\\\?["\']?))([A-Za-z0-9_][A-Za-z0-9_-]{0,31})(?=\3)(?![A-Za-z0-9_.@-])/i',
            function (array $m): string {
                return $m[1] . $this->accountToken($m[4]);
            }, $text) ?? '';
        $text = preg_replace_callback('/(?<![0-9.])(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})(?:\.(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})){3}(?![0-9])(?!\.[0-9])/', function (array $m): string {
            $this->count('ip');
            return $this->token('ip-', $m[0]);
        }, $text) ?? '';
        $text = preg_replace_callback('/(?<![A-Za-z0-9:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![A-Za-z0-9:])/i', function (array $m): string {
            if (!str_contains($m[0], '::') && substr_count($m[0], ':') !== 7) {
                return $m[0]; // a time (12:30:15) or a port pair, not an address
            }
            $this->count('ip');
            return $this->token('ip6-', $m[0]);
        }, $text) ?? '';
        if ($this->accountPattern !== '') {
            $text = preg_replace_callback($this->accountPattern, function (array $m): string {
                $this->count('account');
                return $this->token('acct-', $m[0]);
            }, $text) ?? '';
        }
        return $text;
    }

    /**
     * A decoded JSON value with every string (and every key) redacted, and the value of any key that names a secret removed.
     */
    public function data(mixed $value): mixed
    {
        if (is_string($value)) {
            return $this->text($value);
        }
        if (!is_array($value)) {
            return $value;
        }
        $out = [];
        foreach ($value as $key => $item) {
            $name = is_string($key) ? $this->text($key) : $key;
            if (is_string($key) && preg_match('/(?:' . self::SECRET_NAMES . ')/i', $key) === 1 && !is_bool($item) && $item !== null && $item !== '') {
                $this->count('secret');
                $out[$name] = '[REDACTED]';
                continue;
            }
            if ($this->anonymize && is_string($key) && is_string($item) && preg_match('/^(?:' . self::ACCOUNT_FIELDS . ')$/iD', $key) === 1
                && preg_match('/^[A-Za-z0-9_][A-Za-z0-9_-]{0,31}$/D', $item) === 1) {
                $out[$name] = $this->accountToken($item); // the account of a structured record, also one that was removed
                continue;
            }
            $out[$name] = $this->data($item);
        }
        return $out;
    }
}
