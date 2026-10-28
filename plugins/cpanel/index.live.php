<?php
// OLS-cPanel cPanel interface (G0-H, plan 21.4). LivePHP runs as the logged-in account: the broker
// identifies it from the socket peer credentials, and every file this page reads is read with the
// account's own privileges. No account, domain or path is taken from the request.
declare(strict_types=1);

require __DIR__ . '/lib/BrokerClient.php';
require __DIR__ . '/lib/AssetManifest.php';
require __DIR__ . '/lib/HtaccessTranslator.php';
require __DIR__ . '/lib/HtaccessRewrite.php';
require_once '/usr/local/cpanel/php/cpanel.php';

use OlsCpanel\Broker\BrokerClient;
use OlsCpanel\Ols\Compiler\HtaccessRewrite;
use OlsCpanel\Ols\Compiler\HtaccessRewriteRefused;
use OlsCpanel\Ols\Compiler\HtaccessTranslator;
use OlsCpanel\Ui\AssetManifest;

const FEATURE = 'ols_cpanel';
const SCAN_FILE_LIMIT = 200;
const SCAN_DEPTH = 10;
const SCAN_FILE_BYTES = 262144;
// The walk itself is bounded too, so an account with millions of files cannot stall the page
// (human review 2026-10-22, concern 7).
const SCAN_ENTRY_LIMIT = 200000;
const SCAN_SECONDS = 5.0;
/** Operations that may run a product command in the broker (30 s there) get a longer client timeout. */
const SLOW_TIMEOUT = 40.0;
const BODY_LIMIT = 1024;
const RESOLUTION = '/^(?:hour|day|week)$/D';
/** The request to the administrator carries up to 1000 characters of text. */
const REQUEST_BODY_LIMIT = 8192;
const HTACCESS_PATH = '/^~\/(?:(?!\.{1,2}\/)[A-Za-z0-9._-]{1,100}\/){0,20}\.htaccess$/D';
const HTACCESS_ID = '/^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$/D';
const LOG_KINDS = ['access', 'access_http', 'error'];
const HTACCESS_STATUS = ['BAD_PATH' => 400, 'OUT_OF_SCOPE' => 403, 'LINK' => 422, 'NOT_FOUND' => 404, 'UNREADABLE' => 422, 'STALE' => 409,
    'NO_REWRITE' => 422, 'BUSY' => 409, 'BACKUP' => 500, 'WRITE' => 500, 'CORRUPT' => 422, 'HOME' => 500];
const DOMAIN = '/^(?=.{3,253}$)[a-z0-9][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)+$/D';
/** Broker error codes with their own HTTP status; any other broker error is 502. */
const ERROR_STATUS = ['BAD_ARGS' => 400, 'NOT_FOUND' => 404, 'FORBIDDEN' => 403, 'REFUSED' => 422, 'RATE_LIMITED' => 429, 'BUSY' => 503, 'UNREADABLE' => 422, 'UNREACHABLE' => 502];

function respond_json(int $status, array $body): void
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');
    header("Content-Security-Policy: default-src 'none'; frame-ancestors 'self'");
    echo json_encode($body, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
}

/** Classify only the translator's existing account-local finding; never inspect other sites. */
function htaccess_reason_key(string $directive): string
{
    $detail = explode(': ', $directive, 2)[1] ?? $directive;
    foreach (['Directory Privacy' => 'privacy', '<Files' => 'files_block', 'access rule combination' => 'access_rules',
              'unsupported Options' => 'options', 'conditional Header' => 'conditional_header', 'rewrite' => 'rewrite',
              'CacheLookup' => 'rewrite', 'CacheKeyModify' => 'rewrite', 'expir' => 'expiry', 'ExpiresByType' => 'expiry',
              'unsafe path' => 'unsafe_path', '.htaccess unreadable' => 'unreadable'] as $needle => $key) {
        if (stripos($detail, $needle) !== false) {
            return $key;
        }
    }
    return 'directive';
}

/** @return array{roots:int,files:list<array>,truncated:bool,stopped:?string,limit:int} */
function htaccess_report(array $domains, string $home): array
{
    $roots = [];
    foreach ($domains as $row) {
        $root = rtrim((string) ($row['docroot'] ?? ''), '/');
        if (in_array($row['type'] ?? '', ['main', 'sub'], true) && ($root === $home || str_starts_with($root, $home . '/'))) {
            $roots[$root] = true;
        }
    }
    $roots = array_keys($roots);
    // Nested document roots (a subdomain inside public_html) claim their own files first.
    usort($roots, fn(string $a, string $b): int => strlen($b) <=> strlen($a));
    // The API and interface share one English reason catalog. No extra account data is read.
    $reasonCatalog = json_decode((string) file_get_contents(__DIR__ . '/lib/i18n.htaccess.en.json'), true, 512, JSON_THROW_ON_ERROR);
    $translator = new HtaccessTranslator();
    $files = [];
    $claimed = [];
    $stopped = null;
    $entries = 0;
    $deadline = microtime(true) + SCAN_SECONDS;
    foreach ($roots as $root) {
        if (!is_dir($root) || is_link($root)) {
            continue;
        }
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS | FilesystemIterator::CURRENT_AS_FILEINFO),
            RecursiveIteratorIterator::SELF_FIRST,
            RecursiveIteratorIterator::CATCH_GET_CHILD
        );
        $iterator->setMaxDepth(SCAN_DEPTH);
        foreach ($iterator as $info) {
            if (++$entries > SCAN_ENTRY_LIMIT) {
                $stopped = 'entries';
                break 2;
            }
            if (($entries & 1023) === 0 && microtime(true) > $deadline) {
                $stopped = 'time';
                break 2;
            }
            if ($info->getFilename() !== '.htaccess' || $info->isLink() || !$info->isFile() || isset($claimed[$info->getPathname()])) {
                continue;
            }
            if (count($files) >= SCAN_FILE_LIMIT) {
                $stopped = 'files';
                break 2;
            }
            $claimed[$info->getPathname()] = true;
            $text = $info->getSize() <= SCAN_FILE_BYTES ? @file_get_contents($info->getPathname()) : false;
            $rel = trim(substr($info->getPath(), strlen($root)), '/');
            if ($text === false) {
                $blockers = ["/$rel: .htaccess unreadable"];
            } else {
                [, , $blockers] = $translator->translate([$rel => $text], $root);
            }
            $proposal = $text === false ? null : HtaccessRewrite::proposal($text);
            $reasons = [];
            foreach ($blockers as $directive) {
                $key = htaccess_reason_key($directive);
                $reasons[] = ['directive' => $directive, 'reason_key' => $key, 'reason' => $reasonCatalog[$key]];
            }
            $files[] = ['path' => '~' . substr($info->getPathname(), strlen($home)), 'docroot' => '~' . substr($root, strlen($home)),
                        'blockers' => $blockers, 'outcome' => $blockers ? 'kept_on_apache' : 'translated', 'reasons' => $reasons,
                        'digest' => $text === false ? null : HtaccessRewrite::digest($text), 'fixes' => $proposal === null ? [] : $proposal['rules']];
        }
    }
    usort($files, fn(array $a, array $b): int => strcmp($a['path'], $b['path']));
    return ['roots' => count($roots), 'files' => $files, 'truncated' => $stopped !== null, 'stopped' => $stopped, 'limit' => SCAN_FILE_LIMIT];
}


/** The account's own site document roots (main and sub domains), from the broker's view of the caller. */
function own_docroots(): ?array
{
    $reply = (new BrokerClient(BrokerClient::TENANT_SOCKET))->call('tenant.domains');
    if (!$reply['ok']) {
        return null;
    }
    $roots = [];
    foreach ($reply['result']['domains'] ?? [] as $row) {
        if (in_array($row['type'] ?? '', ['main', 'sub'], true) && is_string($row['docroot'] ?? null)) {
            $roots[] = (string) $row['docroot'];
        }
    }
    return $roots;
}

/** Runs the rewrite as this process (the logged-in account); never as root. */
function htaccess_change(string $action, array $body): array
{
    $roots = own_docroots();
    $home = (string) (posix_getpwuid(posix_geteuid())['dir'] ?? '');
    if ($roots === null) {
        return [502, ['ok' => false, 'error' => ['code' => 'BROKER', 'message' => 'The OLS-cPanel service did not answer.']]];
    }
    try {
        $rewrite = new HtaccessRewrite($home);
        $result = $action === 'htaccess_apply' ? $rewrite->apply($body['path'], $body['digest'], $roots) : $rewrite->undo($body['id'], $roots);
        return [200, ['ok' => true, 'result' => $result]];
    } catch (HtaccessRewriteRefused $e) {
        return [HTACCESS_STATUS[$e->reason] ?? 422, ['ok' => false, 'error' => ['code' => $e->reason, 'message' => $e->getMessage()]]];
    }
}

/** A domain argument of an API request, or null. */
function query_domain(): ?string
{
    $d = $_GET['domain'] ?? null;
    return is_string($d) && preg_match(DOMAIN, $d) === 1 ? $d : null;
}

$cpanel = new CPANEL();
// Features::has_feature answers status 1 even for unknown features; the decision is in data (1 or
// null). Fail closed on any other shape.
$feature = $cpanel->uapi('Features', 'has_feature', ['name' => FEATURE]);
$outer = is_array($feature['cpanelresult'] ?? null) ? $feature['cpanelresult'] : (is_array($feature) ? $feature : []);
$answer = is_array($outer['result'] ?? null) && array_key_exists('status', $outer['result']) ? $outer['result'] : $outer;
$allowed = is_array($answer) && (int) ($answer['status'] ?? 0) === 1 && (int) ($answer['data'] ?? 0) === 1;

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    // Mutations: ?action=cache_purge or ?action=php_restart only, the request header (a cross-site form cannot send
    // it; cpsrvd's session token in the URL is the CSRF boundary), a JSON body ({domain?} for the purge, {} for the
    // restart). The account is the broker's SO_PEERCRED view of this process; the broker also checks that the
    // domain is one of that account's, rate-limits both actions and audits them.
    $name = $_GET['action'] ?? null;
    $limit = $name === 'request' ? REQUEST_BODY_LIMIT : BODY_LIMIT;
    if (!$allowed) {
        respond_json(403, ['ok' => false, 'error' => ['code' => 'FEATURE_DISABLED', 'message' => 'This feature is not enabled for your account.']]);
    } elseif (!is_string($name) || array_keys($_GET) !== ['action']) {
        respond_json(405, ['ok' => false, 'error' => ['code' => 'METHOD', 'message' => 'Actions use POST ?action=<name>.']]);
    } elseif (!in_array($name, ['cache_purge', 'php_restart', 'htaccess_apply', 'htaccess_undo', 'request'], true)) {
        respond_json(404, ['ok' => false, 'error' => ['code' => 'UNKNOWN_ACTION', 'message' => 'Unknown action.']]);
    } elseif (($_SERVER['HTTP_X_OLS_CPANEL_REQUEST'] ?? null) !== '1') {
        respond_json(403, ['ok' => false, 'error' => ['code' => 'REQUEST_HEADER', 'message' => 'The X-OLS-cPanel-Request header is required.']]);
    } else {
        $length = $_SERVER['CONTENT_LENGTH'] ?? '';
        if (!is_string($length) || preg_match('/^[0-9]{1,4}$/D', $length) !== 1 || (int) $length > $limit) {
            respond_json(413, ['ok' => false, 'error' => ['code' => 'BODY', 'message' => 'The request body is too large.']]);
        } else {
            try {
                $body = json_decode((string) file_get_contents('php://input', false, null, 0, $limit + 1), true, 3, JSON_THROW_ON_ERROR);
            } catch (JsonException) {
                $body = null;
            }
            $domain = is_array($body) ? ($body['domain'] ?? null) : null;
            $keys = is_array($body) && !array_is_list($body) ? array_keys($body) : null;
            $shapeOk = match ($name) {
                'cache_purge' => is_array($body) && ($body === [] || ($keys === ['domain'] && is_string($domain) && preg_match(DOMAIN, $domain) === 1)),
                'php_restart' => $body === [],
                'htaccess_apply' => $keys === ['path', 'digest'] && is_string($body['path']) && preg_match(HTACCESS_PATH, $body['path']) === 1
                    && is_string($body['digest']) && preg_match('/^[0-9a-f]{64}$/D', $body['digest']) === 1,
                'htaccess_undo' => $keys === ['id'] && is_string($body['id']) && preg_match(HTACCESS_ID, $body['id']) === 1,
                'request' => $keys === ['subject', 'text'] && is_string($body['subject']) && is_string($body['text']) && strlen($body['subject']) <= 32,
            };
            if (!$shapeOk) {
                respond_json(400, ['ok' => false, 'error' => ['code' => 'BAD_BODY', 'message' => 'The request body does not fit this action.']]);
            } elseif ($name === 'php_restart') {
                $reply = (new BrokerClient(BrokerClient::TENANT_SOCKET, SLOW_TIMEOUT))->call('tenant.php_restart');
                respond_json($reply['ok'] ? 200 : (ERROR_STATUS[$reply['error']['code'] ?? ''] ?? 502), $reply);
            } elseif ($name === 'htaccess_apply' || $name === 'htaccess_undo') {
                [$status, $reply] = htaccess_change($name, $body);
                respond_json($status, $reply);
            } elseif ($name === 'request') {
                $reply = (new BrokerClient(BrokerClient::TENANT_SOCKET))->call('tenant.request', $body);
                respond_json($reply['ok'] ? 200 : (ERROR_STATUS[$reply['error']['code'] ?? ''] ?? 502), $reply);
            } else {
                $reply = (new BrokerClient(BrokerClient::TENANT_SOCKET, SLOW_TIMEOUT))->call('tenant.cache_purge', $body === [] ? null : ['domain' => $domain]);
                respond_json($reply['ok'] ? 200 : (ERROR_STATUS[$reply['error']['code'] ?? ''] ?? 502), $reply);
            }
        }
    }
    $cpanel->end();
    exit;
}

if (isset($_GET['api'])) {
    $name = is_string($_GET['api']) ? $_GET['api'] : '';
    if (!$allowed) {
        respond_json(403, ['ok' => false, 'error' => ['code' => 'FEATURE_DISABLED', 'message' => 'This feature is not enabled for your account.']]);
    } elseif ($name === 'status' || $name === 'sites') {
        // The broker answers for the socket peer's own account only (tenant.sites: domains, engine, PHP, TLS expiry).
        $reply = (new BrokerClient(BrokerClient::TENANT_SOCKET))->call($name === 'status' ? 'tenant.status' : 'tenant.sites');
        respond_json($reply['ok'] ? 200 : 502, $reply);
    } elseif ($name === 'cache') {
        // This account's own LSCache stores (tenant.cache_stats); no argument is taken from the request.
        $reply = (new BrokerClient(BrokerClient::TENANT_SOCKET, SLOW_TIMEOUT))->call('tenant.cache_stats');
        respond_json($reply['ok'] ? 200 : (ERROR_STATUS[$reply['error']['code'] ?? ''] ?? 502), $reply);
    } elseif ($name === 'php') {
        // This account's own PHP view (tenant.php): site versions and handlers, own lsphp processes, OPcache, limits.
        $reply = (new BrokerClient(BrokerClient::TENANT_SOCKET, SLOW_TIMEOUT))->call('tenant.php');
        respond_json($reply['ok'] ? 200 : (ERROR_STATUS[$reply['error']['code'] ?? ''] ?? 502), $reply);
    } elseif ($name === 'objcache') {
        // This account's own object cache (tenant.objcache): connection values, usage, WordPress sites and their state.
        $reply = (new BrokerClient(BrokerClient::TENANT_SOCKET, SLOW_TIMEOUT))->call('tenant.objcache');
        respond_json($reply['ok'] ? 200 : (ERROR_STATUS[$reply['error']['code'] ?? ''] ?? 502), $reply);
    } elseif ($name === 'history') {
        // This account's own traffic history (tenant.metrics): the optional resolution and one of its own vhosts; the
        // broker answers NOT_FOUND for a vhost that is not the account's and returns nothing of the server.
        $args = [];
        $valid = true;
        foreach ($_GET as $key => $value) {
            if ($key === 'api') {
                continue;
            }
            if (($key === 'resolution' && is_string($value) && preg_match(RESOLUTION, $value) === 1)
                || ($key === 'vhost' && is_string($value) && preg_match(DOMAIN, $value) === 1)) {
                $args[$key] = $value;
            } else {
                $valid = false;
            }
        }
        if (!$valid) {
            respond_json(400, ['ok' => false, 'error' => ['code' => 'BAD_QUERY', 'message' => 'Invalid query.']]);
        } else {
            $reply = (new BrokerClient(BrokerClient::TENANT_SOCKET))->call('tenant.metrics', $args === [] ? null : $args);
            respond_json($reply['ok'] ? 200 : (ERROR_STATUS[$reply['error']['code'] ?? ''] ?? 502), $reply);
        }
    } elseif (in_array($name, ['logs', 'logs_download', 'php_errors', 'perf'], true)) {
        // Account tools (FV-08): the domain, log kind, line count and search text are checked here and again by the
        // broker, which only serves the caller's own domains.
        $allowedKeys = match ($name) { 'logs' => ['api', 'domain', 'kind', 'lines', 'search'], 'logs_download' => ['api', 'domain', 'kind', 'search'],
            default => ['api', 'domain'] };
        $domain = query_domain();
        $kind = $_GET['kind'] ?? 'access';
        $lines = $_GET['lines'] ?? null;
        $search = $_GET['search'] ?? null;
        $valid = $domain !== null && array_diff(array_keys($_GET), $allowedKeys) === [] && in_array($kind, LOG_KINDS, true)
            && ($lines === null || (is_string($lines) && preg_match('/^[1-9][0-9]{0,2}$/D', $lines) === 1 && (int) $lines <= 500))
            && ($search === null || (is_string($search) && mb_strlen($search) <= 100 && preg_match('/[\x00-\x1f\x7f]/', $search) !== 1));
        if (!$valid) {
            respond_json(400, ['ok' => false, 'error' => ['code' => 'BAD_QUERY', 'message' => 'Invalid query arguments for this API.']]);
        } else {
            $args = ['domain' => $domain];
            if ($name === 'logs' || $name === 'logs_download') {
                $args['kind'] = $kind;
                $args += $lines === null ? [] : ['lines' => (int) $lines];
                $args += ($search === null || $search === '') ? [] : ['search' => $search];
                $args += $name === 'logs_download' ? ['download' => true] : [];
            }
            $op = ['logs' => 'tenant.logs', 'logs_download' => 'tenant.logs', 'php_errors' => 'tenant.php_errors', 'perf' => 'tenant.perf'][$name];
            $reply = (new BrokerClient(BrokerClient::TENANT_SOCKET, SLOW_TIMEOUT))->call($op, $args);
            if ($name === 'logs_download' && $reply['ok']) {
                header('Content-Type: text/plain; charset=utf-8');
                header('Content-Disposition: attachment; filename="' . preg_replace('/[^A-Za-z0-9._-]/', '_', (string) ($reply['result']['file'] ?? 'log')) . '.txt"');
                header('Cache-Control: no-store');
                header('X-Content-Type-Options: nosniff');
                echo (string) ($reply['result']['text'] ?? '');
            } else {
                respond_json($reply['ok'] ? 200 : (ERROR_STATUS[$reply['error']['code'] ?? ''] ?? 502), $reply);
            }
        }
    } elseif ($name === 'requests') {
        $reply = (new BrokerClient(BrokerClient::TENANT_SOCKET))->call('tenant.requests');
        respond_json($reply['ok'] ? 200 : (ERROR_STATUS[$reply['error']['code'] ?? ''] ?? 502), $reply);
    } elseif ($name === 'htaccess_backups') {
        // The account's own change records, read from its home as the account.
        try {
            $home = (string) (posix_getpwuid(posix_geteuid())['dir'] ?? '');
            respond_json(200, ['ok' => true, 'result' => ['backups' => (new HtaccessRewrite($home))->backups()]]);
        } catch (HtaccessRewriteRefused) {
            respond_json(200, ['ok' => true, 'result' => ['backups' => []]]);
        }
    } elseif ($name === 'domains' || $name === 'htaccess') {
        $reply = (new BrokerClient(BrokerClient::TENANT_SOCKET))->call('tenant.domains');
        if (!$reply['ok'] || $name === 'domains') {
            respond_json($reply['ok'] ? 200 : 502, $reply);
        } else {
            $home = (string) (posix_getpwuid(posix_geteuid())['dir'] ?? '');
            respond_json(200, ['ok' => true, 'result' => htaccess_report($reply['result']['domains'] ?? [], rtrim($home, '/'))]);
        }
    } else {
        respond_json(404, ['ok' => false, 'error' => ['code' => 'UNKNOWN_API', 'message' => 'Unknown API.']]);
    }
    $cpanel->end();
    exit;
}

print $cpanel->header('OLS-cPanel');
if (!$allowed) {
    echo '<p>This feature is not enabled for your account.</p>';
} else {
    $tags = AssetManifest::fromFile(__DIR__ . '/manifest.json')->tags('src/cpanel/main.js');
    echo $tags === null ? '<p>OLS-cPanel interface assets are missing.</p>'
        : '<div id="ols-cpanel-app" data-endpoint="index.live.php"></div>' . "\n" . $tags;
}
print $cpanel->footer();
$cpanel->end();
