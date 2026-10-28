#!/usr/local/cpanel/3rdparty/bin/php-cgi
<?php
// OLS-cPanel WHM gateway (plan 5.2-5.3, docs/product-interfaces.md "Plugin data and actions"). Runs as root
// under cpsrvd, which authenticates the session and enforces the AppConfig ACL before this script starts.
// Trusted computing base: no templates, no plugin loading. Input is a fixed API or action name, query
// arguments checked against each operation's schema, and for actions a small JSON body {scope, digest};
// nothing else from the request reaches the broker and no reply echoes request text. The principal comes
// only from cpsrvd's REMOTE_USER (request headers arrive as HTTP_*, never as REMOTE_USER). Mutations are
// POSTs: cpsrvd's session token in the URL is the CSRF boundary, and the X-OLS-cPanel-Request header (which
// a cross-site form cannot send) is required as well.
declare(strict_types=1);

require __DIR__ . '/lib/BrokerClient.php';
require __DIR__ . '/lib/AssetManifest.php';

use OlsCpanel\Broker\BrokerClient;
use OlsCpanel\Ui\AssetManifest;

const ALLOWED_PRINCIPALS = ['root'];           // plan 21.1: root only unless policy says otherwise
/** GET ?api=<name>: the broker operation and the query arguments it accepts ("!" = required). */
const API = [
    'status' => ['server.status', []],
    'metrics' => ['server.metrics', []],
    'inventory' => ['inventory.accounts', ['query', 'page', 'size']],
    'compat' => ['compat.findings', ['query', 'page', 'size']],
    'plan' => ['plan.latest', []],
    'generations' => ['generation.list', []],
    'doctor' => ['doctor.report', []],
    'jobs' => ['job.list', []],
    'job' => ['job.status', ['job!']],
    'cache' => ['cache.stats', ['account', 'domain']],
    'cache_limits' => ['admin.cache_limits', []],
    'objcache' => ['admin.objcache', []],
    'php' => ['php.status', []],
    'history' => ['admin.metrics', ['resolution', 'vhost']],
    'requests' => ['admin.requests', []],
    // FV-07 operations: the activity log, the notification settings, maintenance windows, the update channel, support bundles.
    'audit' => ['admin.audit', ['query', 'page', 'size', 'event', 'result']],
    'notify' => ['admin.notify', []],
    'schedule' => ['admin.schedule', []],
    'update' => ['admin.update', ['refresh']],
    'bundle' => ['admin.bundle', []],
];
/** Query argument grammars; page and size are passed as integers. */
const PARAMS = [
    'query' => '/^[A-Za-z0-9._-]{0,253}$/D',
    'page' => '/^[1-9][0-9]{0,5}$/D',
    'size' => '/^(?:[1-9][0-9]?|1[0-9]{2}|200)$/D',
    'job' => '/^j[0-9]{10}-[0-9a-f]{8}$/D',
    'account' => '/^[a-z0-9][a-z0-9_-]{0,31}$/D',
    'domain' => '/^(?=.{3,253}$)[a-z0-9][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)+$/D',
    'vhost' => '/^(?=.{3,253}$)[a-z0-9][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)+$/D',
    'resolution' => '/^(?:hour|day|week)$/D',
    'event' => '/^[a-z_]{1,40}$/D',
    'result' => '/^(?:ok|failed)$/D',
    'refresh' => '/^1$/D',
];
const INTEGER_PARAMS = ['page', 'size'];
const BOOLEAN_PARAMS = ['refresh'];
/** POST ?action=<name>: the job actions and the scope each takes ("server", a plan id, or a cache purge scope). */
const ACTIONS = ['ols.sync' => 'server', 'ols.rollback' => 'server', 'ols.plan' => 'server', 'ols.plan_hybrid' => 'server',
    'ols.cutover' => 'plan', 'ols.apache_return' => 'server', 'ols.cache_purge' => 'cache', 'ols.php_restart' => 'php_restart',
    'ols.opcache_install' => 'opcache', 'ols.php_env_repair' => 'server', 'ols.support_bundle' => 'server', 'ols.support_bundle_raw' => 'server',
    'ols.update' => 'server'];
/** The scope of ols.cache_purge: "server", "account:<user>" or "domain:<domain>". */
const CACHE_SCOPE = '/^(?:server|account:[a-z0-9][a-z0-9_-]{0,31}|domain:(?=.{3,253}$)[a-z0-9][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)+)$/D';
/** The scope of ols.php_restart: "server" or "account:<user>"; of ols.opcache_install: "server" or "version:ea-phpNN". */
const PHP_RESTART_SCOPE = '/^(?:server|account:[a-z0-9][a-z0-9_-]{0,31})$/D';
const OPCACHE_SCOPE = '/^(?:server|version:ea-php[0-9]{2,3})$/D';
const PLAN_ID = '/^[0-9A-Za-z_][0-9A-Za-z_-]{0,63}$/D';
const DIGEST = '/^[0-9a-f]{64}$/D';
/** POST ?action=cache_limits: the limits of the automatic cache cleanup, a settings change (no job) with these inclusive bounds. */
const CACHE_LIMITS = ['per_site_mb' => [16, 102400], 'server_percent' => [1, 50], 'server_max_gb' => [1, 2048]];
/** POST ?action=<name> settings changes and small operations (no job, no digest): the broker operation each relays to. */
const SETTINGS = ['cache_limits' => 'admin.cache_limits', 'request_status' => 'admin.request_status', 'notify_settings' => 'admin.notify_set', 'notify_test' => 'admin.notify_test',
    'schedule_add' => 'admin.schedule_add', 'schedule_cancel' => 'admin.schedule_cancel', 'objcache_automatic' => 'admin.objcache'];
const EMAIL = '/^[A-Za-z0-9][A-Za-z0-9._%+-]{0,63}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/D';
const WEBHOOK = '/^https:\/\/[A-Za-z0-9._~:\/?#@!$&()*+,;=%-]{1,500}$/D';
const NOTIFY_EVENTS = ['job', 'held', 'php_env', 'upgrade', 'cache_emergency', 'disk', 'objcache', 'schedule'];
const SCHEDULE_ACTIONS = ['ols.cutover', 'ols.apache_return'];
const SCHEDULE_ID = '/^s[0-9]{14}-[0-9a-f]{6}$/D';
/** Support bundles: the directory the product writes them to (root 0600) and the only name shape that is served. */
const BUNDLE_DIR = '/var/lib/ols-cpanel/support';
const BUNDLE_NAME = '/^bundle-[0-9]{10}-[0-9a-f]{8}\.tar\.gz$/D';
const BUNDLE_MAX = 21 * 1024 * 1024;
const BODY_LIMIT = 4096;
/** Operations that may run a product command (30 s in the broker) get a longer client timeout. */
const SLOW_TIMEOUT = 40.0;
/** Broker error codes with their own HTTP status; any other broker error is 502. */
const ERROR_STATUS = ['BAD_ARGS' => 400, 'NOT_FOUND' => 404, 'BUSY' => 409, 'STALE' => 409, 'FORBIDDEN' => 403, 'REFUSED' => 422];

/** An https URL with a host name and no credentials (the broker and the engine check it again). */
function webhook_valid(string $url): bool
{
    $parts = preg_match(WEBHOOK, $url) === 1 ? parse_url($url) : false;
    return is_array($parts) && !isset($parts['user']) && !isset($parts['pass']) && is_string($parts['host'] ?? null)
        && preg_match('/^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$/D', $parts['host']) === 1
        && (!isset($parts['port']) || ($parts['port'] >= 1 && $parts['port'] <= 65535));
}

/** Whether the body of a settings action fits its schema (the broker checks every value again). */
function settings_body_valid(string $name, mixed $body): bool
{
    if ($name === 'cache_limits') {
        // {per_site_mb?, server_percent?, server_max_gb?}, whole numbers inside the bounds, at least one.
        $valid = is_array($body) && $body !== [] && !array_is_list($body) && array_diff(array_keys($body), array_keys(CACHE_LIMITS)) === [];
        foreach ($valid ? $body : [] as $key => $value) {
            $valid = $valid && is_int($value) && $value >= CACHE_LIMITS[$key][0] && $value <= CACHE_LIMITS[$key][1];
        }
        return $valid;
    }
    if ($name === 'request_status') {
        // {id, status}: one request of an account marked open or done.
        return is_array($body) && !array_is_list($body) && array_keys($body) === ['id', 'status'] && is_string($body['id'])
            && preg_match('/^r[0-9]{10}-[0-9a-f]{8}$/D', $body['id']) === 1 && in_array($body['status'], ['open', 'done'], true);
    }
    if ($name === 'notify_test') {
        return $body === [];
    }
    if ($name === 'objcache_automatic') {
        // {automatic: true|false}: the object cache's automatic mode for accounts with WordPress and LiteSpeed Cache.
        return is_array($body) && !array_is_list($body) && array_keys($body) === ['automatic'] && is_bool($body['automatic']);
    }
    if (!is_array($body) || $body === [] || array_is_list($body)) {
        return false;
    }
    $keys = array_keys($body);
    if ($name === 'notify_settings') {
        $emails = $body['emails'] ?? [];
        $events = $body['events'] ?? [];
        return array_diff($keys, ['emails', 'webhook', 'events']) === []
            && is_array($emails) && array_is_list($emails) && count($emails) <= 5
            && array_filter($emails, static fn($e): bool => !is_string($e) || strlen($e) > 254 || preg_match(EMAIL, $e) !== 1) === []
            && (!array_key_exists('webhook', $body) || $body['webhook'] === '' || (is_string($body['webhook']) && webhook_valid($body['webhook'])))
            && is_array($events) && array_is_list($events) && count($events) <= count(NOTIFY_EVENTS)
            && array_filter($events, static fn($e): bool => !is_string($e) || !in_array($e, NOTIFY_EVENTS, true)) === [];
    }
    if ($name === 'schedule_cancel') {
        return $keys === ['id'] && is_string($body['id']) && preg_match(SCHEDULE_ID, $body['id']) === 1;
    }
    // schedule_add: {action, scope, digest, at, window?}
    return array_diff($keys, ['action', 'scope', 'digest', 'at', 'window']) === []
        && is_string($body['action'] ?? null) && in_array($body['action'], SCHEDULE_ACTIONS, true)
        && is_string($body['scope'] ?? null) && ($body['action'] === 'ols.apache_return' ? $body['scope'] === 'server'
            : ($body['scope'] !== 'server' && preg_match(PLAN_ID, $body['scope']) === 1))
        && is_string($body['digest'] ?? null) && preg_match(DIGEST, $body['digest']) === 1
        && is_int($body['at'] ?? null) && $body['at'] > 0 && $body['at'] < 4102444800
        && (!array_key_exists('window', $body) || (is_int($body['window']) && $body['window'] >= 15 && $body['window'] <= 720));
}

function respond_json(int $status, array $body): void
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');
    header("Content-Security-Policy: default-src 'none'; frame-ancestors 'self'");
    echo json_encode($body, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
}

function refuse(int $status, string $code, string $message): never
{
    respond_json($status, ['ok' => false, 'error' => ['code' => $code, 'message' => $message]]);
    exit;
}

function relay(array $reply, int $success = 200): never
{
    $status = $reply['ok'] ? $success : (ERROR_STATUS[$reply['error']['code'] ?? ''] ?? 502);
    respond_json($status, $reply);
    exit;
}

/** The broker arguments of a GET API request, or null when the query does not fit the operation's schema. */
function api_arguments(array $query, array $allowed): ?array
{
    $args = [];
    $names = array_map(static fn(string $p): string => rtrim($p, '!'), $allowed);
    foreach ($query as $key => $value) {
        if ($key === 'api') {
            continue;
        }
        if (!is_string($key) || !in_array($key, $names, true) || !is_string($value) || preg_match(PARAMS[$key], $value) !== 1) {
            return null;
        }
        $args[$key] = in_array($key, INTEGER_PARAMS, true) ? (int) $value : (in_array($key, BOOLEAN_PARAMS, true) ? $value === '1' : $value);
    }
    foreach ($allowed as $param) {
        if (str_ends_with($param, '!') && !array_key_exists(rtrim($param, '!'), $args)) {
            return null;
        }
    }
    return $args;
}

$principal = getenv('REMOTE_USER');
if (!is_string($principal) || !in_array($principal, ALLOWED_PRINCIPALS, true)) {
    refuse(403, 'FORBIDDEN', 'Root access is required.');
}
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

if ($method === 'POST') {
    // Mutations: ?action=<name> only, the request header, a JSON body {scope, digest}.
    $name = $_GET['action'] ?? null;
    if (!is_string($name) || array_keys($_GET) !== ['action']) {
        refuse(405, 'METHOD', 'Read operations use GET; actions use POST ?action=<name>.');
    }
    if (!array_key_exists($name, ACTIONS) && !array_key_exists($name, SETTINGS)) {
        refuse(404, 'UNKNOWN_ACTION', 'Unknown action.');
    }
    if (($_SERVER['HTTP_X_OLS_CPANEL_REQUEST'] ?? null) !== '1') {
        refuse(403, 'REQUEST_HEADER', 'The X-OLS-cPanel-Request header is required.');
    }
    $length = $_SERVER['CONTENT_LENGTH'] ?? '';
    if (!is_string($length) || preg_match('/^[0-9]{1,5}$/D', $length) !== 1 || (int) $length > BODY_LIMIT) {
        refuse(413, 'BODY', 'The request body must be a JSON object of at most 4 KiB.');
    }
    $text = (string) file_get_contents('php://input', false, null, 0, BODY_LIMIT + 1);
    try {
        $body = json_decode($text, true, 3, JSON_THROW_ON_ERROR);
    } catch (JsonException) {
        $body = null;
    }
    if (array_key_exists($name, SETTINGS)) {
        // A settings change or a small operation, not a job: a JSON object checked against this action's schema (no digest).
        if (!settings_body_valid($name, $body)) {
            refuse(400, 'BAD_BODY', 'The body does not fit this action: see docs/product-interfaces.md, "Gateways".');
        }
        relay((new BrokerClient(BrokerClient::ADMIN_SOCKET, SLOW_TIMEOUT))->call(SETTINGS[$name], $body === [] ? null : $body));
    }
    $scope = is_array($body) ? ($body['scope'] ?? null) : null;
    $digest = is_array($body) ? ($body['digest'] ?? null) : null;
    $scopeOk = is_string($scope) && match (ACTIONS[$name]) {
        'server' => $scope === 'server',
        'cache' => preg_match(CACHE_SCOPE, $scope) === 1,
        'php_restart' => preg_match(PHP_RESTART_SCOPE, $scope) === 1,
        'opcache' => preg_match(OPCACHE_SCOPE, $scope) === 1,
        default => $scope !== 'server' && preg_match(PLAN_ID, $scope) === 1,
    };
    if (!is_array($body) || array_is_list($body) || count($body) !== 2 || !$scopeOk || !is_string($digest)
        || preg_match(DIGEST, $digest) !== 1) {
        refuse(400, 'BAD_BODY', 'The body must be {"scope", "digest"} with the scope this action takes and a SHA-256 digest.');
    }
    // Issue the capability as the cPanel principal and execute it at once: the broker binds it to exactly
    // this action, scope and digest, checks the digest against the current plan or status, starts the job.
    $broker = new BrokerClient(BrokerClient::ADMIN_SOCKET, SLOW_TIMEOUT);
    $capability = ['principal' => $principal, 'action' => $name, 'scope' => $scope, 'digest' => $digest];
    $issued = $broker->call('cap.issue', $capability);
    if (!$issued['ok'] || !is_string($issued['result']['token'] ?? null)) {
        relay($issued['ok'] ? ['ok' => false, 'error' => ['code' => 'BROKER_REPLY', 'message' => 'Unexpected reply from the OLS-cPanel service.']] : $issued);
    }
    $executed = $broker->call('cap.execute', ['token' => $issued['result']['token'], 'action' => $name, 'scope' => $scope,
        'digest' => $digest]);
    relay($executed, 202);
}
if ($method !== 'GET') {
    refuse(405, 'METHOD', 'Only GET and POST are supported.');
}
if (isset($_GET['action'])) {
    refuse(405, 'METHOD', 'Actions use POST.');
}
if (isset($_GET['download'])) {
    // A support bundle: the one name shape the product writes, from its own directory, never through a link.
    $name = $_GET['download'];
    if (array_keys($_GET) !== ['download'] || !is_string($name) || preg_match(BUNDLE_NAME, $name) !== 1) {
        refuse(400, 'BAD_QUERY', 'Invalid download name.');
    }
    $path = BUNDLE_DIR . '/' . $name;
    $size = is_file($path) && !is_link($path) ? filesize($path) : false;
    if ($size === false || $size > BUNDLE_MAX) {
        refuse(404, 'NOT_FOUND', 'No such support bundle.');
    }
    header('Content-Type: application/gzip');
    header('Content-Disposition: attachment; filename="' . $name . '"');
    header('Content-Length: ' . $size);
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');
    readfile($path);
    exit;
}
if (isset($_GET['api'])) {
    $name = is_string($_GET['api']) ? $_GET['api'] : '';
    if (!array_key_exists($name, API)) {
        refuse(404, 'UNKNOWN_API', 'Unknown API.');
    }
    [$op, $allowed] = API[$name];
    $args = api_arguments($_GET, $allowed);
    if ($args === null) {
        refuse(400, 'BAD_QUERY', 'Invalid query arguments for this API.');
    }
    $reply = (new BrokerClient(BrokerClient::ADMIN_SOCKET, SLOW_TIMEOUT))->call($op, $args === [] ? null : $args);
    relay($reply);
}

/**
 * WHM's PHP chrome (WHM::getHeaderString) is a copy cPanel pre-renders without the user's saved settings, so its analytics
 * consent slideout always starts as "no choice made" and opened on every load of a PHP plugin page, although the choice was
 * saved (lab finding 2026-10-28). The user's own saved choice (WHM nvdata, the same keys the slideout writes) is put back
 * into that copy: the saved consent as the current setting, and a dismissed slideout stays closed. Only display state is
 * changed; nothing is saved here. When cPanel's markup differs, nothing is replaced and WHM behaves as before.
 */
function whm_consent_state(string $header, string $user): string
{
    if (preg_match('/^[a-z0-9][a-z0-9_.-]{0,63}$/D', $user) !== 1) {
        return $header;
    }
    $text = @file_get_contents("/var/cpanel/whm/nvdata/$user.yaml", false, null, 0, 65536);
    if (!is_string($text)) {
        return $header;
    }
    $value = static fn(string $key): ?string => preg_match('/^' . preg_quote($key, '/') . ":\s*'?([A-Za-z0-9]+)'?\s*$/m", $text, $m) === 1
        ? $m[1] : null;
    $consent = $value('analytics');
    if ($consent === 'on' || $consent === 'off') {
        $header = str_replace('var currentConsentSetting = null;', 'var currentConsentSetting = ' . ($consent === 'on' ? 'true' : 'false') . ';', $header);
    }
    if ($value('slideoutDismissed') === '1') {
        $header = str_replace('if(currentConsentSetting === null && !slideoutDismissed){', 'if(false){', $header);
    }
    return $header;
}

// Page: WHM chrome around the prebuilt application; asset names come from the build manifest.
require_once '/usr/local/cpanel/php/WHM.php';
$tags = AssetManifest::fromFile(__DIR__ . '/manifest.json')->tags('src/whm/main.js');
header('Content-Type: text/html; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');
// cPanel regenerates the WHM chrome cache asynchronously (e.g. right after an AppConfig change) and
// WHM::header() throws while it is missing; fall back to a minimal frame instead of failing the page.
try {
    $header = WHM::getHeaderString('OLS-cPanel', 0, 0);
    $footer = WHM::getFooterString();
} catch (Throwable) {
    $header = "<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\"><title>OLS-cPanel</title></head><body>\n";
    $footer = "</body></html>\n";
}
echo whm_consent_state($header, getenv('REMOTE_USER') ?: '');
echo $tags === null ? '<p>OLS-cPanel interface assets are missing.</p>'
    : '<div id="ols-cpanel-app" data-endpoint="index.cgi"></div>' . "\n" . $tags;
echo $footer;
