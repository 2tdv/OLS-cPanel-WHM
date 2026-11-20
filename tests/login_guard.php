<?php
declare(strict_types=1);

// WordPress login guard (RV-64, CMP-04) on temporary trees: the 2026-11-12 xmlrpc flood is blocked within the minute while a
// site owner's login, the soak harness's editors, Jetpack and the server itself never are; blocks are per site, expire and
// double on repeats; the map is what the compiled vhost rule reads; the log scanner follows appends, rotation and partial
// lines; the switch empties the map; an unblock from another process is not undone by the watcher; the CLI's root rule.
require dirname(__DIR__) . '/src/bootstrap.php';

use OlsCpanel\Cli\Application;
use OlsCpanel\Cli\Command\LoginGuardCommand;
use OlsCpanel\Cli\EngineContext;
use OlsCpanel\Cli\Output;
use OlsCpanel\Ols\Compiler\CpanelSurface;
use OlsCpanel\Operations\LoginGuard;

$count = 0;
function check(bool $condition, string $name): void
{
    global $count;
    if (!$condition) {
        throw new RuntimeException('FAIL: ' . $name);
    }
    ++$count;
    echo "PASS: $name\n";
}

function tree_remove(string $path): void
{
    if (is_dir($path) && !is_link($path)) {
        foreach (scandir($path) as $name) {
            if ($name !== '.' && $name !== '..') {
                tree_remove("$path/$name");
            }
        }
        rmdir($path);
    } elseif (file_exists($path) || is_link($path)) {
        unlink($path);
    }
}

/** A cPanel domlog line (combined format) at Unix time $at. */
function line(string $ip, string $method, string $uri, int $at, int $status = 200, int $bytes = 401): string
{
    return sprintf('%s - - [%s] "%s %s HTTP/1.1" %d %d "-" "Mozilla/5.0"', $ip, gmdate('d/M/Y:H:i:s +0000', $at), $method, $uri, $status, $bytes);
}

$root = sys_get_temp_dir() . '/ols-login-guard-' . bin2hex(random_bytes(4));
$state = "$root/state";
$logs = "$root/domlogs";
$map = "$root/run/guard/login.map";
mkdir($state, 0700, true);
mkdir($logs, 0755, true);
mkdir("$root/run", 0711);
$group = (string) (posix_getgrgid(posix_getegid())['name'] ?? 'nobody');
$own = ['203.0.113.5', '2001:db8::5'];
$guard = static fn(): LoginGuard => new LoginGuard($state, $logs, $map, $own, $group);
$entries = static function () use ($map): array {
    clearstatcache();
    $lines = is_file($map) ? file($map, FILE_IGNORE_NEW_LINES) : [];
    return array_values(array_filter($lines, static fn(string $l): bool => $l !== '' && $l[0] !== '#'));
};
$t0 = 1794488040;   // 2026-11-12 12:54:00 UTC

try {
    // --- Address ranges -----------------------------------------------------------------------------------------------------
    check(LoginGuard::inCidr('192.0.84.10', '192.0.64.0/18') && !LoginGuard::inCidr('192.0.128.1', '192.0.64.0/18')
        && LoginGuard::inCidr('2001:db8::1', '2001:db8::/32') && !LoginGuard::inCidr('10.0.0.1', '2001:db8::/32')
        && LoginGuard::inCidr('34.30.196.241', '34.30.196.241') && !LoginGuard::inCidr('34.30.196.242', '34.30.196.241/32')
        && LoginGuard::inCidr('10.1.2.3', '10.0.0.0/7') && !LoginGuard::inCidr('12.0.0.1', '10.0.0.0/7'),
        'address ranges: IPv4, IPv6, single addresses and prefixes that are not byte-aligned');
    check(LoginGuard::validCidr('1.2.3.4') && LoginGuard::validCidr('1.2.3.0/24') && LoginGuard::validCidr('2001:db8::/48')
        && !LoginGuard::validCidr('1.2.3.0/33') && !LoginGuard::validCidr('2001:db8::/129') && !LoginGuard::validCidr('example.com')
        && !LoginGuard::validCidr('1.2.3.4/x') && !LoginGuard::validCidr(''), 'allow entries are addresses or ranges only');

    // --- The compiled rule reads what the watcher writes --------------------------------------------------------------------
    $rules = (new CpanelSurface())->guardRules('olstest1.example.test');
    check($rules[0] === 'RewriteCond ${ols_login_guard:olstest1.example.test/%{REMOTE_ADDR}} =1'
        && $rules[1] === 'RewriteRule (?:^|/)(?:wp-login|xmlrpc)\.php(?:/|$) - [F,NC,L]'
        && CpanelSurface::GUARD_FILE === '/run/ols-cpanel/guard/login.map', 'vhost rule: map key <domain>/<client address>, value 1, the two login paths only');
    foreach (['/xmlrpc.php' => true, '/wp-login.php' => true, '/blog/xmlrpc.php' => true, '/XMLRPC.PHP' => true, '/wp-login.php.bak' => false,
              '/xmlrpc.php/x' => true, '/wp-login.php/' => true, '/my-xmlrpc.php' => false, '/wp-admin/' => false, '/' => false] as $uri => $hit) {
        check((preg_match('~' . CpanelSurface::GUARD_PATHS . '~i', $uri) === 1) === $hit, "the guard rule's path pattern on $uri");
    }

    // --- 2026-11-12: about 250 xmlrpc POSTs a minute from one address -------------------------------------------------------
    $g = $guard();
    for ($i = 0; $i < 30; ++$i) {
        $g->observe('ltwp05.example.test', line('34.30.196.241', 'POST', '/xmlrpc.php', $t0 + intdiv($i, 5)), $t0 + 10);
    }
    $g->commit($t0 + 10, true);
    check($entries() === [], 'thirty xmlrpc POSTs in a minute are not blocked (a busy client, an app sync)');
    $g->observe('ltwp05.example.test', line('34.30.196.241', 'POST', '/xmlrpc.php', $t0 + 10), $t0 + 10);
    $g->commit($t0 + 10, true);
    check($entries() === ['ltwp05.example.test/34.30.196.241 1'], 'the 31st within a minute blocks the address for that site (at 250 a minute: within 8 s)');
    check((fileperms($map) & 0777) === 0640 && (fileperms(dirname($map)) & 0777) === 0750 && file_get_contents($map)[0] === '#',
        'map 0640 in a 0750 directory, a comment header that OLS skips');
    $status = $g->status($t0 + 10);
    $block = $status['blocked'][0] ?? [];
    check(count($status['blocked']) === 1 && $block['address'] === '34.30.196.241' && $block['domain'] === 'ltwp05.example.test'
        && $block['endpoint'] === 'xmlrpc.php' && $block['until'] === $t0 + 10 + LoginGuard::BLOCK && $block['strike'] === 1 && $block['requests'] === 31,
        'status lists the block: site, address, endpoint, requests that tripped it, expiry after 15 minutes');
    // While blocked, OLS answers 403: counted as refused, never extending the block.
    for ($i = 0; $i < 200; ++$i) {
        $g->observe('ltwp05.example.test', line('34.30.196.241', 'POST', '/xmlrpc.php', $t0 + 20, 403, 199), $t0 + 20);
    }
    $g->commit($t0 + 20, true);
    $status = $g->status($t0 + 20);
    check($status['blocked'][0]['refused'] === 200 && $status['blocked'][0]['until'] === $t0 + 10 + LoginGuard::BLOCK
        && $status['seen']['refused'] === 200, 'refused requests are counted for the view; the block keeps its expiry');
    // Per site: the same address on another site is counted on its own.
    $g->observe('ltwp04.example.test', line('34.30.196.241', 'POST', '/xmlrpc.php', $t0 + 20), $t0 + 20);
    $g->commit($t0 + 20, true);
    check($entries() === ['ltwp05.example.test/34.30.196.241 1'], 'a block is per site: one request elsewhere is not blocked');
    for ($i = 0; $i < 31; ++$i) {
        $g->observe('ltwp04.example.test', line('34.30.196.241', 'POST', '/xmlrpc.php', $t0 + 21), $t0 + 21);
    }
    $g->commit($t0 + 21, true);
    check($entries() === ['ltwp04.example.test/34.30.196.241 1', 'ltwp05.example.test/34.30.196.241 1'], 'the flood on a second site blocks it there too');

    // Expiry and the doubled repeat.
    $mtime = filemtime($map);
    $g->commit($t0 + 10 + LoginGuard::BLOCK, true);
    clearstatcache();
    check($entries() === ['ltwp04.example.test/34.30.196.241 1'] && filemtime($map) > $mtime, 'an expired block leaves the map (a strictly newer mtime for OLS)');
    $later = $t0 + 10 + LoginGuard::BLOCK + 120;
    for ($i = 0; $i < 31; ++$i) {
        $g->observe('ltwp05.example.test', line('34.30.196.241', 'POST', '/xmlrpc.php', $later), $later);
    }
    $g->commit($later, true);
    $again = array_values(array_filter($g->status($later)['blocked'], static fn(array $b): bool => $b['domain'] === 'ltwp05.example.test'))[0];
    check($again['strike'] === 2 && $again['until'] === $later + 2 * LoginGuard::BLOCK, 'a repeat within a day doubles the block');
    check($g->status($later)['recent'][0]['reason'] === 'expired', 'ended blocks stay in the recent list with the reason');

    // --- Never blocked ------------------------------------------------------------------------------------------------------
    tree_remove($state);
    mkdir($state, 0700);
    @unlink($map);
    $g = $guard();
    $t = $t0 + 5000;
    foreach (['192.0.84.10' => 'Jetpack', '122.248.245.244' => 'Jetpack (single address)', '127.0.0.1' => 'loopback', '::1' => 'loopback IPv6',
              '203.0.113.5' => "the server's own address", '2001:db8::5' => "the server's own IPv6 address"] as $ip => $who) {
        for ($i = 0; $i < 100; ++$i) {
            $g->observe('site.example.test', line($ip, 'POST', '/xmlrpc.php', $t), $t);
        }
        $g->commit($t, true);
        check($entries() === [], "never blocked: $who ($ip), 100 xmlrpc POSTs in a second");
    }
    for ($i = 0; $i < 100; ++$i) {
        $g->observe('site.example.test', line('198.51.100.7', 'POST', '/xmlrpc.php', $t), $t, ['198.51.100.0/24']);
    }
    $g->commit($t, true);
    check($entries() === [], "never blocked: the operator's allow list");

    // A site owner's login: the form, a wrong password, the right one, the dashboard (and logged-in POSTs elsewhere).
    $owner = '198.51.100.20';
    foreach ([['GET', '/wp-login.php'], ['POST', '/wp-login.php'], ['POST', '/wp-login.php'], ['GET', '/wp-admin/'],
              ['POST', '/wp-admin/admin-ajax.php'], ['POST', '/wp-admin/post.php'], ['POST', '/wp-login.php?action=postpass'],
              ['POST', '/wp-login.php?action=lostpassword']] as [$method, $uri]) {
        $g->observe('site.example.test', line($owner, $method, $uri, $t), $t);
    }
    // The soak harness: every editor and customer of one site logging in from the load generator in the same minute.
    for ($i = 0; $i < 12; ++$i) {
        $g->observe('ltwp01.example.test', line('192.168.122.1', 'POST', '/wp-login.php', $t), $t);
    }
    $g->commit($t, true);
    check($entries() === [], "a site owner's login and the harness's logins (12 a minute from one address) are not blocked");
    // A password guesser through wp-login.php.
    for ($i = 0; $i < 21; ++$i) {
        $g->observe('ltwp01.example.test', line('45.0.0.9', 'POST', '/wp-login.php', $t + $i), $t + 21);
    }
    $g->commit($t + 21, true);
    check($entries() === ['ltwp01.example.test/45.0.0.9 1'], 'more than 20 wp-login.php POSTs a minute from one address are blocked');
    // A slow guesser is not (the limit is a flood guard, not a password policy), nor old lines outside the minute.
    $g2 = $guard();
    for ($i = 0; $i < 60; ++$i) {
        $g2->observe('ltwp02.example.test', line('45.0.0.10', 'POST', '/wp-login.php', $t + $i * 4), $t + $i * 4);
        $g2->observe('ltwp02.example.test', line('45.0.0.11', 'POST', '/xmlrpc.php', $t - 3600), $t + $i * 4);
    }
    $g2->commit($t + 240, true);
    check(!in_array('ltwp02.example.test/45.0.0.10 1', $entries(), true) && !in_array('ltwp02.example.test/45.0.0.11 1', $entries(), true),
        'fifteen POSTs a minute are not blocked; log lines older than the minute do not count');
    // Encoded and subdirectory paths count; GET floods and other files do not.
    $g3 = $guard();
    for ($i = 0; $i < 31; ++$i) {
        $g3->observe('blog.example.test', line('45.0.0.12', 'POST', '/blog/xmlrp%63.php?rsd', $t), $t);
        $g3->observe('blog.example.test', line('45.0.0.13', 'GET', '/xmlrpc.php', $t), $t);
        $g3->observe('blog.example.test', line('45.0.0.14', 'POST', '/xmlrpc.php.old', $t), $t);
        $g3->observe('blog.example.test', 'garbage "POST /xmlrpc.php HTTP/1.1"', $t);
        $g3->observe('blog.example.test', line('not-an-ip', 'POST', '/xmlrpc.php', $t), $t);
    }
    $g3->commit($t, true);
    $now = $entries();
    check(in_array('blog.example.test/45.0.0.12 1', $now, true) && !preg_grep('~/45\.0\.0\.1[34] |not-an-ip~', $now),
        'an encoded path in a subdirectory install counts; GETs, other files and malformed lines do not');
    // Path info after the script name still runs it (OLS and PHP give it as PATH_INFO): it counts like the script.
    $g4 = $guard();
    for ($i = 0; $i < 31; ++$i) {
        $g4->observe('blog.example.test', line('45.0.0.15', 'POST', '/xmlrpc.php/x', $t), $t);
    }
    $g4->commit($t, true);
    check(in_array('blog.example.test/45.0.0.15 1', $entries(), true), 'POSTs to xmlrpc.php with path info count and are blocked');
    // Before OLS is the server (no /run/ols-cpanel) nothing reads a map, and none is written.
    $offline = new LoginGuard("$root/offline-state", $logs, "$root/no-run/guard/login.map", $own, $group);
    mkdir("$root/offline-state", 0700);
    for ($i = 0; $i < 31; ++$i) {
        $offline->observe('site.example.test', line('45.0.0.20', 'POST', '/xmlrpc.php', $t), $t);
    }
    $offline->commit($t, true);
    check(!file_exists("$root/no-run") && count($offline->status($t)['blocked']) === 1,
        'without the OLS runtime directory the block is recorded but no map (and no directory) is created');

    // --- The switch -----------------------------------------------------------------------------------------------------------
    check(LoginGuard::settings($state)['enabled'] === true, 'on by default (no settings file)');
    LoginGuard::saveSettings($state, false, null, $t);
    $result = $guard()->pass($t + 30);
    check($result['enabled'] === false && $entries() === [] && $guard()->status($t + 30)['blocked'] === []
        && $guard()->status($t + 30)['recent'][0]['reason'] === 'guard_off', 'off: the map is emptied at once and the blocks end');
    LoginGuard::saveSettings($state, true, ['198.51.100.0/24', '2001:db8:1::/48'], $t);
    check(LoginGuard::settings($state) === ['enabled' => true, 'allow' => ['198.51.100.0/24', '2001:db8:1::/48'], 'changed_at' => $t],
        'settings: switch and allow list saved');
    $refused = false;
    try {
        LoginGuard::saveSettings($state, null, ['10.0.0.0/8', 'evil host'], $t);
    } catch (\OlsCpanel\Cli\Refused) {
        $refused = true;
    }
    check($refused && LoginGuard::settings($state)['allow'] === ['198.51.100.0/24', '2001:db8:1::/48'], 'an invalid allow entry is refused, nothing saved');
    check((fileperms("$state/" . LoginGuard::SETTINGS) & 0777) === 0600, 'settings are root 0600');

    // --- The log scanner ------------------------------------------------------------------------------------------------------
    tree_remove($state);
    mkdir($state, 0700);
    $site = "$logs/ltwoo02.example.test";
    file_put_contents($site, line('9.9.9.9', 'POST', '/xmlrpc.php', $t) . "\n");
    file_put_contents("$logs/ltwoo02.example.test-ssl_log", '');
    file_put_contents("$logs/ltwoo02.example.test-bytes_log", '');
    file_put_contents("$logs/ftp.ltwoo02.example.test-ftp_log", '');
    $w = $guard();
    $w->scan($t);
    check($w->scan($t) === 0, 'the first pass starts at the end of every log (no history is replayed)');
    $flood = '';
    for ($i = 0; $i < 31; ++$i) {
        $flood .= line('34.26.237.3', 'POST', '/xmlrpc.php', $t) . "\n";
    }
    file_put_contents("$logs/ltwoo02.example.test-ssl_log", $flood . substr(line('34.26.237.3', 'POST', '/xmlrpc.php', $t), 0, 20), FILE_APPEND);
    file_put_contents("$logs/ltwoo02.example.test-bytes_log", $flood, FILE_APPEND);
    check($w->scan($t) === 31, 'new whole lines of the HTTPS log are read; the bytes log is not; a partial line waits');
    $w->commit($t, true);
    check($entries() === ['ltwoo02.example.test/34.26.237.3 1'], 'a flood in the HTTPS log blocks the site (domain from the file name)');
    file_put_contents("$logs/ltwoo02.example.test-ssl_log", substr(line('34.26.237.3', 'POST', '/xmlrpc.php', $t), 20) . "\n", FILE_APPEND);
    check($w->scan($t) === 1, 'the rest of a partial line is read on the next pass');
    file_put_contents($site, '');   // cpanellogd truncates a processed log
    file_put_contents($site, line('9.9.9.9', 'POST', '/wp-login.php', $t) . "\n", FILE_APPEND);
    check($w->scan($t) === 1, 'a truncated (rotated) log is read again from its start');
    symlink('/etc/passwd', "$logs/evil.example.test");
    check($w->scan($t) === 0, 'links in the log directory are never followed');

    // --- An unblock from another process is not undone by the watcher -------------------------------------------------------
    $cli = $guard();
    check($cli->unblock('34.26.237.3', null, $t + 1) === 1 && $entries() === [], 'unblock lifts the block at once');
    $w->pass($t + 2);
    check($entries() === [] && $w->status($t + 2)['blocked'] === [], "the watcher's next pass keeps the unblock (it works on the saved state)");
    check($w->status($t + 2)['recent'][0]['reason'] === 'unblocked', 'the unblock is in the recent list');

    // --- CLI ------------------------------------------------------------------------------------------------------------------
    $run = static function (array $argv, ?int $uid = 0) use ($guard, $state): array {
        $stdout = fopen('php://memory', 'w+');
        $stderr = fopen('php://memory', 'w+');
        $commands = array_map(static fn(string $a): LoginGuardCommand => new LoginGuardCommand(new EngineContext($uid), $a, $guard, $state),
            array_keys(LoginGuardCommand::ACTIONS));
        $code = (new Application($commands))->run([...$argv, '--format=json'], new Output(true, $stdout, $stderr));
        rewind($stdout);
        return [$code, json_decode((string) stream_get_contents($stdout), true)];
    };
    [$code, $out] = $run(['login-guard', 'status']);
    check($code === 0 && $out['enabled'] === true && $out['limits'] === ['xmlrpc' => 30, 'wp-login' => 20] && $out['map'] === $map,
        'login-guard status: switch, limits, map');
    [$code, $out] = $run(['login-guard', 'set', '--enabled=no']);
    check($code === 0 && $out['enabled'] === false && $out['changed'] === true && LoginGuard::settings($state)['enabled'] === false, 'login-guard set --enabled=no');
    [$code, $out] = $run(['login-guard', 'set', '--enabled=yes', '--allow=none']);
    check($code === 0 && $out['enabled'] === true && $out['allow'] === [], 'login-guard set --enabled=yes --allow=none');
    foreach ([['set'], ['set', '--enabled=maybe'], ['set', '--allow=bad host'], ['unblock'], ['unblock', '--address=x'],
              ['unblock', '--address=1.2.3.4', '--domain=../x'], ['status', '--x']] as $bad) {
        check($run(['login-guard', ...$bad])[0] === Application::EXIT_USAGE, 'usage error: login-guard ' . implode(' ', $bad));
    }
    check($run(['login-guard', 'status'], 1000)[0] === Application::EXIT_REFUSED, 'root only');
    [$code, $out] = $run(['login-guard', 'run', '--once']);
    check($code === 0 && $out['pass']['enabled'] === true, 'login-guard run --once: one pass');
} finally {
    tree_remove($root);
}
echo "$count login guard checks passed.\n";
