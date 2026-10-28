<?php
declare(strict_types=1);

// FV-07 operations on temporary trees: notification settings, de-duplication, the daily limit and the sent-ledger; maintenance-window
// validation and the scheduled run through a scripted broker; the update check's parsing; the support bundle's redaction with
// planted secrets; the CLI commands' root rule. Nothing reaches the host: mail, webhook, broker and package manager are scripted.
require dirname(__DIR__) . '/src/bootstrap.php';

use OlsCpanel\Cli\Application;
use OlsCpanel\Cli\Output;
use OlsCpanel\Cli\Refused;
use OlsCpanel\Deployment\Host;
use OlsCpanel\Infrastructure\Process\CommandRunner;
use OlsCpanel\Infrastructure\Process\LocalCommandRunner;
use OlsCpanel\Operations\Notifier;
use OlsCpanel\Operations\NotifySettings;
use OlsCpanel\Operations\Redactor;
use OlsCpanel\Operations\Schedule;
use OlsCpanel\Operations\StateFile;
use OlsCpanel\Operations\SupportBundle;
use OlsCpanel\Operations\UpdateCheck;

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

function refused(callable $call, string $name): void
{
    try {
        $call();
        check(false, $name);
    } catch (Refused) {
        check(true, $name);
    }
}

function fresh_state(): string
{
    $state = sys_get_temp_dir() . '/ols-ops-' . bin2hex(random_bytes(6));
    mkdir($state, 0700, true);
    return $state;
}

function write_json(string $path, array $data): void
{
    if (!is_dir(dirname($path))) {
        mkdir(dirname($path), 0700, true);
    }
    file_put_contents($path, json_encode($data));
}

// ---- Settings --------------------------------------------------------------------------------------------------------
$state = fresh_state();
check(!NotifySettings::load($state)->enabled(), 'notifications are off until configured (opt-in)');
foreach (['a@b.test', 'first.last+tag@mail.example.org'] as $ok) {
    check(NotifySettings::validEmail($ok), "valid address $ok");
}
foreach (['', 'a', 'a@b', 'a b@c.test', "a@b.test\nBcc: x@y.test", 'a@b..test', '@b.test', 'a@-b.test', str_repeat('x', 250) . '@b.test', 'a@b.test,c@d.test'] as $bad) {
    check(!NotifySettings::validEmail($bad), 'invalid address ' . json_encode(substr($bad, 0, 30)));
}
foreach (['https://hooks.example.com/services/T1/B2/xyz', 'https://example.org:8443/hook?x=1'] as $ok) {
    check(NotifySettings::validWebhook($ok), "valid webhook $ok");
}
foreach (['http://example.com/h', 'https://user:pw@example.com/h', 'ftp://example.com', 'https://', 'https://exa mple.com', "https://example.com/h\r\nX: y",
          'https://example.com:99999/h', 'javascript:alert(1)', 'https://' . str_repeat('a', 520), "https://example.com/'x"] as $bad) {
    check(!NotifySettings::validWebhook($bad), 'invalid webhook ' . json_encode(substr($bad, 0, 40)));
}
$saved = NotifySettings::save($state, ['Admin@Example.test'], 'https://hooks.example.com/services/T1/B2/SECRETPART', null, 1000);
check($saved->emails === ['admin@example.test'] && $saved->enabled() && $saved->enabledSince === 1000, 'settings saved, address lower-cased, enabled_since recorded');
check((fileperms($state . '/notify.json') & 0777) === 0600, 'notify.json is root 0600');
$view = json_encode($saved->view());
check(!str_contains($view, 'SECRETPART') && !str_contains($view, 'T1/B2') && str_contains($view, 'hooks.example.com'), 'the view never contains the webhook URL, only its host');
$kept = NotifySettings::save($state, ['admin@example.test'], null, ['job'], 2000);
check($kept->webhook !== null && $kept->enabledSince === 1000 && $kept->events === ['job'], 'a left-out webhook is kept, enabled_since stays');
refused(fn() => NotifySettings::save($state, ['x'], null, null, 1), 'bad address refused');
refused(fn() => NotifySettings::save($state, [], 'http://x.test/h', null, 1), 'http webhook refused');
refused(fn() => NotifySettings::save($state, [], null, ['nonsense'], 1), 'unknown event refused');
refused(fn() => NotifySettings::save($state, array_map(fn($i) => "u$i@b.test", range(1, 6)), null, null, 1), 'more than five addresses refused');
$off = NotifySettings::save($state, [], '', null, 3000);
check(!$off->enabled() && $off->enabledSince === 0, 'removing every channel switches notifications off');
tree_remove($state);

// ---- Notifier --------------------------------------------------------------------------------------------------------
function notifier(string $state, int &$now, array &$mail, array &$hooks, ?array $diskFree = null, bool $mailFails = false, array $failedUnits = []): Notifier
{
    return new Notifier($state, $state . '/cache', static function () use (&$now): int {
        return $now;
    }, static function (array $to, string $subject, string $body) use (&$mail, &$mailFails): ?string {
        if ($mailFails) {
            return 'smtp down';
        }
        $mail[] = [$to, $subject, $body];
        return null;
    }, static function (string $url, array $payload) use (&$hooks): ?string {
        $hooks[] = [$url, $payload];
        return null;
    }, static fn(string $path): array => $diskFree ?? [1000 * 1048576, 500 * 1048576],
        static fn(array $argv): array => $argv[1] === 'is-failed' ? ['exit_code' => in_array($argv[3] ?? '', $failedUnits, true) ? 0 : 1, 'stdout' => '']
            : ['exit_code' => 0, 'stdout' => "Tue 2026-10-27 10:00:00 UTC\n"], 'host.example');
}

$state = fresh_state();
mkdir($state . '/cache');
$now = 1_800_000_000;
$mail = [];
$hooks = [];
check(notifier($state, $now, $mail, $hooks)->run()['result'] === 'disabled', 'a disabled notifier does nothing');
NotifySettings::save($state, ['ops@example.test'], 'https://hooks.example.com/h/SECRETPART', null, $now - 2000);
write_json($state . '/active/summary.json', ['held_vhosts' => ['old.test' => ['x']], 'hybrid_vhosts' => ['legacy.test']]);
$job = static fn(string $id, string $state_, string $action, int $finished, ?string $reason = null): array => ['job' => $id, 'action' => $action, 'state' => $state_,
    'started' => $finished - 5, 'finished' => $finished, 'exit_code' => $state_ === 'done' ? 0 : 1, 'reason' => $reason];
write_json($state . '/jobs/j1799999000-aaaaaaaa/job.json', $job('j1799999000-aaaaaaaa', 'done', 'ols.cutover', $now - 1000));
write_json($state . '/jobs/j1799990000-bbbbbbbb/job.json', $job('j1799990000-bbbbbbbb', 'done', 'ols.cutover', $now - 10000)); // before the opt-in
write_json($state . '/jobs/j1799999500-cccccccc/job.json', $job('j1799999500-cccccccc', 'failed', 'ols.apache_return', $now - 500, 'the return refused'));
write_json($state . '/jobs/j1799999600-dddddddd/job.json', $job('j1799999600-dddddddd', 'done', 'ols.sync', $now - 400)); // not a watched action
$r = notifier($state, $now, $mail, $hooks)->run();
check($r['result'] === 'ok' && $r['sent'] === 2 && count($mail) === 2 && count($hooks) === 2, 'first pass sends the two jobs finished since the opt-in, one mail and one webhook each');
$subjects = array_column($mail, 1);
check(in_array('[OLS-cPanel] Switch to OpenLiteSpeed finished', $subjects, true) && in_array('[OLS-cPanel] Return to Apache failed', $subjects, true),
    'subjects name the event and result');
check(str_contains(json_encode($hooks), 'the return refused') && $hooks[0][1]['product'] === 'ols-cpanel' && $hooks[0][1]['server'] === 'host.example', 'webhook payload is JSON with product, server and the reason');
check(!str_contains(json_encode($mail), 'SECRETPART') && !str_contains(json_encode($hooks[0][1]), 'SECRETPART'), 'the webhook URL is in no message');
check(str_contains($mail[0][2], "\n") && !str_contains($mail[0][2], "\r"), 'plain text body');
check(!str_contains($mail[0][2], 'old.test'), 'pre-existing held sites were recorded, not announced');
$ledger = StateFile::read($state . '/notify-ledger.json');
check((fileperms($state . '/notify-ledger.json') & 0777) === 0600 && isset($ledger['sent']['job:j1799999000-aaaaaaaa']) && !str_contains(json_encode($ledger), 'SECRETPART'),
    'the sent-ledger is root 0600 and holds no secret');
$now += 300;
$mail = [];
$hooks = [];
check(notifier($state, $now, $mail, $hooks)->run()['sent'] === 0 && $mail === [], 'the next pass sends nothing new (one-shot job events)');
// A newly held site is announced once; the same key is not repeated.
write_json($state . '/active/summary.json', ['held_vhosts' => ['old.test' => ['x'], 'new.test' => ['y']], 'hybrid_vhosts' => ['legacy.test']]);
$now += 300;
$r = notifier($state, $now, $mail, $hooks)->run();
check($r['sent'] === 1 && str_contains($mail[0][2], 'new.test') && !str_contains($mail[0][2], 'old.test'), 'a newly held site is announced, the known ones are not');
$now += 300;
$mail = [];
check(notifier($state, $now, $mail, $hooks)->run()['sent'] === 0, 'the same held site is not announced again');
// Same event key within six hours is not resent even if the condition clears and returns; after six hours it is.
write_json($state . '/active/summary.json', ['held_vhosts' => ['old.test' => ['x']], 'hybrid_vhosts' => ['legacy.test']]);
$now += 300;
notifier($state, $now, $mail, $hooks)->run();
write_json($state . '/active/summary.json', ['held_vhosts' => ['old.test' => ['x'], 'new.test' => ['y']], 'hybrid_vhosts' => ['legacy.test']]);
$now += 300;
$r = notifier($state, $now, $mail, $hooks)->run();
check($r['sent'] === 0 && $r['duplicate'] === 1, 'the same event key is sent at most once per six hours');
write_json($state . '/active/summary.json', ['held_vhosts' => ['old.test' => ['x']], 'hybrid_vhosts' => ['legacy.test']]);
$now += 300;
notifier($state, $now, $mail, $hooks)->run();
write_json($state . '/active/summary.json', ['held_vhosts' => ['old.test' => ['x'], 'new.test' => ['y']], 'hybrid_vhosts' => ['legacy.test']]);
$now += 6 * 3600;
check(notifier($state, $now, $mail, $hooks)->run()['sent'] === 1, 'after six hours the same event key may be sent again');
tree_remove($state);

// Disk, PHP, upgrade, cache and object cache events; the daily limit.
$state = fresh_state();
mkdir($state . '/cache');
$now = 1_800_000_000;
$mail = [];
$hooks = [];
NotifySettings::save($state, ['ops@example.test'], null, null, $now - 100);
write_json($state . '/php-env.json', ['schema_version' => 1, 'checked_at' => $now, 'versions' => ['ea-php83' => ['status' => 'complete']]]);
write_json($state . '/objcache.json', ['schema_version' => 1, 'wordpress' => ['shopacct' => ['public_html' => ['state' => 'automatic', 'error' => null]]]]);
notifier($state, $now, $mail, $hooks)->run();
write_json($state . '/php-env.json', ['schema_version' => 1, 'checked_at' => $now, 'versions' => ['ea-php83' => ['status' => 'failed', 'error' => 'dnf failed']]]);
write_json($state . '/cache-clean.json', ['emergency' => true, 'last_run' => $now - 60]);
write_json($state . '/objcache.json', ['schema_version' => 1, 'wordpress' => ['shopacct' => ['public_html' => ['state' => 'error', 'error' => 'x']]]]);
$now += 300;
$r = notifier($state, $now, $mail, $hooks, [1000 * 1048576, 20 * 1048576], false, ['ols-cpanel-upgrade.service'])->run();
$titles = implode('|', array_column($mail, 1));
check($r['sent'] >= 5 && str_contains($titles, 'PHP environment check failed') && str_contains($titles, 'Upgrade failed') && str_contains($titles, 'Page cache trimmed')
    && str_contains($titles, 'Disk nearly full') && str_contains($titles, 'Object cache site check failed'), 'PHP, upgrade, cache emergency, disk and object cache events are sent');
tree_remove($state);

$state = fresh_state();
mkdir($state . '/cache');
$now = 1_800_000_000;
$mail = [];
$hooks = [];
NotifySettings::save($state, ['ops@example.test'], null, ['job'], $now - 100);
for ($i = 0; $i < 30; $i++) {
    $id = sprintf('j%010d-%08x', 1_799_999_000 + $i, $i);
    write_json("$state/jobs/$id/job.json", ['job' => $id, 'action' => 'ols.cutover', 'state' => 'done', 'started' => $now - 90, 'finished' => $now - 60 + $i, 'exit_code' => 0, 'reason' => null]);
}
$r = notifier($state, $now, $mail, $hooks)->run();
check($r['sent'] === Notifier::MAX_PER_DAY && $r['deferred'] === 10 && count($mail) === 20, 'at most twenty messages per day; the rest is deferred');
$now += 3600;
check(notifier($state, $now, $mail, $hooks)->run()['sent'] === 0, 'still limited within the same 24 hours');
$now += 86400;
$r = notifier($state, $now, $mail, $hooks)->run();
check($r['sent'] === 10, 'deferred events go out when the day has passed');
// Failed deliveries: retried, then given up with the error recorded, without secrets.
tree_remove($state);
$state = fresh_state();
mkdir($state . '/cache');
$now = 1_800_000_000;
$mail = [];
NotifySettings::save($state, ['ops@example.test'], null, ['job'], $now - 100);
write_json($state . '/jobs/j1799999000-aaaaaaaa/job.json', $job('j1799999000-aaaaaaaa', 'done', 'ols.cutover', $now - 10));
for ($i = 1; $i <= 3; $i++) {
    $r = notifier($state, $now, $mail, $hooks, null, true)->run();
    check($r['failed'] === 1 && $r['sent'] === 0, "delivery failure $i is counted");
}
check(notifier($state, $now, $mail, $hooks, null, false)->run()['sent'] === 0, 'after three failures the event is given up');
$status = notifier($state, $now, $mail, $hooks)->status();
check(($status['last_error']['message'] ?? '') === 'email: smtp down' && $status['sent_last_24h'] === 0, 'the last delivery error is shown');
// The test message goes to every channel and is not limited.
NotifySettings::save($state, ['ops@example.test'], 'https://hooks.example.com/h/S', null, $now);
$mail = [];
$hooks = [];
$test = notifier($state, $now, $mail, $hooks)->test();
check($test['result'] === 'sent' && count($test['channels']) === 2 && count($mail) === 1 && count($hooks) === 1, 'the test notification goes to e-mail and webhook');
tree_remove($state);
check(Notifier::post('http://example.com/x', []) === 'invalid webhook' && Notifier::sendmail(["a@b.test\nBcc: c@d.test"], 's', 'b') === 'invalid recipient',
    'the real senders refuse an http URL and a header-injecting recipient');
// Review 9: delivery per channel. The e-mail goes through while the webhook fails: the message counts against the daily allowance
// at once, the e-mail is not sent again, and only the webhook is retried (at most three times).
$hookFails = true;
$hookTries = 0;
$channelNotifier = static function (string $state) use (&$now, &$mail, &$hookFails, &$hookTries): Notifier {
    return new Notifier($state, $state . '/cache', static function () use (&$now): int {
        return $now;
    }, static function (array $to, string $subject, string $body) use (&$mail): ?string {
        $mail[] = $subject;
        return null;
    }, static function (string $url, array $payload) use (&$hookFails, &$hookTries): ?string {
        $hookTries++;
        return $hookFails ? 'the webhook answered 503' : null;
    }, static fn(string $path): array => [1000 * 1048576, 500 * 1048576], static fn(array $argv): array => ['exit_code' => 1, 'stdout' => ''], 'host.example');
};
$state = fresh_state();
mkdir($state . '/cache');
$now = 1_800_000_000;
$mail = [];
NotifySettings::save($state, ['ops@example.test'], 'https://hooks.example.com/h/S', ['job'], $now - 100);
write_json($state . '/jobs/j1799999000-aaaaaaaa/job.json', $job('j1799999000-aaaaaaaa', 'done', 'ols.cutover', $now - 10));
$r = $channelNotifier($state)->run();
check($r['failed'] === 1 && count($mail) === 1 && $hookTries === 1 && $channelNotifier($state)->status()['sent_last_24h'] === 1,
    'an e-mail delivered while the webhook fails counts against the daily allowance');
$now += 300;
$channelNotifier($state)->run();
check(count($mail) === 1 && $hookTries === 2, 'the next pass retries only the webhook, not the delivered e-mail');
$hookFails = false;
$now += 300;
$r = $channelNotifier($state)->run();
check($r['sent'] === 1 && count($mail) === 1 && $hookTries === 3 && $channelNotifier($state)->status()['sent_last_24h'] === 1,
    'the webhook delivered later completes the event, counted once');
$now += 300;
check($channelNotifier($state)->run()['sent'] === 0 && count($mail) === 1 && $hookTries === 3, 'a completed event is not sent again');
write_json($state . '/jobs/j1800000600-bbbbbbbb/job.json', $job('j1800000600-bbbbbbbb', 'done', 'ols.cutover', $now - 10));
$hookFails = true;
for ($i = 0; $i < 4; $i++) {
    $now += 300;
    $channelNotifier($state)->run();
}
check(count($mail) === 2 && $hookTries === 6, 'a failing webhook is given up after three attempts, the e-mail was sent once');
tree_remove($state);
// Review 9: the bound of a pass applies after events already sent and events not subscribed to are set aside, and takes every kind
// in turn: 150 finished jobs already announced (or with job notifications off) never hide a disk alert.
foreach ([null, ['disk']] as $events) {
    $state = fresh_state();
    mkdir($state . '/cache');
    $now = 1_800_000_000;
    $mail = [];
    $hooks = [];
    NotifySettings::save($state, ['ops@example.test'], null, $events, $now - 5000);
    $sent = [];
    for ($i = 0; $i < 150; $i++) {
        $id = sprintf('j%010d-%08x', 1_799_996_000 + $i, $i);
        write_json("$state/jobs/$id/job.json", ['job' => $id, 'action' => 'ols.cutover', 'state' => 'done', 'started' => $now - 4000, 'finished' => $now - 3000 + $i,
            'exit_code' => 0, 'reason' => null]);
        $sent["job:$id"] = $now - 1000;
    }
    if ($events === null) {
        StateFile::write($state . '/notify-ledger.json', ['sent' => $sent, 'times' => []]);
    }
    $r = notifier($state, $now, $mail, $hooks, [1000 * 1048576, 20 * 1048576])->run();
    check($r['sent'] === 1 && count($mail) === 1 && $mail[0][1] === '[OLS-cPanel] Disk nearly full',
        'a disk alert is sent although 150 job events ' . ($events === null ? 'were already sent' : 'are not subscribed to'));
    tree_remove($state);
}
// Fairness across kinds when more fresh events than the bound exist: every kind is represented.
$fair = (new ReflectionMethod(Notifier::class, 'fair'))->invoke(null, [...array_map(static fn(int $i): array => ['kind' => 'job', 'key' => "j$i"], range(1, 150)),
    ['kind' => 'disk', 'key' => 'disk:state'], ['kind' => 'schedule', 'key' => 's1']], Notifier::MAX_EVENTS);
check(count($fair) === Notifier::MAX_EVENTS && in_array('disk:state', array_column($fair, 'key'), true) && in_array('s1', array_column($fair, 'key'), true),
    'the bound takes the events of every kind in turn');

// ---- Schedule --------------------------------------------------------------------------------------------------------
$state = fresh_state();
$now = 1_800_000_000;
$digest = str_repeat('a', 64);
$calls = [];
$responses = [];
$broker = static function (string $op, ?array $args) use (&$calls, &$responses): array {
    $calls[] = [$op, $args];
    $next = $responses[$op] ?? null;
    return $next instanceof Closure ? $next($args) : ($next ?? ['ok' => false, 'error' => ['code' => 'BAD_ARGS', 'message' => 'unscripted']]);
};
$schedule = new Schedule($state, static function () use (&$now): int {
    return $now;
}, $broker);
refused(fn() => $schedule->add('ols.sync', 'server', $digest, $now + 3600, 60), 'only a switch or a return can be scheduled');
refused(fn() => $schedule->add('ols.cutover', 'server', $digest, $now + 3600, 60), 'a switch needs a plan id, not "server"');
refused(fn() => $schedule->add('ols.cutover', '../x', $digest, $now + 3600, 60), 'a plan id is checked');
refused(fn() => $schedule->add('ols.apache_return', 'p1', $digest, $now + 3600, 60), 'a return takes "server"');
refused(fn() => $schedule->add('ols.cutover', 'p1', 'xyz', $now + 3600, 60), 'the digest is checked');
refused(fn() => $schedule->add('ols.cutover', 'p1', $digest, $now + 10, 60), 'a start time in the past or under a minute away is refused');
refused(fn() => $schedule->add('ols.cutover', 'p1', $digest, $now + 91 * 86400, 60), 'more than 90 days ahead is refused');
refused(fn() => $schedule->add('ols.cutover', 'p1', $digest, $now + 3600, 14), 'a window under 15 minutes is refused');
refused(fn() => $schedule->add('ols.cutover', 'p1', $digest, $now + 3600, 721), 'a window over 12 hours is refused');
$a = $schedule->add('ols.cutover', 'p1', $digest, $now + 3600, 60);
check((fileperms($state . '/schedule.json') & 0777) === 0600 && $a['state'] === 'scheduled', 'a scheduled job is stored root 0600');
refused(fn() => $schedule->add('ols.cutover', 'p1', $digest, $now + 3600 + 20, 60), 'the same job at the same time is refused');
$b = $schedule->add('ols.apache_return', 'server', $digest, $now + 7200, 30);
check(!isset($schedule->view()['entries'][0]['digest']), 'the view never shows the digest');
// Not due yet: nothing happens and the broker is not called.
check($schedule->run()['started'] === 0 && $calls === [], 'nothing before the time');
// Due: the cutover goes through cap.issue and cap.execute with the stored plan id and digest.
$now += 3600 + 5;
$responses = ['cap.issue' => ['ok' => true, 'result' => ['token' => 'root.n.1.m']], 'cap.execute' => ['ok' => true, 'result' => ['job' => 'j1800003605-abcdef01']]];
$r = $schedule->run();
check($r['started'] === 1 && $calls[0] === ['cap.issue', ['principal' => 'root', 'action' => 'ols.cutover', 'scope' => 'p1', 'digest' => $digest]]
    && $calls[1][0] === 'cap.execute' && $calls[1][1] === ['token' => 'root.n.1.m', 'action' => 'ols.cutover', 'scope' => 'p1', 'digest' => $digest],
    'a due switch is started through the capability flow with the approved plan id and digest');
check($schedule->view()['entries'][0]['state'] === 'running' && $schedule->view()['entries'][0]['job'] === 'j1800003605-abcdef01', 'the entry follows its job');
$calls = [];
$responses = ['job.status' => ['ok' => true, 'result' => ['state' => 'running']]];
$schedule->run();
check($schedule->view()['entries'][0]['state'] === 'running', 'a running job stays running');
$responses = ['job.status' => ['ok' => true, 'result' => ['state' => 'done']]];
$schedule->run();
check($schedule->view()['entries'][0]['state'] === 'done', 'a finished job is recorded');
// A plan that changed is refused, never run.
$c = $schedule->add('ols.cutover', 'p2', $digest, $now + 120, 60);
$now += 130;
$calls = [];
$responses = ['cap.issue' => ['ok' => true, 'result' => ['token' => 't']], 'cap.execute' => ['ok' => false, 'error' => ['code' => 'STALE', 'message' => 'changed']]];
$schedule->run();
$entry = array_values(array_filter($schedule->view()['entries'], static fn(array $e): bool => $e['id'] === $c['id']))[0];
check($entry['state'] === 'refused' && str_contains((string) $entry['note'], 'plan changed'), 'a plan that changed after approval is refused and never run');
// A busy broker is retried inside the window; a missed window is final.
$d = $schedule->add('ols.cutover', 'p3', $digest, $now + 120, 15);
$now += 130;
$responses = ['cap.issue' => ['ok' => true, 'result' => ['token' => 't']], 'cap.execute' => ['ok' => false, 'error' => ['code' => 'BUSY', 'message' => 'busy']]];
$schedule->run();
$entry = array_values(array_filter($schedule->view()['entries'], static fn(array $e): bool => $e['id'] === $d['id']))[0];
check($entry['state'] === 'scheduled', 'a busy broker is retried inside the window');
$now += 16 * 60;
$schedule->run();
$entry = array_values(array_filter($schedule->view()['entries'], static fn(array $e): bool => $e['id'] === $d['id']))[0];
check($entry['state'] === 'missed', 'a window that passed marks the job missed');
// The return reads the status digest at the time and needs a switched server.
$now = 1_800_000_000 + 7300;
$calls = [];
$responses = ['server.status' => ['ok' => true, 'result' => ['digest' => str_repeat('b', 64), 'cut_over' => false]]];
$schedule->run();
$entry = array_values(array_filter($schedule->view()['entries'], static fn(array $e): bool => $e['id'] === $b['id']))[0];
check($entry['state'] === 'refused' && str_contains((string) $entry['note'], 'not switched') && array_column($calls, 0) === ['server.status'], 'a return on a server that is not switched is refused');
$e = $schedule->add('ols.apache_return', 'server', $digest, $now + 120, 60);
$now += 130;
$calls = [];
$responses = ['server.status' => ['ok' => true, 'result' => ['digest' => str_repeat('b', 64), 'cut_over' => true]],
    'cap.issue' => ['ok' => true, 'result' => ['token' => 't2']], 'cap.execute' => ['ok' => true, 'result' => ['job' => 'j1800007430-00000001']]];
$schedule->run();
check($calls[1] === ['cap.issue', ['principal' => 'root', 'action' => 'ols.apache_return', 'scope' => 'server', 'digest' => str_repeat('b', 64)]], 'a return uses the status digest of the time it runs');
// Cancel.
$f = $schedule->add('ols.cutover', 'p9', $digest, $now + 600, 60);
$schedule->cancel($f['id']);
check(array_values(array_filter($schedule->view()['entries'], static fn(array $x): bool => $x['id'] === $f['id']))[0]['state'] === 'cancelled', 'a scheduled job can be cancelled');
refused(fn() => $schedule->cancel($f['id']), 'a cancelled job cannot be cancelled again');
refused(fn() => $schedule->cancel('s00000000000000-000000'), 'an unknown job cannot be cancelled');
for ($i = 0; $i < Schedule::MAX_PENDING; $i++) {
    try {
        $schedule->add('ols.cutover', "q$i", $digest, $now + 1000 + $i * 120, 60);
    } catch (Refused) {
        break;
    }
}
refused(fn() => $schedule->add('ols.cutover', 'qlast', $digest, $now + 99999, 60), 'at most ten pending jobs');
tree_remove($state);
// Review 9: every read-modify-write holds schedule.lock. A cancel that arrives while the timer is starting the entry (between its
// read and the broker's answer) is refused as already started, and the start is recorded instead of overwriting the cancellation.
$state = fresh_state();
$now = 1_800_000_000;
$schedule = new Schedule($state, static function () use (&$now): int {
    return $now;
}, $broker);
$g = $schedule->add('ols.cutover', 'p1', $digest, $now + 120, 60);
$now += 130;
$calls = [];
$cancelled = null;
$responses = ['cap.issue' => ['ok' => true, 'result' => ['token' => 't']], 'cap.execute' => static function () use (&$schedule, &$cancelled, $g): array {
    try {
        $schedule->cancel($g['id']);
        $cancelled = 'cancelled';
    } catch (Refused $e) {
        $cancelled = $e->getMessage();
    }
    return ['ok' => true, 'result' => ['job' => 'j1800000130-0000000a']];
}];
check($schedule->run()['started'] === 1, 'the due entry is started');
$entry = $schedule->entries()[0];
check(is_string($cancelled) && str_contains($cancelled, 'already started') && $entry['state'] === 'running' && $entry['job'] === 'j1800000130-0000000a'
    && ($entry['claimed'] ?? null) === false, 'a cancel during the start is refused as already started; the started job is recorded, not lost');
refused(fn() => $schedule->cancel($g['id']), 'a running job cannot be cancelled');
// A claim left by a pass that died after claiming: never started again, marked failed for the operator to check.
$now += 60;
StateFile::write($state . '/schedule.json', ['entries' => [['id' => 's20270115080000-cccccc', 'action' => 'ols.cutover', 'scope' => 'p2', 'digest' => $digest,
    'at' => $now - 60, 'window_minutes' => 60, 'state' => 'running', 'claimed' => true, 'created' => $now - 600, 'updated' => $now - 60, 'job' => null, 'note' => 'starting']]]);
$calls = [];
$schedule->run();
check($schedule->entries()[0]['state'] === 'failed' && !in_array('cap.issue', array_column($calls, 0), true), 'an entry left claimed by a dead pass is marked failed, never started twice');
// Two writers: an add from another process waits for the lock held by a writer that read the file before it, and both entries stay.
tree_remove($state);
$state = fresh_state();
$child = $state . '/add-child.php';
file_put_contents($child, '<?php require ' . var_export(dirname(__DIR__) . '/src/bootstrap.php', true) . ";\n"
    . '$s = new OlsCpanel\Operations\Schedule($argv[1], static fn(): int => (int) $argv[2], static fn(): array => []);' . "\n"
    . '$s->add("ols.cutover", "child", str_repeat("a", 64), (int) $argv[2] + 3600, 60);' . "\necho 'added';\n");
$schedule = new Schedule($state, static function () use (&$now): int {
    return $now;
}, $broker);
$schedule->add('ols.cutover', 'first', $digest, $now + 7200, 60);
$held = fopen($state . '/' . Schedule::LOCK, 'c');
flock($held, LOCK_EX);
$read = StateFile::read($state . '/schedule.json');
$process = proc_open([PHP_BINARY, '-n', $child, $state, (string) $now], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
usleep(500000);
$waiting = proc_get_status($process)['running'];
$read['entries'][] = ['id' => 's20270115080000-dddddd', 'action' => 'ols.cutover', 'scope' => 'second', 'digest' => $digest, 'at' => $now + 9000,
    'window_minutes' => 60, 'state' => 'scheduled', 'created' => $now, 'updated' => $now, 'job' => null, 'note' => null];
StateFile::write($state . '/schedule.json', $read);
flock($held, LOCK_UN);
fclose($held);
$childOut = stream_get_contents($pipes[1]) . stream_get_contents($pipes[2]);
proc_close($process);
$scopes = array_column($schedule->entries(), 'scope');
sort($scopes);
check($waiting && $childOut === 'added' && $scopes === ['child', 'first', 'second'], 'a concurrent add waits for the lock and no add is lost');
tree_remove($state);

// ---- Update check ----------------------------------------------------------------------------------------------------
final class ScriptedRunner implements CommandRunner
{
    /** @var array<string,array{exit_code:int,stdout:string,stderr?:string}> */
    public array $answers = [];
    public array $calls = [];

    public function run(string $name, array $argv, int $timeout): array
    {
        $this->calls[] = [$name, $argv];
        if ($name === 'support-tar') {
            return (new LocalCommandRunner())->run($name, $argv, $timeout);
        }
        return $this->answers[$name] ?? ['exit_code' => 0, 'stdout' => ''];
    }
}
$state = fresh_state();
$runner = new ScriptedRunner();
$runner->answers['package-ols-cpanel'] = ['exit_code' => 0, 'stdout' => '1.0.0-1.el9.x86_64'];
$runner->answers['package-ols-cpanel-openlitespeed'] = ['exit_code' => 0, 'stdout' => '1.8.5-1.el9.x86_64'];
$runner->answers['update-check'] = ['exit_code' => 100, 'stdout' => "\nols-cpanel.x86_64                1.1.0-1.el9      ols-cpanel\nsomething-else.noarch 2-1 repo\n"];
$runner->answers['signature-ols-cpanel'] = ['exit_code' => 0, 'stdout' => 'RSA/SHA256, Mon 01 Jan 2026 10:00:00 AM UTC, Key ID 0123456789abcdef|(none)'];
$runner->answers['signature-key-ols-cpanel'] = ['exit_code' => 0, 'stdout' => 'gpg-pubkey-89abcdef-1'];
$runner->answers['signature-ols-cpanel-openlitespeed'] = ['exit_code' => 0, 'stdout' => '(none)|(none)'];
$now = 1_800_000_000;
$check = new UpdateCheck(new Host($runner), $state, static function () use (&$now): int {
    return $now;
});
$report = $check->report();
check($report['update_available'] && $report['packages'][0]['available'] === '1.1.0-1.el9.x86_64' && $report['packages'][1]['available'] === null
    && $report['packages'][0]['installed'] === '1.0.0-1.el9.x86_64', 'the update check lists installed and available versions of the product packages only');
check($report['packages'][0]['signature']['state'] === 'signed' && $report['packages'][1]['signature']['state'] === 'unsigned', 'signature state: signed with a known key, unsigned for a lab build');
$runner->answers['signature-key-ols-cpanel'] = ['exit_code' => 1, 'stdout' => ''];
$calls = count($runner->calls);
$cached = $check->report();
check($cached['cached'] === true && count($runner->calls) === $calls, 'the result is cached for fifteen minutes');
check($check->report(true)['packages'][0]['signature']['state'] === 'signed-key-missing', 'a refresh asks again; a signature key that is not imported is reported');
$runner->answers['update-check'] = ['exit_code' => 1, 'stdout' => '', 'stderr' => 'Failed to download metadata'];
$err = (new UpdateCheck(new Host($runner), fresh_state(), static fn(): int => $now))->report();
check($err['error'] !== null && !$err['update_available'], 'an unreachable repository is reported as an error, not as "up to date"');
check(in_array('--refresh', array_column(array_filter($runner->calls, static fn(array $c): bool => $c[0] === 'update-check'), 1)[0], true)
    && !in_array('install', $runner->calls[0][1], true), 'only read-only package manager commands are used');
tree_remove($state);

// ---- Redaction and the support bundle --------------------------------------------------------------------------------
$state = fresh_state();
$userdata = $state . '/userdatadomains';
file_put_contents($userdata, "customer-site.com: shopacct==root==main==customer-site.com==/home/shopacct/public_html==198.51.100.9:80==198.51.100.9:443====0==ea-php83\n");
$PEM = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7PLANTEDKEYMATERIAL\n-----END PRIVATE KEY-----";
$CERT = "-----BEGIN CERTIFICATE-----\nMIIDdzCCAl+gAwIBAgIEPLANTEDCERTIFICATE\n-----END CERTIFICATE-----";
$SECRETS = ['PLANTEDKEYMATERIAL', 'PLANTEDCERTIFICATE', 'Hunter2Secret', 's3cr3tPW', 'abcdefTOKENvalue123', 'SECRETPART', 'ops-owner@customer-site.com',
    'pw-in-url', 'token=abc123', 'cafebabe0123456789cafebabe0123456789cafebabe0123456789cafebabe01', 'cookiesecretvalue', 'sk_live_PLANTEDAPIKEY99'];
write_json($state . '/active/summary.json', ['compiled_at' => '2026-10-28T10:00:00Z', 'vhosts' => ['customer-site.com' => ['user' => 'shopacct', 'type' => 'main',
    'docroot' => '/home/shopacct/public_html', 'php' => 'ea-php83', 'php_handler' => 'fpm', 'pool' => 'x']], 'hybrid_vhosts' => ['customer-site.com'],
    'htaccess_blockers' => ['customer-site.com' => ["/: unsupported RewriteRule '^secret-customer-page$ https://other.example.org/x'"]],
    'tls_sources' => ['customer-site.com' => '/var/cpanel/ssl/apache_tls/customer-site.com/combined']]);
write_json($state . '/notify.json', ['emails' => ['ops-owner@customer-site.com'], 'webhook' => 'https://hooks.example.com/services/SECRETPART', 'events' => ['job'], 'enabled_since' => 5]);
write_json($state . '/schedule.json', ['entries' => [['id' => 's20261028100000-aaaaaa', 'action' => 'ols.cutover', 'scope' => 'p1', 'digest' => str_repeat('c', 64),
    'at' => time() + 100, 'window_minutes' => 60, 'state' => 'scheduled', 'created' => time(), 'updated' => time(), 'job' => null, 'note' => null]]]);
write_json($state . '/php-env.json', ['schema_version' => 1, 'versions' => ['ea-php83' => ['status' => 'failed', 'error' => 'connect to 203.0.113.77 failed password=Hunter2Secret']]]);
write_json($state . '/cache-clean.json', ['last_run' => 1, 'stores' => ['customer-site.com' => ['files' => 1]]]);
mkdir($state . '/tls', 0700);
file_put_contents($state . '/tls/default.key', $PEM . "\n");
file_put_contents($state . '/broker-secret', str_repeat('cafe', 16) . "\n");
file_put_contents($state . '/broker-audit.log', "{\"event\":\"job_start\",\"job\":\"j1\",\"principal\":\"root\",\"note\":\"login from 203.0.113.77\"}\n"
    . "{\"event\":\"tenant\",\"user\":\"formeracct\",\"action\":\"tenant.sites\"}\n");
$errorLog = $state . '/error.log';
file_put_contents($errorLog, "2026-10-28 10:00:00 [NOTICE] [203.0.113.77:51234] GET /?token=abc123 HTTP/1.1 customer-site.com\n"
    . "Authorization: Bearer abcdefTOKENvalue123\nCookie: session=cookiesecretvalue\nset api_key=sk_live_PLANTEDAPIKEY99 for shopacct\n"
    . "connecting to https://admin:pw-in-url@db.customer-site.com/x?y=1 from 2001:db8::7334 ok\n$PEM\n$CERT\nowner ops-owner@customer-site.com\n"
    . "secret hash cafebabe0123456789cafebabe0123456789cafebabe0123456789cafebabe01\n");
$runner = new ScriptedRunner();
$runner->answers['bundle-rpm'] = ['exit_code' => 0, 'stdout' => "ols-cpanel-1.0.0-1.el9.x86_64\nols-cpanel-openlitespeed-1.8.5-1.el9.x86_64\n"];
$runner->answers['bundle-status'] = ['exit_code' => 0, 'stdout' => json_encode(['cut_over' => true, 'db_password' => 's3cr3tPW', 'ports' => ['80' => '198.51.100.9'], 'epoch' => 3])];
$runner->answers['bundle-doctor'] = ['exit_code' => 2, 'stdout' => json_encode(['supported' => false, 'private_key' => $PEM, 'host' => 'customer-site.com'])];
$runner->answers['bundle-generations'] = ['exit_code' => 0, 'stdout' => json_encode(['generations' => ['r1']])];
$runner->answers['bundle-journal'] = ['exit_code' => 0, 'stdout' => "Oct 28 broker[1]: webhook https://hooks.example.com/services/SECRETPART failed for shopacct\nOct 28 x: password=Hunter2Secret\n"
    . "Oct 28 lsws[2]: [ERROR] Authorization: Bearer prefixedshortsecret open /home/removeduser/public_html/old.customer.agency-error.log\n"];
$now = 1_800_000_000;
$builder = static fn(): SupportBundle => new SupportBundle($runner, $state, '/usr/local/ols-cpanel/bin/ols-cpanel', $errorLog, $userdata, static function () use (&$now): int {
    return $now;
});
function bundle_text(string $archive): array
{
    $dir = sys_get_temp_dir() . '/ols-bundle-x-' . bin2hex(random_bytes(5));
    mkdir($dir);
    $r = (new LocalCommandRunner())->run('untar', ['/usr/bin/tar', '-xzf', $archive, '-C', $dir], 60);
    if ($r['exit_code'] !== 0) {
        throw new RuntimeException('tar failed');
    }
    $files = [];
    foreach (scandir($dir) as $name) {
        if ($name !== '.' && $name !== '..') {
            $files[$name] = (string) file_get_contents("$dir/$name");
        }
    }
    tree_remove($dir);
    return $files;
}
$created = $builder()->create(true);
$archive = $state . '/support/' . $created['name'];
check(preg_match(SupportBundle::NAME, $created['name']) === 1 && is_file($archive) && (fileperms($archive) & 0777) === 0600 && $created['size'] < SupportBundle::MAX_BYTES,
    'the bundle is a bounded root 0600 tar.gz with a validated name');
$files = bundle_text($archive);
$all = implode("\n", $files);
foreach ($SECRETS as $secret) {
    check(!str_contains($all, $secret), "planted secret absent from every file of the bundle: $secret");
}
foreach (['BEGIN PRIVATE KEY', 'BEGIN CERTIFICATE', '203.0.113.77', '198.51.100.9', '2001:db8', 'customer-site.com', 'shopacct', 'hooks.example.com', 'other.example.org',
          'secret-customer-page', '/home/shopacct', 'prefixedshortsecret', 'removeduser', 'old.customer.agency', 'formeracct'] as $leak) {
    check(!str_contains($all, $leak), "anonymized bundle holds no $leak");
}
check(isset($files['manifest.json']) && isset($files['versions.txt']) && isset($files['status.json']) && isset($files['doctor.json']) && isset($files['journal.log'])
    && isset($files['ols-error-log-tail.log']) && isset($files['php-env.json']) && isset($files['active-summary.json']) && !isset($files['broker-secret'])
    && !array_filter(array_keys($files), static fn(string $n): bool => str_contains($n, 'key') || str_contains($n, 'tls')), 'the expected files are present, no key or secret file is');
check(str_contains($files['versions.txt'], 'ols-cpanel-1.0.0-1.el9') && str_contains($files['status.json'], '"epoch": 3'), 'diagnostic content (versions, status) is kept');
check(!str_contains($files['notify.json'], 'webhook') && str_contains($files['notify.json'], '"enabled": true') && !str_contains($files['schedule.json'], str_repeat('c', 64)),
    'notification addresses and URL and the schedule digests are not copied');
$placeholder = null;
preg_match('/domain-[0-9a-f]{8}\.invalid/', $files['ols-error-log-tail.log'], $m);
$placeholder = $m[0] ?? null;
check($placeholder !== null && str_contains($files['journal.log'] . $files['cache-clean.json'] . $files['active-summary.json'], $placeholder),
    'a domain has the same placeholder in every file');
check(preg_match('/ip-[0-9a-f]{8}/', $files['ols-error-log-tail.log']) === 1 && preg_match('/acct-[0-9a-f]{8}/', $files['ols-error-log-tail.log']) === 1, 'IP addresses and accounts have placeholders');
$again = bundle_text($state . '/support/' . $builder()->create(true)['name']);
check(str_contains($again['ols-error-log-tail.log'], $placeholder), 'placeholders are stable across bundles of one server');
// Without anonymization the keys, passwords and tokens still go; names and addresses stay.
$plain = bundle_text($state . '/support/' . $builder()->create(false)['name']);
$plainAll = implode("\n", $plain);
foreach ($SECRETS as $secret) {
    check(!str_contains($plainAll, $secret), "secret absent without anonymization too: $secret");
}
check(str_contains($plainAll, '203.0.113.77') && str_contains($plainAll, 'customer-site.com') && !str_contains($plainAll, 'BEGIN PRIVATE KEY'),
    'without anonymization IP addresses and names stay, keys do not');
// Only the last three bundles are kept.
$now += 10;
$builder()->create(true);
$now += 10;
$builder()->create(true);
check(count((new SupportBundle($runner, $state, '/x', $errorLog, $userdata))->bundles()) === SupportBundle::KEEP, 'only the last three bundles are kept');
// The redactor on its own.
$r = new Redactor(true, ['mysite.org'], ['alice1'], str_repeat('1', 64));
$out = $r->text("user alice1 at mysite.org from 192.0.2.1 token: abc123def456 file error.log ols.sync php-env.json 12:30:15 mail me@x.test");
check(!str_contains($out, 'alice1') && !str_contains($out, 'mysite.org') && !str_contains($out, '192.0.2.1') && !str_contains($out, 'abc123def456') && !str_contains($out, 'me@x.test')
    && str_contains($out, 'error.log') && str_contains($out, 'ols.sync') && str_contains($out, 'php-env.json') && str_contains($out, '12:30:15'), 'the redactor replaces names, addresses and secrets and leaves file names and times');
$out = $r->text('log /usr/local/lsws/logs/vhosts/mysite.org-error.log sock /run/x/blog.mysite.org-php.sock other /logs/shop.example.com-error.log');
check(!str_contains($out, 'mysite.org') && !str_contains($out, 'example.com') && str_contains($out, '-error.log') && str_contains($out, '-php.sock'),
    'domain names inside OpenLiteSpeed file names (<domain>-error.log, <domain>-php.sock) are replaced');
// Review 9: sensitive headers after any prefix, in any case, as quoted or JSON-escaped keys and inside JSON strings lose the
// whole value; Bearer and Basic credentials lose the token anywhere.
$plainRedactor = new Redactor(false, [], [], str_repeat('1', 64));
$headerCases = [
    '[ERROR] Authorization: Bearer shortsecret' => '[ERROR] Authorization: [REDACTED]',
    '2026-10-28 10:00:00 [NOTICE] authorization: Basic dXNlcjpwYXNz' => '2026-10-28 10:00:00 [NOTICE] authorization: [REDACTED]',
    '[DEBUG] proxy-authorization: Digest username="u", response="shortsecret"' => '[DEBUG] proxy-authorization: [REDACTED]',
    'req x-api-key: k3y and more' => 'req x-api-key: [REDACTED]',
    '> Cookie: sid=shortsecret; theme=dark' => '> Cookie: [REDACTED]',
    '< set-cookie: sid=shortsecret; Path=/; HttpOnly' => '< set-cookie: [REDACTED]',
    '{"headers":{"Authorization":"Bearer shortsecret","X-Auth-Token":"shortsecret"},"ok":true}' => '{"headers":{"Authorization":"[REDACTED]","X-Auth-Token":"[REDACTED]"},"ok":true}',
    '{"msg":"request had \"Cookie\": \"sid=shortsecret; b=c\" set","level":"error"}' => '{"msg":"request had \"Cookie\": \"[REDACTED]\" set","level":"error"}',
    '{"msg":"upstream said Authorization: Basic c2hvcnQ6c2VjcmV0","n":1}' => '{"msg":"upstream said Authorization: [REDACTED]","n":1}',
    'the client sent Bearer shortsecret twice; Basic setup is fine' => 'the client sent Bearer [REDACTED] twice; Basic setup is fine',
];
foreach ($headerCases as $in => $expected) {
    check($plainRedactor->text($in) === $expected, 'header redacted wherever it is written: ' . substr($in, 0, 40));
}
// Review 9: a quoted local part is an e-mail address too.
$out = $plainRedactor->text('to "first.last"@example.com and {"to":"\"j.doe\"@example.org"}');
check(!str_contains($out, 'first.last') && !str_contains($out, 'j.doe') && !str_contains($out, '@example.com') && substr_count($out, '@example.invalid') === 2,
    'e-mail addresses with a quoted local part are redacted, also JSON-escaped');
// Review 9: names this server no longer hosts (journal and audit records keep them): any /home* account, the account fields of
// structured records and any host name (not only a list of top-level domains) get placeholders; file names and product words stay.
$r = new Redactor(true, ['mysite.org'], ['alice1'], str_repeat('1', 64));
$out = $r->text("open /home/removeduser/public_html/old.customer.agency-error.log failed\n/home2/virtfs/gone2/x /home/gone3\n"
    . 'user=gone4 {"account":"gone5","actor":"gone6","principal":"root"} \"user\": \"gone7\" --account=gone8 scope account:gone9' . "\n"
    . 'mail relay shop.example.pl cdn.brand.photography www.site.co.uk' . "\n"
    . 'keep error.log ols.sync php-env.json job.status cap.issue opcache.enable run.sh README.md jquery.min.js archive.tar.gz ols-cpanel-notify.timer'
    . ' lsws.service httpd_config.conf ols-cpanel-1.0.0-1.el9.x86_64 wp-config.php 12:30:15 "actor":"root"');
foreach (['removeduser', 'old.customer.agency', 'gone2', 'gone3', 'gone4', 'gone5', 'gone6', 'gone7', 'gone8', 'gone9', 'shop.example.pl', 'brand.photography', 'site.co.uk'] as $gone) {
    check(!str_contains($out, $gone), "a name this server no longer hosts is anonymized: $gone");
}
foreach (['-error.log failed', '/public_html/', 'error.log', 'ols.sync', 'php-env.json', 'job.status', 'cap.issue', 'opcache.enable', 'run.sh', 'README.md', 'jquery.min.js',
          'archive.tar.gz', 'ols-cpanel-notify.timer', 'lsws.service', 'httpd_config.conf', 'ols-cpanel-1.0.0-1.el9.x86_64', 'wp-config.php', '12:30:15',
          '"principal":"root"', '"actor":"root"'] as $kept) {
    check(str_contains($out, $kept), "a file name, product word or system account stays: $kept");
}
check($r->data(['user' => 'gone10', 'nested' => ['owner' => 'root', 'account' => 'gone11']]) === ['user' => (fn() => $this->token('acct-', 'gone10'))->call($r),
    'nested' => ['owner' => 'root', 'account' => (fn() => $this->token('acct-', 'gone11'))->call($r)]], 'the account fields of decoded records are anonymized the same way');
tree_remove($state);

// ---- The CLI commands are root only -----------------------------------------------------------------------------------
if (function_exists('posix_geteuid') && posix_geteuid() !== 0) {
    foreach ([['notify', 'show'], ['notify', 'run'], ['schedule', 'list'], ['update', 'check'], ['support', 'bundle'], ['support', 'list']] as $argv) {
        $stdout = fopen('php://memory', 'w+');
        $stderr = fopen('php://memory', 'w+');
        $code = (new Application())->run([...$argv, '--format=json'], new Output(true, $stdout, $stderr));
        check($code === Application::EXIT_REFUSED, implode(' ', $argv) . ' refuses a caller that is not root');
    }
}
$help = (new Application())->help();
foreach (['notify show', 'notify set', 'notify test', 'notify run', 'schedule list', 'schedule add', 'schedule cancel', 'schedule run', 'update check', 'support bundle', 'support list'] as $words) {
    check(str_contains($help, $words), "the command line lists `$words`");
}
echo "$count checks passed\n";
