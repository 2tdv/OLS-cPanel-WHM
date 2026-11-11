<?php
declare(strict_types=1);

// RV-53 demand-based PHP children: the log scan (both line spellings, incremental reads, rotation), raise, cap, memory
// budget, decay, the state file's trust rules, and the precedence against the operator's php-limits.json. Temporary
// trees only; nothing on the host is read or changed.
require dirname(__DIR__) . '/src/bootstrap.php';

use OlsCpanel\Php\PhpDemand;
use OlsCpanel\Php\PhpLimits;

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

$dir = sys_get_temp_dir() . '/ols-php-demand-' . bin2hex(random_bytes(6));
mkdir($dir, 0700);
register_shutdown_function(static fn() => exec('/usr/bin/rm -rf -- ' . escapeshellarg($dir)));
$now = 1_800_000_000;
$GiB = 1073741824;

/** @return list<array{user:string, limit:int, time:int}> */
$reports = static fn(string $user, int $n, int $limit = 5, int $time = 0): array => array_fill(0, $n, ['user' => $user, 'limit' => $limit, 'time' => $time ?: $now]);

// ---- raise, cap -------------------------------------------------------------------------------------------
$state = PhpDemand::empty();
check($state->children() === [], 'no state: no automatic value');
$state->apply($reports('busy', PhpDemand::RAISE_HITS - 1), $now, 16 * $GiB);
check($state->children() === [], 'fewer than ' . PhpDemand::RAISE_HITS . ' reports at the limit do not raise');
$result = $state->apply($reports('busy', 1), $now, 16 * $GiB);
check($state->children() === ['busy' => 8] && $result['raised'] === ['busy'], 'enough reports at the limit raise 5 to 8');
$state->apply($reports('busy', 20, 5), $now + 60, 16 * $GiB);
check($state->children() === ['busy' => 8], 'reports from an lsphp still running with the old limit 5 do not raise again');
$state->apply($reports('busy', 3, 8), $now + 120, 16 * $GiB);
check($state->children() === ['busy' => 12], 'reports at the raised limit raise 8 to 12');
$result = $state->apply($reports('busy', 500, 12), $now + 180, 16 * $GiB);
check($state->children() === ['busy' => 12] && $result['raised'] === [], 'never above 12');
$state->apply($reports('quiet', 1, 3), $now, 16 * $GiB);
check(!isset($state->children()['quiet']) && isset($state->describe()['quiet']), 'a report below the account\'s current limit keeps the built-in value but is recorded');

// ---- memory budget: 60 MB per extra child, 25% of MemTotal, busiest first ------------------------------------
$state = PhpDemand::empty();
$memory = intdiv(200 * 1048576 * 100, 25);  // a budget of 200 MiB: one 5 -> 8 step (180 MiB), not two
$result = $state->apply([...$reports('small', 4), ...$reports('big', 30), ...$reports('mid', 9)], $now, $memory);
check($result['budget_mb'] === 200 && $state->children() === ['big' => 8] && $result['raised'] === ['big'],
    'the busiest account gets the budget');
check($result['budget_limited'] === ['mid', 'small'] && $state->describe()['mid']['budget_limited'] === true
    && str_contains($state->describe()['mid']['reason'], 'memory budget'), 'accounts that do not fit are marked as limited by the budget, with the reason');
$result = $state->apply([], $now + 60, $memory);
check($result['extra_mb'] === 180 && $state->children() === ['big' => 8], 'the extra children of all accounts are counted against the budget');
$result = $state->apply([], $now + 120, 8 * $GiB);
check($state->children() === ['big' => 8, 'mid' => 8, 'small' => 8] && $result['extra_mb'] === 540, 'with memory to spare the waiting accounts are raised');
$state = PhpDemand::empty();
$state->apply($reports('a', 5), $now, 0);
check($state->children() === [], 'an unknown MemTotal (0) allows no extra child');

// ---- decay by one step after 7 days without a report ----------------------------------------------------------
$state = PhpDemand::empty();
$state->apply($reports('old', 3), $now, 16 * $GiB);
$state->apply($reports('old', 3, 8), $now, 16 * $GiB);
check($state->children() === ['old' => 12], 'raised to 12');
$state->apply([], $now + PhpDemand::DECAY_SECONDS - 1, 16 * $GiB);
check($state->children() === ['old' => 12], 'one second short of 7 days: unchanged');
$result = $state->apply([], $now + PhpDemand::DECAY_SECONDS, 16 * $GiB);
check($state->children() === ['old' => 8] && $result['decayed'] === ['old'], '7 days without a report: one step down (12 to 8)');
$state->apply([], $now + PhpDemand::DECAY_SECONDS + 3600, 16 * $GiB);
check($state->children() === ['old' => 8], 'the next step needs another 7 days');
$state->apply([], $now + 2 * PhpDemand::DECAY_SECONDS, 16 * $GiB);
check($state->children() === [] && isset($state->describe()['old']), '14 days: back to the built-in value');
$state->apply([], $now + 3 * PhpDemand::DECAY_SECONDS, 16 * $GiB);
check($state->describe() === [], 'and an idle account is forgotten');
$state = PhpDemand::empty();
$state->apply($reports('flapping', 3), $now, 16 * $GiB);
$state->apply($reports('flapping', 1, 5, $now + PhpDemand::DECAY_SECONDS - 10), $now + PhpDemand::DECAY_SECONDS - 10, 16 * $GiB);
$state->apply([], $now + PhpDemand::DECAY_SECONDS + 100, 16 * $GiB);
check($state->children() === ['flapping' => 8], 'a report restarts the 7 days');

// ---- the log scan and the state file -----------------------------------------------------------------------
$log = "$dir/stderr.log";
$statePath = "$dir/php-demand.json";
$meminfo = "$dir/meminfo";
file_put_contents($meminfo, "MemTotal:       16384000 kB\nMemFree:  1 kB\n");
$stamp = static fn(int $t): string => date('Y-m-d H:i:s', $t) . '.123';
$line = static fn(string $who, int $t, int $limit = 5): string => $stamp($t) . " [STDERR] $who Reached max children process limit: $limit, extra: 0, current: $limit, busy: 6, please increase LSAPI_CHILDREN.\n";
$accounts = static fn(int $uid): ?string => [1001 => 'olscpa', 1002 => 'olscpb', 0 => 'root'][$uid] ?? null;
$text = '';
for ($i = 0; $i < 4; ++$i) {
    $text .= $line('[UID:1001][' . (100 + $i) . ']', $now - 600 + $i);
}
$text .= $line('olscpb-php', $now - 500, 4) . $line('[UID:0][5]', $now - 400) . $line('[UID:4242][6]', $now - 300) . "unrelated line\n";
$text .= $line('[UID:1002][7]', $now - 5 * 86400 * 2 - 3 * 86400) . $stamp($now) . ' [STDERR] [UID:1001][8] Reached max children process limit: 5, extra: 0, cur';  // half a line
file_put_contents($log, $text);
$first = PhpDemand::scan($statePath, $log, $meminfo, $now, $accounts);
check($first['result'] === 'scanned' && $first['lines'] === 8 && $first['unattributed'] === 2 && $first['raised'] === ['olscpa'],
    'the scan attributes both spellings (the extprocessor name and [UID:n]), skips root and unknown users, ignores old lines and raises');
$saved = json_decode((string) file_get_contents($statePath), true);
check($saved['version'] === 1 && $saved['accounts']['olscpa']['children'] === 8 && $saved['accounts']['olscpb']['waits'] === 1
    && decoct(fileperms($statePath) & 0777) === '644', 'the state file is written (0644) with the value, the counts and the log position');
check(PhpDemand::load($statePath)->children() === ['olscpa' => 8], 'it is the input the compile reads: only the raised account differs from the built-in value');
$offset = $saved['log']['offset'];
check($offset === strlen($text) - strlen($stamp($now) . ' [STDERR] [UID:1001][8] Reached max children process limit: 5, extra: 0, cur'),
    'the scan stops before an incomplete last line');
$second = PhpDemand::scan($statePath, $log, $meminfo, $now + 10, $accounts);
check($second['lines'] === 0, 'a second scan of an unchanged log counts nothing again');
file_put_contents($log, "rent: 5, busy: 6, please increase LSAPI_CHILDREN.\n" . $line('[UID:1001][9]', $now + 20) . $line('[UID:1001][9]', $now + 21), FILE_APPEND);
$third = PhpDemand::scan($statePath, $log, $meminfo, $now + 30, $accounts);
check($third['lines'] === 3 && PhpDemand::load($statePath)->describe()['olscpa']['waits'] === 7, 'only the lines added since the last scan are read (the completed half line included)');
rename($log, "$log.1");
file_put_contents($log, $line('[UID:1002][1]', $now + 40) . $line('[UID:1002][1]', $now + 41) . $line('[UID:1002][1]', $now + 42));
$rotated = PhpDemand::scan($statePath, $log, $meminfo, $now + 50, $accounts);
check($rotated['lines'] === 3 && PhpDemand::load($statePath)->children() === ['olscpa' => 8, 'olscpb' => 8], 'a rotated log is read from its start');
unlink($log);
check(PhpDemand::scan($statePath, $log, $meminfo, $now + 60, $accounts)['log'] === 'absent'
    && PhpDemand::load($statePath)->children() === ['olscpa' => 8, 'olscpb' => 8], 'an absent log changes nothing');
$late = PhpDemand::scan($statePath, $log, $meminfo, $now + PhpDemand::DECAY_SECONDS + 1000, $accounts);
check($late['decayed'] === ['olscpa', 'olscpb'] && PhpDemand::load($statePath)->children() === [],
    'a scan with no new reports applies the decay: after 7 days the accounts are back at the built-in value');

// ---- the state file is trusted only when it is root's (or ours), a plain file and not writable by others -------
$bad = "$dir/bad.json";
foreach (['{', '[]', '{"version": 2, "accounts": {}}', '{"version": 1, "accounts": {"olscpa": {"children": 99}}}',
             '{"version": 1, "accounts": {"Bad Name": {"children": 8}}}'] as $text) {
    file_put_contents($bad, $text);
    check(PhpDemand::load($bad)->children() === [], 'a malformed or impossible state is no automatic value: ' . substr($text, 0, 40));
}
file_put_contents($bad, '{"version": 1, "accounts": {"olscpa": {"children": 8}}}');
check(PhpDemand::load($bad)->children() === ['olscpa' => 8], 'a minimal valid state is read');
chmod($bad, 0666);
check(PhpDemand::load($bad)->children() === [], 'a world-writable state file is ignored');
chmod($bad, 0644);
unlink($bad);
symlink('/etc/passwd', $bad);
check(PhpDemand::load($bad)->children() === [] && PhpDemand::load("$dir/none.json")->children() === [], 'a link or an absent file is ignored');

// ---- precedence: the operator always wins ----------------------------------------------------------------------
$demand = PhpDemand::load($statePath);
file_put_contents($statePath, '{"version": 1, "accounts": {"olscpa": {"children": 12, "waits": 90, "last_hit": ' . $now . '}, "olscpb": {"children": 8}}}');
chmod($statePath, 0644);
$demand = PhpDemand::load($statePath);
$plain = PhpLimits::fromArray([]);
check($plain->forAccount('olscpa') === PhpLimits::BUILTIN && !$plain->withDemand(PhpDemand::empty())->overrides(),
    'without demand state the limits are the built-in set (the compiler output is unchanged)');
$with = $plain->withDemand($demand);
check($with->forAccount('olscpa')['children'] === 12 && $with->forAccount('olscpa')['max_conns'] === 12 && $with->forAccount('olscpb')['children'] === 8
    && $with->forAccount('other') === PhpLimits::BUILTIN, 'the automatic value replaces the built-in one, max_conns follows it');
check($with->accountsWithLimits() === ['olscpa', 'olscpb'] && !$with->overrides(), 'automatic accounts are listed without being an operator override');
$own = PhpLimits::fromArray(['accounts' => ['olscpa' => ['children' => 6]]])->withDemand($demand);
check($own->forAccount('olscpa')['children'] === 6 && $own->forAccount('olscpb')['children'] === 8, 'an account\'s own children win over the automatic value');
$defaults = PhpLimits::fromArray(['defaults' => ['children' => 7]])->withDemand($demand);
check($defaults->forAccount('olscpa')['children'] === 7 && $defaults->forAccount('olscpb')['children'] === 7, 'the operator\'s defaults win over the automatic value');
$capped = PhpLimits::fromArray(['accounts' => ['olscpa' => ['max_conns' => 9], 'olscpb' => ['proc_soft' => 6]]])->withDemand($demand);
check($capped->forAccount('olscpa')['children'] === 9 && $capped->forAccount('olscpa')['max_conns'] === 9 && $capped->forAccount('olscpb')['children'] === 6,
    'an operator\'s max_conns or proc_soft below the automatic value caps it instead of invalidating the file');
$report = $own->describe();
check($report['automatic']->olscpa['applied'] === false && $report['automatic']->olscpa['source'] === 'operator'
    && $report['automatic']->olscpa['effective_children'] === 6 && $report['automatic']->olscpb['source'] === 'automatic',
    'the report says whether the automatic value is in force or the operator\'s value wins');
check($with->describe()['automatic']->olscpa['reason'] !== '' && str_contains($with->describe()['automatic']->olscpa['reason'], '90 times'),
    'the reason names the number of reports');

echo "$count checks passed\n";
