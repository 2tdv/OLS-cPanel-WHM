<?php
declare(strict_types=1);

// The automatic LSCache cleanup (FV-01): expiry, per-site cap (oldest first), server cap, emergency trim, link safety, control files,
// young entries, the limits file, the confined helper chain and the CLI, on temporary trees. Python/PHP equality of the primitive
// is in tests/lscache.py.
require dirname(__DIR__) . '/src/bootstrap.php';

use OlsCpanel\Cli\Application;
use OlsCpanel\Cli\Command;
use OlsCpanel\Cli\EngineContext;
use OlsCpanel\Cli\Output;
use OlsCpanel\Infrastructure\Process\CommandRunner;
use OlsCpanel\Ols\AuditLogRotator;
use OlsCpanel\Ols\Cache\CacheCleaner;
use OlsCpanel\Ols\Cache\CacheLimits;
use OlsCpanel\Ols\Cache\CacheStorage;
use OlsCpanel\Ols\Compiler\CachePolicy;

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
                chmod($path, 0700);
                tree_remove("$path/$name");
            }
        }
        rmdir($path);
    } elseif (file_exists($path) || is_link($path)) {
        unlink($path);
    }
}

/** An entry file of a store, written with a modification time. */
function put(string $cache, string $store, string $hash, int $size, int $mtime, string $suffix = '', bool $private = false): string
{
    $dir = "$cache/$store/" . ($private ? 'priv/' : '') . "$hash[0]/$hash[1]/$hash[2]";
    @mkdir($dir, 0770, true);
    $path = "$dir/$hash$suffix";
    file_put_contents($path, str_repeat('x', $size));
    touch($path, $mtime);
    return $path;
}

$now = 1_800_000_000;
$max = CachePolicy::maxEntryAge();
check($max === max(CachePolicy::MIN_ENTRY_AGE, 3600 + 200 + CachePolicy::CLEAN_MARGIN) && $max === 691200,
    'the expiry age comes from the compiled policy (longest lifetime + stale window + margin), at least eight days');
$base = sys_get_temp_dir() . '/ols-cache-clean-' . bin2hex(random_bytes(6));
$state = "$base/state";
$cache = "$base/cache";
mkdir($state, 0755, true);
mkdir($cache, 0711);
chmod($cache, 0711);
$uid = getmyuid();
$GLOBALS['workerCalls'] = [];
$worker = static function (string $root, string $store, int $u, int $g, int $cutoff, int $cap, int $at): array {
    $GLOBALS['workerCalls'][] = [$store, $cutoff, $cap];
    return (new CacheStorage($root))->trimStore($store, $cutoff, $cap, $at);
};
$make = static function (int $total = 100_000_000_000, int $free = 50_000_000_000) use ($state, $cache, $uid, $worker, &$now): CacheCleaner {
    return new CacheCleaner($state, new CacheStorage($cache, $uid), $cache, $worker, static fn(): int => $now,
        static fn(string $path): array => [$total, $free]);
};

// ---- expiry, link safety, control files, young entries, emptied directories -------------------------------------------------
$victim = "$base/victim";
mkdir($victim);
file_put_contents("$victim/keep.txt", 'precious');
mkdir("$cache/olscpa@a.test", 0770);
$old = $now - $max - 100;
$fresh = $now - 3000;
$expired = put($cache, 'olscpa@a.test', '0123456789abcdef', 100, $old);
$expiredStale = put($cache, 'olscpa@a.test', '0123456789abcdef', 40, $old, '.S');
$expiredTmp = put($cache, 'olscpa@a.test', '0223456789abcdef', 9, $old, '.tmp');
$expiredPrivate = put($cache, 'olscpa@a.test', 'aaaaaaaaaaaaaaaa', 30, $old, '', true);
$young = put($cache, 'olscpa@a.test', '1123456789abcdef', 70, $now - 5);
$youngOld = put($cache, 'olscpa@a.test', '2123456789abcdef', 60, $now - 100);
$kept = put($cache, 'olscpa@a.test', '3123456789abcdef', 20, $fresh);
file_put_contents("$cache/olscpa@a.test/.cacheman.shm", str_repeat('i', 4096));
touch("$cache/olscpa@a.test/.cacheman.shm", $old);
file_put_contents("$cache/olscpa@a.test/.cacheman.lock", '');
touch("$cache/olscpa@a.test/.cacheman.lock", $old);
@mkdir("$cache/olscpa@a.test/x", 0770);
file_put_contents("$cache/olscpa@a.test/x/notes", 'n');
touch("$cache/olscpa@a.test/x/notes", $old);
symlink("$victim/keep.txt", "$cache/olscpa@a.test/0/1/2/1111111111111111");
@mkdir("$cache/olscpa@a.test/8/8", 0770, true);
symlink($victim, "$cache/olscpa@a.test/8/8/8");
symlink($victim, "$cache/olscpa@a.test/7");

mkdir("$cache/server", 0770);
$report = $make()->clean();
check($report['result'] === 'cleaned' && $report['emergency'] === false, 'a clean run on a healthy disk');
check(!file_exists($expired) && !file_exists($expiredStale) && !file_exists($expiredTmp) && !file_exists($expiredPrivate),
    'expired entries (public, stale copy, old .tmp, private) are removed');
check(file_exists($young) && file_exists($youngOld) && file_exists($kept), 'entries within their lifetime and young ones stay');
check(file_exists("$cache/olscpa@a.test/.cacheman.shm") && file_exists("$cache/olscpa@a.test/.cacheman.lock") && file_exists("$cache/olscpa@a.test/x/notes"),
    'control files and unknown names are never removed, however old');
check(is_link("$cache/olscpa@a.test/0/1/2/1111111111111111") && is_link("$cache/olscpa@a.test/7") && is_link("$cache/olscpa@a.test/8/8/8")
    && file_get_contents("$victim/keep.txt") === 'precious' && is_dir($victim), 'links are neither followed nor removed');
check(!is_dir("$cache/olscpa@a.test/priv") && !is_dir("$cache/olscpa@a.test/0/2") && is_dir("$cache/olscpa@a.test/3"), 'directories emptied by the cleanup are removed, the others stay');
check($report['stores']['olscpa@a.test']['files'] === 4 && $report['stores']['olscpa@a.test']['bytes'] === 100 + 40 + 9 + 30
    && $report['stores']['olscpa@a.test']['failed'] === 0, 'files and bytes removed are counted per store');
$last = (new CacheCleaner($state, new CacheStorage($cache, $uid), $cache))->last();
check($last !== null && $last['last_run'] === $now && $last['stores']['olscpa@a.test']['files'] === 4 && $last['totals']['files'] === 4
    && (fileperms("$state/" . CacheCleaner::STATE_FILE) & 0777) === 0600, 'the run is recorded in the state file (root 0600)');
$noop = $make()->clean();
check($noop['totals']['files'] === 0 && $noop['stores']['olscpa@a.test']['remaining_files'] === 3, 'a second run removes nothing');
tree_remove("$cache/olscpa@a.test");

// ---- per-site cap, oldest first, young protected -------------------------------------------------------------------------------
file_put_contents("$state/" . CacheLimits::FILE, json_encode(['per_site_mb' => 16]));
mkdir("$cache/olscpb@b.test", 0770);
$mb = 1024 * 1024;
$files = [];
foreach (['a', 'b', 'c', 'd', 'e', 'f'] as $i => $letter) {
    // 4 MB each, 24 MB in all: the cap is 16 MB. Ages: a is the oldest.
    $files[$letter] = put($cache, 'olscpb@b.test', str_repeat($letter, 16), 4 * $mb, $now - 7000 + $i * 100);
}
$youngBig = put($cache, 'olscpb@b.test', 'fffffffffffffff0', 4 * $mb, $now - 10);
$report = $make()->clean();
$left = array_keys(array_filter($files, 'file_exists'));
check($report['per_site_bytes'] === 16 * $mb && $left === ['d', 'e', 'f'] && file_exists($youngBig),
    'a store above its cap loses the oldest entries first until it fits (the entry written seconds ago stays)');
check($report['stores']['olscpb@b.test']['files'] === 3 && $report['stores']['olscpb@b.test']['remaining_bytes'] === 4 * 4 * $mb, 'the removal is counted');
unlink("$state/" . CacheLimits::FILE);
// A young entry is never removed even when the cap is zero.
$cleaner = $make();
$direct = (new CacheStorage($cache))->trimStore('olscpb@b.test', $now + 1_000_000, 0, $now);
check(file_exists($youngBig) && $direct['remaining_files'] === 1 && $direct['remaining_bytes'] === 4 * $mb, 'a young entry survives a cap of zero and a cut-off in the future');
tree_remove("$cache/olscpb@b.test");

// ---- server cap over all stores, oldest first ----------------------------------------------------------------------------------
foreach (['olscpc@c.test', 'olscpd@d.test'] as $store) {
    mkdir("$cache/$store", 0770);
}
$order = [];
// Ten entries of 10 000 bytes in two stores, interleaved ages. Disk 1 000 000 bytes, 10%: the cap is 100 000 bytes: all fit.
// With a 5% setting it is 50 000: the five oldest go.
foreach (range(0, 9) as $i) {
    $store = $i % 2 === 0 ? 'olscpc@c.test' : 'olscpd@d.test';
    $order[$i] = put($cache, $store, sprintf('%016x', $i + 1), 10_000, $now - 20_000 + $i * 600);
}
$report = $make(1_000_000, 900_000)->clean();
check($report['server_bytes'] === 100_000 && $report['totals']['files'] === 0 && !$report['over_server_cap'], 'within the server cap nothing is removed');
file_put_contents("$state/" . CacheLimits::FILE, json_encode(['server_percent' => 5]));
$report = $make(1_000_000, 900_000)->clean();
$alive = array_keys(array_filter($order, 'file_exists'));
check($report['server_bytes'] === 50_000 && $alive === [5, 6, 7, 8, 9] && $report['totals']['files'] === 5 && $report['totals']['bytes'] === 50_000,
    'above the server cap the oldest entries of the whole server go first, across stores');
check($report['stores']['olscpc@c.test']['files'] + $report['stores']['olscpd@d.test']['files'] === 5, 'the server-wide removal is added to each store\'s count');
file_put_contents("$state/" . CacheLimits::FILE, json_encode(['server_max_gb' => 1, 'server_percent' => 50]));
$report = $make(100 * 1024 ** 3, 90 * 1024 ** 3)->clean();
check($report['server_bytes'] === 1024 ** 3, 'the server cap is never above server_max_gb');
$report = $make(0, 0)->clean();
check($report['server_bytes'] === 1024 ** 3 && $report['emergency'] === false, 'an unreadable filesystem size falls back to server_max_gb and is not an emergency');

// ---- emergency: free space under 5% halves every cap ----------------------------------------------------------------------------
file_put_contents("$state/" . CacheLimits::FILE, json_encode(['server_percent' => 10]));
foreach ($alive as $i) {
    unlink($order[$i]);
}
foreach (range(0, 9) as $i) {
    $store = $i % 2 === 0 ? 'olscpc@c.test' : 'olscpd@d.test';
    $order[$i] = put($cache, $store, sprintf('%016x', $i + 1), 10_000, $now - 20_000 + $i * 600);
}
$normal = $make(1_000_000, 100_000)->clean();   // exactly 10% free: not an emergency
check($normal['emergency'] === false && $normal['totals']['files'] === 0, '10% free space is no emergency');
$emergency = $make(1_000_000, 49_000)->clean();  // 4.9% free
check($emergency['emergency'] === true && $emergency['server_bytes'] === 50_000 && $emergency['per_site_bytes'] === 256 * $mb
    && $emergency['totals']['files'] === 5 && array_keys(array_filter($order, 'file_exists')) === [5, 6, 7, 8, 9],
    'under 5% free space every cap is halved and the oldest half is trimmed');
$status = $make(1_000_000, 49_000)->status();
check($status['emergency'] === true && $status['last_clean']['totals']['files'] === 5 && $status['max_entry_age'] === $max
    && $status['filesystem']['free_percent'] === 4.9, 'the status shows the caps, the disk and the last cleanup');

// ---- the limits file ---------------------------------------------------------------------------------------------------------------
$limits = new CacheLimits($state);
$path = "$state/" . CacheLimits::FILE;
$try = static function (string $text) use ($limits, $path): array {
    file_put_contents($path, $text);
    return $limits->load();
};
unlink($path);
check($limits->load() === ['limits' => CacheLimits::DEFAULTS, 'problem' => null, 'from_file' => false], 'no file: the defaults, no problem');
$good = $try('{"per_site_mb": 1024, "server_percent": 20}');
check($good['limits'] === ['per_site_mb' => 1024, 'server_percent' => 20, 'server_max_gb' => 20] && $good['problem'] === null, 'a partial file keeps the defaults of the missing keys');
foreach (['not json', '[]', '[1,2]', '"x"', '{"per_site_mb": "512"}', '{"per_site_mb": 512.5}', '{"per_site_mb": true}', '{"per_site_mb": 15}',
    '{"per_site_mb": 102401}', '{"server_percent": 0}', '{"server_percent": 51}', '{"server_max_gb": 0}', '{"server_max_gb": 2049}',
    '{"surprise": 1}', '{"per_site_mb": 600, "surprise": 1}', '{"per_site_mb": -5}', '{"per_site_mb": null}', str_repeat(' ', 5000) . '{}'] as $bad) {
    $got = $try($bad);
    check($got['limits'] === CacheLimits::DEFAULTS && is_string($got['problem']) && str_contains($got['problem'], 'defaults are in force'), "a bad file (" . substr($bad, 0, 30) . ") gives the defaults and a reported problem");
}
$report = (static function () use ($make, $try): array {
    $try('{"per_site_mb": 3}');
    return $make()->clean();
})();
check($report['limits'] === CacheLimits::DEFAULTS && is_string($report['limits_problem']) && $report['result'] === 'cleaned', 'a bad limits file never stops the cleanup, and the run reports the problem');
unlink($path);
symlink("$victim/keep.txt", $path);
check($limits->load()['problem'] !== null && $limits->load()['limits'] === CacheLimits::DEFAULTS, 'a limits file that is a link is not read');
unlink($path);
check($limits->save(['per_site_mb' => 2048]) === ['per_site_mb' => 2048, 'server_percent' => 10, 'server_max_gb' => 20]
    && (fileperms($path) & 0777) === 0600 && $limits->save(['server_max_gb' => 5])['per_site_mb'] === 2048, 'save keeps the other keys and writes root 0600');
foreach ([['per_site_mb' => 1], ['server_percent' => 90], ['x' => 1], ['per_site_mb' => '5']] as $bad) {
    try {
        $limits->save($bad);
        check(false, 'a refused save');
    } catch (InvalidArgumentException) {
        check(json_decode(file_get_contents($path), true)['per_site_mb'] === 2048, 'a save outside the bounds is refused and changes nothing');
    }
}
unlink($path);

// ---- the confined helper chain and the CLI ---------------------------------------------------------------------------------------------
tree_remove("$cache/olscpc@c.test");
tree_remove("$cache/olscpd@d.test");
$runs = [];
$runner = new class ($runs) implements CommandRunner {
    public function __construct(public array &$runs)
    {
    }

    public function run(string $name, array $argv, int $timeout): array
    {
        $this->runs[] = $argv;
        $cli = array_search(dirname(__DIR__) . '/bin/ols-cpanel', $argv, true);
        return (new OlsCpanel\Infrastructure\Process\LocalCommandRunner())->run($name,
            ['/usr/local/cpanel/3rdparty/php/84/bin/php', '-n', ...array_slice($argv, $cli)], $timeout);
    }
};
$helper = CacheStorage::confinedTrimHelper($runner, dirname(__DIR__) . '/bin/ols-cpanel');
mkdir("$cache/olscpe@e.test", 0770);
$real = time();
$gone = put($cache, 'olscpe@e.test', '9999999999999999', 50, $real - $max - 10);
$goneKept = put($cache, 'olscpe@e.test', '8888888888888888', 50, $real - 1000);
$context = new EngineContext(0, 'root', null, null, $state, "$state/profile.json", '/proc', $cache, $uid, null, $helper,
    static fn(): AuditLogRotator => new AuditLogRotator("$base/cli-logs/modsec_audit.log", static fn(): bool => true));
$app = new Application([new Command\CacheCleanCommand($context), new Command\CacheLimitsCommand($context), new Command\CacheCleanStoreCommand($context)]);
function run_cli(Application $app, array $argv): array
{
    $stdout = fopen('php://memory', 'w+');
    $stderr = fopen('php://memory', 'w+');
    $code = $app->run([...$argv, '--format=json'], new Output(true, $stdout, $stderr));
    rewind($stdout);
    $text = stream_get_contents($stdout);
    return [$code, $text === '' ? null : json_decode($text, true)];
}
[$code, $result] = run_cli($app, ['cache', 'clean']);
check($code === 0 && $result['command'] === 'cache clean' && $result['stores']['olscpe@e.test']['files'] === 1 && !file_exists($gone) && file_exists($goneKept),
    '`cache clean` removes through the helper process chain');
$argv = $runs[0];
check(in_array('--reuid=' . $uid, $argv, true) && in_array('--no-new-privs', $argv, true) && in_array('--inh-caps=-all', $argv, true)
    && in_array('--bounding-set=-all', $argv, true) && in_array('clean-store', $argv, true), 'the helper is started through setpriv as the store owner without capabilities');
$helperRuns = count($runs);
$rootless = CacheStorage::confinedTrimHelper($runner, dirname(__DIR__) . '/bin/ols-cpanel');
$refused = $rootless($cache, 'olscpe@e.test', 0, 0, 1, 1, 1);
check($refused['failed'] === 1 && str_contains($refused['error'], 'not cleaned as root') && count($runs) === $helperRuns, 'a store owned by root is never cleaned by root');
[$code, $result] = run_cli($app, ['cache', 'limits']);
check($code === 0 && $result['limits'] === CacheLimits::DEFAULTS && $result['changed'] === false && $result['last_clean']['totals']['files'] === 1
    && $result['bounds']['per_site_mb'] === [16, 102400] && $result['problem'] === null, '`cache limits` shows the limits, the bounds and the last cleanup');
[$code, $result] = run_cli($app, ['cache', 'limits', '--per-site-mb=1024', '--server-percent=15']);
check($code === 0 && $result['changed'] === true && $result['limits'] === ['per_site_mb' => 1024, 'server_percent' => 15, 'server_max_gb' => 20]
    // The CLI reads the real filesystem: on a nearly full test disk the emergency halving applies.
    && $result['per_site_bytes'] === intdiv(1024 * $mb, $result['emergency'] ? 2 : 1), '`cache limits --per-site-mb=.. --server-percent=..` saves them');
[$code, $result] = run_cli($app, ['cache', 'limits', '--per-site-mb=1']);
check($code === 1 && str_contains($result['error'], 'between 16 and 102400') && (new CacheLimits($state))->load()['limits']['per_site_mb'] === 1024, 'an out-of-range value is refused and changes nothing');
[$code] = run_cli($app, ['cache', 'limits', '--per-site-mb=abc']);
check($code !== 0, 'a value that is not a number is a usage error');
$stranger = new Application([new Command\CacheCleanCommand(new EngineContext(1000, 'someone', null, null, $state, "$state/profile.json", '/proc', $cache, $uid)),
    new Command\CacheLimitsCommand(new EngineContext(1000, 'someone', null, null, $state, "$state/profile.json", '/proc', $cache, $uid))]);
check(run_cli($stranger, ['cache', 'clean'])[0] !== 0 && run_cli($stranger, ['cache', 'limits'])[0] !== 0, 'cleaning and the limits are root only');
[$code] = run_cli(new Application([new Command\CacheCleanStoreCommand(new EngineContext(0, 'root', null, null, $state, "$state/profile.json", '/proc', $cache, $uid))]),
    ['cache', 'clean-store', "--root=$cache", '--store=olscpe@e.test', '--cutoff=1', '--cap=1', '--now=1']);
check($code !== 0, 'the helper command refuses to run as root');
[$code, $result] = run_cli(new Application([new Command\CacheCleanStoreCommand(new EngineContext(1000, 'someone', null, null, $state, "$state/profile.json", '/proc', $cache, $uid))]),
    ['cache', 'clean-store', "--root=$cache", '--store=../x', '--cutoff=1', '--cap=1', '--now=1']);
check($code === 1, 'the helper refuses a store name that is not a store');
// A root that is not a directory or is writable by others refuses.
chmod($cache, 0777);
[$code, $result] = run_cli($app, ['cache', 'clean']);
check($code === 1 && str_contains($result['error'], 'must be owned'), 'a writable cache root is refused');
chmod($cache, 0711);

// Rename, main-domain change and transfer away all leave stores absent from the active summary.
$orphans = "$base/orphans";
$orphanState = "$base/orphan-state";
mkdir($orphans, 0711);
chmod($orphans, 0711);
mkdir("$orphanState/active", 0755, true);
$orphanFile = put($orphans, 'olduser@old.test', '0123456789abcdef', 20, $now - 5);
file_put_contents("$orphans/olduser@old.test/.cacheman.shm", 'stale index');
$liveFile = put($orphans, 'newuser@new.test', '0123456789abcdef', 30, $now - 5);
symlink("$victim/keep.txt", "$orphans/olduser@old.test/outside");
$retireCalls = [];
$retireWorker = static function (string $root, string $store, int $u, int $g, bool $retire = false) use (&$retireCalls): array {
    $retireCalls[] = [$store, $retire];
    return (new CacheStorage($root))->purgeStore($store, $retire);
};
$orphanStorage = new CacheStorage($orphans, $uid, null, $retireWorker);
$orphanCleaner = new CacheCleaner($orphanState, $orphanStorage, $orphans, $worker, static fn(): int => $now,
    static fn(string $path): array => [100_000_000_000, 50_000_000_000]);
file_put_contents("$orphanState/active/summary.json", '{broken');
$orphanCleaner->clean();
check(is_file($orphanFile) && $retireCalls === [], 'a malformed active summary cannot retire stores');
file_put_contents("$orphanState/active/summary.json", json_encode(['vhosts' => ['new.test' => ['user' => 'newuser']],
    'cache' => ['new.test' => ['storage' => "$orphans/newuser@new.test"]]]));
$report = $orphanCleaner->clean();
check($report['result'] === 'cleaned' && !file_exists("$orphans/olduser@old.test") && is_file($liveFile)
    && file_get_contents("$victim/keep.txt") === 'precious' && $retireCalls === [['olduser@old.test', true]],
    'obsolete stores are purged with their control files and removed; live stores and link targets survive');
file_put_contents("$orphanState/active/summary.json", json_encode(['vhosts' => [], 'cache' => []]));
$orphanCleaner->clean();
check(!file_exists("$orphans/newuser@new.test"), 'removing the last account retires the final tenant store');
$argvs = [];
$retireRunner = new class($argvs) implements CommandRunner {
    public function __construct(public array &$argvs) {}
    public function run(string $name, array $argv, int $timeout): array {
        $this->argvs[] = $argv;
        return ['exit_code' => 0, 'stdout' => json_encode(['public_entries' => 0, 'public_bytes' => 0,
            'private_entries' => 0, 'private_bytes' => 0, 'failed' => 0])];
    }
};
$helper = CacheStorage::confinedHelper($retireRunner);
$helper($orphans, 'olduser@old.test', 65534, 65534, true);
check(in_array('--retire', $argvs[0], true) && in_array('--no-new-privs', $argvs[0], true)
    && in_array('--reuid=65534', $argvs[0], true), 'store retirement uses the confined owner helper');

$failedStore = put($orphans, 'gone@removed.test', '0123456789abcdef', 20, $now - 5);
$failRetire = true;
$retryWorker = static function (string $root, string $store, int $u, int $g, bool $retire = false) use (&$failRetire): array {
    return $failRetire ? ['failed' => 1, 'present' => true] : (new CacheStorage($root))->purgeStore($store, $retire);
};
$retryCleaner = new CacheCleaner($orphanState, new CacheStorage($orphans, $uid, null, $retryWorker), $orphans, $worker,
    static fn(): int => $now, static fn(string $path): array => [100_000_000_000, 50_000_000_000]);
check($retryCleaner->clean()['result'] === 'partial' && is_file($failedStore), 'failed orphan-store retirement is reported and retains the store');
$failRetire = false;
check($retryCleaner->clean()['result'] === 'cleaned' && !file_exists("$orphans/gone@removed.test"),
    'a later cache pass retries failed orphan-store retirement');

// Retirement races with an activation: it is skipped while the activation lock is held and done by the next run (review 8, finding 11).
$lockedStore = put($orphans, 'late@late.test', '0123456789abcdef', 20, $now - 5);
file_put_contents("$orphanState/active/summary.json", json_encode(['vhosts' => [], 'cache' => []]));
$activation = fopen("$orphanState/activation.lock", 'cb');
check(flock($activation, LOCK_EX), 'the test holds the activation lock');
$locked = $retryCleaner->clean();
check(is_file($lockedStore) && $locked['retired_stores'] === [] && is_string($locked['retirement_skipped']), 'a busy activation lock skips retirement');
flock($activation, LOCK_UN);
fclose($activation);
$free = $retryCleaner->clean();
check(!file_exists($lockedStore) && $free['retirement_skipped'] === null && isset($free['retired_stores']['late@late.test']),
    'the next run retires the store once the lock is free');
$again = fopen("$orphanState/activation.lock", 'cb');
check(flock($again, LOCK_EX | LOCK_NB), 'the cleaner releases the lock');
fclose($again);

// ---- RV-66: rotation of the ModSecurity audit log, run by the same pass ------------------------------------------------------
$logs = "$base/logs";
mkdir($logs, 0755);
$log = "$logs/modsec_audit.log";
$reloads = 0;
$reloadOk = true;
$clockNow = 1_800_000_000;
$rotator = static function (int $max = 1000) use ($log, &$reloads, &$reloadOk, &$clockNow): AuditLogRotator {
    return new AuditLogRotator($log, static function () use (&$reloads, &$reloadOk): bool {
        ++$reloads;
        return $reloadOk;
    }, static fn(): int => $clockNow, $max, 4);
};
$gz = static fn(string $path): string => (string) gzdecode((string) file_get_contents($path));
$absent = $rotator()->rotate();
check($absent['result'] === 'current' && $reloads === 0, 'no audit log: nothing to do, OLS is not reloaded');
file_put_contents($log, str_repeat("a\n", 400));
chmod($log, 0600);
$result = $rotator()->rotate();
check($result['result'] === 'current' && $reloads === 0 && !file_exists("$log.1"), 'a log under the size is left alone');
file_put_contents($log, str_repeat("line-one\n", 200));
$inode = fileinode($log);
$result = $rotator()->rotate();
check($result['result'] === 'rotated' && $reloads === 1 && !file_exists($log) && fileinode("$log.1") === $inode
    && file_get_contents("$log.1") === str_repeat("line-one\n", 200),
    'a log over the size is renamed (same inode: no copy, no truncation, no line lost) and OLS is reloaded once');
check((fileperms("$log.1") & 0777) === 0600, 'the rotated file keeps the mode OLS gave it');
file_put_contents($log, "new\n");
chmod($log, 0600);
touch("$log.1", $clockNow - 60);
$result = $rotator()->rotate();
check($result['result'] === 'current' && is_file("$log.1") && !file_exists("$log.1.gz"), 'the fresh rotated copy is not compressed while it may still be written');
$clockNow += 700;
$result = $rotator()->rotate();
check($result['compressed'] === ['modsec_audit.log.1'] && !file_exists("$log.1") && $gz("$log.1.gz") === str_repeat("line-one\n", 200)
    && (fileperms("$log.1.gz") & 0777) === 0600 && is_file($log) && file_get_contents($log) === "new\n",
    'a settled rotated copy is compressed with gzip, keeps its mode, and the live file is untouched');
// Four generations are kept, the fifth is dropped, in order.
for ($n = 1; $n <= 6; ++$n) {
    file_put_contents($log, "gen$n " . str_repeat('x', 1100) . "\n");
    $r = $rotator()->rotate();
    check($r['result'] === 'rotated', "rotation $n");
    $clockNow += 700;
    $rotator()->rotate();
}
$present = array_map('basename', glob("$log.*"));
sort($present);
check($present === ['modsec_audit.log.1.gz', 'modsec_audit.log.2.gz', 'modsec_audit.log.3.gz', 'modsec_audit.log.4.gz'],
    'at most four compressed copies are kept: ' . implode(' ', $present));
check(str_starts_with($gz("$log.1.gz"), 'gen6') && str_starts_with($gz("$log.4.gz"), 'gen3'), 'the oldest copies are dropped and the order is newest first');
file_put_contents("$log.7.gz", 'old');
$rotator()->rotate();
check(!file_exists("$log.7.gz"), 'a copy numbered above the retention is removed');
// A failed reload puts the file back: OLS keeps writing to the path it knows.
file_put_contents($log, str_repeat('y', 1500));
$reloadOk = false;
$before = $reloads;
$result = $rotator()->rotate();
check($result['result'] === 'failed' && $reloads === $before + 1 && is_file($log) && strlen((string) file_get_contents($log)) === 1500 && !file_exists("$log.1"),
    'when OLS does not reload, the log is put back and the failure is reported');
$reloadOk = true;
// Links are never followed: a link as the live log, and a planted link as the compressed target.
unlink($log);
file_put_contents("$base/victim-log", str_repeat('z', 5000));
symlink("$base/victim-log", $log);
$before = $reloads;
$result = $rotator()->rotate();
check($result['result'] === 'failed' && $reloads === $before && is_link($log) && file_get_contents("$base/victim-log") === str_repeat('z', 5000),
    'a link in place of the audit log is neither rotated nor followed');
unlink($log);
file_put_contents("$log.1", 'plain copy');
touch("$log.1", $clockNow - 5000);
file_put_contents("$base/target", 'precious');
symlink("$base/target", "$log.1.gz.tmp");
$result = $rotator()->rotate();
check(file_get_contents("$base/target") === 'precious' && is_file("$log.1.gz") && !is_link("$log.1.gz") && $gz("$log.1.gz") === 'plain copy',
    'a link planted where the compressed copy is written is replaced, never followed');
// The CLI pass: the audit log result is part of the output and a failure fails the unit.
mkdir("$base/cli-logs", 0755);
mkdir("$base/cli-state", 0755);
mkdir("$base/cli-cache", 0711);
chmod("$base/cli-cache", 0711);
file_put_contents("$base/cli-logs/modsec_audit.log", str_repeat('c', 3000));
$cliRotator = static fn(): AuditLogRotator => new AuditLogRotator("$base/cli-logs/modsec_audit.log", static fn(): bool => true, null, 1000);
$cliContext = new EngineContext(0, 'root', null, null, "$base/cli-state", "$base/cli-state/profile.json", '/proc', "$base/cli-cache", $uid, null, $helper, $cliRotator);
[$code, $result] = run_cli(new Application([new Command\CacheCleanCommand($cliContext)]), ['cache', 'clean']);
check($code === 0 && $result['audit_log']['result'] === 'rotated' && is_file("$base/cli-logs/modsec_audit.log.1") && !file_exists("$base/cli-logs/modsec_audit.log"),
    '`cache clean` rotates the audit log in the same pass and reports it');
file_put_contents("$base/cli-logs/modsec_audit.log", str_repeat('c', 3000));
$failing = static fn(): AuditLogRotator => new AuditLogRotator("$base/cli-logs/modsec_audit.log", static fn(): bool => false, null, 1000);
$failContext = new EngineContext(0, 'root', null, null, "$base/cli-state", "$base/cli-state/profile.json", '/proc', "$base/cli-cache", $uid, null, $helper, $failing);
[$code, $result] = run_cli(new Application([new Command\CacheCleanCommand($failContext)]), ['cache', 'clean']);
check($code !== 0 && $result['audit_log']['result'] === 'failed' && $result['result'] === 'cleaned', 'a failed rotation fails the unit but the cache cleanup still ran');

tree_remove($base);
echo "Cache cleanup checks passed: $count\n";
