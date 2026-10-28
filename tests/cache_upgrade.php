<?php
declare(strict_types=1);

// `cache stats|purge` (FV-01 plugin part) on temporary trees, and `upgrade` / `php restart` against a scripted
// fake runner (no command reaches the host).
require dirname(__DIR__) . '/src/bootstrap.php';
require __DIR__ . '/LsphpFake.php';

use OlsCpanel\Cli\Application;
use OlsCpanel\Cli\Command;
use OlsCpanel\Cli\EngineContext;
use OlsCpanel\Cli\Output;
use OlsCpanel\Deployment\Environment;
use OlsCpanel\Deployment\Upgrade;
use OlsCpanel\Infrastructure\Process\CommandRunner;

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

/** @param list<string> $argv @return array{0:int, 1:?array<string,mixed>} */
function run_cli(Application $app, array $argv): array
{
    $stdout = fopen('php://memory', 'w+');
    $stderr = fopen('php://memory', 'w+');
    $code = $app->run([...$argv, '--format=json'], new Output(true, $stdout, $stderr));
    rewind($stdout);
    $text = stream_get_contents($stdout);
    return [$code, $text === '' ? null : json_decode($text, true, 64, JSON_THROW_ON_ERROR)];
}

// ---- cache ----------------------------------------------------------------------------------------------
$base = sys_get_temp_dir() . '/ols-cache-cli-' . bin2hex(random_bytes(6));
$state = "$base/state";
$cache = "$base/cache";
mkdir($state, 0755, true);
mkdir($cache, 0711);
chmod($cache, 0711);
$uid = getmyuid();

function entry(string $store, string $hash, int $size, bool $private = false): void
{
    global $cache;
    $dir = "$cache/$store/" . ($private ? 'priv/' : '') . "$hash[0]/$hash[1]/$hash[2]";
    mkdir($dir, 0770, true);
    file_put_contents("$dir/$hash", str_repeat('x', $size));
}
$long = str_repeat('a', 60) . '.' . str_repeat('b', 60) . '.' . str_repeat('c', 60) . '.' . str_repeat('d', 60) . '.example.test';
$summary = [
    'vhosts' => [
        'a.test' => ['user' => 'olscpa', 'type' => 'main', 'docroot' => '/home/olscpa/public_html', 'aliases' => ['www.a.test', 'parked.test'],
            'php' => 'ea-php83', 'php_handler' => 'fpm', 'pool' => 'x', 'service_domains' => []],
        'shop.a.test' => ['user' => 'olscpa', 'type' => 'sub', 'docroot' => '/home/olscpa/shop', 'aliases' => [], 'php' => 'ea-php83',
            'php_handler' => 'fpm', 'pool' => 'x', 'service_domains' => []],
        'hy.test' => ['user' => 'olscpa', 'type' => 'main', 'docroot' => '/home/olscpa/hy', 'aliases' => [], 'php' => 'ea-php83',
            'php_handler' => 'cgi', 'pool' => 'x', 'service_domains' => []],
        'b.test' => ['user' => 'olscpb', 'type' => 'main', 'docroot' => '/home/olscpb/public_html', 'aliases' => [], 'php' => 'ea-php83',
            'php_handler' => 'fpm', 'pool' => 'x', 'service_domains' => []],
        $long => ['user' => 'olscpb', 'type' => 'sub', 'docroot' => '/home/olscpb/long', 'aliases' => [], 'php' => 'ea-php83',
            'php_handler' => 'fpm', 'pool' => 'x', 'service_domains' => []],
    ],
    'cache' => [
        'a.test' => ['enabled' => true, 'storage' => "$cache/olscpa@a.test"],
        'shop.a.test' => ['enabled' => true, 'storage' => "$cache/olscpa@shop.a.test"],
        'hy.test' => ['enabled' => false, 'storage' => null],
        'b.test' => ['enabled' => false, 'storage' => "$cache/olscpb@b.test"],
        $long => ['enabled' => true, 'storage' => 'unused'],
    ],
    'compiled_at' => '2026-10-26T12:00:00Z',
];
mkdir("$state/generations/r1", 0755, true);
file_put_contents("$state/generations/r1/summary.json", json_encode($summary));
symlink("$state/generations/r1", "$state/active");
$policy = new OlsCpanel\Ols\Compiler\CachePolicy();
$longStore = $policy->storeName('olscpb', $long);
check(str_starts_with($longStore, 'olscpb@h-'), 'a long vhost gets a hashed store name');
foreach (['server', 'olscpa@a.test', 'olscpa@shop.a.test', 'olscpb@b.test', $longStore, 'olscpgone@gone.test'] as $store) {
    mkdir("$cache/$store", 0770);
}
entry('olscpa@a.test', '0123456789abcdef', 100);
entry('olscpa@a.test', '1123456789abcdef', 50, true);
entry('olscpa@a.test', '2123456789abcdef', 10);
entry('olscpa@shop.a.test', '3123456789abcdef', 7);
entry('olscpb@b.test', '4123456789abcdef', 1000);
entry($longStore, '5123456789abcdef', 5);
entry('olscpgone@gone.test', '6123456789abcdef', 3);
entry('server', '7123456789abcdef', 9);
file_put_contents("$cache/olscpa@a.test/.cacheman.shm", 'index');
$clock = 1_800_000_000;
// The purge helper chain as production runs it (CacheStorage::confinedHelper -> setpriv -> `cache purge-store`), with the
// privilege drop replaced by the current user: the fake runner records the argv, strips setpriv and its options and runs the
// product CLI under cPanel's PHP.
$helperRuns = [];
$helperRunner = new class ($helperRuns) implements CommandRunner {
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
$cacheWorker = OlsCpanel\Ols\Cache\CacheStorage::confinedHelper($helperRunner, dirname(__DIR__) . '/bin/ols-cpanel');
$context = new EngineContext(0, 'root', null, null, $state, "$state/profile.json", '/proc', $cache, $uid, $cacheWorker);
$app = new Application([new Command\CacheStatsCommand($context), new Command\CachePurgeCommand($context)]);
$rows = static function (array $result): array {
    $by = [];
    foreach ($result['stores'] as $row) {
        $by[$row['store']] = $row;
    }
    return $by;
};

[$code, $all] = run_cli($app, ['cache', 'stats']);
check($code === 0 && $all['scope'] === ['scope' => 'server', 'account' => null, 'domain' => null], 'stats of the whole server');
$by = $rows($all);
check(array_keys($by) === ['olscpa@a.test', 'olscpa@shop.a.test', 'olscpb@b.test', $longStore, 'olscpgone@gone.test', 'server'],
    'every store is listed, the server store and an orphan included');
check($by['olscpa@a.test']['public_entries'] === 2 && $by['olscpa@a.test']['public_bytes'] === 110
    && $by['olscpa@a.test']['private_entries'] === 1 && $by['olscpa@a.test']['private_bytes'] === 50
    && $by['olscpa@a.test']['entries'] === 3 && $by['olscpa@a.test']['bytes'] === 160, 'entry and byte counts (index file not counted)');
check($by['olscpa@a.test']['domains'] === ['a.test', 'www.a.test', 'parked.test'] && $by['olscpa@a.test']['vhost'] === 'a.test'
    && $by['olscpa@a.test']['enabled'] === true && $by['olscpb@b.test']['enabled'] === false, 'domains and cache state from the summary');
check($by[$longStore]['vhost'] === $long && $by[$longStore]['bytes'] === 5, 'a hashed store maps back to its vhost');
check($by['olscpgone@gone.test']['enabled'] === null && $by['server']['account'] === null, 'orphan and server stores are labelled');
check(!isset($by['olscpa@hy.test']) && $all['totals']['stores'] === 6 && $all['totals']['entries'] === 8 && $all['generation'] === 'r1',
    'hybrid vhosts have no store; totals and generation');

[$code, $acct] = run_cli($app, ['cache', 'stats', '--account=olscpa']);
check($code === 0 && array_keys($rows($acct)) === ['olscpa@a.test', 'olscpa@shop.a.test'], 'stats of one account');
[$code, $dom] = run_cli($app, ['cache', 'stats', '--domain=parked.test']);
check($code === 0 && array_keys($rows($dom)) === ['olscpa@a.test'] && $dom['scope']['domain'] === 'parked.test', 'an alias maps to its vhost store');
[$code, $none] = run_cli($app, ['cache', 'stats', '--account=olscpb']);
check(array_keys($rows($none)) === ['olscpb@b.test', $longStore], 'stats of another account');
foreach ([['--account=nobody'], ['--domain=unknown.test'], ['--domain=hy.test'], ['--domain=a.test', '--account=olscpb'],
          ['--account=Bad Name'], ['--domain=../x']] as $bad) {
    [$code, $result] = run_cli($app, ['cache', 'stats', ...$bad]);
    check($code === 1 && $result['result'] === 'refused', 'refused: ' . implode(' ', $bad));
}
[$code, $result] = run_cli($app, ['cache', 'stats', '--bogus=1']);
check($code === 64, 'unknown option is a usage error');
[$code, $result] = run_cli($app, ['cache', 'purge']);
check($code === 64, 'purge needs a scope');
[$code, $result] = run_cli($app, ['cache', 'purge', '--all', '--account=olscpa']);
check($code === 64, 'purge --all takes no other option');
[$code, $result] = run_cli($app, ['cache', 'purge', '--domain=a.test', '--account=olscpb']);
check($code === 1 && is_file("$cache/olscpa@a.test/0/1/2/0123456789abcdef"), 'a domain of another account is refused and nothing is removed');
$stranger = new Application([new Command\CacheStatsCommand(new EngineContext(1000, 'someone', null, null, $state, "$state/profile.json", '/proc', $cache, $uid))]);
[$code] = run_cli($stranger, ['cache', 'stats']);
check($code === 1, 'cache commands are root only');

[$code, $purged] = run_cli($app, ['cache', 'purge', '--domain=shop.a.test']);
$by = $rows($purged);
check($code === 0 && $purged['command'] === 'cache purge' && array_keys($by) === ['olscpa@shop.a.test'] && $by['olscpa@shop.a.test']['bytes'] === 7
    && $by['olscpa@shop.a.test']['last_purge'] !== null, 'purge of one domain reports what it removed');
check(!file_exists("$cache/olscpa@shop.a.test/3") && is_file("$cache/olscpa@a.test/0/1/2/0123456789abcdef")
    && is_file("$cache/olscpb@b.test/4/1/2/4123456789abcdef"), 'only that store was emptied');
[$code, $stats] = run_cli($app, ['cache', 'stats', '--account=olscpa']);
check($rows($stats)['olscpa@shop.a.test']['entries'] === 0 && $rows($stats)['olscpa@shop.a.test']['last_purge'] === $purged['purged_at'], 'last purge is recorded');
check(decoct(fileperms("$state/" . OlsCpanel\Ols\Cache\CacheManager::LEDGER) & 0777) === '600', 'ledger is root-only');

[$code, $purged] = run_cli($app, ['cache', 'purge', '--account=olscpa']);
check($code === 0 && $purged['totals']['entries'] === 3 && !is_file("$cache/olscpa@a.test/0/1/2/0123456789abcdef")
    && is_file("$cache/olscpa@a.test/.cacheman.shm") && is_file("$cache/olscpb@b.test/4/1/2/4123456789abcdef"), 'account purge keeps the index and other accounts');
[$code, $purged] = run_cli($app, ['cache', 'purge', '--all']);
check($code === 0 && $purged['scope']['scope'] === 'server' && $purged['totals']['entries'] === 4 && !is_file("$cache/server/7/1/2/7123456789abcdef")
    && !is_file("$cache/olscpb@b.test/4/1/2/4123456789abcdef"), 'server purge empties every store');
[$code, $stats] = run_cli($app, ['cache', 'stats']);
check($stats['totals']['entries'] === 0 && $stats['totals']['bytes'] === 0, 'nothing left after the server purge');

// ---- RV-31 items 12 and 15: honest purge counts and the confined helper ----------------------------------------------
check($helperRuns !== [] && $helperRuns[0][0] === OlsCpanel\Ols\Cache\CacheStorage::SETPRIV
    && array_slice($helperRuns[0], 1, 6) === ['--reuid=' . $uid, '--regid=' . getmygid(), '--clear-groups', '--no-new-privs', '--inh-caps=-all', '--bounding-set=-all']
    && in_array('purge-store', $helperRuns[0], true) && in_array("--root=$cache", $helperRuns[0], true),
    'a purge runs each store through setpriv as the store directory\'s owner, without groups, capabilities or new privileges');
$helperRuns = [];
[$code, $stats] = run_cli($app, ['cache', 'stats']);
check($helperRuns === [], 'statistics never start a helper');

foreach (['olscpb@b.test' => '4123456789abcdef', $longStore => '5123456789abcdef'] as $store => $hash) {
    mkdir("$cache/$store/$hash[0]/$hash[1]/$hash[2]", 0770, true);
    file_put_contents("$cache/$store/$hash[0]/$hash[1]/$hash[2]/$hash", str_repeat('y', 40));
}
if (getmyuid() !== 0) {
    // A removal that cannot happen (the directory is not writable): the entry stays, it is not counted as removed, the purge
    // is partial, exits 1 and the ledger is not advanced for that store.
    $ledgerBefore = json_decode((string) file_get_contents("$state/" . OlsCpanel\Ols\Cache\CacheManager::LEDGER), true);
    chmod("$cache/olscpb@b.test/4/1/2", 0500);
    [$code, $partial] = run_cli($app, ['cache', 'purge', '--account=olscpb']);
    $by = $rows($partial);
    check($code === 1 && $partial['result'] === 'partial' && $partial['purged_at'] === null && $partial['totals']['failed'] >= 1
        && $by['olscpb@b.test']['failed'] >= 1 && $by['olscpb@b.test']['entries'] === 0
        && is_file("$cache/olscpb@b.test/4/1/2/4123456789abcdef") && str_contains((string) $partial['error'], 'olscpb@b.test'),
        'a purge that cannot remove an entry is partial, counts nothing it did not remove and exits 1');
    check($by[$longStore]['failed'] === 0 && $by[$longStore]['entries'] === 1 && $by[$longStore]['last_purge'] !== null
        && $by['olscpb@b.test']['last_purge'] === ($ledgerBefore['olscpb@b.test'] ?? null),
        'the store that was emptied is recorded, the one that was not is not');
    $ledger = json_decode((string) file_get_contents("$state/" . OlsCpanel\Ols\Cache\CacheManager::LEDGER), true);
    check(isset($ledger[$longStore]) && $ledger[$longStore] > ($ledgerBefore[$longStore] ?? 0) - 1 && ($ledgerBefore['olscpb@b.test'] ?? null) === ($ledger['olscpb@b.test'] ?? null),
        'last_purge is recorded only on full success');
    [$code, $failedOnly] = run_cli($app, ['cache', 'purge', '--domain=b.test']);
    check($code === 1 && $failedOnly['result'] === 'failed' && $failedOnly['totals']['entries'] === 0 && $failedOnly['purged_at'] === null,
        'a purge that removes nothing is reported as failed');
    chmod("$cache/olscpb@b.test/4/1/2", 0770);
    [$code, $again] = run_cli($app, ['cache', 'purge', '--domain=b.test']);
    check($code === 0 && $again['result'] === 'purged' && $again['totals']['entries'] === 1 && $again['totals']['failed'] === 0
        && !is_file("$cache/olscpb@b.test/4/1/2/4123456789abcdef"), 'the next purge removes it and succeeds');
}

// The helper refuses to run as root, and takes only a valid store name.
$rootHelper = new Application([new Command\CachePurgeStoreCommand(new EngineContext(0, 'root', null, null, $state, "$state/profile.json", '/proc', $cache, $uid))]);
[$code, $result] = run_cli($rootHelper, ['cache', 'purge-store', "--root=$cache", '--store=olscpa@a.test']);
check($code === 1 && str_contains((string) $result['error'], 'never runs as root'), 'cache purge-store refuses to run as root');
$helper = new Application([new Command\CachePurgeStoreCommand(new EngineContext(1000, 'someone', null, null, $state, "$state/profile.json", '/proc', $cache, $uid))]);
foreach (['../x', 'olscpa@', 'a/b@c.test', 'SERVER'] as $bad) {
    [$code, $result] = run_cli($helper, ['cache', 'purge-store', "--root=$cache", "--store=$bad"]);
    check($code === 1 && $result['result'] === 'refused', "cache purge-store refuses the store name $bad");
}
[$code] = run_cli($helper, ['cache', 'purge-store', '--root=relative', '--store=server']);
check($code === 64, 'cache purge-store needs an absolute root');

// The privileged side never purges as root and never trusts a missing or malformed answer.
$never = new class implements CommandRunner {
    public int $runs = 0;

    public function run(string $name, array $argv, int $timeout): array
    {
        ++$this->runs;
        return ['exit_code' => 0, 'stdout' => 'not json', 'stderr' => ''];
    }
};
$helperFn = OlsCpanel\Ols\Cache\CacheStorage::confinedHelper($never, '/x/ols-cpanel');
$r = $helperFn($cache, 'server', 0, 0);
check($never->runs === 0 && $r['failed'] === 1 && str_contains($r['error'], 'not purged as root'), 'a root-owned store is never purged by the helper path');
$r = $helperFn($cache, 'server', 65534, 65534);
check($never->runs === 1 && $r['failed'] === 1 && str_contains($r['error'], 'failed'), 'an unusable helper answer is a failed store, never a success');

unlink("$state/active");
[$code, $result] = run_cli($app, ['cache', 'stats', '--domain=a.test']);
check($code === 1 && str_contains($result['error'], 'no active generation'), 'a domain needs the active generation');
[$code, $result] = run_cli($app, ['cache', 'stats', '--account=olscpa']);
check($code === 0 && $result['generation'] === null && $rows($result) !== [], 'stats of an account still work from the stores on disk without a generation');
tree_remove($base);

// ---- upgrade and php restart ----------------------------------------------------------------------------
/** A scripted host for `upgrade` and `php restart`. */
final class ScriptHost implements CommandRunner
{
    /** @var array<string,string> package => version, absent = not installed */
    public array $packages = ['ols-cpanel' => '1.2.0-1.el9.x86_64', 'ols-cpanel-openlitespeed' => '1.9.3-1.olscp8.el9.x86_64'];
    /** @var array<string,string> package => rpm -V output (nonzero exit when set) */
    public array $verify = [];
    /** @var array<string,bool> */
    public array $active = ['ols-cpanel-broker.service' => true, 'ols-cpanel-reconciler.service' => true];
    /** @var array<string,bool> */
    public array $enabled = ['ols-cpanel-broker.service' => true, 'ols-cpanel-reconciler.service' => true];
    /** @var array<string,true> units that do not come back */
    public array $broken = [];
    /** @var array<string,list<int>> user => lsphp pids */
    public array $lsphp = [];
    public bool $stubborn = false;
    /** @var array<int,int> pid => start time */
    public array $starts = [];
    /** @var \Closure(int,string):(bool|null)|null */
    public ?\Closure $onSignal = null;
    public bool $reloadFails = false;
    /** @var array<string,true> units whose `systemctl enable` fails */
    public array $enableFails = [];
    /** The executable link of the running OLS main process (`readlink /proc/<pid>/exe`). */
    public string $olsExe = '/usr/local/lsws/bin/openlitespeed';
    public int $olsReloads = 0;
    /** `manage_hooks list` output; empty: the product's hooks are not installed. */
    public string $hookList = '';
    /** @var list<list<string>> */
    public array $hookCalls = [];
    /** @var list<list<string>> */
    public array $calls = [];

    public function run(string $name, array $argv, int $timeout): array
    {
        $this->calls[] = $argv;
        if (str_starts_with($name, 'plugin-')) {
            return ['exit_code' => 0, 'stdout' => '', 'stderr' => ''];
        }
        $ok = static fn(string $out = ''): array => ['exit_code' => 0, 'stdout' => $out, 'stderr' => ''];
        $no = static fn(int $code = 1, string $out = ''): array => ['exit_code' => $code, 'stdout' => $out, 'stderr' => ''];
        $args = array_slice($argv, 1);
        switch ($argv[0]) {
            case '/usr/bin/rpm':
                if ($args[0] === '-q') {
                    $package = end($args);
                    return isset($this->packages[$package]) ? $ok($this->packages[$package]) : $no(1, "package $package is not installed");
                }
                return isset($this->verify[end($args)]) ? $no(1, $this->verify[end($args)]) : $ok();
            case '/usr/bin/systemctl':
                $unit = end($args);
                if ($args[0] === 'is-active') {
                    return $this->active[$unit] ?? false ? $ok("active\n") : $no(3, "inactive\n");
                }
                if ($args[0] === 'is-enabled') {
                    return $this->enabled[$unit] ?? false ? $ok("enabled\n") : $no(1, "disabled\n");
                }
                if ($args[0] === 'restart') {
                    $this->active[$unit] = !isset($this->broken[$unit]);
                    return $ok();
                }
                if ($args[0] === 'reload' && $unit === 'ols-cpanel.service') {
                    $this->olsReloads++;
                    $this->olsExe = '/usr/local/lsws/bin/openlitespeed';
                    return $ok();
                }
                if ($args[0] === 'daemon-reload') {
                    return $this->reloadFails ? $no(1, "Failed to reload daemon\n") : $ok();
                }
                if ($args[0] === 'enable') {
                    if (isset($this->enableFails[$unit])) {
                        return $no(1, "Failed to enable unit\n");
                    }
                    $this->enabled[$unit] = true;
                    return $ok();
                }
                if ($args[0] === 'disable') {
                    $this->enabled[$unit] = false;
                    return $ok();
                }
                if ($args[0] === 'stop') {
                    $this->active[$unit] = false;
                    return $ok();
                }
                throw new LogicException('unexpected systemctl ' . implode(' ', $args));
            case '/usr/bin/id':
                $users = ['olscpa' => 1001, 'root' => 0, 'postfix' => 89];
                return isset($users[$args[1]]) ? $ok($users[$args[1]] . "\n") : $no(1);
            case '/usr/local/cpanel/bin/manage_hooks':
                $this->hookCalls[] = $args;
                return $ok($args[0] === 'list' ? $this->hookList : '');
            case '/usr/bin/readlink':
                return $ok($this->olsExe . "\n");
            case '/usr/bin/cat':
                if (end($args) === '/run/ols-cpanel/lshttpd/lshttpd.pid') {
                    return $ok("4242\n");
                }
                return LsphpFake::handle($this->lsphp, $this->starts, $this->stubborn, $argv, $this->onSignal);
            case '/usr/bin/pgrep':
            case '/usr/bin/kill':
                return LsphpFake::handle($this->lsphp, $this->starts, $this->stubborn, $argv, $this->onSignal);
        }
        throw new LogicException('unexpected command ' . implode(' ', $argv));
    }
}

function world(ScriptHost $host): Environment
{
    $plugins = sys_get_temp_dir() . '/ols-plugins-' . bin2hex(random_bytes(4));
    foreach (['whm', 'cpanel'] as $tree) {
        @mkdir("$plugins/$tree", 0755, true);
        file_put_contents("$plugins/$tree/manifest.json", '{}');
        file_put_contents("$plugins/$tree/" . ($tree === 'whm' ? 'index.cgi' : 'index.live.php'), 'entry');
    }
    $state = sys_get_temp_dir() . '/ols-upgrade-state-' . bin2hex(random_bytes(4));
    @mkdir($state, 0700, true);
    return new Environment($host, $state, null, null, true, null, static function (float $s): void {
    }, pluginSource: $plugins, ea4Root: "$plugins/ea4");
}

/** @param list<string> $argv @return array{0:int, 1:?array<string,mixed>} */
function admin(ScriptHost $host, array $argv, bool $root = true): array
{
    $env = $root ? world($host) : new Environment($host, '/nonexistent', null, null, false);
    $app = new Application([new Command\UpgradeCommand(static fn(): Environment => $env), new Command\PhpRestartCommand(static fn(): Environment => $env)]);
    return run_cli($app, $argv);
}

$host = new ScriptHost();
[$code, $result] = admin($host, ['upgrade']);
check($code === 0 && $result['result'] === 'upgraded' && count($result['plugins'] ?? []) === 2 && $result['packages'][0] === ['package' => 'ols-cpanel', 'version' => '1.2.0-1.el9.x86_64', 'verified' => true]
    && $result['packages'][1]['package'] === 'ols-cpanel-openlitespeed', 'upgrade verifies both packages');
check(array_column($result['units'], 'unit') === ['ols-cpanel-broker.service', 'ols-cpanel-reconciler.service']
    && array_column($result['units'], 'action') === ['restarted', 'restarted'] && array_column($result['units'], 'active') === [true, true],
    'the broker is restarted before the reconciler and both come back');
$restarts = array_values(array_filter($host->calls, static fn(array $c): bool => ($c[1] ?? '') === 'restart'));
check(array_column($restarts, 2) === ['ols-cpanel-broker.service', 'ols-cpanel-reconciler.service'], 'restart order in the commands');
check(array_filter($host->calls, static fn(array $c): bool => in_array('ols-cpanel.service', $c, true) && ($c[1] ?? '') !== 'is-active') === []
    && $result['ols'] === 'not-running', 'a stopped OLS server is never touched');
check($result['php_environment_units'] === true && ($host->enabled['ols-cpanel-php.path'] ?? false) && ($host->enabled['ols-cpanel-php.timer'] ?? false)
    && ($host->enabled['ols-cpanel-php-ext.path'] ?? true) === false && $result['ea4_profile']['result'] === 'written'
    && str_ends_with($result['ea4_profile']['path'], '/custom/ols-cpanel-recommended.json'),
    'upgrade enables the PHP environment units, retires the old watcher and refreshes the recommended EA4 profile');
check($result['hybrid_trust_timer'] === true && ($host->enabled['ols-cpanel-hybrid-trust.timer'] ?? false),
    'upgrade enables the hybrid trust timer on a prepared host');
check($result['cache_clean_timer'] === true && ($host->enabled['ols-cpanel-cache-clean.timer'] ?? false),
    'upgrade enables the hourly LSCache cleanup timer on hosts prepared before it existed');
check($result['operations_timers'] === ['ols-cpanel-notify.timer' => true, 'ols-cpanel-schedule.timer' => true]
    && ($host->enabled['ols-cpanel-notify.timer'] ?? false) && ($host->enabled['ols-cpanel-schedule.timer'] ?? false),
    'upgrade enables the notification and maintenance-window timers on hosts prepared before they existed (FV-07)');
check($result['account_state_timer'] === true && ($host->enabled['ols-cpanel-objcache.timer'] ?? false),
    'upgrade enables account-state cleanup even without explicit object cache accounts');

// Automatic upgrade after a package transaction: pending until an upgrade recorded the installed versions.
$host = new ScriptHost();
$env = world($host);
check(Upgrade::pending($env), 'a prepared host without an upgrade record has an upgrade pending');
(new Upgrade($env))->run();
check(!Upgrade::pending($env), 'after the upgrade the installed versions are recorded');
$host->packages['ols-cpanel-openlitespeed'] = '1.9.3-1.olscp9.el9.x86_64';
check(Upgrade::pending($env), 'a changed OLS package makes the upgrade pending again');
$host->enabled['ols-cpanel-broker.service'] = false;
check(!Upgrade::pending($env), 'a host that was never prepared has nothing pending');
// A failing timer or hook registration leaves the upgrade pending, so a later pass retries it (review 8, finding 10).
$host = new ScriptHost();
$host->enableFails['ols-cpanel-cache-clean.timer'] = true;
$env = world($host);
$failedRun = (new Upgrade($env))->run();
check($failedRun['result'] === 'failed' && $failedRun['incomplete'] === ['cache_clean_timer'] && !is_file($env->state . '/' . Upgrade::RECORD)
    && Upgrade::pending($env), 'a timer that could not be enabled leaves the upgrade pending and unrecorded');
$host->enableFails = [];
$retry = (new Upgrade($env))->run();
check($retry['result'] === 'upgraded' && $retry['incomplete'] === [] && is_file($env->state . '/' . Upgrade::RECORD) && !Upgrade::pending($env),
    'the retry records the versions once everything succeeded');
$host = new ScriptHost();
$host->hookList = "Whostmgr::Accounts::Remove\n";
$host->enabled['ols-cpanel-php.path'] = false;
$host->enableFails['ols-cpanel-php.path'] = true;
$env = world($host);
$phpFail = (new Upgrade($env))->run();
check($phpFail['result'] === 'failed' && in_array('php_environment_units', $phpFail['incomplete'], true) && Upgrade::pending($env),
    'a PHP environment unit that could not be enabled leaves the upgrade pending');
// A running OLS keeps its binary unless the package replaced it; a replaced one is reloaded gracefully.
$host = new ScriptHost();
$host->active['ols-cpanel.service'] = true;
[$code, $result] = admin($host, ['upgrade']);
check($code === 0 && $result['ols'] === 'current' && $host->olsReloads === 0, 'a current OLS binary is not reloaded');
$host = new ScriptHost();
$host->active['ols-cpanel.service'] = true;
$host->olsExe = '/usr/local/lsws/bin/openlitespeed (deleted)';
[$code, $result] = admin($host, ['upgrade']);
check($code === 0 && $result['ols'] === 'reloaded' && $host->olsReloads === 1, 'a replaced OLS binary is reloaded gracefully');
check($result['hooks'] === 'not-installed' && array_filter($host->hookCalls, static fn(array $c): bool => $c[0] !== 'list') === [],
    'without the product hooks (never cut over) upgrade registers none');

$host = new ScriptHost();
$host->active['ols-cpanel-reconciler.service'] = false;
$host->enabled['ols-cpanel-reconciler.service'] = false;
[$code, $result] = admin($host, ['upgrade']);
check($code === 0 && $result['units'][1]['action'] === 'skipped' && $result['units'][0]['action'] === 'restarted', 'a unit that is neither enabled nor active is skipped');
$host = new ScriptHost();
$host->active['ols-cpanel-reconciler.service'] = false;
[$code, $result] = admin($host, ['upgrade']);
check($result['units'][1]['action'] === 'restarted' && $result['units'][1]['was_active'] === false, 'an enabled but stopped unit is started by the restart');

$host = new ScriptHost();
$host->verify['ols-cpanel'] = 'S.5....T.  /usr/local/ols-cpanel/lib/x.php';
[$code, $result] = admin($host, ['upgrade']);
check($code === 1 && $result['result'] === 'refused' && str_contains($result['error'], 'differ from the package')
    && array_filter($host->calls, static fn(array $c): bool => ($c[1] ?? '') === 'restart') === [], 'a payload that does not verify refuses before any restart');
$host = new ScriptHost();
unset($host->packages['ols-cpanel-openlitespeed']);
[$code, $result] = admin($host, ['upgrade']);
check($code === 1 && str_contains($result['error'], 'ols-cpanel-openlitespeed is not installed'), 'a missing package refuses');
$host = new ScriptHost();
$host->broken['ols-cpanel-broker.service'] = true;
[$code, $result] = admin($host, ['upgrade']);
check($code === 1 && $result['result'] === 'failed' && $result['units'][0]['active'] === false, 'a unit that does not come back fails the upgrade');
// RV-31 item 13: daemon-reload runs after the verification and before any enable or restart, and is checked.
$host = new ScriptHost();
[$code, $result] = admin($host, ['upgrade']);
$verbs = array_map(static fn(array $c): string => ($c[0] === '/usr/bin/rpm' ? 'rpm-' : '') . ($c[1] ?? ''), $host->calls);
$reload = array_search('daemon-reload', $verbs, true);
$lastVerify = max(array_keys(array_filter($verbs, static fn(string $v): bool => $v === 'rpm--V')));
$firstChange = min(array_keys(array_filter($verbs, static fn(string $v): bool => in_array($v, ['restart', 'enable', 'disable'], true))));
check($code === 0 && $reload !== false && $reload > $lastVerify && $reload < $firstChange && count(array_keys($verbs, 'daemon-reload', true)) === 1,
    'upgrade runs one daemon-reload after verifying the packages and before enabling or restarting anything');
$host = new ScriptHost();
$host->reloadFails = true;
[$code, $result] = admin($host, ['upgrade']);
check($code === 1 && $result['result'] === 'refused' && str_contains($result['error'], 'daemon-reload')
    && array_filter($host->calls, static fn(array $c): bool => in_array($c[1] ?? '', ['restart', 'enable', 'disable'], true)) === [],
    'a failing daemon-reload stops the upgrade before any restart');
[$code] = admin(new ScriptHost(), ['upgrade'], false);
check($code === 1, 'upgrade is root only');
[$code] = admin(new ScriptHost(), ['upgrade', '--force']);
check($code === 64, 'upgrade takes no option');

$host = new ScriptHost();
$host->lsphp = ['olscpa' => [11, 12], 'olscpb' => [13]];
[$code, $result] = admin($host, ['php', 'restart', '--account=olscpa']);
check($code === 0 && $result['result'] === 'restarted' && $result['found'] === 2 && $result['killed'] === 2 && $result['killed_with_sigkill'] === 0
    && $host->lsphp['olscpb'] === [13], 'php restart of one account ends only its lsphp processes');
$pgrep = array_values(array_filter($host->calls, static fn(array $c): bool => $c[0] === '/usr/bin/pgrep'))[0];
check($pgrep === ['/usr/bin/pgrep', '-u', 'olscpa', '-x', 'lsphp'], 'pgrep matches by user and exact process name');
$kills = array_values(array_filter($host->calls, static fn(array $c): bool => $c[0] === '/usr/bin/kill'));
check($kills === [['/usr/bin/kill', '-TERM', '--', '11'], ['/usr/bin/kill', '-TERM', '--', '12']], 'SIGTERM goes to each pid of the original cohort, one fixed argv each');
check(array_filter($host->calls, static fn(array $c): bool => $c[0] === '/usr/bin/pkill') === [], 'no pkill by name any more');
$host = new ScriptHost();
$host->lsphp = ['olscpa' => [11], 'olscpb' => [13]];
[$code, $result] = admin($host, ['php', 'restart', '--all']);
check($code === 0 && $result['scope'] === 'all' && $result['found'] === 2 && $host->lsphp === ['olscpa' => [], 'olscpb' => []], 'php restart --all');
$host = new ScriptHost();
$host->lsphp = ['olscpa' => [11]];
$host->stubborn = true;
[$code, $result] = admin($host, ['php', 'restart', '--account=olscpa']);
check($code === 0 && $result['killed_with_sigkill'] === 1, 'a process that ignores SIGTERM is killed');
$host = new ScriptHost();
[$code, $result] = admin($host, ['php', 'restart', '--account=olscpa']);
check($code === 0 && $result['found'] === 0 && array_filter($host->calls, static fn(array $c): bool => $c[0] === '/usr/bin/kill') === [], 'nothing to end');
// RV-31 item 9: only the original cohort (pid + start time) is signalled and waited for.
$host = new ScriptHost();
$host->lsphp = ['olscpa' => [11, 12]];
$host->onSignal = static function (int $pid, string $signal) use ($host): ?bool {
    if ($signal === 'TERM' && $pid === 11) {
        $host->lsphp['olscpa'][] = 99;  // OLS starts a replacement while the restart runs
    }
    return null;
};
[$code, $result] = admin($host, ['php', 'restart', '--account=olscpa']);
check($code === 0 && $result['result'] === 'restarted' && $result['found'] === 2 && $result['remaining'] === 0 && $result['killed_with_sigkill'] === 0
    && $host->lsphp['olscpa'] === [99], 'a replacement process started after the snapshot is neither waited for nor signalled; the restart succeeds');
check(array_filter($host->calls, static fn(array $c): bool => $c[0] === '/usr/bin/kill' && in_array('99', $c, true)) === [], 'no signal ever reaches the new process');
$host = new ScriptHost();
$host->lsphp = ['olscpa' => [11]];
$host->stubborn = true;
$host->onSignal = static function (int $pid, string $signal) use ($host): ?bool {
    if ($signal === 'TERM') {
        $host->lsphp['olscpa'][] = 77;  // a new worker appears while the old one ignores SIGTERM
    }
    return null;
};
[$code, $result] = admin($host, ['php', 'restart', '--account=olscpa']);
check($result['killed_with_sigkill'] === 1 && $result['result'] === 'restarted' && $host->lsphp['olscpa'] === [77]
    && array_values(array_filter($host->calls, static fn(array $c): bool => $c[0] === '/usr/bin/kill' && $c[1] === '-KILL')) === [['/usr/bin/kill', '-KILL', '--', '11']],
    'SIGKILL goes only to the surviving member of the original cohort, never to a process started after the snapshot');
// A pid reused by another process (different start time) is not ours: it is not signalled and counts as gone.
$host = new ScriptHost();
$host->lsphp = ['olscpa' => [11]];
$host->stubborn = true;
$host->onSignal = static function (int $pid, string $signal) use ($host): ?bool {
    if ($signal === 'TERM') {
        $host->starts[11] = 5555;  // the old process exited and the pid now belongs to a younger one
    }
    return null;
};
[$code, $result] = admin($host, ['php', 'restart', '--account=olscpa']);
check($result['result'] === 'restarted' && $result['killed_with_sigkill'] === 0 && $result['remaining'] === 0
    && array_filter($host->calls, static fn(array $c): bool => $c[0] === '/usr/bin/kill' && $c[1] === '-KILL') === [], 'a reused pid (other start time) is never killed');
// A member that survives SIGKILL is reported as failed.
$host = new ScriptHost();
$host->lsphp = ['olscpa' => [11]];
$host->stubborn = true;
$host->onSignal = static function (int $pid, string $signal) use ($host): ?bool {
    return $signal === 'KILL';  // unkillable (uninterruptible sleep)
};
[$code, $result] = admin($host, ['php', 'restart', '--account=olscpa']);
check($code === 1 && $result['result'] === 'failed' && $result['remaining'] === 1, 'an original process that survives SIGKILL is a failed restart');
foreach (['root', 'postfix', 'nobody', 'Bad;Name', '../x'] as $account) {
    $host = new ScriptHost();
    [$code, $result] = admin($host, ['php', 'restart', "--account=$account"]);
    check($code === 1 && array_filter($host->calls, static fn(array $c): bool => $c[0] === '/usr/bin/kill') === [], "php restart refuses account $account");
}
foreach ([[], ['--all', '--account=olscpa']] as $bad) {
    [$code] = admin(new ScriptHost(), ['php', 'restart', ...$bad]);
    check($code === 64, 'php restart needs exactly one of --all or --account');
}
[$code] = admin(new ScriptHost(), ['php', 'restart', '--all'], false);
check($code === 1, 'php restart is root only');

echo "$count checks passed\n";
