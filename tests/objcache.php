<?php
declare(strict_types=1);

// Object cache (FV-09) against a scripted fake host: configuration and drop-in texts, enable, disable, flush,
// status, packages, refusals (accounts, memory, paths), lifecycle by reconcile (suspend, unsuspend, removal,
// package changes), the wp-cli argv, the hook trigger and the CLI.
require dirname(__DIR__) . '/src/bootstrap.php';

use OlsCpanel\Cli\Application;
use OlsCpanel\Cli\Command\ObjectCacheCommand;
use OlsCpanel\Cli\EngineContext;
use OlsCpanel\Cli\Output;
use OlsCpanel\Cli\Refused;
use OlsCpanel\Events\HookEntry;
use OlsCpanel\Infrastructure\Process\CommandRunner;
use OlsCpanel\ObjectCache\ObjectCacheManager;
use OlsCpanel\ObjectCache\ObjectCacheState;
use OlsCpanel\ObjectCache\ValkeyConfig;

$count = 0;
function check(bool $condition, string $name): void
{
    global $count;
    if (!$condition) {
        throw new RuntimeException('FAIL: ' . $name);
    }
    ++$count;
}

function refused(callable $call, string $contains, string $name): void
{
    try {
        $call();
    } catch (Refused $error) {
        check(str_contains($error->getMessage(), $contains), $name . ' (' . $error->getMessage() . ')');
        return;
    }
    check(false, $name . ': expected a refusal');
}

/** A cPanel server in memory; every command is answered from (and changes) this state. */
class FakeServer implements CommandRunner
{
    /** @var array<string,array{uid:int, home:string, plan:string}> */
    public array $users = [];
    /** @var array<string,true> */
    public array $suspended = [];
    /** @var array<string,string> account => active state */
    public array $units = [];
    public bool $timerEnabled = false;
    /** @var list<array{0:string, 1:list<string>}> */
    public array $calls = [];
    /** @var array<string,true> directories that exist in homes */
    public array $sockets = [];
    public bool $startFails = false;
    public bool $stopFails = false;
    public bool $enableFails = false;
    /** the suspension marker directory exists but cannot be listed */
    public bool $suspendedListFails = false;
    /** the marker directory does not exist at all (an authoritative empty set) */
    public bool $suspendedDirMissing = false;
    /** `test -e` on a marker fails with an error exit code */
    public bool $suspendedTestErrors = false;
    /** /var/cpanel/users is readable (so an empty grep result is authoritative) */
    public bool $usersDirReadable = false;
    public bool $redis = true;
    public bool $wpActive = true;
    /** LiteSpeed Cache's plugin directory exists (the cheap look). */
    public bool $lscwpInstalled = true;
    /** site path => the site's wp-content files the cheap look reads (object-cache.php, .litespeed_conf.php) */
    public array $siteFiles = [];
    public int $wpRuns = 0;
    public bool $wpConfig = true;
    public string $info = "used_memory:1048576\r\nmaxmemory:67108864\r\nconnected_clients:2\r\nuptime_in_seconds:99\r\nevicted_keys:5\r\nkeyspace_hits:30\r\nkeyspace_misses:10\r\ndb0:keys=7,expires=0\r\n";
    public string $versions = '';
    /** /etc/userdatadomains */
    public string $userdata = '';
    /** @var array<string,list<string>> account => wp-config.php files that exist (any depth; find filters by root) */
    public array $wpFiles = [];
    /** @var array<string,true> install directories whose LiteSpeed Cache plugin is not active */
    public array $wpInactive = [];
    /** @var array<string,array<string,string>> install directory => LiteSpeed option => value */
    public array $wpOptions = [];
    /** @var array<string,true> install directories where wp-cli fails with an error */
    public array $wpBroken = [];
    public bool $wpSetFails = false;
    /** @var array<string,true> install directories whose wp-config.php was removed */
    public array $wpMissing = [];

    public function add(string $user, int $uid, string $plan = 'default', ?string $home = null): void
    {
        $this->users[$user] = ['uid' => $uid, 'home' => $home ?? "/home/$user", 'plan' => $plan];
    }

    /** @return list<list<string>> argv of the calls whose first element after runuser matches */
    public function argvs(string $executable): array
    {
        return array_values(array_filter(array_column($this->calls, 1), static fn(array $a): bool => in_array($executable, $a, true)));
    }

    public function systemctl(string $verb): array
    {
        return array_values(array_filter(array_column($this->calls, 1),
            static fn(array $a): bool => $a[0] === '/usr/bin/systemctl' && $a[1] === $verb));
    }

    public function run(string $name, array $argv, int $timeout): array
    {
        $this->calls[] = [$name, $argv];
        $ok = static fn(string $out = ''): array => ['exit_code' => 0, 'stdout' => $out, 'stderr' => ''];
        $no = static fn(int $code = 1, string $err = ''): array => ['exit_code' => $code, 'stdout' => '', 'stderr' => $err];
        $cmd = $argv[0];
        $a = array_slice($argv, 1);
        switch ($cmd) {
            case '/usr/bin/test':
                if ($a[0] === '-e' && str_starts_with($a[1], '/var/cpanel/users/')) {
                    return isset($this->users[basename($a[1])]) ? $ok() : $no();
                }
                if ($a[0] === '-e' && str_starts_with($a[1], '/var/cpanel/suspended/')) {
                    return $this->suspendedTestErrors ? $no(2, 'Permission denied') : (isset($this->suspended[basename($a[1])]) ? $ok() : $no());
                }
                if ($a[0] === '-e' && $a[1] === '/var/cpanel/suspended') {
                    return $this->suspendedDirMissing ? $no() : $ok();
                }
                if ($a[0] === '-d' && $a[1] === '/var/cpanel/users') {
                    return $this->usersDirReadable ? $ok() : $no();
                }
                if ($a[0] === '-x' && $a[1] === ValkeyConfig::SERVER) {
                    return $ok();
                }
                return $no();
            case '/usr/bin/cat':
                return $a[0] === '/etc/userdatadomains' ? $ok($this->userdata) : $no(1, 'cat: ' . $a[0]);
            case '/usr/bin/getent':
                $lines = [];
                foreach ($this->users as $user => $u) {
                    if (count($a) < 2 || $a[1] === $user) {
                        $lines[] = "$user:x:{$u['uid']}:{$u['uid']}::{$u['home']}:/bin/bash";
                    }
                }
                return $lines === [] ? $no(2) : $ok(implode("\n", $lines) . "\n");
            case '/usr/bin/grep':
                if ($a[0] === '-rH') {
                    $lines = [];
                    foreach ($this->users as $user => $u) {
                        $lines[] = "/var/cpanel/users/$user:PLAN={$u['plan']}";
                    }
                    return $lines === [] ? $no() : $ok(implode("\n", $lines) . "\n");
                }
                $user = basename($a[3]);
                return isset($this->users[$user]) ? $ok("PLAN={$this->users[$user]['plan']}\n") : $no();
            case '/usr/bin/ls':
                if ($a[2] === '/var/cpanel/users') {
                    return $this->usersDirReadable ? $ok() : $no(2, 'Permission denied');
                }
                if ($this->suspendedListFails || $this->suspendedDirMissing) {
                    return $no(2, 'ls: cannot access');
                }
                return $ok(implode("\n", array_keys($this->suspended)) . "\n");
            case '/usr/bin/systemctl':
                return $this->systemctlCall($a, $ok, $no);
            case '/usr/sbin/runuser':
                return $this->asUser($a[1], array_slice($a, 3), $ok, $no);
        }
        throw new RuntimeException("unexpected command $cmd");
    }

    private function unitUser(string $unit): string
    {
        preg_match('/^ols-cpanel-objcache@(.+)\.service$/', $unit, $m);
        return $m[1];
    }

    private function systemctlCall(array $a, \Closure $ok, \Closure $no): array
    {
        switch ($a[0]) {
            case 'list-units':
                $lines = [];
                foreach ($this->units as $user => $state) {
                    $lines[] = "ols-cpanel-objcache@$user.service loaded $state running OLS-cPanel object cache";
                }
                return $ok(implode("\n", $lines) . "\n");
            case 'is-active':
                return ($this->units[$this->unitUser($a[2])] ?? '') === 'active' ? $ok() : $no(3);
            case 'restart':
                if ($this->startFails) {
                    return $no(1, 'Job failed');
                }
                $this->units[$this->unitUser($a[1])] = 'active';
                return $ok();
            case 'stop':
                if ($this->stopFails) {
                    return $no(1, 'Job for stop failed');
                }
                unset($this->units[$this->unitUser($a[1])]);
                return $ok();
            case 'is-enabled':
                return $this->timerEnabled ? $ok() : $no();
            case 'enable':
                if ($this->enableFails) {
                    return $no(1, 'Failed to enable unit');
                }
                $this->timerEnabled = true;
                return $ok();
            default:
                return $ok();
        }
    }

    private function asUser(string $user, array $a, \Closure $ok, \Closure $no): array
    {
        $home = $this->users[$user]['home'] ?? null;
        $cmd = $a[0];
        if ($cmd === '/usr/bin/test') {
            if ($a[1] === '-L') {
                return $no();
            }
            if ($a[1] === '-f') {
                return str_ends_with($a[2], '/wp-config.php') && $this->wpConfig && !isset($this->wpMissing[dirname($a[2])]) ? $ok() : $no();
            }
            if ($a[1] === '-d' && str_ends_with($a[2], '/wp-content/plugins/litespeed-cache')) {
                return $this->lscwpInstalled ? $ok() : $no();
            }
            if ($a[1] === '-e' && str_contains($a[2], '/wp-content/')) {
                [$site, $name] = explode('/wp-content/', $a[2], 2);
                return isset($this->siteFiles[$site]["wp-content/$name"]) || ($name === 'plugins/litespeed-cache' && $this->lscwpInstalled) ? $ok() : $no();
            }
            return str_starts_with($a[2], '/opt/cpanel/ea-php') ? $ok() : $no();
        }
        if ($cmd === '/usr/bin/install') {
            $this->sockets[$a[4]] = true;
            return $ok();
        }
        if ($cmd === '/usr/bin/rm') {
            unset($this->sockets[$a[3]]);
            return $ok();
        }
        if ($cmd === ValkeyConfig::CLI) {
            if ($a[3] === 'FLUSHALL') {
                return $ok("OK\n");
            }
            return $ok($this->info);
        }
        if (str_starts_with($cmd, '/opt/cpanel/ea-php') && $a[1] === '-r') {
            return $this->redis ? $ok() : $no(3);
        }
        if ($cmd === '/usr/bin/find') {
            $root = $a[2];
            $lines = [];
            foreach ($this->wpFiles[$user] ?? [] as $file) {
                if (str_starts_with($file, "$root/") && substr_count(substr($file, strlen($root) + 1), '/') <= 1) {
                    $lines[] = $file;
                }
            }
            return $ok($lines === [] ? '' : implode("\n", $lines) . "\n");
        }
        if ($cmd === '/usr/bin/head') {
            [$site, $name] = explode('/wp-content/', end($a), 2);
            $text = $this->siteFiles[$site]["wp-content/$name"] ?? null;
            return $text === null ? $no(1, 'No such file or directory') : $ok($text);
        }
        if ($cmd === '/usr/bin/env') {
            $this->wpRuns++;
            $path = '';
            $args = [];
            foreach ($a as $k => $v) {
                if (str_starts_with($v, '--path=')) {
                    $path = substr($v, 7);
                    $args = array_values(array_diff(array_slice($a, $k + 1), ['--skip-themes']));
                }
            }
            if (isset($this->wpBroken[$path])) {
                return $no(1, 'Error: Error establishing a database connection.');
            }
            if ($args[0] === 'plugin') {
                return $this->wpActive && !isset($this->wpInactive[$path]) ? $ok() : $no();
            }
            if ($args[0] === 'litespeed-option' && $args[1] === 'get') {
                return $ok(($this->wpOptions[$path][$args[2]] ?? ($args[2] === 'object' ? 'false' : '')) . "\n");
            }
            if ($args[0] === 'litespeed-option' && $args[1] === 'set') {
                if ($this->wpSetFails) {
                    return $no(1, 'Error: could not save');
                }
                $this->wpOptions[$path][$args[2]] = $args[3];
            }
            return $ok("Success\n");
        }
        throw new RuntimeException("unexpected command as $user: $cmd for $home");
    }
}

class FakeWhm extends FakeServer
{
    public function run(string $name, array $argv, int $timeout): array
    {
        if ($argv[0] === ObjectCacheManager::WHMAPI) {
            $this->calls[] = [$name, $argv];
            return ['exit_code' => 0, 'stdout' => $this->versions, 'stderr' => ''];
        }
        return parent::run($name, $argv, $timeout);
    }
}

$root = sys_get_temp_dir() . '/objcache-test-' . bin2hex(random_bytes(6));
mkdir($root, 0700);
register_shutdown_function(static function () use ($root): void {
    exec('rm -rf ' . escapeshellarg($root));
});
$clock = new class {
    public int $t = 1_800_000_000;
};
$fresh = static function (string $name) use ($root, $clock): array {
    $dir = "$root/$name";
    mkdir($dir, 0755);
    mkdir("$dir/units");
    $server = new FakeWhm();
    $server->add('olscpa', 1001, 'gold');
    $server->add('olscpb', 1002, 'default', '/home2/olscpb');
    $server->add('daemon', 2, 'default', '/sbin');
    $server->versions = json_encode(['data' => ['versions' => [
        ['account' => 'olscpa', 'main_domain' => 0, 'version' => 'ea-php74'],
        ['account' => 'olscpa', 'main_domain' => 1, 'version' => 'ea-php83'],
        ['account' => 'olscpb', 'main_domain' => 1, 'version' => 'ea-php82']]]]);
    $manager = new ObjectCacheManager($server, "$dir/objcache.json", "$dir/conf", "$dir/units", "$dir/lock", null, static fn(): int => $clock->t);
    return [$server, $manager, $dir];
};

// --- Configuration text (exact) -------------------------------------------------------------------------------
$expected = <<<'TEXT'
# OLS-cPanel object cache for olscpa. Generated by ols-cpanel; changes are overwritten.
port 0
unixsocket /home/olscpa/.ols-objcache/valkey.sock
unixsocketperm 600
protected-mode yes
daemonize no
dir /home/olscpa/.ols-objcache
logfile ""
loglevel notice
databases 16
maxclients 256
timeout 300
maxmemory 64mb
maxmemory-policy allkeys-lru
save ""
appendonly no
stop-writes-on-bgsave-error no
enable-debug-command no
enable-module-command no
enable-protected-configs no
rename-command CONFIG ""
rename-command DEBUG ""
rename-command MODULE ""
rename-command REPLICAOF ""
rename-command SLAVEOF ""
rename-command FAILOVER ""
rename-command SAVE ""
rename-command BGSAVE ""
rename-command BGREWRITEAOF ""
rename-command SYNC ""
rename-command PSYNC ""

TEXT;
check(ValkeyConfig::render('olscpa', '/home/olscpa', 64) === rtrim($expected, "\n") . "\n", 'configuration text is exact');
check(!str_contains($expected, 'port 6379') && !str_contains($expected, 'bind '), 'no TCP listener in the configuration');
check(ValkeyConfig::dropIn('/home2/olscpb', 128) === "# OLS-cPanel object cache: per-account settings. Generated by ols-cpanel; changes are overwritten.\n"
    . "[Service]\nReadWritePaths=/home2/olscpb/.ols-objcache\nMemoryMax=192M\n", 'drop-in text is exact');
check(ValkeyConfig::memoryMax(64) === 112 && ValkeyConfig::memoryMax(16) === 52, 'MemoryMax above maxmemory');
check(ValkeyConfig::unit('olscpa') === 'ols-cpanel-objcache@olscpa.service', 'unit name');
check(ValkeyConfig::parseMemory('64') === 64 && ValkeyConfig::parseMemory('15') === null && ValkeyConfig::parseMemory('8193') === null
    && ValkeyConfig::parseMemory('064') === null && ValkeyConfig::parseMemory('-5') === null && ValkeyConfig::parseMemory('64mb') === null
    && ValkeyConfig::parseMemory('') === null && ValkeyConfig::parseMemory('16') === 16 && ValkeyConfig::parseMemory('8192') === 8192, 'memory parsing');
foreach (['', 'Root', 'root', 'a b', '-a', 'a/b', 'a..b', str_repeat('a', 33), "a\n", '.a'] as $bad) {
    check(!ValkeyConfig::validUser($bad), 'account name refused: ' . json_encode($bad));
}
check(ValkeyConfig::validUser('olscpa') && ValkeyConfig::validUser('a.b-c_d9'), 'account names accepted');

// --- enable -------------------------------------------------------------------------------------------------
[$server, $manager, $dir] = $fresh('enable');
$result = $manager->enable('olscpa', null);
check($result['result'] === 'enabled' && $result['memory_mb'] === 64 && $result['socket'] === '/home/olscpa/.ols-objcache/valkey.sock'
    && $result['active'] === true && $result['timer'] === true && $server->timerEnabled, 'enable result');
check(file_get_contents("$dir/conf/olscpa/valkey.conf") === ValkeyConfig::render('olscpa', '/home/olscpa', 64), 'configuration written');
check(file_get_contents("$dir/units/ols-cpanel-objcache@olscpa.service.d/50-account.conf") === ValkeyConfig::dropIn('/home/olscpa', 64), 'drop-in written');
check((fileperms("$dir/conf/olscpa/valkey.conf") & 0777) === 0644 && (fileperms("$dir/conf/olscpa") & 0777) === 0755
    && (fileperms("$dir/conf") & 0777) === 0755, 'configuration modes (files 0644, directories 0755)');
check(($server->units['olscpa'] ?? '') === 'active' && count($server->systemctl('daemon-reload')) === 1, 'started after one daemon-reload');
check(isset($server->sockets['/home/olscpa/.ols-objcache']), 'socket directory created as the account');
$install = array_values(array_filter($server->calls, static fn(array $c): bool => in_array('/usr/bin/install', $c[1], true)))[0][1];
check($install === ['/usr/sbin/runuser', '-u', 'olscpa', '--', '/usr/bin/install', '-d', '-m', '0700', '/home/olscpa/.ols-objcache'],
    'socket directory argv: install -d -m 0700 through runuser');
foreach ($server->calls as [$name, $argv]) {
    check(array_is_list($argv) && str_starts_with($argv[0], '/') && str_starts_with($name, 'objcache-'), 'fixed absolute argv: ' . $argv[0]);
}
$state = json_decode(file_get_contents("$dir/objcache.json"), true);
check($state === ['schema_version' => 1, 'defaults' => ['memory_mb' => 64], 'packages' => [],
    'accounts' => ['olscpa' => ['enabled' => true, 'memory_mb' => 64]]], 'state file content');
check((fileperms("$dir/objcache.json") & 0777) === 0644 && glob("$dir/objcache.json.tmp-*") === [], 'state written atomically');
$again = count($server->calls);
$manager->enable('olscpa', null);
check($server->systemctl('restart') !== [] && count($server->systemctl('restart')) === 1, 'enable twice does not restart an unchanged running instance');
$result = $manager->enable('olscpa', '128');
check($result['memory_mb'] === 128 && str_contains(file_get_contents("$dir/conf/olscpa/valkey.conf"), 'maxmemory 128mb')
    && str_contains(file_get_contents("$dir/units/ols-cpanel-objcache@olscpa.service.d/50-account.conf"), 'MemoryMax=192M')
    && count($server->systemctl('restart')) === 2, 'new limit rewrites both files and restarts');
$manager->enable('olscpa', null);
check(json_decode(file_get_contents("$dir/objcache.json"), true)['accounts']['olscpa']['memory_mb'] === 128, 'enable without --memory keeps the account limit');
$result = $manager->enable('olscpb', '32');
check(str_contains(file_get_contents("$dir/conf/olscpb/valkey.conf"), 'unixsocket /home2/olscpb/.ols-objcache/valkey.sock')
    && isset($server->sockets['/home2/olscpb/.ols-objcache']), 'home on another mount (/home2)');

// --- refusals ---------------------------------------------------------------------------------------------
foreach (['', 'root', 'Bad Name', 'nosuch', 'daemon', 'a/b'] as $bad) {
    refused(static fn() => $manager->enable($bad, null), $bad === 'nosuch' ? 'not a cPanel account' : ($bad === 'daemon' ? 'regular account' : 'invalid account'),
        'enable refuses ' . json_encode($bad));
}
foreach (['15', '8193', 'lots', '1e3', '0', '-1', ' 64'] as $bad) {
    refused(static fn() => $manager->enable('olscpa', $bad), 'memory must be', 'enable refuses memory ' . json_encode($bad));
}
$server->add('olscpc', 1003, 'default', '/data/olscpc');
refused(static fn() => $manager->enable('olscpc', null), 'home directory', 'home outside /home<suffix> refused');
$server->add('olscpd', 1004, 'default', '/home/someoneelse');
refused(static fn() => $manager->enable('olscpd', null), 'home directory', 'home of another name refused');
$server->add(str_repeat('a', 32), 1005, 'default', '/home' . str_repeat('x', 60) . '/' . str_repeat('a', 32));
refused(static fn() => $manager->enable(str_repeat('a', 32), null), 'home directory', 'too long a socket path refused');
refused(static fn() => $manager->disable('Bad Name'), 'invalid account', 'disable refuses an invalid name');
$server->add('olscpf', 1007);
refused(static fn() => $manager->flush('olscpf'), 'not enabled', 'flush refuses an account without a cache');
$server->startFails = true;
$server->users['olscpe'] = ['uid' => 1006, 'home' => '/home/olscpe', 'plan' => 'default'];
refused(static fn() => $manager->enable('olscpe', null), 'did not start', 'a failed start is reported');
check(json_decode(file_get_contents("$dir/objcache.json"), true)['accounts']['olscpe']['enabled'] === true, 'the wish is kept after a failed start');
$server->startFails = false;
$bad = "$root/malformed.json";
file_put_contents($bad, '{"schema_version": 2}');
refused(static fn() => (new ObjectCacheManager($server, $bad, "$dir/conf", "$dir/units", "$dir/lock"))->enable('olscpa', null), 'malformed', 'malformed state refused');

// --- status and flush ---------------------------------------------------------------------------------------
$list = $manager->status(null);
check($list['engine']['present'] === true && array_column($list['accounts'], 'account') === ['olscpa', 'olscpb', 'olscpe'], 'status lists accounts');
$one = $manager->status('olscpa');
check($one['enabled'] === true && $one['memory_mb'] === 128 && $one['state'] === 'active' && $one['package'] === 'gold'
    && $one['usage']['used_memory'] === 1048576 && $one['usage']['hit_rate'] === 0.75 && $one['usage']['evicted_keys'] === 5
    && $one['usage']['keys'] === 7 && $one['suspended'] === false, 'status of one account with usage');
$flush = $manager->flush('olscpa');
check($flush === ['result' => 'flushed', 'account' => 'olscpa'], 'flush');
$cli = array_values(array_filter($server->calls, static fn(array $c): bool => in_array('FLUSHALL', $c[1], true)))[0][1];
check($cli === ['/usr/sbin/runuser', '-u', 'olscpa', '--', '/usr/bin/valkey-cli', '-s', '/home/olscpa/.ols-objcache/valkey.sock', 'FLUSHALL'],
    'flush argv: valkey-cli as the account on its own socket');
unset($server->units['olscpa']);
refused(static fn() => $manager->flush('olscpa'), 'not running', 'flush refuses a stopped instance');
$server->units['olscpa'] = 'active';

// --- disable ------------------------------------------------------------------------------------------------
$result = $manager->disable('olscpb');
check($result === ['result' => 'disabled', 'account' => 'olscpb'] && !isset($server->units['olscpb']) && !file_exists("$dir/conf/olscpb")
    && !file_exists("$dir/units/ols-cpanel-objcache@olscpb.service.d") && !isset($server->sockets['/home2/olscpb/.ols-objcache'])
    && json_decode(file_get_contents("$dir/objcache.json"), true)['accounts']['olscpb'] === ['enabled' => false, 'memory_mb' => 32],
    'disable stops, removes files and socket directory, and records the durable "off" (memory kept for a later enable)');
$rm = array_values(array_filter($server->calls, static fn(array $c): bool => in_array('/usr/bin/rm', $c[1], true)))[0][1];
check($rm === ['/usr/sbin/runuser', '-u', 'olscpb', '--', '/usr/bin/rm', '-rf', '--', '/home2/olscpb/.ols-objcache'], 'socket directory removed as the account');
check($manager->disable('olscpb')['result'] === 'unchanged', 'disable twice is unchanged');

// --- lifecycle by reconcile -----------------------------------------------------------------------------------
[$server, $manager, $dir] = $fresh('lifecycle');
$manager->enable('olscpa', '64');
$manager->enable('olscpb', '32');
$before = count($server->calls);
$result = $manager->reconcile();
check($result['result'] === 'reconciled' && $result['actions'] === [], 'reconcile of a converged state does nothing');
$restarts = count($server->systemctl('restart'));
check($restarts === 2, 'no restart by a converged reconcile');
$server->suspended['olscpa'] = true;
$result = $manager->reconcile();
check($result['actions'] === [['account' => 'olscpa', 'action' => 'stopped (suspended)']] && !isset($server->units['olscpa'])
    && isset($server->units['olscpb']) && is_file("$dir/conf/olscpa/valkey.conf"), 'suspension stops the instance and keeps its configuration');
$result = $manager->reconcile();
check($result['actions'] === [], 'a suspended account stays stopped');
unset($server->suspended['olscpa']);
$result = $manager->reconcile();
check($result['actions'] === [['account' => 'olscpa', 'action' => 'started']] && ($server->units['olscpa'] ?? '') === 'active', 'unsuspension starts the instance');
$server->units['olscpb'] = 'failed';
$result = $manager->reconcile();
check($result['actions'] === [['account' => 'olscpb', 'action' => 'started']] && $server->systemctl('reset-failed') !== [], 'a failed instance is reset and started');
unset($server->users['olscpa']);
$result = $manager->reconcile();
check($result['actions'] === [['account' => 'olscpa', 'action' => 'removed (account gone)']] && !isset($server->units['olscpa'])
    && !file_exists("$dir/conf/olscpa") && !file_exists("$dir/units/ols-cpanel-objcache@olscpa.service.d")
    && !isset(json_decode(file_get_contents("$dir/objcache.json"), true)['accounts']['olscpa'])
    , 'account removal stops the instance, deletes files and the state entry');
check(array_filter($server->calls, static fn(array $c): bool => in_array('/usr/bin/rm', $c[1], true) && in_array('olscpa', $c[1], true)) === [],
    'no account-home deletion once the account is gone (no home to resolve)');
$saved = $server->users;
$server->users = [];
$server->calls = [];
refused(static fn() => $manager->reconcile(), 'cannot read the cPanel account list', 'an empty account list never means every account was removed');
check(isset($server->units['olscpb']) && is_dir("$dir/conf/olscpb"), 'nothing changed by the refused pass');
$server->users = $saved;
unset($server->users['olscpa']);

// --- RV-31 item 1: suspension fails closed ---------------------------------------------------------------------------
$keep = [$server, $manager, $dir];
[$server, $manager, $dir] = $fresh('suspend-closed');
$manager->enable('olscpa', '64');
$manager->enable('olscpb', '32');
// An unreadable marker directory is an error, never "nobody is suspended": nothing is started, restarted or stopped.
$server->suspended['olscpa'] = true;
$server->suspendedListFails = true;
unset($server->units['olscpb']);
$server->calls = [];
$result = $manager->reconcile();
check($result['result'] === 'errors' && count($result['errors']) === 2 && $result['actions'] === []
    && str_contains($result['errors'][0]['error'], 'suspension state'), 'a failed marker listing is an error for every wanted instance');
check($server->systemctl('restart') === [] && $server->systemctl('stop') === [] && !isset($server->units['olscpb']) && ($server->units['olscpa'] ?? '') === 'active',
    'with the suspension state unknown nothing is started and a running instance is left as it is');
// A missing marker directory is an authoritative "nobody suspended".
$server->suspendedListFails = false;
$server->suspendedDirMissing = true;
$server->suspended = [];
$result = $manager->reconcile();
check($result['result'] === 'reconciled' && ($server->units['olscpb'] ?? '') === 'active', 'a missing marker directory means nobody is suspended');
$server->suspendedDirMissing = false;
// enable() of an account whose marker cannot be tested never starts it.
$server->suspendedTestErrors = true;
$server->units = [];
refused(static fn() => $manager->enable('olscpa', '64'), 'cannot tell whether olscpa is suspended', 'enable refuses to start with an unknown suspension state');
check(!isset($server->units['olscpa']), 'no instance was started by the refused enable');
$server->suspendedTestErrors = false;
// A suspended instance is stopped before any file is written, even when the write fails.
$manager->enable('olscpa', '64');
check(($server->units['olscpa'] ?? '') === 'active', 'running again');
$server->suspended['olscpa'] = true;
rename("$dir/conf/olscpa", "$dir/conf/.olscpa-moved");
file_put_contents("$dir/conf/olscpa", 'blocked');  // the configuration directory cannot be (re)created
$server->calls = [];
$result = $manager->reconcile();
check(!isset($server->units['olscpa']) && count($server->systemctl('stop')) >= 1, 'the suspended instance is stopped although the configuration cannot be written');
unlink("$dir/conf/olscpa");
rename("$dir/conf/.olscpa-moved", "$dir/conf/olscpa");
// A stop that fails is an error, and a stop that does not take effect is detected.
$server->suspended['olscpa'] = true;
$manager->enable('olscpb', '32');
$server->suspended = [];
$manager->enable('olscpa', '64');
$server->suspended['olscpa'] = true;
$server->stopFails = true;
$result = $manager->reconcile();
check($result['result'] === 'errors' && str_contains($result['errors'][0]['error'], 'could not be stopped') && ($server->units['olscpa'] ?? '') === 'active',
    'a failing stop of a suspended instance is reported');
$server->stopFails = false;
$result = $manager->reconcile();
check($result['result'] === 'reconciled' && $result['actions'] === [['account' => 'olscpa', 'action' => 'stopped (suspended)']] && !isset($server->units['olscpa']),
    'the next pass stops it');
$server->suspended = [];
$manager->reconcile();

// --- RV-31 item 2: zero accounts is authoritative only when the account directory is readable -----------------------------
$server->users = [];
$server->usersDirReadable = false;
refused(static fn() => $manager->reconcile(), 'cannot read the cPanel account list', 'an unreadable account directory is a failure, not zero accounts');
check(isset($server->units['olscpb']), 'nothing was removed after the failed enumeration');
$server->usersDirReadable = true;
$result = $manager->reconcile();
$gone = array_column($result['actions'], 'action', 'account');
check($result['result'] === 'reconciled' && $gone === ['olscpa' => 'removed (account gone)', 'olscpb' => 'removed (account gone)'] && $server->units === []
    && !file_exists("$dir/conf/olscpa") && !file_exists("$dir/conf/olscpb")
    && json_decode(file_get_contents("$dir/objcache.json"), true)['accounts'] === [], 'after the last account is removed (authoritative empty list) everything is cleaned up');
// A failed grep (exit 2) with a readable directory is still a failure.
$server->usersDirReadable = true;
$server->add('olscpa', 1001, 'gold');
$manager->enable('olscpa', '64');
$server->users = [];
$failing = new class($server) implements CommandRunner {
    public function __construct(private FakeServer $inner)
    {
    }

    public function run(string $name, array $argv, int $timeout): array
    {
        if ($argv[0] === '/usr/bin/grep' && $argv[1] === '-rH') {
            return ['exit_code' => 2, 'stdout' => '', 'stderr' => 'grep: /var/cpanel/users: Permission denied'];
        }
        return $this->inner->run($name, $argv, $timeout);
    }
};
$failingManager = new ObjectCacheManager($failing, "$dir/objcache.json", "$dir/conf", "$dir/units", "$dir/lock");
refused(static fn() => $failingManager->reconcile(), 'cannot read the cPanel account list', 'a failing grep is never zero accounts');
[$server, $manager, $dir] = $keep;
// A package covers accounts; opting out and removing the package.
$manager->package('gold', '48', false);
$server->add('olscpg', 1010, 'gold');
$server->add('olscph', 1011, 'gold');
$result = $manager->reconcile();
$started = array_column($result['actions'], 'account');
check(in_array('olscpg', $started, true) && in_array('olscph', $started, true)
    && str_contains(file_get_contents("$dir/conf/olscpg/valkey.conf"), 'maxmemory 48mb'), 'package enables its accounts with the package memory');
$manager->enable('olscph', '96');
$manager->disable('olscpg');
check(json_decode(file_get_contents("$dir/objcache.json"), true)['accounts']['olscpg'] === ['enabled' => false, 'memory_mb' => 48]
    && !isset($server->units['olscpg']), 'disable inside an enabled package opts the account out');
$manager->reconcile();
check(!isset($server->units['olscpg']) && ($server->units['olscph'] ?? '') === 'active'
    && str_contains(file_get_contents("$dir/conf/olscph/valkey.conf"), 'maxmemory 96mb'), 'opt-out and explicit memory survive reconcile');
$manager->package('gold', null, true);
$result = $manager->reconcile();
check(!isset($server->units['olscpg']) && ($server->units['olscph'] ?? '') === 'active' && is_file("$dir/conf/olscpb/valkey.conf"),
    'removing the package keeps explicitly enabled accounts');
check($server->systemctl('start') !== [] && in_array('--no-block', $server->systemctl('start')[0], true), 'package change triggers the service without waiting');
$bad = $manager;
refused(static fn() => $bad->package('bad/name', '64', false), 'invalid package', 'package name refused');
refused(static fn() => $bad->package('gold', '9', false), 'memory must be', 'package memory refused');

// --- wp-cli --------------------------------------------------------------------------------------------------
[$server, $manager, $dir] = $fresh('wp');
refused(static fn() => $manager->configureWordPress('olscpa', '/home/olscpa/public_html', null), 'enable it first', 'configure needs an enabled cache');
$manager->enable('olscpa', '64');
$result = $manager->configureWordPress('olscpa', '/home/olscpa/public_html/blog', null);
check($result['result'] === 'configured' && $result['php'] === 'ea-php83' && $result['host'] === '/home/olscpa/.ols-objcache/valkey.sock'
    && $result['port'] === 0 && $result['method'] === 'redis', 'configure result (main domain PHP discovered)');
$wp = array_values(array_filter($server->calls, static fn(array $c): bool => in_array('/usr/local/bin/wp', $c[1], true)));
$prefix = ['/usr/sbin/runuser', '-u', 'olscpa', '--', '/usr/bin/env', 'HOME=/home/olscpa', 'WP_CLI_DISABLE_AUTO_CHECK_UPDATE=1',
    'WP_CLI_CACHE_DIR=/home/olscpa/.ols-objcache/wp-cli-cache', '/opt/cpanel/ea-php83/root/usr/bin/php', '-d', 'memory_limit=512M',
    '/usr/local/bin/wp', '--path=/home/olscpa/public_html/blog', '--skip-themes'];
check(array_column($wp, 1) === [[...$prefix, 'plugin', 'is-active', 'litespeed-cache'],
    [...$prefix, 'litespeed-option', 'set', 'object-kind', '1'],
    [...$prefix, 'litespeed-option', 'set', 'object-host', '/home/olscpa/.ols-objcache/valkey.sock'],
    [...$prefix, 'litespeed-option', 'set', 'object-port', '0'],
    [...$prefix, 'litespeed-option', 'set', 'object', 'true']], 'wp-cli argv, in order, as the account');
check(ObjectCacheManager::wpArgv('/home/olscpa', '/p', '/home/olscpa/x', ['a'])[0] === '/usr/bin/env', 'wpArgv shape');
$manager->configureWordPress('olscpa', '/home/olscpa/public_html', 'ea-php74');
check(array_values(array_filter($server->calls, static fn(array $c): bool => in_array('/opt/cpanel/ea-php74/root/usr/bin/php', $c[1], true))) !== [], '--php overrides discovery');
foreach (['/etc', '/home/olscpb/public_html', '/home/olscpab/x', 'relative', '/home/olscpa/../olscpb', '/home/olscpa/./x', '/home/olscpa/public_html/',
          '/home/olscpa//x', "/home/olscpa/x\n", '/home/olscpa/a b', '/home2/olscpa/x', '/home/olscpa/$(id)', '/home/olscpa/x;y'] as $bad) {
    refused(static fn() => $manager->configureWordPress('olscpa', $bad, null), 'must be a directory inside', 'path refused: ' . json_encode($bad));
}
refused(static fn() => $manager->configureWordPress('olscpa', '/home/olscpa/x', 'php83'), '--php must look like', '--php refused');
refused(static fn() => $manager->configureWordPress('olscpa', '/home/olscpa/x', 'ea-php83; id'), '--php must look like', '--php injection refused');
$server->wpConfig = false;
refused(static fn() => $manager->configureWordPress('olscpa', '/home/olscpa/x', null), 'no WordPress', 'missing wp-config refused');
$server->wpConfig = true;
$server->redis = false;
refused(static fn() => $manager->configureWordPress('olscpa', '/home/olscpa/x', null), 'redis extension', 'missing redis extension refused');
$server->redis = true;
$server->wpActive = false;
refused(static fn() => $manager->configureWordPress('olscpa', '/home/olscpa/x', null), 'LiteSpeed Cache is not active', 'inactive plugin refused');
$server->wpActive = true;
$server->versions = '{"data":{"versions":[]}}';
refused(static fn() => $manager->configureWordPress('olscpa', '/home/olscpa/x', null), 'pass --php', 'undeterminable PHP version refused');
refused(static fn() => $manager->configureWordPress('olscpb', '/home/olscpb/x', 'ea-php82'), 'enable it first', 'account without a cache refused');

// --- WordPress sites with LiteSpeed Cache: automatic ---------------------------------------------------------------
$socketA = '/home/olscpa/.ols-objcache/valkey.sock';
$userdata = "a.test: olscpa==root==main==a.test==/home/olscpa/public_html==1.2.3.4:80==1.2.3.4:443====0==ea-php83\n"
    . "blog.a.test: olscpa==root==sub==a.test==/home/olscpa/blog==1.2.3.4:80==1.2.3.4:443====0==ea-php82\n"
    . "b.test: olscpb==root==main==b.test==/home2/olscpb/public_html==1.2.3.4:80==1.2.3.4:443====0==ea-php82\n";
$wpSetup = static function (string $name) use ($fresh, $userdata): array {
    [$server, $manager, $dir] = $fresh($name);
    $server->userdata = $userdata;
    $server->wpFiles['olscpa'] = ['/home/olscpa/public_html/wp-config.php', '/home/olscpa/public_html/wp/wp-config.php',
        '/home/olscpa/public_html/a/b/wp-config.php', '/home/olscpa/public_html/we ird/wp-config.php', '/home/olscpa/blog/wp-config.php',
        '/home/olscpa/public_html/wp/wp-config.php'];
    $server->wpFiles['olscpb'] = ['/home2/olscpb/public_html/wp-config.php'];
    // These cases are about explicitly enabled accounts: the automatic mode (which would also take olscpb, a WordPress
    // with LiteSpeed Cache) has its own cases below.
    $manager->automatic(false);
    return [$server, $manager, $dir];
};
$sitesOf = static fn(array $result): array => array_column($result['wordpress'], 'state', 'path');
$setCalls = static fn(FakeServer $s): array => array_values(array_filter($s->argvs('/usr/local/bin/wp'),
    static fn(array $a): bool => in_array('set', $a, true)));

// Discovery: docroots of the account's own domains, the docroot and one level below, plain paths only.
[$server, $manager, $dir] = $wpSetup('wp-auto');
$result = $manager->enable('olscpa', null);
check($sitesOf($result) === ['/home/olscpa/blog' => 'automatic', '/home/olscpa/public_html' => 'automatic', '/home/olscpa/public_html/wp' => 'automatic'],
    'discovery finds wp-config.php in the docroot and one level below, nothing deeper, nothing with odd names, nothing of another account');
foreach (['/home/olscpa/blog', '/home/olscpa/public_html', '/home/olscpa/public_html/wp'] as $path) {
    check(($server->wpOptions[$path] ?? []) === ['object-kind' => '1', 'object-host' => $socketA, 'object-port' => '0', 'object' => 'true'],
        "LiteSpeed Cache configured on $path");
}
$find = array_values(array_filter($server->calls, static fn(array $c): bool => in_array('/usr/bin/find', $c[1], true)));
check(count($find) === 2 && $find[0][1] === ['/usr/sbin/runuser', '-u', 'olscpa', '--', '/usr/bin/find', '-P', '/home/olscpa/public_html', '-mindepth', '1',
    '-maxdepth', '2', '-name', 'wp-config.php', '-type', 'f'], 'the search runs as the account with find -P (links are not followed)');
check(array_filter($server->argvs('/usr/local/bin/wp'), static fn(array $a): bool => !in_array('--path=/home/olscpa/public_html', $a, true)
    && !in_array('--path=/home/olscpa/public_html/wp', $a, true) && !in_array('--path=/home/olscpa/blog', $a, true)) === [], 'wp-cli only on the found sites');
$php82 = array_filter($server->argvs('/usr/local/bin/wp'), static fn(array $a): bool => in_array('--path=/home/olscpa/blog', $a, true));
check(count($php82) > 0 && array_filter($php82, static fn(array $a): bool => !in_array('/opt/cpanel/ea-php82/root/usr/bin/php', $a, true)) === [],
    'each site runs with the PHP version of the domain that serves it');
$saved = json_decode(file_get_contents("$dir/objcache.json"), true);
check(array_column($saved['wordpress']['olscpa'], 'product_set') === [true, true, true]
    && array_keys($saved['wordpress']['olscpa']) === ['/home/olscpa/blog', '/home/olscpa/public_html', '/home/olscpa/public_html/wp']
    && ObjectCacheState::load("$dir/objcache.json")->wordpress['olscpa']['/home/olscpa/blog']['state'] === 'automatic', 'the sites the product set are recorded in the state');

// Idempotent: within the recheck interval wp-cli is not run at all; later it only reads when everything matches.
$clock->t += 10;
$server->calls = [];
$result = $manager->reconcile();
check($result['result'] === 'reconciled' && $server->argvs('/usr/local/bin/wp') === [], 'a pass shortly after looks at no site again');
$clock->t += ObjectCacheManager::RECHECK_OK;
$server->calls = [];
$manager->reconcile();
check($server->argvs('/usr/local/bin/wp') !== [] && $setCalls($server) === [], 'a later pass only reads: values already match, nothing is written');
$clock->t += ObjectCacheManager::RECHECK_OK;
$server->wpOptions['/home/olscpa/blog']['object'] = 'false';  // switched off in the WordPress admin
$server->calls = [];
$manager->reconcile();
check(($server->wpOptions['/home/olscpa/blog']['object'] ?? '') === 'true' && count($setCalls($server)) === 4, 'an object cache that was switched off again is set up again (four settings)');
$service = $manager->status('olscpa');
check($service['connection'] === ['host' => $socketA, 'port' => 0, 'password' => null] && $service['socket'] === $socketA
    && array_column($service['wordpress'], 'state', 'path') === ['/home/olscpa/blog' => 'automatic', '/home/olscpa/public_html' => 'automatic', '/home/olscpa/public_html/wp' => 'automatic']
    && $service['wordpress'][0]['configured_by_product'] === true, 'status shows the connection values and the sites');
$list = $manager->status(null);
check($list['accounts'][0]['connection']['port'] === 0 && count($list['accounts'][0]['wordpress']) === 3, 'the status list carries both too');

// A different object cache chosen by the site owner is never overridden, and never turned off later.
[$server, $manager, $dir] = $wpSetup('wp-owner');
$server->wpOptions['/home/olscpa/public_html/wp'] = ['object' => 'true', 'object-kind' => '1', 'object-host' => '/var/run/redis/redis.sock', 'object-port' => '0'];
$server->wpOptions['/home/olscpa/blog'] = ['object' => 'true', 'object-kind' => '0', 'object-host' => 'localhost', 'object-port' => '11211'];
$result = $manager->enable('olscpa', null);
check($sitesOf($result) === ['/home/olscpa/blog' => 'owner', '/home/olscpa/public_html' => 'automatic', '/home/olscpa/public_html/wp' => 'owner'], 'sites with the owner\'s own object cache are reported as such');
check($server->wpOptions['/home/olscpa/public_html/wp']['object-host'] === '/var/run/redis/redis.sock' && $server->wpOptions['/home/olscpa/blog']['object-host'] === 'localhost'
    && $server->wpOptions['/home/olscpa/blog']['object-kind'] === '0', 'the owner\'s settings are untouched');
check(array_filter($setCalls($server), static fn(array $a): bool => !in_array('--path=/home/olscpa/public_html', $a, true)) === [], 'no setting was written on the owner\'s sites');
$manager->disable('olscpa');
check($server->wpOptions['/home/olscpa/public_html/wp']['object'] === 'true' && $server->wpOptions['/home/olscpa/blog']['object'] === 'true'
    && $server->wpOptions['/home/olscpa/public_html']['object'] === 'false', 'disable turns off only the site the product configured');
check(!isset(json_decode(file_get_contents("$dir/objcache.json"), true)['wordpress']), 'the records are gone after the disable');

// LiteSpeed Cache not active, and errors: recorded, retried after their interval, never failing the pass.
[$server, $manager, $dir] = $wpSetup('wp-errors');
$server->wpInactive['/home/olscpa/blog'] = true;
$server->wpBroken['/home/olscpa/public_html/wp'] = true;
$result = $manager->enable('olscpa', null);
check($sitesOf($result) === ['/home/olscpa/blog' => 'inactive', '/home/olscpa/public_html' => 'automatic', '/home/olscpa/public_html/wp' => 'error']
    && str_contains(array_column($result['wordpress'], 'error', 'path')['/home/olscpa/public_html/wp'], 'database connection'), 'inactive plugin and wp-cli error are recorded per site');
check(!isset($server->wpOptions['/home/olscpa/blog']), 'nothing is configured where LiteSpeed Cache is not active');
unset($server->wpBroken['/home/olscpa/public_html/wp']);
$clock->t += 10;
$server->calls = [];
$result = $manager->reconcile();
check($result['result'] === 'reconciled' && $server->argvs('/usr/local/bin/wp') === [], 'an error is not retried before its interval');
$clock->t += ObjectCacheManager::RECHECK_ERROR;
$result = $manager->reconcile();
check($result['result'] === 'reconciled' && ObjectCacheState::load("$dir/objcache.json")->wordpress['olscpa']['/home/olscpa/public_html/wp']['state'] === 'automatic',
    'the failed site is retried by the next pass and succeeds');
$server->wpInactive = [];
$clock->t += ObjectCacheManager::RECHECK_OK;
$server->calls = [];
$manager->reconcile();
check(ObjectCacheState::load("$dir/objcache.json")->wordpress['olscpa']['/home/olscpa/blog']['state'] === 'inactive'
    && array_filter($server->argvs('/usr/local/bin/wp'), static fn(array $c): bool => in_array('--path=/home/olscpa/blog', $c, true)) === [],
    'an inactive plugin is not asked again while its files are unchanged (no wp-cli)');
// Activating LiteSpeed Cache installs its advanced-cache.php drop-in: the changed markers make the next look ask wp-cli.
$server->siteFiles['/home/olscpa/blog']['wp-content/advanced-cache.php'] = '<?php';
$clock->t += ObjectCacheManager::RECHECK_OK;
$server->wpSetFails = true;
$server->wpOptions['/home/olscpa/blog'] = [];
$result = $manager->reconcile();
check($result['result'] === 'reconciled' && ObjectCacheState::load("$dir/objcache.json")->wordpress['olscpa']['/home/olscpa/blog']['state'] === 'error',
    'a failing write is a site error, not an error of the pass');
$server->wpSetFails = false;

// The redis extension is not loaded yet: an error that goes away once it is.
[$server, $manager, $dir] = $wpSetup('wp-redis');
$server->redis = false;
$result = $manager->enable('olscpa', null);
check(array_unique(array_values($sitesOf($result))) === ['error'] && str_contains($result['wordpress'][0]['error'], 'redis extension is not loaded'), 'a missing redis extension is a retried site error');
$server->redis = true;
$clock->t += ObjectCacheManager::RECHECK_ERROR;
$manager->reconcile();
check(ObjectCacheState::load("$dir/objcache.json")->wordpress['olscpa']['/home/olscpa/blog']['state'] === 'automatic', 'configured once the extension is there');

// Suspension turns the product's sites off, unsuspension sets them up again; disable by reconcile does too.
[$server, $manager, $dir] = $wpSetup('wp-suspend');
$server->wpOptions['/home/olscpa/public_html/wp'] = ['object' => 'true', 'object-kind' => '1', 'object-host' => '/elsewhere.sock', 'object-port' => '0'];
$manager->enable('olscpa', null);
$server->suspended['olscpa'] = true;
$result = $manager->reconcile();
check($result['result'] === 'reconciled' && $server->wpOptions['/home/olscpa/public_html']['object'] === 'false' && $server->wpOptions['/home/olscpa/blog']['object'] === 'false'
    && $server->wpOptions['/home/olscpa/public_html/wp']['object'] === 'true', 'suspension turns off the sites the product configured, not the owner\'s');
check(!isset(json_decode(file_get_contents("$dir/objcache.json"), true)['wordpress']), 'and forgets them');
unset($server->suspended['olscpa']);
$manager->reconcile();
check($server->wpOptions['/home/olscpa/public_html']['object'] === 'true' && $server->wpOptions['/home/olscpa/blog']['object'] === 'true', 'unsuspension configures them again');
$manager->disable('olscpa');
$manager->enable('olscpa', null);
$server->wpFiles['olscpa'] = ['/home/olscpa/public_html/wp-config.php'];
$server->wpOptions['/home/olscpa/public_html']['object'] = 'true';
$state = ObjectCacheState::load("$dir/objcache.json");
$state->accounts['olscpa'] = ['enabled' => false, 'memory_mb' => 64];
$state->wordpress['olscpa'] = ['/home/olscpa/public_html' => ['state' => 'automatic', 'product_set' => true, 'checked' => 1, 'php' => 'ea-php83', 'error' => null]];
$state->save("$dir/objcache.json");
$manager->reconcile();
check($server->wpOptions['/home/olscpa/public_html']['object'] === 'false' && !isset(json_decode(file_get_contents("$dir/objcache.json"), true)['wordpress']),
    'a pass finds an account that is no longer wanted and turns its sites off');

// A turn-off that fails is kept and retried by the pass; a removed installation is simply forgotten.
[$server, $manager, $dir] = $wpSetup('wp-off-fails');
$manager->enable('olscpa', null);
$server->wpSetFails = true;
$off = $manager->disable('olscpa');
check($off['result'] === 'disabled' && count(array_filter($off['wordpress'], static fn(array $r): bool => $r['result'] === 'error')) === 3
    && count(ObjectCacheState::load("$dir/objcache.json")->wordpress['olscpa']) === 3 && !isset($server->units['olscpa']), 'a failed turn-off does not fail the disable and stays recorded');
$server->wpMissing['/home/olscpa/blog'] = true;
$server->wpSetFails = false;
$result = $manager->reconcile();
check($result['result'] === 'reconciled' && $server->wpOptions['/home/olscpa/public_html']['object'] === 'false'
    && $server->wpOptions['/home/olscpa/blog']['object'] === 'true' && !isset(json_decode(file_get_contents("$dir/objcache.json"), true)['wordpress']),
    'the next pass turns them off (a removed installation is only forgotten)');

// --- Automatic mode: every account with WordPress and LiteSpeed Cache gets its own cache, nobody enables it ------------------
$siteA = '/home/olscpa/public_html';
$autoSetup = static function (string $name) use ($fresh): array {
    [$server, $manager, $dir] = $fresh($name);
    $server->userdata = "a.test: olscpa==root==main==a.test==/home/olscpa/public_html==1.2.3.4:80==1.2.3.4:443====0==ea-php83\n"
        . "b.test: olscpb==root==main==b.test==/home2/olscpb/public_html==1.2.3.4:80==1.2.3.4:443====0==ea-php82\n";
    $server->wpFiles['olscpa'] = ['/home/olscpa/public_html/wp-config.php'];
    return [$server, $manager, $dir];
};
$entryOf = static fn(string $dir, string $user): ?array => json_decode(file_get_contents("$dir/objcache.json"), true)['accounts'][$user] ?? null;

// A customer switched LiteSpeed Cache's object cache on with its defaults (Redis, localhost:6379): the pass gives the account
// its own instance and points the site at the private socket. olscpb has no WordPress: no instance.
[$server, $manager, $dir] = $autoSetup('auto-enable');
$server->wpOptions[$siteA] = ['object' => 'true', 'object-kind' => '1', 'object-host' => 'localhost', 'object-port' => '6379'];
$result = $manager->reconcile();
check($result['result'] === 'reconciled' && in_array(['account' => 'olscpa', 'action' => 'started'], $result['actions'], true)
    && ($server->units['olscpa'] ?? '') === 'active' && !isset($server->units['olscpb']), 'automatic: an account with WordPress and LiteSpeed Cache is started, one without is not');
check($entryOf($dir, 'olscpa') === ['enabled' => true, 'memory_mb' => 64, 'origin' => 'automatic'], 'automatic: the entry records its origin and the default memory');
check(($server->wpOptions[$siteA] ?? []) === ['object' => 'true', 'object-kind' => '1', 'object-host' => $socketA, 'object-port' => '0'],
    'automatic: the plugin default host localhost:6379 is replaced with the account socket');
check(ObjectCacheState::load("$dir/objcache.json")->wordpress['olscpa'][$siteA]['product_set'] === true, 'automatic: the site is recorded as set by the product');
check(!is_dir("$dir/conf/olscpb") && isset(ObjectCacheState::load("$dir/objcache.json")->discovery['olscpb']), 'automatic: an account without WordPress is only remembered as looked at');
$one = $manager->status('olscpa');
check($one['origin'] === 'automatic' && $one['enabled'] === true && $one['automatic'] === true, 'automatic: the account status shows the origin');
check(array_column($manager->status(null)['accounts'], 'origin', 'account') === ['olscpa' => 'automatic'], 'automatic: the status list shows the origin');
// The look itself never ran wp-cli for an account that does not get an instance.
check(array_filter($server->argvs('/usr/local/bin/wp'), static fn(array $a): bool => in_array('olscpb', $a, true)) === [], 'automatic: no wp-cli to discover');

// Within the interval nothing is looked at again; after it the account without WordPress is looked at once more.
$server->calls = [];
$clock->t += 60;
$manager->reconcile();
check(array_filter($server->argvs('/usr/bin/find'), static fn(array $a): bool => in_array('olscpb', $a, true)) === [], 'automatic: no second look within the interval');
check(count(array_filter($server->calls, static fn(array $c): bool => $c[1] === ['/usr/bin/cat', '/etc/userdatadomains'])) <= 2,
    'automatic: the domain table is read once for the WordPress search of the pass (plus the leftover check)');
$clock->t += ObjectCacheManager::DISCOVERY_INTERVAL;
$server->calls = [];
$manager->reconcile();
check(count(array_filter($server->argvs('/usr/bin/find'), static fn(array $a): bool => in_array('olscpb', $a, true))) === 1, 'automatic: looked at again after the interval');

// An owner's own Redis server (another host) is left alone; the account still gets its instance for other applications.
[$server, $manager, $dir] = $autoSetup('auto-owner');
$server->wpOptions[$siteA] = ['object' => 'true', 'object-kind' => '1', 'object-host' => 'redis.example.net', 'object-port' => '6379'];
$result = $manager->reconcile();
check(($server->units['olscpa'] ?? '') === 'active' && $server->wpOptions[$siteA]['object-host'] === 'redis.example.net'
    && ObjectCacheState::load("$dir/objcache.json")->wordpress['olscpa'][$siteA]['state'] === 'owner', 'automatic: an owner-chosen host is never overridden');
// The cheap look (LiteSpeed Cache's runtime files) also treats the plugin default as nobody's choice.
[$server, $manager, $dir] = $autoSetup('auto-quick');
$server->siteFiles[$siteA] = ['wp-content/object-cache.php' => "<?php // https://www.litespeedtech.com object cache\n",
    'wp-content/.litespeed_conf.php' => '<?php exit; ?>{"object-host":"127.0.0.1","object-port":6379,"object-kind":true}'];
$server->wpOptions[$siteA] = ['object' => 'true', 'object-kind' => '1', 'object-host' => '127.0.0.1', 'object-port' => '6379'];
$manager->reconcile();
check($server->wpOptions[$siteA]['object-host'] === $socketA && $server->wpOptions[$siteA]['object-port'] === '0',
    'automatic: 127.0.0.1:6379 in the runtime file is replaced too');
$server->siteFiles[$siteA]['wp-content/.litespeed_conf.php'] = '<?php exit; ?>{"object-host":"localhost","object-port":6380,"object-kind":true}';
$server->wpOptions[$siteA] = ['object' => 'true', 'object-kind' => '1', 'object-host' => 'localhost', 'object-port' => '6380'];
$clock->t += ObjectCacheManager::RECHECK_OK;
$manager->reconcile();
check($server->wpOptions[$siteA]['object-port'] === '6380' && ObjectCacheState::load("$dir/objcache.json")->wordpress['olscpa'][$siteA]['state'] === 'owner',
    'automatic: another port on localhost is the owner\'s choice');

// WordPress without the LiteSpeed Cache plugin: no instance, and no wp-cli.
[$server, $manager, $dir] = $autoSetup('auto-no-plugin');
$server->lscwpInstalled = false;
$result = $manager->reconcile();
check($result['actions'] === [] && $server->units === [] && $entryOf($dir, 'olscpa') === null && $server->argvs('/usr/local/bin/wp') === [],
    'automatic: WordPress without LiteSpeed Cache gets no instance');

// A suspended account is never started by the automatic mode.
[$server, $manager, $dir] = $autoSetup('auto-suspended');
$server->suspended['olscpa'] = true;
$manager->reconcile();
check($server->units === [] && $entryOf($dir, 'olscpa') === null && !is_dir("$dir/conf/olscpa")
    && array_filter($server->argvs('/usr/bin/find'), static fn(array $a): bool => in_array('olscpa', $a, true)) === [],
    'automatic: a suspended account is not looked at and not started');
unset($server->suspended['olscpa']);
$manager->reconcile();
check(($server->units['olscpa'] ?? '') === 'active', 'automatic: after the unsuspension it is');

// A package switched off (memory 0) is off for its accounts; an automatic account in it is removed.
[$server, $manager, $dir] = $autoSetup('auto-package');
$manager->package('gold', '0', false);
$manager->reconcile();
check($server->units === [] && $entryOf($dir, 'olscpa') === null, 'automatic: a package with memory 0 keeps its accounts off');
$manager->package('gold', null, true);
$manager->reconcile();
check(($server->units['olscpa'] ?? '') === 'active' && $entryOf($dir, 'olscpa')['origin'] === 'automatic', 'automatic: the package setting removed, the account is taken');
$manager->package('gold', null, false, true);
$result = $manager->reconcile();
check(!isset($server->units['olscpa']) && $entryOf($dir, 'olscpa') === null && in_array(['account' => 'olscpa', 'action' => 'removed (disabled)'], $result['actions'], true)
    && $server->wpOptions[$siteA]['object'] === 'false', 'automatic: switching the package off removes the automatic instance and turns the product\'s site off');
check($manager->status('olscpa')['origin'] === 'package_off', 'automatic: the status says the package is off');
refused(static fn() => $manager->package('gold', '15', false), 'memory must be 0 (off)', 'package memory below the minimum is refused');

// The administrator's "off" is durable; enable clears it.
[$server, $manager, $dir] = $autoSetup('auto-disable');
$manager->reconcile();
check(($server->units['olscpa'] ?? '') === 'active', 'automatic: running');
$off = $manager->disable('olscpa');
check($off['result'] === 'disabled' && $entryOf($dir, 'olscpa') === ['enabled' => false, 'memory_mb' => 64] && !isset($server->units['olscpa'])
    && $server->wpOptions[$siteA]['object'] === 'false', 'disable of an automatic account records the administrator\'s off');
$clock->t += ObjectCacheManager::DISCOVERY_INTERVAL + ObjectCacheManager::RECHECK_OK;
$manager->reconcile();
check(!isset($server->units['olscpa']) && $entryOf($dir, 'olscpa')['enabled'] === false && $manager->status('olscpa')['origin'] === 'disabled',
    'the explicit off survives the automatic pass');
check($manager->disable('olscpa')['result'] === 'unchanged', 'disable of an account that is off already is unchanged');
$manager->enable('olscpa', null);
check($entryOf($dir, 'olscpa') === ['enabled' => true, 'memory_mb' => 64] && $manager->status('olscpa')['origin'] === 'administrator'
    && ($server->units['olscpa'] ?? '') === 'active', 'enable clears the off and makes the account the administrator\'s');
$server->wpFiles['olscpa'] = [];
$clock->t += ObjectCacheManager::RECHECK_OK;
$manager->reconcile();
check(($server->units['olscpa'] ?? '') === 'active', 'an account the administrator enabled keeps its instance without WordPress');

// The global switch: off removes only automatic accounts, on brings them back.
[$server, $manager, $dir] = $autoSetup('auto-global');
$manager->enable('olscpb', '32');
$manager->reconcile();
check(($server->units['olscpa'] ?? '') === 'active' && ($server->units['olscpb'] ?? '') === 'active', 'one automatic, one explicit account');
$switched = $manager->automatic(false);
check($switched['result'] === 'automatic_off' && $server->systemctl('start') !== [], 'auto --off is stored and starts a pass without waiting');
$result = $manager->reconcile();
check(!isset($server->units['olscpa']) && ($server->units['olscpb'] ?? '') === 'active' && $entryOf($dir, 'olscpa') === null
    && $entryOf($dir, 'olscpb') === ['enabled' => true, 'memory_mb' => 32] && $server->wpOptions[$siteA]['object'] === 'false',
    'auto --off removes only the automatic account and turns its site off');
check(!array_key_exists('discovery', json_decode(file_get_contents("$dir/objcache.json"), true)), 'nothing is looked at while the mode is off');
$clock->t += ObjectCacheManager::DISCOVERY_INTERVAL;
$manager->reconcile();
check(!isset($server->units['olscpa']) && $manager->status('olscpa')['origin'] === null && $manager->status(null)['automatic'] === false, 'the mode stays off');
check($manager->automatic(false)['result'] === 'unchanged', 'auto --off twice is unchanged');
$manager->automatic(true);
$manager->reconcile();
check(($server->units['olscpa'] ?? '') === 'active' && $entryOf($dir, 'olscpa')['origin'] === 'automatic', 'auto --on takes the account again');

// An automatic account whose last WordPress with LiteSpeed Cache disappears is disabled and its instance removed.
[$server, $manager, $dir] = $autoSetup('auto-lapse');
$manager->reconcile();
$server->lscwpInstalled = false;  // the plugin was deleted
$clock->t += 60;
$manager->reconcile();
check(($server->units['olscpa'] ?? '') === 'active', 'automatic: kept while the site record is not due');
$clock->t += ObjectCacheManager::RECHECK_OK;
$result = $manager->reconcile();
check(in_array(['account' => 'olscpa', 'action' => 'removed (no WordPress with LiteSpeed Cache left)'], $result['actions'], true)
    && !isset($server->units['olscpa']) && !is_dir("$dir/conf/olscpa") && $entryOf($dir, 'olscpa') === null
    && isset(ObjectCacheState::load("$dir/objcache.json")->discovery['olscpa']), 'automatic: the plugin removed, the instance is removed');
$server->lscwpInstalled = true;
$clock->t += ObjectCacheManager::DISCOVERY_INTERVAL;
$manager->reconcile();
check(($server->units['olscpa'] ?? '') === 'active', 'automatic: the plugin back, the account is taken again');
$server->wpFiles['olscpa'] = [];  // the WordPress installation was deleted
$result = $manager->reconcile();
check(in_array(['account' => 'olscpa', 'action' => 'removed (no WordPress with LiteSpeed Cache left)'], $result['actions'], true)
    && !isset($server->units['olscpa']) && !isset(ObjectCacheState::load("$dir/objcache.json")->wordpress['olscpa']),
    'automatic: the last WordPress deleted, the instance is removed at once');

// Bounded: one pass looks at DISCOVERY_PER_PASS accounts at most; the rest are looked at by the next passes.
[$server, $manager, $dir] = $autoSetup('auto-bounded');
for ($i = 0; $i < 30; $i++) {
    $server->add(sprintf('zbulk%02d', $i), 2000 + $i);  // sorted after olscpa: the never-looked-at come by name
}
$manager->reconcile();
$seen = ObjectCacheState::load("$dir/objcache.json")->discovery;
check(count($seen) === ObjectCacheManager::DISCOVERY_PER_PASS - 1 && ($server->units['olscpa'] ?? '') === 'active',
    'automatic: the first pass looks at DISCOVERY_PER_PASS accounts (one of them got its instance)');
$clock->t += 60;
$manager->reconcile();
$manager->reconcile();
check(count(ObjectCacheState::load("$dir/objcache.json")->discovery) === 32, 'automatic: the next pass looks at the rest, then nothing is due');

// The state keeps the new keys strictly.
$base = ['schema_version' => 1, 'defaults' => ['memory_mb' => 64], 'packages' => new stdClass(), 'accounts' => new stdClass()];
foreach ([['automatic' => 'no'], ['discovery' => ['olscpa' => 'x']], ['accounts' => ['olscpa' => ['enabled' => true, 'memory_mb' => 64, 'origin' => 'robot']]],
          ['packages' => ['gold' => ['memory_mb' => 5]]]] as $bad) {
    file_put_contents("$dir/bad.json", json_encode($bad + $base));
    refused(static fn() => ObjectCacheState::load("$dir/bad.json"), 'invalid', 'malformed automatic-mode state refused: ' . json_encode($bad));
}

// The state file stays valid for older readers: no wordpress key without sites, malformed entries are refused.
(new ObjectCacheState())->save("$dir/empty.json");
check(!array_key_exists('wordpress', json_decode(file_get_contents("$dir/empty.json"), true)), 'no wordpress key without sites');
file_put_contents("$dir/bad.json", json_encode(['schema_version' => 1, 'defaults' => ['memory_mb' => 64], 'packages' => new stdClass(), 'accounts' => new stdClass(),
    'wordpress' => ['olscpa' => ['/home/olscpa/x' => ['state' => 'weird', 'product_set' => true, 'checked' => 1]]]]));
refused(static fn() => ObjectCacheState::load("$dir/bad.json"), 'invalid wordpress entry', 'a malformed site record is refused');

// --- CLI ------------------------------------------------------------------------------------------------------
[$server, $manager, $dir] = $fresh('cli');
$root0 = new EngineContext(0, 'root');
$commands = array_map(static fn(string $action): ObjectCacheCommand => new ObjectCacheCommand($root0, $action, static fn() => $manager),
    array_keys(ObjectCacheCommand::ACTIONS));
$app = new Application($commands);
$run = static function (array $argv) use ($app): array {
    $stdout = fopen('php://memory', 'w+');
    $stderr = fopen('php://memory', 'w+');
    $code = $app->run($argv, new Output(true, $stdout, $stderr));
    rewind($stdout);
    rewind($stderr);
    return [$code, json_decode(stream_get_contents($stdout), true), stream_get_contents($stderr)];
};
[$code, $json] = $run(['objcache', 'enable', '--account=olscpa', '--memory=96', '--format=json']);
check($code === 0 && $json['result'] === 'enabled' && $json['memory_mb'] === 96, 'CLI enable');
[$code, $json] = $run(['objcache', 'status', '--account=olscpa', '--format=json']);
check($code === 0 && $json['usage']['hit_rate'] === 0.75, 'CLI status --account');
[$code, $json] = $run(['objcache', 'status', '--format=json']);
check($code === 0 && count($json['accounts']) === 1, 'CLI status');
[$code, $json] = $run(['objcache', 'flush', '--account=olscpa', '--format=json']);
check($code === 0 && $json['result'] === 'flushed', 'CLI flush');
[$code, $json] = $run(['objcache', 'enable', '--format=json']);
check($code === 64 && $json['result'] === 'usage', 'CLI enable needs --account');
[$code, $json] = $run(['objcache', 'enable', '--account=olscpa', '--memory=4', '--format=json']);
check($code === 1 && $json['result'] === 'refused' && str_contains($json['error'], 'memory must be'), 'CLI refusal is exit 1');
[$code] = $run(['objcache', 'enable', '--account=olscpa', '--bogus=1', '--format=json']);
check($code === 64, 'unknown option is a usage error');
[$code, $json] = $run(['objcache', 'configure-wordpress', '--account=olscpa', '--format=json']);
check($code === 64, 'configure-wordpress needs --path');
[$code, $json] = $run(['objcache', 'package', '--name=gold', '--memory=32', '--remove', '--format=json']);
check($code === 64, 'package: --memory and --remove exclude each other');
[$code, $json] = $run(['objcache', 'package', '--name=gold', '--memory=32', '--format=json']);
check($code === 0 && $json['result'] === 'package_enabled', 'CLI package');
[$code, $json] = $run(['objcache', 'reconcile', '--format=json']);
check($code === 0 && $json['result'] === 'reconciled', 'CLI reconcile');
$server->startFails = true;
$server->units = [];
[$code, $json] = $run(['objcache', 'reconcile', '--format=json']);
check($code === 1 && $json['result'] === 'errors' && $json['errors'][0]['account'] === 'olscpa', 'CLI reconcile reports per-account errors (exit 1)');
[$code, $json] = $run(['objcache', 'disable', '--account=olscpa', '--format=json']);
check($code === 0 && $json['result'] === 'disabled', 'CLI disable');
$user = new EngineContext(1001, 'olscpa');
$denied = new Application([new ObjectCacheCommand($user, 'status', static fn() => $manager)]);
check($denied->run(['objcache', 'status', '--format=json'], new Output(true, fopen('php://memory', 'w+'), fopen('php://memory', 'w+'))) === 1, 'non-root caller refused');
[$code, $json] = $run(['objcache', 'auto', '--off', '--format=json']);
check($code === 0 && $json['result'] === 'automatic_off' && $json['automatic'] === false
    && json_decode(file_get_contents("$dir/objcache.json"), true)['automatic'] === false, 'CLI auto --off is stored');
[$code, $json] = $run(['objcache', 'status', '--format=json']);
check($code === 0 && $json['automatic'] === false, 'the status shows the automatic mode');
[$code, $json] = $run(['objcache', 'auto', '--on', '--format=json']);
check($code === 0 && $json['result'] === 'automatic_on' && !array_key_exists('automatic', json_decode(file_get_contents("$dir/objcache.json"), true)),
    'CLI auto --on (the default, not written)');
foreach ([['objcache', 'auto'], ['objcache', 'auto', '--on', '--off'], ['objcache', 'auto', '--on=1']] as $bad) {
    [$code] = $run([...$bad, '--format=json']);
    check($code === 64, 'auto usage error: ' . implode(' ', $bad));
}
[$code, $json] = $run(['objcache', 'package', '--name=gold', '--off', '--format=json']);
check($code === 0 && $json['result'] === 'package_off' && $json['memory_mb'] === 0, 'CLI package --off');
[$code] = $run(['objcache', 'package', '--name=gold', '--off', '--memory=32', '--format=json']);
check($code === 64, 'package: --off and --memory exclude each other');
check(count(array_filter(Application::defaultCommands(), static fn($c): bool => $c->words()[0] === 'objcache')) === 8, 'eight objcache commands registered');

// --- Hook trigger ---------------------------------------------------------------------------------------------
$spool = "$root/spool";
$intents = "$root/intents";
$stateFile = "$root/hook-objcache.json";
$hookRunner = new class implements CommandRunner {
    public array $calls = [];
    public function run(string $name, array $argv, int $timeout): array
    {
        $this->calls[] = $argv;
        return ['exit_code' => $argv[1] === 'start' ? 0 : 0, 'stdout' => '{"epoch": 4}', 'stderr' => ''];
    }
};
$event = static fn(string $name): string => json_encode(['context' => ['category' => 'Whostmgr', 'event' => $name, 'stage' => 'post', 'user' => 'olscpa'], 'data' => []]);
$emit = static function (HookEntry $hook, string $json): string {
    $out = fopen('php://memory', 'w+');
    $hook->handle($json, $out, fopen('php://memory', 'w+'));
    rewind($out);
    return stream_get_contents($out);
};
$hook = new HookEntry($spool, $hookRunner, '/opt/activator', $intents, $stateFile);
check($emit($hook, $event('Accounts::suspendacct')) === '1', 'hook answers 1');
check(array_column($hookRunner->calls, 1) === ['restrict', 'start'], 'account maintenance starts even before object cache state exists');
file_put_contents($stateFile, '{}');
$hookRunner->calls = [];
$emit($hook, $event('Accounts::unsuspendacct'));
check($hookRunner->calls === [['/usr/bin/systemctl', 'start', '--no-block', 'ols-cpanel-objcache.service']], 'unsuspend triggers the reconciliation without waiting');
$hookRunner->calls = [];
$emit($hook, $event('Accounts::Remove'));
check(count($hookRunner->calls) === 2 && $hookRunner->calls[1][1] === 'start', 'removal raises the epoch, then triggers');
$hookRunner->calls = [];
$emit($hook, $event('SSL::installssl'));
check($hookRunner->calls === [], 'other events do not trigger');
$failing = new class implements CommandRunner {
    public function run(string $name, array $argv, int $timeout): array
    {
        throw new RuntimeException('systemd unavailable');
    }
};
check($emit(new HookEntry($spool, $failing, '/opt/activator', $intents, $stateFile), $event('Accounts::unsuspendacct')) === '1', 'a failing trigger never fails the hook');

// Account names in modify hooks are supplied in data, even when context names the old account.
foreach ([['Whostmgr', 'Accounts::SiteIP::set'], ['Whostmgr', 'Accounts::Modify'], ['PkgAcct', 'Restore'],
          ['Whostmgr', 'Transfers::Session'], ['Whostmgr', 'Accounts::Create']] as [$category, $name]) {
    $hookRunner->calls = [];
    $before = count(glob("$spool/*.json"));
    check($emit($hook, json_encode(['context' => ['category' => $category, 'event' => $name, 'stage' => 'post'],
        'data' => ['user' => 'olscpa']])) === '1' && count(glob("$spool/*.json")) === $before + 1, "$name spools a reconcile event");
    if (in_array($name, HookEntry::TRUST_EVENTS, true)) {
        check(in_array(['/usr/bin/systemctl', 'start', '--no-block', HookEntry::TRUST_SERVICE], $hookRunner->calls, true),
            "$name refreshes hybrid address trust");
    }
    if (in_array($name, HookEntry::OBJCACHE_EVENTS, true)) {
        check(in_array(['/usr/bin/systemctl', 'start', '--no-block', HookEntry::OBJCACHE_SERVICE], $hookRunner->calls, true),
            "$name applies account package object cache");
    }
}

[$server, $manager, $dir] = $fresh('account-rename');
$manager->enable('olscpa', '96');
$oldSite = '/home/olscpa/public_html';
$newSite = '/home/renamed/public_html';
$state = ObjectCacheState::load("$dir/objcache.json");
$state->wordpress['olscpa'][$oldSite] = ['state' => 'automatic', 'product_set' => true, 'checked' => 1,
    'php' => 'ea-php83', 'error' => null];
$state->save("$dir/objcache.json");
file_put_contents("$dir/php-limits.json", json_encode(['defaults' => ['children' => 7],
    'accounts' => ['olscpa' => ['children' => 12], 'removed' => ['children' => 9]]]));
$server->add('renamed', 1001, 'gold');
unset($server->users['olscpa']);
$server->userdata = "new.test: renamed==root==main==new.test==/home/renamed/public_html==192.0.2.11:80==192.0.2.11:443====0==ea-php83\n";
$server->wpFiles['renamed'] = ["$newSite/wp-config.php"];
$server->wpOptions[$newSite] = ['object' => 'true', 'object-kind' => '1', 'object-host' => '/home/olscpa/.ols-objcache/valkey.sock', 'object-port' => '0'];
$renameHook = new HookEntry("$dir/events", $hookRunner, '/opt/activator', "$dir/intents", "$dir/objcache.json");
$payload = json_encode(['context' => ['category' => 'Whostmgr', 'event' => 'Accounts::Modify', 'stage' => 'post'],
    'data' => ['user' => 'olscpa', 'newuser' => 'renamed', 'password' => 'never-record-this']]);
check($emit($renameHook, $payload) === '1' && count(glob("$dir/account-renames/*.json")) === 1, 'rename records a durable migration job');
check(!str_contains(file_get_contents(glob("$dir/account-renames/*.json")[0]), 'never-record-this'), 'rename jobs contain no payload secrets');
$server->stopFails = true;
$failed = $manager->reconcile();
check($failed['result'] === 'errors' && str_contains(json_encode($failed['errors']), 'could not be stopped'),
    'a rename with a failed old-unit stop is reported and remains pending without aborting the pass');
check(count(glob("$dir/account-renames/*.json")) === 1 && is_file("$dir/conf/olscpa/valkey.conf"), 'failed migration retains the job and old configuration');
$server->stopFails = false;
$result = $manager->reconcile();
$state = ObjectCacheState::load("$dir/objcache.json");
check($result['result'] === 'reconciled' && !isset($state->accounts['olscpa']) && $state->accounts['renamed']['memory_mb'] === 96
    && !isset($server->units['olscpa']) && ($server->units['renamed'] ?? '') === 'active'
    && !file_exists("$dir/conf/olscpa") && str_contains(file_get_contents("$dir/conf/renamed/valkey.conf"), '/home/renamed/.ols-objcache'),
    'rename migrates the explicit account state and recreates the instance at its new home');
check(!isset($state->wordpress['olscpa']) && isset($state->wordpress['renamed'][$newSite])
    && $server->wpOptions[$newSite]['object-host'] === '/home/renamed/.ols-objcache/valkey.sock',
    'rename migrates WordPress records and rewrites the old product socket');
$limits = \OlsCpanel\Php\PhpLimits::load("$dir/php-limits.json");
check($limits->accountsWithOverrides() === ['renamed'] && $limits->forAccount('renamed')['children'] === 12
    && $limits->forAccount('olscpb')['children'] === 7, 'rename moves PHP overrides and prunes orphan entries while keeping defaults');
check(glob("$dir/account-renames/*.json") === [], 'successful migration completes its durable job');
check($manager->reconcile()['actions'] === [], 'a second rename pass is converged');
// Removal after transfer away: keep retry evidence if stopping the instance fails.
unset($server->users['renamed']);
$server->stopFails = true;
$result = $manager->reconcile();
check($result['result'] === 'errors' && is_file("$dir/conf/renamed/valkey.conf"), 'failed removal keeps configuration for the periodic retry');
$server->stopFails = false;
check($manager->reconcile()['result'] === 'reconciled' && !file_exists("$dir/conf/renamed")
    && !isset($server->units['renamed']) && !isset(ObjectCacheState::load("$dir/objcache.json")->wordpress['renamed'])
    && \OlsCpanel\Php\PhpLimits::load("$dir/php-limits.json")->accountsWithOverrides() === [],
    'transfer-away removal converges units, WordPress state and PHP overrides');
// Restore inherits the package without an explicit per-account enable operation.
$manager->package('gold', '80', false);
$server->add('restored', 1003, 'gold');
$result = $manager->reconcile();
check($result['result'] === 'reconciled' && ($server->units['restored'] ?? '') === 'active'
    && str_contains(file_get_contents("$dir/conf/restored/valkey.conf"), 'maxmemory 80mb'), 'restored accounts automatically inherit package object cache');

// Two WHM renames can finish before the next root pass; intermediate PHP entries must survive until moved.
[$server, $manager, $dir] = $fresh('chained-renames');
$manager->enable('olscpa', '112');
file_put_contents("$dir/php-limits.json", json_encode(['accounts' => ['middle' => ['children' => 14]]]));
$renameHook = new HookEntry("$dir/events", $hookRunner, '/opt/activator', "$dir/intents", "$dir/objcache.json");
foreach ([['olscpa', 'middle'], ['middle', 'finaluser']] as [$old, $new]) {
    $emit($renameHook, json_encode(['context' => ['category' => 'Whostmgr', 'event' => 'Accounts::Modify', 'stage' => 'post'],
        'data' => ['user' => $old, 'newuser' => $new]]));
}
unset($server->users['olscpa']);
$server->add('finaluser', 1001, 'gold', '/home2/finaluser');
$result = $manager->reconcile();
check($result['result'] === 'reconciled' && ObjectCacheState::load("$dir/objcache.json")->accounts['finaluser']['memory_mb'] === 112
    && \OlsCpanel\Php\PhpLimits::load("$dir/php-limits.json")->forAccount('finaluser')['children'] === 14
    && glob("$dir/account-renames/*.json") === [], 'chained renames converge to the final username without pruning intermediate PHP settings');
// A failing migration does not stop other accounts; A to B then B to A is valid and not cyclic.
[$server, $manager, $dir] = $fresh('rename-isolation');
$manager->enable('olscpa', '64');
$renameHook = new HookEntry("$dir/events", $hookRunner, '/opt/activator', "$dir/intents", "$dir/objcache.json");
foreach ([['olscpa', 'tempname'], ['tempname', 'olscpa'], ['olscpb', 'neverexists']] as [$old, $new]) {
    $emit($renameHook, json_encode(['context' => ['category' => 'Whostmgr', 'event' => 'Accounts::Modify', 'stage' => 'post'],
        'data' => ['user' => $old, 'newuser' => $new]]));
}
$server->add('newcomer', 1005, 'gold');
$manager->package('gold', '64', false);
$result = $manager->reconcile();
check(!str_contains(json_encode($result['errors']), 'cyclic') && count(glob("$dir/account-renames/*.json")) === 1
    && str_contains(json_encode($result['errors']), 'source still exists')
    && ($server->units['newcomer'] ?? '') === 'active' && isset(ObjectCacheState::load("$dir/objcache.json")->accounts['olscpa']),
    'A to B then B to A completes without a cycle error; a failing job stays queued without stopping the other accounts of the pass');
// Removed accounts leave no requests or OLS error logs for a later account or domain of the same name.
[$server, $manager, $dir] = $fresh('account-removal');
$server->userdata = "a.test: olscpa==root==main==a.test==/home/olscpa/public_html==192.0.2.11:80==192.0.2.11:443====0==ea-php83\n";
mkdir("$dir/requests", 0700);
$request = static fn(string $id, string $user, ?string $identity) => file_put_contents("$dir/requests/$id.json",
    json_encode(['id' => $id, 'user' => $user, 'identity' => $identity, 'subject' => 'php', 'text' => 'x', 'status' => 'open']));
$request('r1800000001-aaaaaaaa', 'ghost', null);
$request('r1800000002-bbbbbbbb', 'olscpa', null);
mkdir("$dir/vhost-logs");
foreach (['a.test-error.log', 'tls.a.test-error.log', 'a.test-error.log.1', 'gone.test-error.log', 'gone.test-error.log.2', 'tls.gone.test-error.log', 'notes.txt'] as $name) {
    file_put_contents("$dir/vhost-logs/$name", "x\n");
    touch("$dir/vhost-logs/$name", time() - 8 * 86400);  // not written for more than a week
}
file_put_contents("$dir/vhost-logs/recent.test-error.log", "x\n");  // written now: kept although not in the domain table
file_put_contents("$dir/outside.log", "keep\n");
symlink("$dir/outside.log", "$dir/vhost-logs/link.test-error.log");
$result = $manager->reconcile();
check(array_map('basename', glob("$dir/requests/*.json")) === ['r1800000002-bbbbbbbb.json']
    && is_file("$dir/requests-archive/r1800000001-aaaaaaaa.json") && (fileperms("$dir/requests-archive") & 0777) === 0700,
    'requests of a removed account are moved to the administrator-only archive');
$left = array_values(array_diff(scandir("$dir/vhost-logs"), ['.', '..']));
sort($left);
check($left === ['a.test-error.log', 'a.test-error.log.1', 'link.test-error.log', 'notes.txt', 'recent.test-error.log', 'tls.a.test-error.log']
    && file_get_contents("$dir/outside.log") === "keep\n", 'error logs of vhosts that no longer exist are removed; links and other files stay');
// Ownership epochs of domains (DomainOwners): first file uses 0, a new domain or a changed owner starts an epoch,
// an unchanged owner keeps it, a removed domain is dropped, a failed read changes nothing.
$ownersFile = "$dir/domain-owners.json";
@unlink($ownersFile);
$owners = new \OlsCpanel\ObjectCache\DomainOwners($ownersFile);
$row = static fn(string $d, string $u): string => "$d: $u==root==main==$d==/home/$u/public_html==192.0.2.1:80==192.0.2.1:443====0==ea-php83\n";
$read = static fn(): array => json_decode((string) file_get_contents($ownersFile), true);
$owners->update(['alice', 'bob'], $row('a.test', 'alice') . $row('b.test', 'bob'), 1000);
check($read() === ['a.test' => ['owner' => 'alice', 'since' => 0], 'b.test' => ['owner' => 'bob', 'since' => 0]]
    && (fileperms($ownersFile) & 0777) === 0600, 'the first domain owner file records since 0 for every domain, mode 0600');
$owners->update(['alice', 'bob'], $row('a.test', 'alice') . $row('b.test', 'bob') . $row('c.test', 'bob'), 2000);
check($read()['c.test'] === ['owner' => 'bob', 'since' => 2000] && $read()['a.test']['since'] === 0, 'a new domain starts an epoch, an unchanged owner keeps since');
$owners->update(['alice', 'bob'], $row('a.test', 'bob') . $row('b.test', 'bob'), 3000);
check($read() === ['a.test' => ['owner' => 'bob', 'since' => 3000], 'b.test' => ['owner' => 'bob', 'since' => 0]],
    'a changed owner resets since and a removed domain is dropped');
$before = file_get_contents($ownersFile);
$owners->update(['alice', 'bob'], null, 4000);
$owners->update(['alice', 'bob'], '', 4000);
check(file_get_contents($ownersFile) === $before, 'an unreadable or empty domain table changes nothing');
file_put_contents($ownersFile, 'not json');
$owners->update(['bob'], $row('a.test', 'bob'), 5000);
check($read() === ['a.test' => ['owner' => 'bob', 'since' => 5000]], 'an unreadable owner file is not a first file: epochs start now');
@unlink($ownersFile);

// A re-created account: its recorded identity differs from the current one.
$removal = new \OlsCpanel\ObjectCache\AccountRemoval("$dir/requests", "$dir/requests-archive", null);
$request('r1800000003-cccccccc', 'olscpa', 'start:100');
$request('r1800000004-dddddddd', 'olscpa', 'start:200');
$done = $removal->run(['olscpa'], null, static fn(string $u): ?string => 'start:200');
check($done['archived'] === 1 && is_file("$dir/requests-archive/r1800000003-cccccccc.json")
    && is_file("$dir/requests/r1800000004-dddddddd.json") && is_file("$dir/requests/r1800000002-bbbbbbbb.json"),
    'requests of an earlier account with the same name are archived, unknown identity is left alone');
// An unreadable or empty domain table never removes logs.
$removal = new \OlsCpanel\ObjectCache\AccountRemoval("$dir/requests", "$dir/requests-archive", "$dir/vhost-logs");
$removal->run(['olscpa'], null, static fn(string $u): ?string => null);
$removal->run(['olscpa'], '', static fn(string $u): ?string => null);
check(is_file("$dir/vhost-logs/a.test-error.log") && is_file("$dir/vhost-logs/a.test-error.log.1"), 'a failed domain table read removes no log');
// A renamed account's opt-out remains effective even when its new name belongs to an enabled package.
[$server, $manager, $dir] = $fresh('rename-opt-out');
(new ObjectCacheState(64, ['gold' => ['memory_mb' => 80]], ['olscpa' => ['enabled' => false, 'memory_mb' => 64]]))->save("$dir/objcache.json");
$renameHook = new HookEntry("$dir/events", $hookRunner, '/opt/activator', "$dir/intents", "$dir/objcache.json");
$emit($renameHook, json_encode(['context' => ['category' => 'Whostmgr', 'event' => 'Accounts::Modify', 'stage' => 'post'],
    'data' => ['user' => 'olscpa', 'newuser' => 'renamed']]));
unset($server->users['olscpa']);
$server->add('renamed', 1001, 'gold');
$result = $manager->reconcile();
check($result['result'] === 'reconciled' && ObjectCacheState::load("$dir/objcache.json")->accounts['renamed']['enabled'] === false
    && !isset($server->units['renamed']), 'rename preserves a package opt-out without requiring an old instance to exist');

// A WordPress error after migration keeps the old product socket for the periodic site's retry.
[$server, $manager, $dir] = $fresh('rename-wordpress-retry');
$manager->enable('olscpa', '64');
$state = ObjectCacheState::load("$dir/objcache.json");
$state->wordpress['olscpa']['/home/olscpa/public_html'] = ['state' => 'automatic', 'product_set' => true,
    'checked' => 1, 'php' => 'ea-php83', 'error' => null];
$state->save("$dir/objcache.json");
$renameHook = new HookEntry("$dir/events", $hookRunner, '/opt/activator', "$dir/intents", "$dir/objcache.json");
$emit($renameHook, json_encode(['context' => ['category' => 'Whostmgr', 'event' => 'Accounts::Modify', 'stage' => 'post'],
    'data' => ['user' => 'olscpa', 'newuser' => 'renamed']]));
unset($server->users['olscpa']);
$server->add('renamed', 1001, 'gold');
$newSite = '/home/renamed/public_html';
$server->userdata = "new.test: renamed==root==main==new.test==/home/renamed/public_html==192.0.2.11:80==192.0.2.11:443====0==ea-php83\n";
$server->wpFiles['renamed'] = ["$newSite/wp-config.php"];
$server->wpOptions[$newSite] = ['object' => 'true', 'object-kind' => '1', 'object-host' => '/home/olscpa/.ols-objcache/valkey.sock', 'object-port' => '0'];
$server->wpSetFails = true;
$manager->reconcile();
$row = ObjectCacheState::load("$dir/objcache.json")->wordpress['renamed'][$newSite];
check($row['state'] === 'error' && $row['previous_socket'] === '/home/olscpa/.ols-objcache/valkey.sock',
    'failed WordPress socket migration persists its previous product socket');
$server->wpSetFails = false;
$clock->t += ObjectCacheManager::RECHECK_ERROR + 1;
$manager->reconcile();
$row = ObjectCacheState::load("$dir/objcache.json")->wordpress['renamed'][$newSite];
check($row['state'] === 'automatic' && !isset($row['previous_socket'])
    && $server->wpOptions[$newSite]['object-host'] === '/home/renamed/.ols-objcache/valkey.sock',
    'the periodic site pass retries the migrated socket instead of treating it as an owner connection');

// --- PHP redis extension wiring (src/PhpExtensions; tests/php_extensions.php covers the installer itself) ----------------
$extension = new class implements \OlsCpanel\PhpExtensions\ExtensionService {
    public array $ensured = [];
    public bool $fixes = true;
    public bool $throws = false;
    public bool $wanted = true;
    public bool $needsSync = false;
    public bool $unitsOff = false;
    public array $rows = [];
    public int $wants = 0;
    public ?FakeServer $server = null;

    public function ensureVersions(array $versions): array
    {
        return [];
    }

    public function status(): array
    {
        return ['result' => 'status', 'wanted' => $this->wanted, 'needs_sync' => $this->needsSync, 'versions' => $this->rows]
            + ($this->unitsOff ? ['watcher' => false, 'timer' => false] : []);
    }

    public function ensureForAccount(string $user, array $versions): array
    {
        if ($this->throws) {
            throw new RuntimeException('dnf exploded');
        }
        $this->ensured[] = [$user, $versions];
        if ($this->fixes && $this->server !== null) {
            $this->server->redis = true;
        }
        return ['result' => 'activated', 'versions' => [['php' => $versions[0], 'status' => $this->fixes ? 'activated' : 'failed', 'message' => 'make: *** Error 1', 'changed' => $this->fixes]],
            'changed' => $this->fixes ? $versions : []];
    }

    public function sync(): array
    {
        return [];
    }

    public function install(?string $only): array
    {
        return [];
    }

    public function remove(): array
    {
        return [];
    }

    public function want(): void
    {
        ++$this->wants;
        $this->wanted = true;
    }
};
$withExtension = static function (string $name) use ($fresh, $extension): array {
    [$server, , $dir] = $fresh($name);
    $extension->server = $server;
    $extension->ensured = [];
    $manager = new ObjectCacheManager($server, "$dir/objcache.json", "$dir/conf", "$dir/units", "$dir/lock", extensions: $extension);
    return [$server, $manager, $dir];
};
[$server, $manager, $dir] = $withExtension('ext-enable');
$result = $manager->enable('olscpa', '64');
check($extension->ensured === [['olscpa', ['ea-php74', 'ea-php83']]] && $result['php_extension']['result'] === 'activated' && $result['result'] === 'enabled',
    'enable ensures the extension for every PHP version of the account (the restart is the service\'s part)');
$extension->throws = true;
$result = $manager->enable('olscpa', '64');
check($result['result'] === 'enabled' && $result['php_extension']['result'] === 'failed' && str_contains($result['php_extension']['error'], 'dnf exploded'),
    'a failing extension step never fails the enable and is reported');
$extension->throws = false;
$server->versions = '{"data":{"versions":[]}}';
$result = $manager->enable('olscpa', '64');
check($result['php_extension']['result'] === 'skipped' && str_contains($result['php_extension']['note'], 'php-ext install'), 'unknown PHP versions: skipped with the command to run');
$status = $manager->status(null);
check($status['php_extension']['result'] === 'status' && $manager->status('olscpa')['php_extension']['wanted'] === true, 'objcache status carries the extension state');
check(!isset((new ObjectCacheManager($server, "$dir/objcache.json", "$dir/conf", "$dir/units", "$dir/lock"))->status(null)['php_extension']), 'no extension service: no extension field');

[$server, $manager, $dir] = $withExtension('ext-wp');
$manager->enable('olscpa', '64');
$extension->ensured = [];
$server->redis = false;
$result = $manager->configureWordPress('olscpa', '/home/olscpa/public_html', null);
check($result['result'] === 'configured' && $extension->ensured === [['olscpa', ['ea-php83']]], 'configure-wordpress activates a missing extension for the account\'s PHP and continues');
$server->redis = false;
$extension->fixes = false;
refused(static fn() => $manager->configureWordPress('olscpa', '/home/olscpa/public_html', null), 'could not be activated (failed: make', 'configure-wordpress reports an activation failure with its reason');
$extension->fixes = true;
$server->redis = true;
$extension->ensured = [];
$manager->configureWordPress('olscpa', '/home/olscpa/public_html', null);
check($extension->ensured === [], 'a loaded extension is not touched');

[$server, $manager, $dir] = $withExtension('ext-reconcile');
$manager->enable('olscpa', '64');
$extension->wanted = false;
$extension->wants = 0;
$result = $manager->reconcile();
check($extension->wants === 1 && count($server->systemctl('start')) === 1 && $server->systemctl('start')[0] === ['/usr/bin/systemctl', 'start', '--no-block', 'ols-cpanel-php.service']
    && in_array('(php-ext)', array_column($result['actions'], 'account'), true), 'reconcile marks the extension wanted and starts the watcher pass without waiting');
$extension->wanted = true;
$extension->needsSync = false;
$before = count($server->systemctl('start'));
$result = $manager->reconcile();
check(count($server->systemctl('start')) === $before && $result['result'] === 'reconciled', 'no pass is started when nothing is due');
$extension->rows = [['php' => 'ea-php83', 'status' => 'inactive', 'last_failure' => ['at' => 1, 'attempts' => 3, 'error' => 'build step make failed']]];
$result = $manager->reconcile();
check($result['result'] === 'errors' && str_contains($result['errors'][0]['error'], 'redis extension in ea-php83: build step make failed')
    && $result['php_extension']['versions'][0]['php'] === 'ea-php83', 'an unresolved extension failure is an error of the reconcile pass (the unit shows failed)');
$extension->rows = [];
// RV-31 item 11: the units that retry failures are enabled again when they were switched off.
$extension->wants = 0;
$extension->needsSync = false;
$extension->rows = [];
$extension->unitsOff = true;
$before = count($server->systemctl('start'));
$result = $manager->reconcile();
check($extension->wants === 1 && count($server->systemctl('start')) === $before + 1, 'wanted but its units are off: the extension is wanted again and a pass is started');
$extension->unitsOff = false;
$server->timerEnabled = false;
$result = $manager->reconcile();
check($server->timerEnabled === true && $result['result'] === 'reconciled', 'the object cache timer is enabled again by a reconcile pass');
$server->timerEnabled = false;
$server->enableFails = true;
$result = $manager->reconcile();
check($result['result'] === 'errors' && $result['errors'][0]['account'] === '(timer)', 'a timer that cannot be enabled is an error of the pass');
$server->enableFails = false;
[$server, $manager, $dir] = $withExtension('ext-idle');
$result = $manager->reconcile();
check(!isset($result['php_extension']), 'no desired accounts: the extension is not looked at');


// The cheap look (lab finding 2026-10-28: wp-cli boots all of WordPress, about 9 s of CPU on a WooCommerce site): LiteSpeed
// Cache's own drop-in and runtime configuration answer without PHP; wp-cli runs only to configure.
[$server, $manager, $dir] = $wpSetup('wp-cheap');
$lscwpDropin = "<?php\n/**\n * Plugin URI: https://www.litespeedtech.com/products/cache-plugins/wordpress-acceleration\n */\n";
$ours = static fn(string $home): string => "<?php exit; ?>\n" . json_encode(['object-kind' => true, 'object-host' => "$home/.ols-objcache/valkey.sock", 'object-port' => 0]);
foreach (['/home/olscpa/public_html', '/home/olscpa/public_html/wp', '/home/olscpa/blog'] as $site) {
    $server->siteFiles[$site] = ['wp-content/object-cache.php' => $lscwpDropin, 'wp-content/.litespeed_conf.php' => $ours('/home/olscpa')];
}
$server->siteFiles['/home/olscpa/blog']['wp-content/object-cache.php'] = "<?php // Redis Object Cache Drop-In\n";
$server->calls = [];
$result = $manager->enable('olscpa', null);
check($sitesOf($result) === ['/home/olscpa/blog' => 'owner', '/home/olscpa/public_html' => 'automatic', '/home/olscpa/public_html/wp' => 'automatic']
    && $server->argvs('/usr/local/bin/wp') === [], 'configured sites and another object cache drop-in are read from files: no wp-cli at all');
$server->siteFiles['/home/olscpa/public_html']['wp-content/.litespeed_conf.php'] = "<?php exit; ?>\n" . json_encode(['object-kind' => true, 'object-host' => '10.0.0.5', 'object-port' => 6379]);
$clock->t += ObjectCacheManager::RECHECK_OK;
$server->calls = [];
$manager->reconcile();
check(ObjectCacheState::load("$dir/objcache.json")->wordpress['olscpa']['/home/olscpa/public_html']['state'] === 'owner'
    && $server->argvs('/usr/local/bin/wp') === [], 'a site owner pointing LiteSpeed Cache elsewhere is seen from the file and left alone');
// Without the plugin directory there is nothing to configure: no wp-cli on any pass.
[$server, $manager, $dir] = $wpSetup('wp-none');
$server->lscwpInstalled = false;
$server->calls = [];
$result = $manager->enable('olscpa', null);
check(array_unique(array_values($sitesOf($result))) === ['inactive'] && $server->argvs('/usr/local/bin/wp') === [], 'sites without LiteSpeed Cache cost no wp-cli');
// Errors back off: 300 s, then 600 s, ... up to a day.
[$server, $manager, $dir] = $wpSetup('wp-backoff');
$server->wpBroken['/home/olscpa/blog'] = true;
$manager->enable('olscpa', null);
$clock->t += ObjectCacheManager::RECHECK_ERROR;
$manager->reconcile();
$row = ObjectCacheState::load("$dir/objcache.json")->wordpress['olscpa']['/home/olscpa/blog'];
check($row['state'] === 'error' && $row['attempts'] === 2, 'a repeated error counts its attempts');
$clock->t += ObjectCacheManager::RECHECK_ERROR;
$server->calls = [];
$manager->reconcile();
check(array_filter($server->argvs('/usr/local/bin/wp'), static fn(array $c): bool => in_array('--path=/home/olscpa/blog', $c, true)) === [],
    'the second retry waits twice as long');
$clock->t += ObjectCacheManager::RECHECK_ERROR;
$manager->reconcile();
check(ObjectCacheState::load("$dir/objcache.json")->wordpress['olscpa']['/home/olscpa/blog']['attempts'] === 3, 'and runs after the doubled interval');

echo "$count assertions passed\n";
