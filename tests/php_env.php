<?php
declare(strict_types=1);

// FV-10 PHP environment: the applier (lsphp, OPcache, redis per EA4 PHP version, state, back-off, units), the CLI,
// the reconciler's lsphp guard (earlier configuration kept, refusal, trigger) and the recommended EA4 profile
// (generation from cPanel's default profile, fallback, write, removal), against temporary trees and a scripted host.
require dirname(__DIR__) . '/src/bootstrap.php';
require __DIR__ . '/LsphpFake.php';

use OlsCpanel\Cli\Application;
use OlsCpanel\Cli\Command;
use OlsCpanel\Cli\Output;
use OlsCpanel\Deployment\Ea4Profile;
use OlsCpanel\Deployment\Environment;
use OlsCpanel\Deployment\Profile;
use OlsCpanel\Events\Reconciler;
use OlsCpanel\Infrastructure\Process\CommandRunner;
use OlsCpanel\Ols\Compiler\CompilationRefused;
use OlsCpanel\Ols\Generation\Engine;
use OlsCpanel\Ols\Generation\GenerationTree;
use OlsCpanel\Php\LsphpGuard;
use OlsCpanel\Php\OpcacheManager;
use OlsCpanel\Php\PhpEnvironment;
use OlsCpanel\PhpExtensions\ExtensionService;

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

function rmtree(string $path): void
{
    if (is_link($path) || is_file($path)) {
        unlink($path);
    } elseif (is_dir($path)) {
        foreach (scandir($path) as $name) {
            if ($name !== '.' && $name !== '..') {
                rmtree("$path/$name");
            }
        }
        rmdir($path);
    }
}

$base = sys_get_temp_dir() . '/ols-php-env-' . bin2hex(random_bytes(6));
mkdir($base, 0755, true);
register_shutdown_function(static fn() => rmtree($base));

/** A server in memory and on disk: EA4 PHP versions, packages, OPcache, units, accounts. */
final class Host implements CommandRunner
{
    /** @var array<string,bool> package => installed */
    public array $packages = [];
    /** @var array<string,bool> package => dnf fails for it */
    public array $dnfFails = [];
    /** @var array<string,bool> version => OPcache loaded */
    public array $opcache = [];
    /** @var array<string,bool> unit => enabled */
    public array $units = [];
    /** @var array<string,list<int>> */
    public array $lsphp = ['olscpa' => [11]];
    /** @var array<int,int> pid => start time */
    public array $starts = [];
    public bool $stubborn = false;
    /** @var array<int,string|null> pid => /proc/PID/environ content (null: unreadable) */
    public array $environs = [];
    /** @var array<string,int> account => uid */
    public array $uids = ['olscpa' => 1001, 'olscpb' => 1002];
    /** @var \Closure(int,string):(bool|null)|null */
    public ?\Closure $onSignal = null;
    public bool $enableFails = false;
    /** @var list<list<string>> */
    public array $calls = [];

    public function __construct(public string $opt)
    {
    }

    /** Adds an installed version; $lsphp: lsphp present, $opcache: OPcache already loaded. */
    public function version(string $v, bool $lsphp, bool $opcache): void
    {
        mkdir("{$this->opt}/$v/root/usr/bin", 0755, true);
        mkdir("{$this->opt}/$v/root/etc/php.d", 0755, true);
        touch("{$this->opt}/$v/root/usr/bin/php");
        if ($lsphp) {
            touch("{$this->opt}/$v/root/usr/bin/lsphp");
            chmod("{$this->opt}/$v/root/usr/bin/lsphp", 0755);
            $this->packages["$v-php-litespeed"] = true;
        }
        $this->opcache[$v] = $opcache;
        $this->packages["$v-php-opcache"] = $opcache;
    }

    public function count(string $binary, ?string $word = null): int
    {
        return count(array_filter($this->calls, static fn(array $c): bool => $c[0] === $binary && ($word === null || ($c[1] ?? '') === $word)));
    }

    public function run(string $name, array $argv, int $timeout): array
    {
        $this->calls[] = $argv;
        $ok = static fn(string $out = ''): array => ['exit_code' => 0, 'stdout' => $out, 'stderr' => ''];
        $no = static fn(int $code = 1, string $out = '', string $err = ''): array => ['exit_code' => $code, 'stdout' => $out, 'stderr' => $err];
        $args = array_slice($argv, 1);
        if (preg_match('~^' . preg_quote($this->opt, '~') . '/(ea-php\d+)/root/usr/bin/(php|lsphp)$~', $argv[0], $m) === 1) {
            if ($m[2] === 'lsphp') {
                return $ok("PHP 8.3.1 (litespeed)\n");
            }
            return $this->phpInfo($m[1]);
        }
        switch ($argv[0]) {
            case '/usr/bin/rpm':
                return ($this->packages[end($args)] ?? false) ? $ok(end($args) . "-1.el9\n") : $no(1, 'package ' . end($args) . " is not installed\n");
            case '/usr/bin/dnf':
                $package = $args[2];
                if ($this->dnfFails[$package] ?? false) {
                    return $no(1, '', "Error: Unable to find a match: $package\n");
                }
                $this->packages[$package] = true;
                $version = substr($package, 0, strlen('ea-php83'));
                if (str_ends_with($package, '-php-litespeed')) {
                    touch("{$this->opt}/$version/root/usr/bin/lsphp");
                    chmod("{$this->opt}/$version/root/usr/bin/lsphp", 0755);
                } elseif (str_ends_with($package, '-php-opcache')) {
                    $this->opcache[$version] = true;
                }
                return $ok("Complete!\n");
            case '/usr/bin/systemctl':
                $unit = (string) end($args);
                if ($args[0] === 'is-enabled') {
                    return ($this->units[$unit] ?? false) ? $ok() : $no(1);
                }
                if ($args[0] === 'enable') {
                    if ($this->enableFails) {
                        return $no(1, '', "Failed to enable unit\n");
                    }
                    $this->units[$unit] = true;
                    return $ok();
                }
                throw new LogicException('unexpected systemctl ' . implode(' ', $args));
            case '/usr/bin/id':
                return isset($this->uids[$args[1]]) ? $ok($this->uids[$args[1]] . "\n") : $no(1);
            case '/usr/bin/pgrep':
            case '/usr/bin/cat':
            case '/usr/bin/kill':
                return LsphpFake::handle($this->lsphp, $this->starts, $this->stubborn, $argv, $this->onSignal, [], $this->environs);
        }
        throw new LogicException('unexpected command ' . implode(' ', $argv));
    }

    private function phpInfo(string $version): array
    {
        $out = "phpinfo()\nPHP Version => 8.3.1\n";
        if ($this->opcache[$version] ?? false) {
            $values = ['enable' => 'On', 'validate_root' => 'Off', 'validate_permission' => 'On', 'memory_consumption' => '128',
                'max_accelerated_files' => '10000', 'revalidate_freq' => '2'];
            $ini = "{$this->opt}/$version/root/etc/php.d/" . OpcacheManager::INI;
            foreach (is_file($ini) ? file($ini, FILE_IGNORE_NEW_LINES) : [] as $line) {
                if (preg_match('/^opcache\.([a-z_]+)=(.*)$/', $line, $m) === 1) {
                    $values[$m[1]] = in_array($m[1], ['enable', 'validate_root', 'validate_permission'], true) ? ($m[2] === '1' ? 'On' : 'Off') : $m[2];
                }
            }
            foreach ($values as $key => $value) {
                $out .= "opcache.$key => $value => $value\n";
            }
        }
        return ['exit_code' => 0, 'stdout' => $out, 'stderr' => ''];
    }
}

/** The redis layer, scripted. */
final class Redis implements ExtensionService
{
    public bool $wanted = false;
    /** @var array<string,bool> */
    public array $loaded = [];
    /** @var array<string,string> version => failure message */
    public array $fails = [];
    /** @var list<list<string>> */
    public array $ensured = [];
    public int $wants = 0;
    /** @var array<string,array<string,mixed>> version => extra status fields */
    public array $rows = [];

    public function status(): array
    {
        $rows = [];
        foreach ($this->loaded as $php => $loaded) {
            $rows[] = ['php' => $php, 'loaded' => $loaded] + ($this->rows[$php] ?? []);
        }
        return ['result' => 'status', 'wanted' => $this->wanted, 'versions' => $rows];
    }

    public function ensureVersions(array $versions): array
    {
        $this->ensured[] = $versions;
        $rows = [];
        $changed = [];
        foreach ($versions as $v) {
            if (isset($this->fails[$v])) {
                $rows[] = ['php' => $v, 'status' => 'failed', 'message' => $this->fails[$v]];
                continue;
            }
            $this->loaded[$v] = true;
            $rows[] = ['php' => $v, 'status' => 'activated'];
            $changed[] = $v;
        }
        return ['result' => 'activated', 'versions' => $rows, 'changed' => $changed, 'restart' => $changed === [] ? [] : ['olscpa' => ['result' => 'restarted']]];
    }

    public function ensureForAccount(string $user, array $versions): array
    {
        return [];
    }

    public function sync(): array
    {
        return ['result' => 'idle'];
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
        $this->wanted = true;
        ++$this->wants;
    }
}

$clock = 1_800_000_000;
/** @return array{0:Host, 1:Redis, 2:Environment, 3:OpcacheManager, 4:PhpEnvironment} */
$world = static function (string $name) use ($base, &$clock): array {
    $dir = "$base/$name";
    mkdir("$dir/state", 0755, true);
    mkdir("$dir/opt", 0755, true);
    file_put_contents("$dir/userdatadomains",
        "a.test: olscpa==root==main==a.test==/home/olscpa/public_html==1.2.3.4:80==1.2.3.4:443====0==ea-php83\n"
        . "b.test: olscpb==root==main==b.test==/home/olscpb/public_html==1.2.3.4:80==1.2.3.4:443====0==ea-php84\n");
    $host = new Host("$dir/opt");
    $env = new Environment($host, "$dir/state", null, null, true, null, static function (float $s): void {
    }, static function () use (&$clock): int {
        return $clock;
    }, phpRoot: "$dir/opt");
    $opcache = new OpcacheManager($env, "$dir/opt", "$dir/userdatadomains");
    $redis = new Redis();
    return [$host, $redis, $env, $opcache, new PhpEnvironment($env, $opcache, $redis, $env->ea4Profile(), "$dir/opt")];
};

// ---- one pass: lsphp, OPcache and redis for every version ----------------------------------------------------------
[$host, $redis, $env, $opcache, $applier] = $world('main');
$host->version('ea-php83', false, false);   // lsphp and OPcache missing: a version a profile just installed
$host->version('ea-php84', true, true);     // complete except the tuning
$redis->loaded = ['ea-php83' => false, 'ea-php84' => false];
$redis->wanted = true;
$status = $applier->status();
check(array_column($status['versions'], 'status', 'version') === ['ea-php83' => 'pending', 'ea-php84' => 'pending'] && $status['checked_at'] === null
    && $status['versions'][0]['lsphp'] === false && $status['units'] === ['watcher' => false, 'timer' => false], 'before the first pass: pending, units off');
$report = $applier->sync();
$rows = array_column($report['versions'], null, 'version');
check($report['result'] === 'repaired' && $rows['ea-php83']['status'] === 'complete' && $rows['ea-php83']['lsphp'] === true
    && $rows['ea-php83']['opcache'] === 'repaired' && $rows['ea-php83']['redis'] === 'repaired' && $rows['ea-php84']['status'] === 'complete'
    && $rows['ea-php84']['opcache'] === 'repaired' && $rows['ea-php84']['redis'] === 'repaired', 'every version is brought complete');
check(in_array(['/usr/bin/dnf', '-y', 'install', 'ea-php83-php-litespeed'], $host->calls, true)
    && in_array(['/usr/bin/dnf', '-y', 'install', 'ea-php83-php-opcache'], $host->calls, true)
    && !in_array(['/usr/bin/dnf', '-y', 'install', 'ea-php84-php-litespeed'], $host->calls, true), 'dnf installs only what is missing, with a fixed argv');
check($redis->ensured === [['ea-php83', 'ea-php84']] && (fileperms("$base/main/opt/ea-php83/root/usr/bin/lsphp") & 0111) !== 0, 'redis step for the versions that lack it; lsphp executable');
check(in_array('olscpa', $rows['ea-php83']['restarted'], true) && in_array('olscpb', $rows['ea-php84']['restarted'], true), 'restarts are recorded per version');
check($host->units === ['ols-cpanel-php.path' => true, 'ols-cpanel-php.timer' => true] && $report['units'] === true, 'the path watcher and the timer are enabled by the pass');
$state = json_decode((string) file_get_contents("$base/main/state/php-env.json"), true);
check($state['schema_version'] === 1 && $state['versions']['ea-php83']['status'] === 'complete' && $state['versions']['ea-php83']['error'] === null
    && $state['checked_at'] === $clock && !isset($state['versions']['ea-php83']['restarted']), 'one state file, complete per version');
check((fileperms("$base/main/state/php-env.json") & 0777) === 0644, 'state file mode');
$host->calls = [];
$again = $applier->sync();
check($again['result'] === 'unchanged' && $host->count('/usr/bin/dnf') === 0 && $host->count('/usr/bin/pkill') === 0 && count($redis->ensured) === 1, 'a complete host: nothing installed, nothing restarted');
$status = $applier->status();
check(array_column($status['versions'], 'status', 'version') === ['ea-php83' => 'complete', 'ea-php84' => 'complete']
    && $status['units'] === ['watcher' => true, 'timer' => true] && $status['opcache_auto'] === true, 'status after the pass');
// Only the accounts on a changed version restart.
$host->version('ea-php85', true, true);
file_put_contents("$base/main/userdatadomains", file_get_contents("$base/main/userdatadomains")
    . "c.test: olscpc==root==main==c.test==/home/olscpc/public_html==1.2.3.4:80==1.2.3.4:443====0==ea-php85\n");
$redis->loaded['ea-php85'] = true;
$host->lsphp = ['olscpa' => [11], 'olscpb' => [21]];
unlink("$base/main/opt/ea-php84/root/etc/php.d/" . OpcacheManager::INI);
$host->opcache['ea-php84'] = true;
$report = $applier->sync();
check($report['result'] === 'repaired' && $host->lsphp === ['olscpa' => [11], 'olscpb' => []], 'PHP restarts only for the accounts on the version that changed');

// ---- failure: reported, back-off, repair ignores it -----------------------------------------------------------------
[$host, $redis, $env, $opcache, $applier] = $world('failing');
$host->version('ea-php83', true, true);
$host->version('ea-php85', false, true);
$host->dnfFails['ea-php85-php-litespeed'] = true;
$redis->wanted = false;
$applier->sync();
$report = $applier->sync();
$bad = array_column($report['versions'], null, 'version')['ea-php85'];
check($report['result'] === 'failed' && $bad['status'] === 'failed' && $bad['attempts'] === 1 && $bad['retry_at'] === $clock + 60
    && str_contains($bad['error'], 'dnf could not install ea-php85-php-litespeed') && ($bad['waiting'] ?? false) === true, 'failure: reason, attempts, retry time; waiting within the back-off');
check($host->count('/usr/bin/dnf') === 1, 'within the back-off dnf is not run again');
$status = $applier->status();
check($status['versions'][1]['status'] === 'failed' && $status['versions'][1]['retry_at'] === $clock + 60 && $status['versions'][0]['status'] === 'complete', 'status reports the failure');
$clock += 61;
$report = $applier->sync();
check($host->count('/usr/bin/dnf') === 2 && array_column($report['versions'], null, 'version')['ea-php85']['attempts'] === 2
    && array_column($report['versions'], null, 'version')['ea-php85']['retry_at'] === $clock + 300, 'after the back-off the version is retried; the next wait grows');
$report = $applier->repair();
check($host->count('/usr/bin/dnf') === 3 && array_column($report['versions'], null, 'version')['ea-php85']['attempts'] === 3
    && array_column($report['versions'], null, 'version')['ea-php85']['retry_at'] === $clock + 900 && $report['forced'] === true, 'repair retries at once, ignoring the back-off');
$host->dnfFails = [];
$report = $applier->repair();
check($report['result'] === 'repaired' && array_column($report['versions'], null, 'version')['ea-php85']['status'] === 'complete'
    && array_column($report['versions'], null, 'version')['ea-php85']['attempts'] === 0, 'a repaired version is complete and its attempts reset');
// Several failures in one version are all reported; a stale "repairing" record is shown as failed.
$host->version('ea-php86', false, false);
$host->dnfFails = ['ea-php86-php-litespeed' => true, 'ea-php86-php-opcache' => true];
$report = $applier->sync();
$row = array_column($report['versions'], null, 'version')['ea-php86'];
check($row['status'] === 'failed' && str_contains($row['error'], 'ea-php86-php-litespeed') && str_contains($row['error'], 'OPcache:'), 'every failing step is reported');
file_put_contents("$base/failing/state/php-env.json", json_encode(['schema_version' => 1, 'checked_at' => $clock, 'profile_error' => null,
    'versions' => ['ea-php83' => ['version' => 'ea-php83', 'php' => '8.3', 'status' => 'repairing', 'checked_at' => $clock - 9000, 'since' => $clock - 9000, 'error' => null]]]));
check($applier->status()['versions'][0]['status'] === 'failed', 'an interrupted pass is shown as failed');
file_put_contents("$base/failing/state/php-env.json", '{not json');
check(array_column($applier->status()['versions'], 'status')[0] === 'pending' && $applier->sync()['result'] !== null, 'a damaged state file is treated as empty and rewritten');

// ---- RV-31 item 8: owed lsphp restarts are persisted per version and retried -------------------------------------------------
[$host, $redis, $env, $opcache, $applier] = $world('owed');
$host->version('ea-php83', true, true);
$host->units = ['ols-cpanel-php.path' => true, 'ols-cpanel-php.timer' => true];
unlink("$base/owed/userdatadomains");
file_put_contents("$base/owed/userdatadomains",
    "a.test: olscpa==root==main==a.test==/home/olscpa/public_html==1.2.3.4:80==1.2.3.4:443====0==ea-php83\n"
    . "b.test: olscpb==root==main==b.test==/home/olscpb/public_html==1.2.3.4:80==1.2.3.4:443====0==ea-php83\n"
    . "c.test: olscpc==root==main==c.test==/home/olscpc/public_html==1.2.3.4:80==1.2.3.4:443====0==ea-php84\n");
$host->lsphp = ['olscpa' => [11], 'olscpb' => [21], 'olscpc' => [31]];
$blocked = true;
$host->onSignal = static function (int $pid, string $signal) use (&$blocked): ?bool {
    return $pid === 11 && $blocked ? true : null;  // olscpa's worker cannot be ended for now
};
$report = $applier->sync();
$row = array_column($report['versions'], null, 'version')['ea-php83'];
check($report['result'] === 'failed' && $row['status'] === 'failed' && str_contains($row['error'], 'lsphp restart pending (ea-php83: olscpa)')
    && $host->lsphp['olscpb'] === [] && $host->lsphp['olscpc'] === [31] && $host->lsphp['olscpa'] === [11],
    'a change to a version restarts ALL its accounts (not other versions); the one that fails is reported and the version is failed');
$state = json_decode((string) file_get_contents("$base/owed/state/php-env.json"), true);
check(array_keys($state['restarts']['ea-php83']['accounts']) === ['olscpa'] && str_starts_with($state['restarts']['ea-php83']['accounts']['olscpa'], 'opcache:')
    && $state['restarts']['ea-php83']['unresolved'] === false && $state['versions']['ea-php83']['status'] === 'failed' && $state['schema_version'] === 1,
    'the owed restart is stored per account and revision in the PHP environment state, next to the version rows');
check($applier->status()['restarts'] === [['version' => 'ea-php83', 'accounts' => ['olscpa'], 'unresolved' => false, 'since' => $clock]], 'status lists what is owed');
$blocked = false;
$report = $applier->sync();  // still inside the version back-off, but the owed restart is retried by every pass
$state = json_decode((string) file_get_contents("$base/owed/state/php-env.json"), true);
check($host->lsphp['olscpa'] === [] && $state['restarts'] === [] && $applier->status()['restarts'] === [], 'the applier retries the owed restart even within a back-off, and clears it only after it succeeded');
$clock += 61;
$report = $applier->sync();
check($report['result'] === 'unchanged' || $report['result'] === 'repaired', 'the version is complete again after its back-off: ' . $report['result']);
check(array_column($applier->status()['versions'], 'status', 'version') === ['ea-php83' => 'complete'], 'and reported complete');
// A reused pid or a restart owed for an account that vanished does not block forever.
$host->lsphp = ['olscpa' => [11]];
unlink("$base/owed/opt/ea-php83/root/etc/php.d/" . OpcacheManager::INI);
$host->opcache['ea-php83'] = true;
$report = $applier->sync();
check($host->lsphp === ['olscpa' => []] && $applier->status()['restarts'] === [], 'a retuned version restarts its accounts again (a new revision)');
// An unreadable domain list is "unknown accounts", retried, never "no accounts".
rename("$base/owed/userdatadomains", "$base/owed/userdatadomains.off");
unlink("$base/owed/opt/ea-php83/root/etc/php.d/" . OpcacheManager::INI);
$clock += 4000;
$report = $applier->sync();
$status = $applier->status();
check($report['result'] === 'failed' && $status['restarts'] === [['version' => 'ea-php83', 'accounts' => [], 'unresolved' => true, 'since' => $clock]]
    && str_contains(array_column($report['versions'], null, 'version')['ea-php83']['error'], 'accounts not enumerable'), 'accounts that cannot be listed leave the restart unresolved and the version failed');
rename("$base/owed/userdatadomains.off", "$base/owed/userdatadomains");
$host->lsphp = ['olscpa' => [12], 'olscpb' => [22]];
$clock += 4000;
$report = $applier->sync();
check($host->lsphp === ['olscpa' => [], 'olscpb' => []] && $applier->status()['restarts'] === [], 'once the list is readable the unresolved restart completes for every account');

// ---- RV-31 item 11: the units that retry failures must be enabled -------------------------------------------------------------------------
[$host, $redis, $env, $opcache, $applier] = $world('units');
$host->version('ea-php83', true, true);
$host->enableFails = true;
$report = $applier->sync();
check($report['result'] === 'failed' && $report['units'] === false && str_contains((string) $report['units_error'], 'nothing would retry it'), 'units that cannot be enabled fail the pass');
$host->enableFails = false;
$report = $applier->sync();
check($report['units'] === true && $host->units === ['ols-cpanel-php.path' => true, 'ols-cpanel-php.timer' => true] && $report['units_error'] === null, 'the next pass enables the path watcher and the timer again');
$host->units = [];  // an administrator disabled them
$applier->sync();
check($host->units === ['ols-cpanel-php.path' => true, 'ols-cpanel-php.timer' => true], 'units that were disabled are enabled again by the next pass');

// ---- unsupported redis versions and replaced artifacts ---------------------------------------------------------------------------------------
[$host, $redis, $env, $opcache, $applier] = $world('unsupp');
$host->version('ea-php83', true, true);
$host->version('ea-php84', true, true);
$redis->wanted = true;
$redis->loaded = ['ea-php83' => false, 'ea-php84' => true];
$redis->rows = ['ea-php83' => ['status' => 'unsupported'], 'ea-php84' => ['replaced' => true]];
$report = $applier->sync();
$rows = array_column($report['versions'], null, 'version');
check($rows['ea-php83']['redis'] === 'unsupported' && $rows['ea-php83']['status'] === 'complete' && $report['result'] !== 'failed'
    && $redis->ensured === [['ea-php84']] && $rows['ea-php84']['redis'] === 'repaired', 'an unsupported PHP is reported as such and is not a failure; a replaced artifact is handed to the redis layer');

// ---- OPcache opt-out, redis not wanted, prepare -----------------------------------------------------------------------
[$host, $redis, $env, $opcache, $applier] = $world('optout');
$host->version('ea-php83', false, false);
file_put_contents("$base/optout/state/php-opcache.json", '{"auto": false}');
$report = $applier->sync();
$row = $report['versions'][0];
check($row['status'] === 'complete' && $row['opcache'] === 'off' && $row['redis'] === 'not_wanted' && $host->opcache['ea-php83'] === false
    && $redis->ensured === [], 'opted out of OPcache and redis not wanted: lsphp only');
$report = $applier->prepare();
check($redis->wants === 1 && $redis->wanted && $report['units'] === true, 'prepare wants redis and enables the units');
unlink("$base/optout/state/php-opcache.json");
// Version with no lsphp binary at all and no php: not listed.
mkdir("$base/optout/opt/ea-php99/root/usr/bin", 0755, true);
check(array_column($applier->status()['versions'], 'version') === ['ea-php83'], 'a directory without a PHP binary is not a version');

// ---- CLI -------------------------------------------------------------------------------------------------------------------
[$host, $redis, $env, $opcache, $applier] = $world('cli');
$host->version('ea-php83', true, true);
$run = static function (array $argv, Environment $e) use ($applier): array {
    $stdout = fopen('php://memory', 'w+');
    $app = new Application([new Command\PhpEnvCommand($argv[2], static fn(): Environment => $e, static fn(Environment $x): PhpEnvironment => $applier)]);
    $code = $app->run([...$argv, '--format=json'], new Output(true, $stdout, fopen('php://memory', 'w+')));
    rewind($stdout);
    return [$code, json_decode((string) stream_get_contents($stdout), true)];
};
[$code, $out] = $run(['php', 'env', 'status'], $env);
check($code === 0 && $out['command'] === 'php env status' && $out['versions'][0]['version'] === 'ea-php83', 'php env status');
[$code, $out] = $run(['php', 'env', 'repair'], $env);
check($code === 0 && $out['command'] === 'php env repair' && $out['forced'] === true, 'php env repair');
[$code, $out] = $run(['php', 'env', 'sync'], $env);
check($code === 0 && $out['result'] === 'unchanged' && $out['forced'] === false, 'php env sync');
$host->version('ea-php85', false, true);
$host->dnfFails['ea-php85-php-litespeed'] = true;
[$code, $out] = $run(['php', 'env', 'sync'], $env);
check($code === 1 && $out['result'] === 'failed', 'a failed pass exits 1 (the service unit shows failed)');
[$code, $out] = $run(['php', 'env', 'sync'], new Environment($host, "$base/cli/state", null, null, false));
check($code === 1 && ($out['error'] ?? '') !== '', 'not root: refused');

// ---- LsphpGuard and the reconciler ------------------------------------------------------------------------------------------
$vhconf = static fn(string $name, string $php): string => "docRoot                  /home/$name/public_html/\nvhDomain                 $name.test\n"
    . "extProcessor $name-php {\n    type                 lsapi\n    path                 /opt/cpanel/$php/root/usr/bin/lsphp\n    extUser              $name\n}\n"
    . "rewrite {\n    enable               1\n    rules                <<<END_rules\nRewriteRule ^x$ /y [L]\nEND_rules\n}\n";
$compile = static function (string $phpA, string $phpB, string $mode = 'native') use ($vhconf): array {
    return ['config' => "listener http {\n    address              127.0.0.1:80\n    secure               0\n    map                  a.test a.test\n"
        . "    map                  b.test b.test\n}\n",
        'vhconf' => ['a.test' => $vhconf('a', $phpA), 'b.test' => $vhconf('b', $phpB)],
        'plan' => ['a.test' => ['php' => $phpA, 'mode' => 'native', 'ip' => ''], 'b.test' => ['php' => $phpB, 'mode' => $mode, 'ip' => '']],
        'summary' => ['vhosts' => ['a.test' => ['php' => $phpA], 'b.test' => ['php' => $phpB]], 'php_versions' => ['a' => $phpA, 'b' => $phpB]]];
};
$opt = "$base/guard/opt";
$state = "$base/guard/state";
mkdir($state, 0755, true);
foreach (['ea-php83', 'ea-php84'] as $v) {
    mkdir("$opt/$v/root/usr/bin", 0755, true);
    touch("$opt/$v/root/usr/bin/lsphp");
    chmod("$opt/$v/root/usr/bin/lsphp", 0755);
}
$triggered = [];
$guard = new LsphpGuard($opt, $state, static function (array $versions) use (&$triggered): void {
    $triggered[] = $versions;
});
check($guard->usable('ea-php83') && !$guard->usable('ea-php85') && !$guard->usable('../x') && !$guard->usable('ea-php8'), 'usable: lsphp present and executable, version name checked');
[$same, $kept] = $guard->apply($compile('ea-php83', 'ea-php84'));
check($kept === [] && $triggered === [] && $same['vhconf']['a.test'] === $vhconf('a', 'ea-php83'), 'every version usable: untouched, no trigger');
// No active generation: a vhost on a missing version refuses the compilation with a reason, and triggers the applier.
try {
    $guard->apply($compile('ea-php83', 'ea-php85'));
    check(false, 'no earlier configuration: refused');
} catch (CompilationRefused $error) {
    check(str_contains($error->getMessage(), 'no usable lsphp for ea-php85') && str_contains($error->getMessage(), 'b.test') && $error->vhosts() === ['b.test']
        && $triggered === [['ea-php85']], 'no earlier configuration: refused with the reason, applier triggered');
}
// An active generation from the first (good) compile.
$tree = new GenerationTree("$state/generations", null, static fn(): int => 1_800_000_000);
$good = $compile('ea-php83', 'ea-php84');
$id = 'r20261022120000-0a1b2c';
$built = $tree->build($good, $id);
foreach ($built['files'] as $path => $text) {
    @mkdir(dirname("$state/generations/$id/$path"), 0755, true);
    file_put_contents("$state/generations/$id/$path", $text);
}
symlink("generations/$id", "$state/active");
check(str_contains(file_get_contents("$state/generations/$id/vhosts/b.test/vhconf.conf"), '.ols-cpanel-generation'), 'the active vhconf carries the tree\'s health additions');
check($guard->previous('b.test') === $good['vhconf']['b.test'], 'the earlier configuration is recovered byte for byte (health additions removed)');
$triggered = [];
// b.test is switched to a version without lsphp (PHP 8.5): it keeps its earlier configuration, a.test is compiled as new.
[$result, $kept] = $guard->apply($compile('ea-php83', 'ea-php85'));
check($kept === [['vhost' => 'b.test', 'php' => 'ea-php85', 'action' => 'kept_previous']] && $result['vhconf']['b.test'] === $good['vhconf']['b.test']
    && $result['vhconf']['a.test'] === $good['vhconf']['a.test'] && $triggered === [['ea-php85']], 'a vhost on an incomplete version keeps its working configuration; trigger');
check($tree->build($result, $id)['files']['vhosts/b.test/vhconf.conf'] === $built['files']['vhosts/b.test/vhconf.conf'],
    'the tree built from the kept configuration reproduces that vhost exactly');
// A hybrid vhost (served by Apache) does not use lsphp.
$triggered = [];
[, $kept] = $guard->apply($compile('ea-php83', 'ea-php85', 'apache'));
check($kept === [] && $triggered === [], 'a hybrid vhost served by Apache is not checked');
// The earlier configuration itself points at a version that is gone too: refused.
unlink("$opt/ea-php84/root/usr/bin/lsphp");
try {
    $guard->apply($compile('ea-php83', 'ea-php85'));
    check(false, 'the earlier configuration is unusable too: refused');
} catch (CompilationRefused $error) {
    check($error->vhosts() === ['b.test'], 'the earlier configuration is unusable too: refused');
}
touch("$opt/ea-php84/root/usr/bin/lsphp");
chmod("$opt/ea-php84/root/usr/bin/lsphp", 0644);
check(!$guard->usable('ea-php84'), 'a non-executable lsphp is not usable');
chmod("$opt/ea-php84/root/usr/bin/lsphp", 0755);

/** A minimal engine: the compile is canned, activation records the files. */
final class MiniEngine implements Engine
{
    /** @var list<array<string,string>> */
    public array $applied = [];

    public function run(string $name, array $argv, int $timeout): array
    {
        return ['exit_code' => 0, 'stdout' => hash('sha256', $argv[count($argv) - 1]) . "  x\n"];
    }

    public function apply(string $generation, array $files, array $health, int $epoch, string $sourceSha256): array
    {
        $this->applied[] = $files;
        return ['generation' => $generation, 'valid' => true, 'result' => 'committed', 'reason' => null];
    }

    public function status(): array
    {
        return ['coherent' => true, 'epoch' => 1, 'source_sha256' => null];
    }

    public function health(int $seconds): array
    {
        return ['generation' => null, 'failing' => []];
    }

    public function enforce(int $grace): array
    {
        return [];
    }

    public function recover(int $grace): array
    {
        return ['actions' => []];
    }

    public function pendingEvents(): array
    {
        return [];
    }

    public function eventsDone(array $names): array
    {
        return $names;
    }

    public function eventsQuarantine(array $names): array
    {
        return $names;
    }

    public function foldRestrictions(): array
    {
        return ['folded' => [], 'epoch' => null];
    }
}

$engine = new MiniEngine();
$current = $compile('ea-php83', 'ea-php85');
$reconciler = new Reconciler($engine, static fn(Profile $p, Engine $e): array => $current, null, new Profile(true, null), '/nonexistent', null, null, null,
    static fn(): string => 'r20261022140000-0a1b2e', null, $guard);
$triggered = [];
$pass = $reconciler->reconcile();
check($pass['action'] === 'committed' && $pass['php_kept'] === [['vhost' => 'b.test', 'php' => 'ea-php85', 'action' => 'kept_previous']]
    && str_contains($engine->applied[0]['vhosts/b.test/vhconf.conf'], '/opt/cpanel/ea-php84/root/usr/bin/lsphp')
    && !str_contains($engine->applied[0]['vhosts/b.test/vhconf.conf'], 'ea-php85'), 'reconciler: the broken vhost is activated with its earlier configuration, never a missing lsphp');
// The applier completes the version; the next pass compiles it for real.
mkdir("$opt/ea-php85/root/usr/bin", 0755, true);
touch("$opt/ea-php85/root/usr/bin/lsphp");
chmod("$opt/ea-php85/root/usr/bin/lsphp", 0755);
$pass = $reconciler->reconcile();
check(!isset($pass['php_kept']) && str_contains($engine->applied[1]['vhosts/b.test/vhconf.conf'], '/opt/cpanel/ea-php85/root/usr/bin/lsphp'),
    'reconciler: once lsphp exists the vhost is compiled with its new version');
// A refusal reaches the caller as a CompilationRefused (nothing is activated).
unlink("$state/active");
rmtree("$state/generations");
unlink("$opt/ea-php85/root/usr/bin/lsphp");
$applied = count($engine->applied);
try {
    $reconciler->reconcile();
    check(false, 'reconciler: no earlier configuration is refused');
} catch (CompilationRefused $error) {
    check(count($engine->applied) === $applied && str_contains($error->getMessage(), 'no usable lsphp'), 'reconciler: no earlier configuration is refused, nothing activated');
}

// ---- the recommended EA4 profile -------------------------------------------------------------------------------------------------
$default = ['desc' => 'standard', 'name' => 'cPanel Default', 'pkgs' => ['ea-apache24', 'ea-apr', 'ea-apr-util', 'ea-apache24-mod_mpm_prefork', 'ea-apache24-mod_ruid2',
    'ea-apache24-mod_ssl', 'ea-nginx', 'ea-php82', 'ea-php82-php-bcmath', 'ea-php82-php-imap', 'ea-php82-runtime', 'ea-php82-php-fpm', 'ea-php83', 'ea-php83-php-bcmath',
    'ea-php83-php-imap', 'ea-php83-runtime', 'ea-php83-php-fpm'], 'tags' => ['Apache 2.4', 'PHP 8.2', 'PHP 8.3'], 'version' => 1.3];
$offered = ['ea-apache24', 'ea-apr', 'ea-apr-util', 'ea-apache24-mod_mpm_prefork', 'ea-apache24-mod_ruid2', 'ea-apache24-mod_ssl', 'ea-nginx'];
foreach (['81', '82', '83', '84', '85'] as $d) {
    array_push($offered, "ea-php$d", "ea-php$d-php-bcmath", "ea-php$d-runtime", "ea-php$d-php-fpm", "ea-php$d-php-litespeed");
    if ($d !== '85') {
        array_push($offered, "ea-php$d-php-opcache", "ea-php$d-php-imap");
    }
}
$profile = Ea4Profile::build($default, $offered);
check(array_keys($profile) === array_keys($default) || (array_diff(array_keys($profile), array_keys($default)) === [] && array_diff(array_keys($default), array_keys($profile)) === []),
    'the schema is cPanel\'s own: name, desc, version, tags, pkgs');
check($profile['name'] === Ea4Profile::NAME && is_float($profile['version']) && is_array($profile['tags']) && array_is_list($profile['pkgs']), 'profile fields');
check(!in_array('ea-nginx', $profile['pkgs'], true) && in_array('ea-apache24-mod_ruid2', $profile['pkgs'], true)
    && array_slice($profile['pkgs'], 0, 6) === ['ea-apache24', 'ea-apr', 'ea-apr-util', 'ea-apache24-mod_mpm_prefork', 'ea-apache24-mod_ruid2', 'ea-apache24-mod_ssl'],
    'Apache base as in the default profile, no ea-nginx');
foreach (['81', '82', '83', '84', '85'] as $d) {
    check(in_array("ea-php$d", $profile['pkgs'], true) && in_array("ea-php$d-php-litespeed", $profile['pkgs'], true)
        && in_array("ea-php$d-php-fpm", $profile['pkgs'], true) && in_array("ea-php$d-php-bcmath", $profile['pkgs'], true)
        && in_array("ea-php$d-php-opcache", $profile['pkgs'], true) === ($d !== '85'), "PHP $d: extension set, lsphp, opcache (not for the built-in 8.5)");
}
check(!in_array('ea-php85-php-imap', $profile['pkgs'], true) && in_array('ea-php84-php-imap', $profile['pkgs'], true), 'packages EasyApache does not offer are left out');
check($profile['tags'] === ['Apache 2.4', 'PHP 8.1', 'PHP 8.2', 'PHP 8.3', 'PHP 8.4', 'PHP 8.5', 'OpenLiteSpeed'], 'tags');
check(count($profile['pkgs']) === count(array_unique($profile['pkgs'])), 'no duplicate package');
$partial = Ea4Profile::build($default, array_values(array_filter($offered, static fn(string $p): bool => !str_starts_with($p, 'ea-php85'))));
check(!in_array('PHP 8.5', $partial['tags'], true) && array_filter($partial['pkgs'], static fn(string $p): bool => str_starts_with($p, 'ea-php85')) === [], 'a PHP version EasyApache does not offer is skipped');
$fallback = Ea4Profile::build(null, null);
check(in_array('ea-apache24-mod_security2', $fallback['pkgs'], true) && in_array('ea-php81-php-litespeed', $fallback['pkgs'], true)
    && in_array('ea-php85-php-litespeed', $fallback['pkgs'], true) && in_array('ea-php81-php-opcache', $fallback['pkgs'], true)
    && !in_array('ea-php85-php-opcache', $fallback['pkgs'], true) && !in_array('ea-nginx', $fallback['pkgs'], true), 'built-in lists without the server\'s default profile');
check(Ea4Profile::available(['EA4' => ['CentOS_9' => ['ea-php83'], 'Almalinux_10' => ['ea-php85']]], 'almalinux', '9.8') === ['ea-php83']
    && Ea4Profile::available(['EA4' => ['CentOS_9' => ['ea-php83'], 'Almalinux_10' => ['ea-php85']]], 'almalinux', '10.1') === ['ea-php85']
    && Ea4Profile::available(['EA4' => ['CentOS_9' => []]], 'ubuntu', '22.04') === null && Ea4Profile::available(null, 'almalinux', '9') === null, 'OS section of the package manifest');
// Written from the files of the server, atomically; rewritten only when different; removed only when ours.
$ea4 = "$base/ea4";
mkdir("$ea4/cpanel", 0755, true);
file_put_contents("$ea4/cpanel/default.json", json_encode($default));
file_put_contents("$ea4/pkg-manifest.json", json_encode(['EA4' => ['CentOS_9' => $offered]]));
file_put_contents("$base/os-release", "NAME=\"AlmaLinux\"\nID=\"almalinux\"\nVERSION_ID=\"9.8\"\n");
$file = new Ea4Profile($ea4, "$base/os-release");
$written = $file->write();
check($written['result'] === 'written' && is_file("$ea4/custom/ols-cpanel-recommended.json") && (fileperms("$ea4/custom/ols-cpanel-recommended.json") & 0777) === 0644
    && json_decode(file_get_contents("$ea4/custom/ols-cpanel-recommended.json"), true) === json_decode(json_encode($profile), true)
    && $written['php'] === ['PHP 8.1', 'PHP 8.2', 'PHP 8.3', 'PHP 8.4', 'PHP 8.5'], 'the profile is generated from the server\'s default profile and manifest, then written');
check($file->write()['result'] === 'unchanged' && $file->present(), 'an unchanged profile is not rewritten');
file_put_contents("$ea4/custom/ols-cpanel-recommended.json", '{}');
check($file->write()['result'] === 'written', 'a damaged profile is rewritten');
file_put_contents("$ea4/custom/mine.json", '{"name": "mine"}');
check($file->remove() === ['result' => 'removed', 'path' => "$ea4/custom/ols-cpanel-recommended.json"] && is_file("$ea4/custom/mine.json")
    && $file->remove()['result'] === 'absent', 'remove deletes only our file');
file_put_contents("$ea4/custom/ols-cpanel-recommended.json", '{"name": "someone else"}');
check($file->remove()['result'] === 'foreign' && is_file("$ea4/custom/ols-cpanel-recommended.json"), 'a file of that name that is not ours is left alone');
unlink("$ea4/custom/ols-cpanel-recommended.json");
// The applier keeps the file present (self-repair).
[$host, $redis, $env, $opcache, $applier] = $world('profile');
$host->version('ea-php83', true, true);
mkdir($env->ea4Root . '/cpanel', 0755, true);
check(!str_starts_with($env->ea4Root, '/etc/'), 'a test environment never points at the real EA4 profile directory');
file_put_contents($env->ea4Root . '/cpanel/default.json', json_encode($default));
$report = $applier->sync();
check($report['profile']['result'] === 'written' && $env->ea4Profile()->present() && $applier->status()['profile']['present'] === true, 'the pass writes the recommended profile');
unlink($env->ea4Profile()->path());
check($applier->sync()['profile']['result'] === 'written', 'and writes it again when it was removed');

// ---- LOG-072: an account whose running lsphp has a stale environment is restarted by the pass -------------------------------
[$host, $redis, $env, $opcache, $applier] = $world('lsenv');
$host->version('ea-php83', true, true);
$host->version('ea-php84', true, true);
$redis->wanted = false;
$applier->sync();                                         // the first pass tunes OPcache (and restarts); the check below starts from a settled host
$vhost = static function (string $user, string $name, array $envLines) use ($env): void {
    @mkdir("{$env->state}/active/vhosts/$name", 0755, true);
    file_put_contents("{$env->state}/active/vhosts/$name/vhconf.conf", "docRoot /home/$user/public_html/\nextProcessor $user-php {\n    type                 lsapi\n"
        . implode('', array_map(static fn(string $l): string => "    env                  $l\n", $envLines)) . "    autoStart            2\n    extUser              $user\n}\nscripthandler {\n}\n");
};
$environ = static fn(array $pairs): string => implode("\0", array_map(static fn(string $k, string $v): string => "$k=$v", array_keys($pairs), $pairs)) . "\0";
$want = ['PHP_LSAPI_CHILDREN' => '4', 'LSPHP_ENABLE_USER_INI' => 'on', 'LSAPI_MAX_IDLE' => '10'];
$lines = ['PHP_LSAPI_CHILDREN=4', 'LSPHP_ENABLE_USER_INI=on', 'LSAPI_MAX_IDLE=10', 'OTHER=1'];
$host->uids += ['olscpc' => 1003, 'olscpd' => 1004, 'svcacct' => 100];
$vhost('olscpa', 'a.test', $lines);                       // stale: its parent predates LSAPI_MAX_IDLE
$vhost('olscpb', 'b.test', $lines);                       // matching
$vhost('olscpc', 'c1.test', $lines);                      // two vhosts disagree on PHP_LSAPI_CHILDREN: that name is skipped
$vhost('olscpc', 'c2.test', ['PHP_LSAPI_CHILDREN=8', 'LSPHP_ENABLE_USER_INI=on', 'LSAPI_MAX_IDLE=10']);
$vhost('olscpd', 'd.test', $lines);                       // environ unreadable
$vhost('svcacct', 's.test', $lines);                      // uid below the tenant range
$host->lsphp = ['olscpa' => [11], 'olscpb' => [21], 'olscpc' => [31], 'olscpd' => [41], 'svcacct' => [51]];
$host->environs = [11 => $environ(['PATH' => '/usr/bin', 'PHP_LSAPI_CHILDREN' => '4', 'LSPHP_ENABLE_USER_INI' => 'on']),
    21 => $environ($want + ['HOME' => '/home/olscpb']), 31 => $environ(['PHP_LSAPI_CHILDREN' => '4', 'LSPHP_ENABLE_USER_INI' => 'on', 'LSAPI_MAX_IDLE' => '10']),
    41 => null, 51 => $environ([])];
$expected = (new \OlsCpanel\Php\LsphpEnvironmentCheck($env))->expected();
check($expected['olscpa'] == $want && !isset($expected['olscpc']['PHP_LSAPI_CHILDREN']) && $expected['olscpc']['LSAPI_MAX_IDLE'] === '10',
    'expected environment: product names only, a name the vhosts disagree on is dropped');
$report = $applier->sync();
$check = $report['lsphp_environment'];
check($check['restarted'] === ['olscpa'] && $check['errors'] === [] && $check['checked'] === 3, 'a stale account is restarted by the pass; checked counts the environments read');
check($host->lsphp['olscpa'] === [] && $host->lsphp['olscpb'] === [21] && $host->lsphp['olscpc'] === [31] && $host->lsphp['olscpd'] === [41] && $host->lsphp['svcacct'] === [51],
    'matching, disagreeing-name, unreadable and non-tenant accounts keep their lsphp');
check(!in_array(['/usr/bin/cat', '/proc/51/environ'], $host->calls, true), 'a uid below the tenant range is never read');
$host->calls = [];
$host->lsphp['olscpa'] = [12];
$host->environs[12] = $environ($want);
$check = $applier->sync()['lsphp_environment'];
check($check['restarted'] === [] && $check['errors'] === [] && $host->count('/usr/bin/kill') === 0, 'once the environment matches, nothing is restarted');
// A restart that cannot end the process is reported and does not fail the pass.
$host->environs[12] = $environ(['LSAPI_MAX_IDLE' => '300'] + $want);
$host->stubborn = true;
$host->onSignal = static fn(int $pid, string $signal): bool => true;
$report = $applier->sync();
check($report['lsphp_environment']['restarted'] === [] && count($report['lsphp_environment']['errors']) === 1
    && str_contains($report['lsphp_environment']['errors'][0], 'olscpa') && $report['result'] === 'unchanged', 'a failed restart is reported, the pass is not failed');
$host->stubborn = false;
$host->onSignal = null;

echo "$count checks passed\n";
