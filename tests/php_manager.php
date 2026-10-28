<?php
declare(strict_types=1);

// FV-03 PHP manager: per-account limits input, `php processes` and runaway detection, OPcache status, install and
// reconcile (package, tuning drop-in, verification, lsphp restart), `php status`, `install --no-opcache`; all
// against temporary trees and a scripted fake runner (no command reaches the host).
require dirname(__DIR__) . '/src/bootstrap.php';
require __DIR__ . '/LsphpFake.php';

use OlsCpanel\Cli\Application;
use OlsCpanel\Cli\Command;
use OlsCpanel\Cli\Output;
use OlsCpanel\Deployment\Environment;
use OlsCpanel\Infrastructure\Process\CommandRunner;
use OlsCpanel\Php\OpcacheManager;
use OlsCpanel\Php\PhpLimits;
use OlsCpanel\Php\PhpProcesses;

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

// ---- limits input ---------------------------------------------------------------------------------------
$none = PhpLimits::fromArray([]);
check($none->forAccount('olscpa') === PhpLimits::BUILTIN && !$none->overrides(), 'no input gives the built-in limits (the compiler output)');
$limits = PhpLimits::fromArray(['defaults' => ['children' => 8, 'proc_soft' => 500, 'proc_hard' => 600],
    'accounts' => ['olscpa' => ['children' => 12, 'max_conns' => 16, 'mem_soft_mb' => 512, 'mem_hard_mb' => 1024], 'olscpb' => ['mem_hard_mb' => 2047]],
    'runaway' => ['cpu_seconds' => 300, 'rss_mb' => 512, 'min_age_seconds' => 30]]);
check($limits->forAccount('olscpa') === ['children' => 12, 'max_conns' => 16, 'mem_soft' => 536870912, 'mem_hard' => 1073741824,
    'proc_soft' => 500, 'proc_hard' => 600], 'account entry over defaults over built-in; memory in bytes');
check($limits->forAccount('olscpb') === ['children' => 8, 'max_conns' => 8, 'mem_soft' => 0, 'mem_hard' => 2146435072, 'proc_soft' => 500, 'proc_hard' => 600],
    'max_conns follows children unless set');
check($limits->forAccount('other')['children'] === 8 && $limits->accountsWithOverrides() === ['olscpa', 'olscpb']
    && $limits->runaway() === ['cpu_seconds' => 300, 'rss_mb' => 512, 'min_age_seconds' => 30], 'defaults apply to accounts without an entry; runaway thresholds');
$bad = [
    ['children' => 0], ['children' => 257], ['children' => '5'], ['children' => 5.5], ['children' => true], ['mem_hard_mb' => 63], ['mem_hard_mb' => 2048],
    ['mem_soft_mb' => 1024, 'mem_hard_mb' => 512], ['max_conns' => 2, 'children' => 5], ['proc_soft' => 3, 'children' => 5],
    ['proc_soft' => 600, 'proc_hard' => 500], ['unknown' => 1], ['memory' => 1],
];
foreach ($bad as $index => $entry) {
    try {
        PhpLimits::fromArray(['accounts' => ['olscpa' => $entry]]);
        check(false, "bad limits entry $index is refused");
    } catch (InvalidArgumentException) {
        check(true, "bad limits entry $index is refused");
    }
}
foreach ([['accounts' => ['Bad Name' => []]], ['accounts' => [['children' => 5]]], ['accounts' => 'x'], ['extra' => 1], ['runaway' => ['rss_mb' => 1]],
             ['runaway' => ['cpu_seconds' => 0]], ['runaway' => ['x' => 1]], ['defaults' => ['children' => 300]], ['defaults' => [5]]] as $index => $document) {
    try {
        PhpLimits::fromArray($document);
        check(false, "bad limits document $index is refused");
    } catch (InvalidArgumentException) {
        check(true, "bad limits document $index is refused");
    }
}
$base = sys_get_temp_dir() . '/ols-php-manager-' . bin2hex(random_bytes(6));
mkdir($base, 0755, true);
$file = "$base/php-limits.json";
check(!PhpLimits::load($file)->overrides(), 'an absent limits file is no override');
file_put_contents($file, '{"accounts": {"olscpa": {"children": 9}}}');
chmod($file, 0644);
check(PhpLimits::load($file)->forAccount('olscpa')['children'] === 9, 'the file is read');
foreach (['{"accounts": ', '[1]', '"x"', '{"accounts": {"olscpa": {"children": 0}}}'] as $text) {
    file_put_contents($file, $text);
    try {
        PhpLimits::load($file);
        check(false, 'a broken limits file is refused');
    } catch (InvalidArgumentException $error) {
        check(str_contains($error->getMessage(), $file), 'a broken limits file is refused with its path');
    }
}
file_put_contents($file, '{}');
chmod($file, 0666);
try {
    PhpLimits::load($file);
    check(false, 'a group or world writable limits file is refused');
} catch (InvalidArgumentException) {
    check(true, 'a group or world writable limits file is refused');
}
[$lenient, $problem] = PhpLimits::loadLenient($file);
check($problem !== null && !$lenient->overrides(), 'read-only views fall back to the built-in set and say why');
unlink($file);
symlink('/etc/passwd', $file);
try {
    PhpLimits::load($file);
    check(false, 'a limits file that is a link is refused');
} catch (InvalidArgumentException) {
    check(true, 'a limits file that is a link is refused');
}
unlink($file);

// ---- scripted host --------------------------------------------------------------------------------------
final class PhpHost implements CommandRunner
{
    /** @var array<string,bool> version => OPcache extension loaded */
    public array $loaded = [];
    /** @var array<string,bool> version => package installed */
    public array $package = [];
    public bool $dnfFails = false;
    public bool $timerEnabled = false;
    public bool $watcherEnabled = false;
    /** @var array<string,list<int>> user => lsphp pids */
    public array $lsphp = [];
    /** @var array<int,int> pid => start time */
    public array $starts = [];
    public bool $stubborn = false;
    /** @var array<string,bool> version => OPcache loaded but off until our drop-in says enable=1 */
    public array $disabled = [];
    /** @var array<string,bool> version => a later ini file keeps it off whatever our drop-in says */
    public array $stickyOff = [];
    public string $ps = '';
    /** @var list<list<string>> */
    public array $calls = [];
    public function __construct(public string $opt)
    {
    }

    public function run(string $name, array $argv, int $timeout): array
    {
        $this->calls[] = $argv;
        $ok = static fn(string $out = ''): array => ['exit_code' => 0, 'stdout' => $out, 'stderr' => ''];
        $no = static fn(int $code = 1, string $out = '', string $err = ''): array => ['exit_code' => $code, 'stdout' => $out, 'stderr' => $err];
        $args = array_slice($argv, 1);
        if (preg_match('~^' . preg_quote($this->opt, '~') . '/(ea-php\d+)/root/usr/bin/(php|lsphp)$~', $argv[0], $m) === 1) {
            return $this->phpInfo($m[1]);
        }
        switch ($argv[0]) {
            case '/usr/bin/rpm':
                $version = substr((string) end($args), 0, strlen('ea-php83'));
                return ($this->package[$version] ?? false) ? $ok(end($args) . "-1.el9\n") : $no(1, 'package ' . end($args) . " is not installed\n");
            case '/usr/bin/dnf':
                if ($this->dnfFails) {
                    return $no(1, '', "Error: Unable to find a match: {$args[2]}\n");
                }
                $version = substr($args[2], 0, strlen('ea-php83'));
                $this->package[$version] = true;
                $this->loaded[$version] = true;
                return $ok("Complete!\n");
            case '/usr/bin/systemctl':
                $isPath = str_ends_with((string) end($args), '.path');
                if ($args[0] === 'is-enabled') {
                    return ($isPath ? $this->watcherEnabled : $this->timerEnabled) ? $ok() : $no(1);
                }
                if ($args[0] === 'enable') {
                    $isPath ? $this->watcherEnabled = true : $this->timerEnabled = true;
                    return $ok();
                }
                throw new LogicException('unexpected systemctl ' . implode(' ', $args));
            case '/usr/bin/id':
                $users = ['olscpa' => 1001, 'olscpb' => 1002, 'root' => 0];
                return isset($users[$args[1]]) ? $ok($users[$args[1]] . "\n") : $no(1);
            case '/usr/bin/pgrep':
            case '/usr/bin/cat':
            case '/usr/bin/kill':
                return LsphpFake::handle($this->lsphp, $this->starts, $this->stubborn, $argv);
            case '/usr/bin/ps':
                return $ok($this->ps);
        }
        throw new LogicException('unexpected command ' . implode(' ', $argv));
    }

    /** What `php -i` of the version prints: the directives only while the extension is loaded, overridden by the drop-in. */
    private function phpInfo(string $version): array
    {
        $out = "phpinfo()\nPHP Version => 8.3.1\n";
        if ($this->loaded[$version] ?? false) {
            $values = ['enable' => 'On', 'validate_root' => 'Off', 'validate_permission' => 'On', 'memory_consumption' => '128',
                'max_accelerated_files' => '10000', 'revalidate_freq' => '2'];
            $ini = "{$this->opt}/$version/root/etc/php.d/" . OpcacheManager::INI;
            foreach (is_file($ini) ? file($ini, FILE_IGNORE_NEW_LINES) : [] as $line) {
                if (preg_match('/^opcache\.([a-z_]+)=(.*)$/', $line, $m) === 1) {
                    $values[$m[1]] = in_array($m[1], ['enable', 'validate_root', 'validate_permission'], true) ? ($m[2] === '1' ? 'On' : 'Off') : $m[2];
                }
            }
            if ($this->disabled[$version] ?? false) {
                $values['enable'] = $this->stickyOff[$version] ?? false ? 'Off' : ($values['enable'] === 'On' && is_file($ini) ? 'On' : 'Off');
            }
            foreach ($values as $key => $value) {
                $out .= "opcache.$key => $value => $value\n";
            }
        }
        return ['exit_code' => 0, 'stdout' => $out, 'stderr' => ''];
    }
}

function world(PhpHost $host, string $base, bool $root = true): Environment
{
    return new Environment($host, "$base/state", null, null, $root, null, static function (float $s): void {
    });
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

/** A fresh /opt/cpanel with ea-php74 and ea-php83 (lsphp only), ea-php56 without any binary and unrelated names. */
function fresh(string $base): array
{
    $opt = "$base/opt";
    tree_remove($opt);
    tree_remove("$base/state");
    mkdir("$base/state", 0755);
    foreach (['ea-php74', 'ea-php83'] as $v) {
        mkdir("$opt/$v/root/usr/bin", 0755, true);
        mkdir("$opt/$v/root/etc/php.d", 0755, true);
        touch("$opt/$v/root/usr/bin/lsphp");
    }
    mkdir("$opt/ea-php56/root/usr/bin", 0755, true);
    mkdir("$opt/ea-phpx/root/usr/bin", 0755, true);
    touch("$opt/ea-phpx/root/usr/bin/lsphp");
    mkdir("$opt/alt-php81/root/usr/bin", 0755, true);
    touch("$opt/alt-php81/root/usr/bin/lsphp");
    file_put_contents("$base/userdatadomains",
        "a.test: olscpa==root==main==a.test==/home/olscpa/public_html==1.2.3.4:80==1.2.3.4:443====0==ea-php83\n"
        . "old.test: olscpa==root==sub==a.test==/home/olscpa/old==1.2.3.4:80==1.2.3.4:443====0==ea-php74\n"
        . "b.test: olscpb==root==main==b.test==/home/olscpb/public_html==1.2.3.4:80==1.2.3.4:443====0==ea-php74\n"
        . "evil.test: ../x==root==main==evil.test==/home/x==1:80==1:443====0==ea-php83\n");
    return [$opt, "$base/userdatadomains"];
}

// ---- processes ------------------------------------------------------------------------------------------
$host = new PhpHost("$base/opt");
// pid ppid user etimes cputimes rss pcpu stat comm
$host->ps = implode("\n", [
    '    1     0 root                                  9000        4  1000  0.0 Ss   systemd',
    ' 4001  3900 olscpa                                 600       20 20000  0.5 S    lsphp',
    ' 4002  4001 olscpa                                 590       30 51200  1.0 S    lsphp',
    ' 4003  4001 olscpa                                 800     1200 90000 99.0 R    lsphp',
    ' 4004  4001 olscpa                                 500       10 1500000  0.1 S    lsphp',
    ' 4005  4001 olscpa                                  10        5 2000000  1.0 S    lsphp',
    ' 5001  3900 olscpb                                7000       12 30000  0.0 S    lsphp',
    ' 5002  5001 olscpb                                7000     2000 40000  3.0 S    lsphp',
    ' 6001  3900 nobody                                  50        1  9000  0.0 S    lsphp5',
    ' 6002  1    nobody                                  50        1  9000  0.0 S    php-fpm',
]) . "\n";
$report = (new PhpProcesses($host, PhpLimits::fromArray([])))->report();
$a = $report['accounts'][0];
check(array_column($report['accounts'], 'account') === ['olscpa', 'olscpb'] && $report['totals']['processes'] === 7 && $report['totals']['children'] === 5,
    'lsphp rows per account; other processes are ignored');
check($a['parents'] === 1 && $a['children'] === 4 && $a['processes'][0]['role'] === 'parent' && $a['processes'][0]['children'] === 4
    && $a['processes'][1]['role'] === 'child', 'parent and children by parent pid');
check($a['processes'][1] === ['pid' => 4002, 'ppid' => 4001, 'elapsed_seconds' => 590, 'cpu_seconds' => 30, 'rss_kb' => 51200, 'cpu_percent' => 1.0,
    'state' => 'S', 'role' => 'child', 'children' => 0, 'runaway' => []], 'one process row');
check($a['rss_kb'] === 20000 + 51200 + 90000 + 1500000 + 2000000 && $a['cpu_percent'] === 101.6, 'account totals');
$flags = array_column($a['processes'], 'runaway', 'pid');
check($flags[4003] === ['cpu'] && $flags[4004] === ['rss'] && $flags[4005] === [] && $flags[4002] === [],
    'runaway: CPU time or RSS over the threshold for at least the minimum age; a young process is not one');
check($report['accounts'][1]['processes'][1]['runaway'] === ['cpu'] && $a['runaway'] === 2 && $report['totals']['runaway'] === 3, 'runaway counts');
$custom = (new PhpProcesses($host, $limits))->report('olscpa');
check(array_column($custom['accounts'], 'account') === ['olscpa'] && $custom['thresholds'] === ['cpu_seconds' => 300, 'rss_mb' => 512, 'min_age_seconds' => 30]
    && array_column($custom['accounts'][0]['processes'], 'runaway', 'pid')[4002] === [], 'one account and the file thresholds');
check($host->calls[0] === ['/usr/bin/ps', '-eo', 'pid=,ppid=,user:32=,etimes=,cputimes=,rss=,pcpu=,stat=,comm='], 'ps runs with a fixed argv');
foreach (['olscpa;id', '../x', 'Root', ''] as $name) {
    try {
        (new PhpProcesses($host))->report($name);
        check(false, "processes refuses account '$name'");
    } catch (OlsCpanel\Cli\Refused) {
        check(true, "processes refuses account '$name'");
    }
}
$host->ps = "garbage line\n";
try {
    (new PhpProcesses($host))->report();
    check(false, 'unexpected ps output is refused');
} catch (OlsCpanel\Cli\Refused) {
    check(true, 'unexpected ps output is refused');
}
$host->ps = '';
check((new PhpProcesses($host))->report()['accounts'] === [], 'no lsphp, no accounts');

// ---- OPcache --------------------------------------------------------------------------------------------
check(array_map([OpcacheManager::class, 'memoryMb'], ['ea-php56', 'ea-php70', 'ea-php74', 'ea-php80', 'ea-php83', 'ea-php85', 'ea-php100'])
    === [64, 96, 96, 128, 128, 128, 128], 'memory sizing per version');
check(OpcacheManager::dotted('ea-php83') === '8.3' && OpcacheManager::dotted('ea-php100') === '10.0', 'version spelling');
[$opt, $userdata] = fresh($base);
$host = new PhpHost($opt);
$manager = new OpcacheManager(world($host, $base), $opt, $userdata);
check($manager->versions() === ['ea-php74', 'ea-php83'], 'installed EA4 versions: with a binary, ea-php names only');
$status = $manager->status();
$v83 = $status['versions'][1];
check($status['auto'] === true && $status['timer'] === false && count($status['versions']) === 2 && $v83['loaded'] === false && $v83['package_installed'] === false
    && $v83['tuned'] === false && $v83['accounts'] === 1 && $status['versions'][0]['accounts'] === 2
    && array_keys($v83['settings']) === OpcacheManager::KEYS && array_filter($v83['settings'], static fn($x): bool => $x !== null) === [], 'status of a host without OPcache: every setting key present, null');
check(str_contains(json_encode($v83), '"settings":{"enable":null,') && $status['watcher'] === false, 'the settings are always a JSON object');
check(array_column($manager->status('ea-php74')['versions'], 'version') === ['ea-php74'], 'status of one version');
try {
    $manager->status('ea-php99');
    check(false, 'status of an unknown version is refused');
} catch (OlsCpanel\Cli\Refused) {
    check(true, 'status of an unknown version is refused');
}
$host->calls = [];
$result = $manager->install('ea-php83', false);
check($result['result'] === 'installed' && $result['changed'] === 1 && $result['versions'][0]['package_installed_now'] === true
    && $result['versions'][0]['ini_written'] === true && $result['versions'][0]['verified'] === true
    && $result['versions'][0]['restarted'] === [['account' => 'olscpa', 'result' => 'restarted']], 'install: package, drop-in, verification, restart of the accounts on it');
check(in_array(['/usr/bin/dnf', '-y', 'install', 'ea-php83-php-opcache'], $host->calls, true), 'dnf runs with a fixed argv');
check(file_get_contents("$opt/ea-php83/root/etc/php.d/zz-ols-cpanel-opcache.ini") === "; Managed by ols-cpanel (php opcache install, rewritten by php opcache reconcile): OPcache for shared hosting.\n"
    . "; enable=1 keeps OPcache on; validate_root and validate_permission keep one account from reading another account's cached scripts.\n"
    . "opcache.enable=1\nopcache.validate_root=1\nopcache.validate_permission=1\nopcache.memory_consumption=128\nopcache.max_accelerated_files=20000\nopcache.revalidate_freq=2\n"
    && (fileperms("$opt/ea-php83/root/etc/php.d/zz-ols-cpanel-opcache.ini") & 0777) === 0644, 'the tuning drop-in');
check(!file_exists("$opt/ea-php74/root/etc/php.d/zz-ols-cpanel-opcache.ini"), 'another version is untouched');
check($manager->state() === ['auto' => true] && is_file("$base/state/php-opcache.json"), 'an install records the automatic management');
check($result['timer'] === true && $host->timerEnabled && $host->watcherEnabled, 'a manual install enables the timer and the package-transaction watcher');
$status = $manager->status()['versions'][1];
check($status['loaded'] && $status['tuned'] && $status['package_installed'] && $status['ini_file']
    && $status['settings']['validate_root'] === 'On' && $status['settings']['memory_consumption'] === '128', 'status after the install');
$host->calls = [];
$again = $manager->install('ea-php83', false);
check($again['result'] === 'installed' && $again['changed'] === 0 && $again['versions'][0]['result'] === 'unchanged' && $again['versions'][0]['restarted'] === []
    && array_filter($host->calls, static fn(array $c): bool => in_array($c[0], ['/usr/bin/dnf', '/usr/bin/pkill'], true)) === [], 'a second install changes nothing and restarts nothing');
$host->lsphp = ['olscpa' => [11, 12], 'olscpb' => [21]];
$all = $manager->install(null, true);
check($all['changed'] === 1 && $all['versions'][0]['version'] === 'ea-php74' && $all['versions'][0]['result'] === 'installed'
    && $all['versions'][0]['restarted'] === [['account' => 'olscpa', 'result' => 'restarted'], ['account' => 'olscpb', 'result' => 'restarted']]
    && $host->lsphp === ['olscpa' => [], 'olscpb' => []], 'install --all converges the remaining version and restarts both accounts on it');
check(str_contains(file_get_contents("$opt/ea-php74/root/etc/php.d/zz-ols-cpanel-opcache.ini"), 'opcache.memory_consumption=96'), 'sizing is per version');

// A drift (an update rewrote what PHP reports) is repaired by the reconcile pass, without dnf.
unlink("$opt/ea-php83/root/etc/php.d/zz-ols-cpanel-opcache.ini");
$host->calls = [];
$pass = $manager->reconcile();
check($pass['result'] === 'reconciled' && $pass['changed'] === 1 && $pass['versions'][1]['result'] === 'tuned' && $pass['versions'][1]['package_installed_now'] === false
    && array_filter($host->calls, static fn(array $c): bool => $c[0] === '/usr/bin/dnf') === [], 'reconcile rewrites a lost drop-in without installing the package');
check($manager->reconcile()['changed'] === 0, 'a converged host needs nothing');
// A new PHP version appears (EasyApache, MultiPHP): the next pass installs it.
mkdir("$opt/ea-php84/root/usr/bin", 0755, true);
mkdir("$opt/ea-php84/root/etc/php.d", 0755, true);
touch("$opt/ea-php84/root/usr/bin/lsphp");
$pass = $manager->reconcile();
check($pass['changed'] === 1 && end($pass['versions'])['version'] === 'ea-php84' && end($pass['versions'])['result'] === 'installed', 'a new PHP version is converged by the next pass');
// A package that is installed but not reported loaded (a transient failure) is not reinstalled as new.
$host->loaded['ea-php84'] = false;
unlink("$opt/ea-php84/root/etc/php.d/zz-ols-cpanel-opcache.ini");
$pass = $manager->reconcile();
check(end($pass['versions'])['package_installed_now'] === false, 'an installed package is not counted as a new installation');

// RV-31 item 10: a disabled OPcache is not "tuned"; opcache.enable=1 is managed and verified.
[$opt, $userdata] = fresh($base);
$host = new PhpHost($opt);
$host->loaded = ['ea-php83' => true];
$host->package = ['ea-php83' => true];
$host->disabled = ['ea-php83' => true];
$manager = new OpcacheManager(world($host, $base), $opt, $userdata);
$off = $manager->versionStatus('ea-php83');
check($off['loaded'] === true && $off['settings']['enable'] === 'Off' && $off['tuned'] === false && OpcacheManager::wanted('ea-php83')['enable'] === '1',
    'OPcache loaded but disabled is not tuned');
check(str_contains(OpcacheManager::iniText('ea-php83'), "opcache.enable=1\n") && !str_contains(OpcacheManager::iniText('ea-php83'), 'enable_cli'),
    'the drop-in sets opcache.enable=1 and leaves enable_cli alone');
$row = $manager->convergeVersion('ea-php83');
check($row['result'] === 'tuned' && $row['ini_written'] === true && $row['verified'] === true && $manager->versionStatus('ea-php83')['tuned'] === true,
    'a disabled OPcache is repaired by writing enable=1 and verified');
$host->stickyOff = ['ea-php83' => true];
unlink("$opt/ea-php83/root/etc/php.d/zz-ols-cpanel-opcache.ini");
$row = $manager->convergeVersion('ea-php83');
check($row['result'] === 'failed' && str_contains((string) $row['error'], 'does not report the wanted OPcache settings'), 'an OPcache that stays disabled after the write is a failure');

// Failure and opt-out.
[$opt, $userdata] = fresh($base);
$host = new PhpHost($opt);
$host->dnfFails = true;
$manager = new OpcacheManager(world($host, $base), $opt, $userdata);
$failed = $manager->install(null, true);
check($failed['result'] === 'failed' && $failed['failed'] === 2 && str_contains($failed['versions'][0]['error'], 'dnf could not install ea-php74-php-opcache')
    && !file_exists("$opt/ea-php74/root/etc/php.d/zz-ols-cpanel-opcache.ini"), 'a failed dnf is reported per version and nothing is written');
$prepared = $manager->prepare(true);
check($prepared['result'] === 'disabled' && $manager->state() === ['auto' => false], 'install --prepare --no-opcache records the opt-out');
$host->dnfFails = false;
$host->calls = [];
$pass = $manager->reconcile();
check($pass['result'] === 'disabled' && $host->calls === [], 'the timer pass does nothing while opted out');
$prepared = $manager->prepare(false);
check($prepared['result'] === 'installed' && $prepared['changed'] === 2 && $prepared['timer'] === true && $host->timerEnabled && $manager->state()['auto'] === true,
    'install --prepare installs OPcache everywhere, turns the management on and enables the timer');
$opted = new OpcacheManager(world($host, $base), $opt, $userdata);
$opted->prepare(true);
$opted->install('ea-php83', false);
check($opted->state()['auto'] === true, 'an explicit install lifts the opt-out');
foreach (['ea-php99', 'ea-php56', 'alt-php81', '../x', 'ea-php83;id'] as $name) {
    try {
        $manager->install($name, false);
        check(false, "install refuses $name");
    } catch (OlsCpanel\Cli\Refused) {
        check(true, "install refuses $name");
    }
}
try {
    $manager->install(null, false);
    check(false, 'install needs a version or --all');
} catch (OlsCpanel\Cli\Refused) {
    check(true, 'install needs a version or --all');
}
try {
    (new OpcacheManager(world($host, $base, false), $opt, $userdata))->status();
    check(false, 'status is root only');
} catch (OlsCpanel\Deployment\DeploymentError) {
    check(true, 'status is root only');
}

// ---- CLI ------------------------------------------------------------------------------------------------
[$opt, $userdata] = fresh($base);
$host = new PhpHost($opt);
$host->lsphp = ['olscpa' => [11]];
$host->ps = " 4001  3900 olscpa  600  20 20000  0.5 S    lsphp\n 4002  4001 olscpa  590  30 51200  1.0 S    lsphp\n";
$limitsFile = "$base/state/php-limits.json";
file_put_contents($limitsFile, '{"accounts": {"olscpa": {"children": 10}}}');
chmod($limitsFile, 0644);
$env = static fn(): Environment => world($host, $base);
$cli = new Application([new Command\PhpOpcacheCommand('status', $env, $opt, $userdata), new Command\PhpOpcacheCommand('install', $env, $opt, $userdata),
    new Command\PhpOpcacheCommand('reconcile', $env, $opt, $userdata),
    new Command\PhpProcessesCommand($env, $limitsFile), new Command\PhpStatusCommand($env, $limitsFile, $opt, $userdata),
    new Command\InstallCommand($env)]);
[$code, $out] = run_cli($cli, ['php', 'opcache', 'status']);
check($code === 0 && $out['command'] === 'php opcache status' && count($out['versions']) === 2, 'php opcache status');
[$code, $out] = run_cli($cli, ['php', 'opcache', 'install', '--version=ea-php83']);
check($code === 0 && $out['result'] === 'installed' && $out['versions'][0]['restarted'][0]['account'] === 'olscpa', 'php opcache install --version');
foreach ([['php', 'opcache', 'install'], ['php', 'opcache', 'install', '--all', '--version=ea-php83'], ['php', 'opcache', 'status', '--all'],
             ['install', '--cutover', '--plan=p20261022120000-a1b2c3', '--no-opcache']] as $bad) {
    [$code] = run_cli($cli, $bad);
    check($code === 64, 'usage: ' . implode(' ', $bad));
}
[$code, $out] = run_cli($cli, ['php', 'opcache', 'install', '--version=ea-php99']);
check($code === 1 && $out['result'] === 'refused', 'php opcache install refuses an unknown version');
$host->dnfFails = true;
[$code, $out] = run_cli($cli, ['php', 'opcache', 'reconcile']);
check($code === 1 && $out['result'] === 'failed' && $out['failed'] === 1, 'a failed reconcile exits 1');
[$code, $out] = run_cli($cli, ['php', 'processes', '--account=olscpa']);
check($code === 0 && $out['totals']['children'] === 1 && $out['accounts'][0]['processes'][0]['pid'] === 4001 && $out['limits_error'] === null, 'php processes --account');
[$code, $out] = run_cli($cli, ['php', 'status']);
check($code === 0 && $out['result'] === 'status' && isset($out['opcache']['versions'][1]) && !isset($out['processes']['accounts'][0]['processes'])
    && $out['processes']['accounts'][0]['children'] === 1 && $out['limits']['overrides'] === true && $out['limits']['error'] === null
    && $out['limits']['accounts']['olscpa']['children'] === 10 && $out['limits']['builtin']['proc_hard'] === 500, 'php status: opcache, process summary, limits');
check($out['environment']['result'] === 'status' && array_column($out['environment']['versions'], 'version') === ['ea-php74', 'ea-php83']
    && array_column($out['environment']['versions'], 'status') === ['pending', 'pending'] && $out['environment']['versions'][1]['lsphp'] === false
    && array_key_exists('profile', $out['environment']) && array_key_exists('units', $out['environment']), 'php status carries the PHP environment per version');
check($out['opcache']['versions'][1]['loaded'] === true && $out['opcache']['versions'][1]['settings']['validate_root'] === 'On'
    && array_keys($out['opcache']['versions'][1]['settings']) === OpcacheManager::KEYS, 'php status: opcache rows expose loaded and every setting');
[$code, $out] = run_cli($cli, ['php', 'status', '--account=olscpa']);
check($code === 0 && $out['account'] === 'olscpa' && isset($out['processes']['accounts'][0]['processes']) && $out['limits']['account']['children'] === 10
    && $out['opcache']['versions'][1]['accounts'] === 1, 'php status --account carries the processes and the effective limits');
file_put_contents($limitsFile, '{"accounts": {"olscpa": {"children": 0}}}');
[$code, $out] = run_cli($cli, ['php', 'status']);
check($code === 0 && $out['limits']['error'] !== null && $out['limits']['overrides'] === false, 'php status shows a broken limits file instead of failing');
$host->ps = "nonsense\n";
[$code, $out] = run_cli($cli, ['php', 'processes']);
check($code === 1 && $out['result'] === 'refused', 'a ps failure is a refusal');
$nonRoot = static fn(): Environment => world($host, $base, false);
$cli = new Application([new Command\PhpOpcacheCommand('install', $nonRoot, $opt, $userdata), new Command\PhpProcessesCommand($nonRoot, $limitsFile), new Command\PhpStatusCommand($nonRoot, $limitsFile)]);
foreach ([['php', 'opcache', 'install', '--all'], ['php', 'processes'], ['php', 'status']] as $argv) {
    [$code] = run_cli($cli, $argv);
    check($code === 1, implode(' ', $argv) . ' is root only');
}
tree_remove($base);
echo "$count checks passed\n";
