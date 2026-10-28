<?php
declare(strict_types=1);

// PHP redis extension layer (src/PhpExtensions, `php-ext` CLI) against a scripted fake host: prebuilt build with a
// matching ABI, already loaded (never touched), ABI mismatch and missing prebuilt build (compiled from the packaged
// source), failed build with back-off and retry, load failure rollback, a foreign INI, the watcher's pass after a
// package transaction and for a new PHP version, restarts of the accounts of changed versions only, removal.
require dirname(__DIR__) . '/src/bootstrap.php';

use OlsCpanel\Cli\Application;
use OlsCpanel\Cli\Command\PhpExtCommand;
use OlsCpanel\Cli\EngineContext;
use OlsCpanel\Cli\Output;
use OlsCpanel\Cli\Refused;
use OlsCpanel\Infrastructure\Process\CommandRunner;
use OlsCpanel\PhpExtensions\ExtensionBundle;
use OlsCpanel\PhpExtensions\ExtensionInstaller;
use OlsCpanel\PhpExtensions\ExtensionService;
use OlsCpanel\PhpExtensions\ExtensionState;
use OlsCpanel\PhpExtensions\ExtensionSync;
use OlsCpanel\Deployment\Environment;
use OlsCpanel\Php\PhpRestartLedger;

$count = 0;
function check(bool $condition, string $name): void
{
    global $count;
    if (!$condition) {
        throw new RuntimeException('FAIL: ' . $name);
    }
    ++$count;
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

const ABIS = ['ea-php56' => ['5.6.40', '20131226'], 'ea-php73' => ['7.3.33', '20180731'], 'ea-php74' => ['7.4.33', '20190902'], 'ea-php81' => ['8.1.34', '20210902'], 'ea-php82' => ['8.2.35', '20220829'], 'ea-php83' => ['8.3.36', '20230831'],
    'ea-php84' => ['8.4.27', '20240924'], 'ea-php85' => ['8.5.12', '20250925']];

/** A server in memory and on disk (temporary directories); every command is answered from this state. */
final class Box implements CommandRunner
{
    public string $php;
    public string $bundle;
    public string $state;
    public string $buildRoot;
    public string $systemdRun;
    /** @var list<array{unit:string, props:list<string>, argv:list<string>}> every sandboxed build step */
    public array $sandboxed = [];
    /** @var list<list<string>> build commands that ran WITHOUT the sandbox (must stay empty) */
    public array $unsandboxed = [];
    public bool $sandboxFails = false;
    /** the make step leaves a symbolic link to this path instead of redis.so */
    public ?string $makeLink = null;
    public ExtensionSync $sync;
    public PhpRestartLedger $ledger;
    /** @var list<string> accounts whose lsphp was restarted, in order */
    public array $restarted = [];
    /** @var array<string,true> accounts whose restart fails */
    public array $restartFails = [];
    /** @var array<string,array{0:string,1:string}> version => [PHP version, API number] */
    public array $abi = [];
    /** @var array<string,true> versions whose redis loads by other means */
    public array $external = [];
    /** @var array<string,true> .so paths that never load (despite a matching ABI) */
    public array $badSo = [];
    public bool $builtLoads = true;
    public bool $dnfOk = true;
    public bool $makeOk = true;
    public bool $abiFails = false;
    public bool $watcher = false;
    public string $vhosts = '{"data":{"versions":[]}}';
    /** @var list<array{0:string,1:list<string>}> */
    public array $calls = [];
    /** @var array<string,string> build directory => version */
    private array $building = [];

    public function addPhp(string $ea): void
    {
        mkdir("{$this->php}/$ea/root/usr/bin", 0755, true);
        mkdir("{$this->php}/$ea/root/etc/php.d", 0755, true);
        file_put_contents("{$this->php}/$ea/root/usr/bin/php", '#!/bin/sh');
        chmod("{$this->php}/$ea/root/usr/bin/php", 0755);
        $this->abi[$ea] = ABIS[$ea];
    }

    public function buildId(string $ea): string
    {
        return 'API' . $this->abi[$ea][1] . ',NTS';
    }

    /** The prebuilt package: builds for $versions (content records the ABI it was compiled for) and the source tarball. */
    public function prebuilt(array $versions, bool $source = true): void
    {
        $entries = [];
        foreach ($versions as $ea) {
            mkdir("{$this->bundle}/$ea", 0755, true);
            $so = "{$this->bundle}/$ea/redis.so";
            file_put_contents($so, "so-prebuilt-$ea-API" . ABIS[$ea][1] . ',NTS');
            $entries[$ea] = ['so' => $so, 'sha256' => hash_file('sha256', $so), 'size' => filesize($so), 'php_api' => ABIS[$ea][1],
                'build_id' => 'API' . ABIS[$ea][1] . ',NTS', 'built_with' => ABIS[$ea][0]];
        }
        $tar = null;
        if ($source) {
            mkdir("{$this->bundle}/src", 0755, true);
            file_put_contents("{$this->bundle}/src/phpredis-6.3.0.tgz", 'tarball');
            $tar = ['file' => 'src/phpredis-6.3.0.tgz', 'sha256' => hash('sha256', 'tarball')];
        }
        ExtensionBundle::create($this->bundle, '6.3.0', $entries, $tar)->save();
    }

    public function ini(string $ea): string
    {
        return "{$this->php}/$ea/root/etc/php.d/zz-ols-cpanel-redis.ini";
    }

    public function loaded(string $ea): bool
    {
        if (isset($this->external[$ea])) {
            return true;
        }
        if (!is_file($this->ini($ea)) || !preg_match('/^extension=(.+)$/m', (string) file_get_contents($this->ini($ea)), $m)) {
            return false;
        }
        $so = $m[1];
        if (!is_file($so) || isset($this->badSo[$so]) || (str_starts_with($so, $this->state) && !$this->builtLoads)) {
            return false;
        }
        // The extension loads only when it was compiled for the ABI the PHP has now.
        return str_ends_with((string) file_get_contents($so), $this->buildId($ea));
    }

    /** @return list<list<string>> argv of calls whose executable (or first env command) matches */
    public function argvs(string $needle): array
    {
        return array_values(array_filter(array_column($this->calls, 1), static fn(array $a): bool => in_array($needle, $a, true)
            || str_ends_with($a[0], $needle) || ($a[0] === '/usr/bin/env' && str_ends_with(end($a) === '' ? '' : implode(' ', $a), $needle))));
    }

    public function count(string $name): int
    {
        return count(array_filter($this->calls, static fn(array $c): bool => $c[0] === "phpext-$name"));
    }

    public function run(string $name, array $argv, int $timeout): array
    {
        $this->calls[] = [$name, $argv];
        $ok = static fn(string $out = ''): array => ['exit_code' => 0, 'stdout' => $out, 'stderr' => ''];
        $no = static fn(string $err = ''): array => ['exit_code' => 1, 'stdout' => '', 'stderr' => $err];
        $cmd = $argv[0];
        $args = array_slice($argv, 1);
        if (str_starts_with($cmd, $this->php . '/')) {
            $ea = explode('/', substr($cmd, strlen($this->php) + 1))[0];
            return $this->php($ea, basename($cmd), $args, $ok, $no);
        }
        if ($cmd === $this->systemdRun) {
            return $this->sandbox($argv, $ok, $no);
        }
        switch ($cmd) {
            case '/usr/bin/systemctl':
                if ($args[0] === 'is-enabled') {
                    return $this->watcher ? $ok() : $no();
                }
                if ($args[0] === 'enable') {
                    $this->watcher = true;
                } elseif ($args[0] === 'disable') {
                    $this->watcher = false;
                }
                return $ok();
            case '/usr/bin/dnf':
                if (!$this->dnfOk) {
                    return $no('Error: Failed to download metadata');
                }
                foreach ($args as $arg) {
                    if (preg_match('/^(ea-php[0-9]+)-php-devel$/', $arg, $m)) {
                        foreach (['phpize', 'php-config'] as $tool) {
                            file_put_contents("{$this->php}/{$m[1]}/root/usr/bin/$tool", '#!/bin/sh');
                            chmod("{$this->php}/{$m[1]}/root/usr/bin/$tool", 0755);
                        }
                    }
                }
                return $ok();
            case '/usr/bin/tar':
            case '/usr/bin/env':
                $this->unsandboxed[] = $argv;
                return $this->inner($argv, $ok, $no);
            case '/usr/bin/rm':
                foreach (array_slice($args, 2) as $path) {
                    rmtree($path);
                }
                return $ok();
            case '/usr/local/cpanel/bin/whmapi1':
                return $ok($this->vhosts);
        }
        throw new RuntimeException("unexpected command $cmd");
    }

    /** `systemd-run ... -p X=Y --unit=U -- command`: records the properties, creates the private state directory, runs the command. */
    private function sandbox(array $argv, \Closure $ok, \Closure $no): array
    {
        $dash = array_search('--', $argv, true);
        $props = [];
        $unit = '';
        for ($i = 1; $i < $dash; ++$i) {
            if ($argv[$i] === '-p') {
                $props[] = $argv[++$i];
            } elseif (str_starts_with($argv[$i], '--unit=')) {
                $unit = substr($argv[$i], 7);
            }
        }
        $command = array_slice($argv, $dash + 1);
        $this->sandboxed[] = ['unit' => $unit, 'props' => $props, 'argv' => $command];
        if ($this->sandboxFails) {
            return $no('Failed to start transient service');
        }
        if (!is_dir("{$this->buildRoot}/$unit")) {
            mkdir("{$this->buildRoot}/$unit", 0700);
        }
        $translated = array_map(fn(string $a): string => str_replace("/var/lib/$unit", "{$this->buildRoot}/$unit", $a), $command);
        return $this->inner($translated, $ok, $no);
    }

    private function inner(array $argv, \Closure $ok, \Closure $no): array
    {
        if ($argv[0] === '/usr/bin/tar') {
            if (!is_file($argv[2])) {
                return $no('tar: cannot open');
            }
            mkdir($argv[4] . '/redis-6.3.0', 0700);
            return $ok();
        }
        return $this->envCommand(array_slice($argv, 1), $ok, $no);
    }

    private function php(string $ea, string $tool, array $args, \Closure $ok, \Closure $no): array
    {
        if ($tool !== 'php') {
            return $ok();
        }
        if ($args === ['-m']) {
            return $ok("[PHP Modules]\nCore\ndate\n" . ($this->loaded($ea) ? "redis\n" : '') . "\n[Zend Modules]\n");
        }
        if ($args === ['-n', '-i']) {
            if ($this->abiFails) {
                return $no('segfault');
            }
            [$version, $api] = $this->abi[$ea];
            return $ok("phpinfo()\nPHP Version => $version\n\nPHP API => $api\nPHP Extension Build => API$api,NTS\nBuild System => x\n");
        }
        if ($args[0] === '-r') {
            return $ok($this->loaded($ea) ? "bool(true)\n" : "bool(false)\n");
        }
        throw new RuntimeException('unexpected php arguments ' . implode(' ', $args));
    }

    private function envCommand(array $args, \Closure $ok, \Closure $no): array
    {
        if ($args[0] !== '-C') {
            throw new RuntimeException('unexpected env');
        }
        $dir = $args[1];
        $rest = array_values(array_filter(array_slice($args, 2), static fn(string $a): bool => !preg_match('/^[A-Z]+=/', $a)));
        $tool = $rest[0];
        if (str_ends_with($tool, '/phpize')) {
            $this->building[$dir] = explode('/', substr($tool, strlen($this->php) + 1))[0];
            return $ok();
        }
        if ($tool === './configure') {
            return $ok();
        }
        if ($tool === '/usr/bin/make') {
            if (!$this->makeOk) {
                return $no('make: *** [redis.lo] Error 1');
            }
            mkdir("$dir/modules");
            if ($this->makeLink !== null) {
                symlink($this->makeLink, "$dir/modules/redis.so");
                return $ok();
            }
            file_put_contents("$dir/modules/redis.so", 'so-built-' . $this->building[$dir] . '-' . $this->buildId($this->building[$dir]));
            return $ok();
        }
        throw new RuntimeException("unexpected env command $tool");
    }
}

$root = sys_get_temp_dir() . '/olscp-phpext-' . bin2hex(random_bytes(4));
mkdir($root, 0700);
register_shutdown_function(static fn() => rmtree($root));
$serial = 0;
/** @return array{0:Box, 1:ExtensionInstaller, 2:int} */
$world = static function (array $installed, array $prebuilt, bool $source = true) use ($root, &$serial, &$now): array {
    $dir = $root . '/w' . ++$serial;
    mkdir($dir);
    $box = new Box();
    $box->php = "$dir/opt";
    $box->bundle = "$dir/bundle";
    $box->state = "$dir/state";
    $box->buildRoot = "$dir/var-lib/private";
    $box->systemdRun = "$dir/systemd-run";
    mkdir($box->buildRoot, 0700, true);
    file_put_contents($box->systemdRun, "#!/bin/sh\n");
    chmod($box->systemdRun, 0755);
    mkdir($box->php);
    foreach ($installed as $ea) {
        $box->addPhp($ea);
    }
    $box->prebuilt($prebuilt, $source);
    $now = 1_800_000_000;
    $installer = new ExtensionInstaller($box, $box->bundle, $box->php, $box->state, static function () use (&$now): int {
        return $now;
    }, $box->buildRoot, static function (string $php, string $revision) use ($box): void {
        $box->ledger->mark($php, $revision);
    }, $box->systemdRun);
    $env = new Environment($box, "$dir/envstate", null, null, true, null, static function (float $s): void {
    }, static function () use (&$now): int {
        return $now;
    }, phpRoot: $box->php);
    $box->ledger = ExtensionSync::ledger($env, $box, static function (string $account) use ($box): array {
        $box->restarted[] = $account;
        return isset($box->restartFails[$account]) ? ['result' => 'failed', 'remaining' => 1] : ['result' => 'restarted'];
    });
    $box->sync = new ExtensionSync($installer, $box->ledger);
    return [$box, $installer];
};
$now = 1_800_000_000;
$statuses = static fn(array $report): array => array_column($report['versions'], 'status', 'php');

// --- Bundle index ------------------------------------------------------------------------------------------------
[$box, $installer] = $world(['ea-php83'], ['ea-php83']);
$bundle = ExtensionBundle::load($box->bundle);
check($bundle !== null && $bundle->extensionVersion === '6.3.0' && array_keys($bundle->versions) === ['ea-php83']
    && $bundle->entry('ea-php83')['php_api'] === '20230831' && $bundle->sourcePath() === "{$box->bundle}/src/phpredis-6.3.0.tgz", 'index round trip');
check(ExtensionBundle::load("{$box->bundle}/none") === null, 'no index means no bundle');
foreach (['{"schema_version":2}', 'not json', '{"schema_version":1,"extension":"redis","extension_version":"6.3.0","versions":{"ea-php83":{"so":"/etc/passwd","sha256":"' . str_repeat('a', 64)
    . '","size":1,"php_api":"20230831","build_id":"API20230831,NTS","built_with":"8.3"}}}'] as $text) {
    file_put_contents("{$box->bundle}/index.json", $text);
    try {
        ExtensionBundle::load($box->bundle);
        check(false, 'malformed index refused');
    } catch (Refused) {
        check(true, 'malformed index refused: ' . substr($text, 0, 30));
    }
}

// --- Prebuilt build with a matching ABI ----------------------------------------------------------------------------
[$box, $installer] = $world(['ea-php83'], ['ea-php83']);
$status = $installer->status();
check($status['wanted'] === false && $status['versions'][0]['status'] === 'inactive' && $status['versions'][0]['candidate'] === 'prebuilt'
    && $status['needs_sync'] === false && $status['watcher'] === false, 'status before: inactive, prebuilt candidate, not wanted');
$idle = $installer->sync();
check($idle['result'] === 'idle' && $box->count('modules') === 1 && !is_file($box->ini('ea-php83')), 'the watcher does nothing while the extension is not wanted');
$report = $installer->install();
check($report['result'] === 'activated' && $statuses($report) === ['ea-php83' => 'activated'] && $report['changed'] === ['ea-php83']
    && $report['versions'][0]['source'] === 'prebuilt' && $report['watcher'] === true && $box->watcher, 'install activates the prebuilt build and starts the watcher');
check(file_get_contents($box->ini('ea-php83')) === ExtensionInstaller::MARKER . "\nextension={$box->bundle}/ea-php83/redis.so\n"
    && (fileperms($box->ini('ea-php83')) & 0777) === 0644, 'INI text and mode');
check(array_values(array_diff(scandir("{$box->php}/ea-php83/root/etc/php.d"), ['.', '..'])) === ['zz-ols-cpanel-redis.ini'], 'one file written, no temporary file left');
check(ExtensionState::load("{$box->state}/state.json")->wanted === true, 'wanted recorded');
check($box->count('build-phpize') === 0 && $box->argvs('/usr/bin/dnf') === [], 'no build and no dnf when the prebuilt build matches');
$report = $installer->install();
check($report['result'] === 'unchanged' && $statuses($report) === ['ea-php83' => 'active'], 'second install changes nothing');
check($installer->status()['versions'][0]['status'] === 'active', 'status after: active');
// A patch update of EA4 PHP keeps the ABI: the same build keeps loading, nothing happens.
$box->abi['ea-php83'] = ['8.3.37', '20230831'];
$report = $installer->sync();
check($report['result'] === 'unchanged' && $report['changed'] === [] && $box->count('build-make') === 0, 'a patch update (same ABI) needs nothing');

// --- Already loaded: never touched ---------------------------------------------------------------------------------
[$box, $installer] = $world(['ea-php82', 'ea-php83'], ['ea-php82', 'ea-php83']);
$box->external['ea-php82'] = true;
$report = $installer->install();
check($statuses($report) === ['ea-php82' => 'already_loaded', 'ea-php83' => 'activated'] && !is_file($box->ini('ea-php82')), 'a redis loaded by other means is left alone');
check($box->count('abi') === 1, 'no ABI probe for a version that already loads redis');
$report = $installer->remove();
check($report['result'] === 'removed' && !is_file($box->ini('ea-php83')) && $box->loaded('ea-php82') && $box->watcher === true
    && ExtensionState::load("{$box->state}/state.json")->wanted === false, 'remove deletes only our INI and clears wanted; the shared PHP environment units keep running');
check($statuses($report) === [] || array_column($report['versions'], 'status', 'php') === ['ea-php83' => 'removed'], 'remove reports what it deleted');

// --- A foreign INI of the same name is never overwritten or removed -------------------------------------------------
[$box, $installer] = $world(['ea-php83'], ['ea-php83']);
file_put_contents($box->ini('ea-php83'), "extension=/somewhere/else.so\n");
$report = $installer->install();
check($statuses($report) === ['ea-php83' => 'failed'] && file_get_contents($box->ini('ea-php83')) === "extension=/somewhere/else.so\n", 'a foreign INI is not overwritten');
$report = $installer->remove();
check($report['versions'][0]['status'] === 'foreign' && is_file($box->ini('ea-php83')), 'a foreign INI is not removed');

// --- ABI mismatch: compile from the packaged source ---------------------------------------------------------------
[$box, $installer] = $world(['ea-php84'], ['ea-php84']);
$box->abi['ea-php84'] = ['8.4.27', '20990101'];  // the prebuilt build is for another API number
$report = $installer->install();
check($statuses($report) === ['ea-php84' => 'activated'] && $report['versions'][0]['source'] === 'local_build_new', 'ABI mismatch: built locally');
$dnf = $box->argvs('/usr/bin/dnf');
check(count($dnf) === 1 && array_slice($dnf[0], 0, 5) === ['/usr/bin/dnf', '-y', '--setopt=install_weak_deps=False', 'install', 'ea-php84-php-devel'],
    'dnf installs the EA4 development package (fixed argv)');
$names = array_column($box->calls, 0);
check(array_values(array_filter($names, static fn(string $n): bool => str_starts_with($n, 'phpext-build-')))
    === ['phpext-build-untar', 'phpext-build-phpize', 'phpext-build-configure', 'phpext-build-make', 'phpext-build-stop', 'phpext-build-cleanup'], 'build steps in order, then the unit is stopped and the directory removed');
$configure = array_values(array_filter($box->calls, static fn(array $c): bool => $c[0] === 'phpext-build-configure'))[0][1];
check(in_array("--with-php-config={$box->php}/ea-php84/root/usr/bin/php-config", $configure, true) && in_array('--disable-redis-igbinary', $configure, true), 'configure against the version\'s php-config, no optional libraries');
$make = array_values(array_filter($box->calls, static fn(array $c): bool => $c[0] === 'phpext-build-make'))[0][1];
check(in_array('-j2', $make, true), 'make -j2');
check(array_diff(scandir($box->buildRoot), ['.', '..']) === [], 'the private build directory is removed');
$local = ExtensionBundle::load("{$box->state}/redis");
check($local !== null && $local->entry('ea-php84')['php_api'] === '20990101' && $local->entry('ea-php84')['so'] === "{$box->state}/redis/ea-php84/redis.so"
    && (fileperms($local->entry('ea-php84')['so']) & 0777) === 0755 && hash_file('sha256', $local->entry('ea-php84')['so']) === $local->entry('ea-php84')['sha256'], 'local index records the build');
check(str_contains(file_get_contents($box->ini('ea-php84')), "extension={$box->state}/redis/ea-php84/redis.so"), 'INI points at the local build');
check($box->loaded('ea-php84'), 'the local build loads');
// Later passes reuse the local build (no second compile) after the INI is lost.
unlink($box->ini('ea-php84'));
$before = $box->count('build-make');
$report = $installer->sync();
check($statuses($report) === ['ea-php84' => 'activated'] && $report['versions'][0]['source'] === 'local_build' && $box->count('build-make') === $before, 'an earlier local build is reused');

// --- Missing prebuilt build (new PHP version) + new version appears later -----------------------------------------------
[$box, $installer] = $world(['ea-php83'], ['ea-php83']);
$installer->install();
$box->addPhp('ea-php85');  // the operator installs a new EA4 PHP; no prebuilt build for it
$box->vhosts = json_encode(['data' => ['versions' => [['account' => 'olscpa', 'version' => 'ea-php83'], ['account' => 'olscpb', 'version' => 'ea-php85'],
    ['account' => 'olscpc', 'version' => 'ea-php85'], ['account' => 'bad;name', 'version' => 'ea-php85']]]]);
$sync = $box->sync;
$status = $installer->status();
check($status['needs_sync'] === true && $status['versions'][1]['candidate'] === 'build_needed', 'status sees the new version needing work');
$report = $sync->sync();
check($statuses($report) === ['ea-php83' => 'active', 'ea-php85' => 'activated'] && $report['changed'] === ['ea-php85'], 'the watcher enables a new version automatically');
check($box->restarted === ['olscpb', 'olscpc'] && array_keys($report['restart']) === ['olscpb', 'olscpc'], 'every account on the changed version is restarted, and only those');
check($box->ledger->pending() === [], 'a successful restart clears the ledger');
check($box->loaded('ea-php85') && $box->count('build-make') === 1, 'built once');
// Account path: all accounts of a changed version restart (not only the one that asked), none when nothing changed.
$box->restarted = [];
$report = $sync->ensureForAccount('olscpa', ['ea-php83', 'ea-php85']);
check($report['changed'] === [] && $box->restarted === [], 'ensureForAccount: nothing changed, no restart');
unlink($box->ini('ea-php85'));
$report = $sync->ensureForAccount('olscpb', ['ea-php85', 'ea-php99']);
check($report['changed'] === ['ea-php85'] && $box->restarted === ['olscpb', 'olscpc'] && $report['not_installed'] === ['ea-php99'],
    'ensureForAccount restarts every account on the changed version and reports versions that are not installed');
// RV-31 item 8: a failing restart stays pending (durably) and is retried; it is never dropped.
$box->restartFails = ['olscpb' => true];
unlink($box->ini('ea-php85'));
$box->restarted = [];
$report = $sync->sync();
check($report['restart']['olscpb']['result'] === 'failed' && $report['restart']['olscpc']['result'] === 'restarted' && $report['changed'] === ['ea-php85']
    && $report['result'] === 'failed' && $report['restart_pending'] === ['ea-php85' => ['olscpb']], 'a failing restart is reported as pending and fails the pass');
$ledgerFile = json_decode((string) file_get_contents("{$box->state}/../envstate/php-env.json"), true);
check(array_keys($ledgerFile['restarts']['ea-php85']['accounts']) === ['olscpb'] && $ledgerFile['schema_version'] === 1
    && str_starts_with($ledgerFile['restarts']['ea-php85']['revision'], 'redis:'), 'the owed restart is persisted in the PHP environment state with its revision');
$box->restarted = [];
$report = $sync->sync();  // nothing changed in the extension, but the owed restart is retried
check($box->restarted === ['olscpb'] && $report['result'] === 'failed', 'the retry restarts only what is owed and keeps failing while it fails');
$box->restartFails = [];
$box->restarted = [];
$report = $sync->sync();
check($box->restarted === ['olscpb'] && $report['restart']['olscpb']['result'] === 'restarted' && !isset($report['restart_pending']) && $box->ledger->pending() === [],
    'once the restart succeeds the entry is cleared');
// Accounts that cannot be enumerated are recorded as unresolved, not as "no accounts".
unlink($box->ini('ea-php85'));
$box->vhosts = 'not json';
$box->restarted = [];
$report = $sync->sync();
check($report['changed'] === ['ea-php85'] && $report['result'] === 'failed' && $report['restart_unresolved'] === ['ea-php85'] && $box->restarted === []
    && $box->ledger->pending()['ea-php85']['unresolved'] === true, 'a failed account enumeration leaves the version unresolved and failed');
$box->vhosts = json_encode(['data' => ['versions' => [['account' => 'olscpb', 'version' => 'ea-php85'], ['account' => 'olscpc', 'version' => 'ea-php85']]]]);
$report = $sync->sync();
check($box->restarted === ['olscpb', 'olscpc'] && $box->ledger->pending() === [], 'the enumeration is retried and the restarts then happen');
// A newer revision supersedes: marking again while an account is still owed keeps one entry per account with the new revision.
$box->restartFails = ['olscpb' => true];
unlink($box->ini('ea-php85'));
$sync->sync();
$first = $box->ledger->pending()['ea-php85']['accounts']['olscpb'];
file_put_contents($box->state . '/redis/ea-php85/redis.so', file_get_contents($box->state . '/redis/ea-php85/redis.so'));  // unchanged content: same revision
unlink($box->ini('ea-php85'));
$sync->sync();
check($box->ledger->pending()['ea-php85']['accounts']['olscpb'] === $first && count($box->ledger->pending()['ea-php85']['accounts']) === 1, 'the same revision marked again does not duplicate');
$box->restartFails = [];
$sync->sync();
// A removed account is not retried forever.
$box->restartFails = [];

// --- No prebuilt index and no source: reported, nothing changed -------------------------------------------------------------
[$box, $installer] = $world(['ea-php83'], [], false);
$report = $installer->install();
check($statuses($report) === ['ea-php83' => 'no_source'] && $report['result'] === 'failed' && !is_file($box->ini('ea-php83')), 'no package data: reported as no_source');

// --- Failed build: recorded, back-off, retry, success clears ---------------------------------------------------------------
[$box, $installer] = $world(['ea-php85'], ['ea-php83']);
$box->makeOk = false;
$report = $installer->install();
check($statuses($report) === ['ea-php85' => 'failed'] && str_contains($report['versions'][0]['message'], 'build step make failed') && $report['versions'][0]['attempts'] === 1
    && $report['result'] === 'failed' && !is_file($box->ini('ea-php85')), 'build failure reported with its reason');
check($box->count('build-cleanup') === 1 && array_diff(scandir($box->buildRoot), ['.', '..']) === [], 'a failed build still removes its directory');
$failure = ExtensionState::load("{$box->state}/state.json")->failures['ea-php85'];
check($failure['attempts'] === 1 && $failure['at'] === $now && str_contains($failure['error'], 'make'), 'failure recorded in state.json');
check(str_contains(file_get_contents("{$box->state}/php-ext.log"), 'ea-php85: FAILED (attempt 1)'), 'failure logged');
$status = $installer->status();
check($status['needs_sync'] === false && $status['versions'][0]['last_failure']['retry_at'] === $now + ExtensionInstaller::RETRY_SECONDS, 'status shows the failure and the retry time; no work due during the back-off');
$builds = $box->count('build-make');
$report = $installer->sync();
check($statuses($report) === ['ea-php85' => 'backoff'] && $box->count('build-make') === $builds && $report['result'] === 'failed', 'within the back-off the watcher does not rebuild but still reports');
$now += ExtensionInstaller::RETRY_SECONDS + 1;
check($installer->status()['needs_sync'] === true, 'after the back-off work is due again');
$report = $installer->sync();
check($statuses($report) === ['ea-php85' => 'failed'] && $report['versions'][0]['attempts'] === 2 && $box->count('build-make') === $builds + 1, 'retried after the back-off');
$box->makeOk = true;
$report = $installer->install();  // the operator retries at once, ignoring the back-off
check($statuses($report) === ['ea-php85' => 'activated'] && ExtensionState::load("{$box->state}/state.json")->failures === [], 'an operator install retries at once; success clears the failure');
// dnf failure
[$box, $installer] = $world(['ea-php85'], ['ea-php83']);
$box->dnfOk = false;
$report = $installer->install();
check(str_contains($report['versions'][0]['message'], 'dnf could not install ea-php85-php-devel') && str_contains($report['versions'][0]['message'], 'Failed to download metadata'), 'dnf failure reported');
// a source tarball that does not match its pin is refused before anything runs
[$box, $installer] = $world(['ea-php85'], ['ea-php83']);
file_put_contents("{$box->bundle}/src/phpredis-6.3.0.tgz", 'tampered');
$report = $installer->install();
check(str_contains($report['versions'][0]['message'], 'does not match its recorded SHA-256') && $box->argvs('/usr/bin/dnf') === [] && $box->count('build-untar') === 0, 'a tampered source is never extracted');

// --- Load failure rolls the INI back; the next layer is tried ------------------------------------------------------------------
[$box, $installer] = $world(['ea-php83'], ['ea-php83']);
$box->badSo["{$box->bundle}/ea-php83/redis.so"] = true;
$report = $installer->install();
check($statuses($report) === ['ea-php83' => 'activated'] && $report['versions'][0]['source'] === 'local_build_new' && str_contains(file_get_contents($box->ini('ea-php83')), $box->state), 'a prebuilt build that does not load is rolled back and replaced by a local build');
[$box, $installer] = $world(['ea-php83'], ['ea-php83']);
$box->badSo["{$box->bundle}/ea-php83/redis.so"] = true;
$box->builtLoads = false;
$report = $installer->install();
check($statuses($report) === ['ea-php83' => 'failed'] && !is_file($box->ini('ea-php83')) && str_contains($report['versions'][0]['message'], 'prebuilt build: php -m does not list redis')
    && str_contains($report['versions'][0]['message'], 'the new build does not load'), 'every candidate failing leaves no INI behind and says why');
check(array_diff(scandir("{$box->php}/ea-php83/root/etc/php.d"), ['.', '..']) === [], 'no stray files in php.d');
// a corrupted prebuilt file
[$box, $installer] = $world(['ea-php83'], ['ea-php83']);
file_put_contents("{$box->bundle}/ea-php83/redis.so", 'corrupt');
$report = $installer->install();
check($report['versions'][0]['source'] === 'local_build_new', 'a prebuilt file that does not match its SHA-256 is never activated');

// --- Package transaction changes the ABI: the stale build is replaced ------------------------------------------------------------
[$box, $installer] = $world(['ea-php83'], ['ea-php83']);
$installer->install();
$box->abi['ea-php83'] = ['8.3.40', '20990202'];  // the PHP now has another ABI: the active build stops loading
check(!$box->loaded('ea-php83') && $installer->status()['versions'][0]['status'] === 'broken' && $installer->status()['needs_sync'] === true, 'status: broken after an ABI change');
$report = $installer->sync();
check($statuses($report) === ['ea-php83' => 'activated'] && $report['versions'][0]['source'] === 'local_build_new' && $box->loaded('ea-php83'), 'the watcher replaces a build that no longer matches');
// an unusable PHP
$box->abiFails = true;
unlink($box->ini('ea-php83'));
$report = $installer->sync();
check($statuses($report) === ['ea-php83' => 'php_unusable'] && $report['result'] === 'failed', 'a PHP that cannot report its build is reported');

// --- Versions: only real EA4 PHP directories ---------------------------------------------------------------------------------------
[$box, $installer] = $world(['ea-php83'], ['ea-php83']);
mkdir("{$box->php}/ea-php99/root/usr/bin", 0755, true);  // no php binary
mkdir("{$box->php}/ea-apr16");
mkdir("{$box->php}/ea-php7x");
check($installer->versions() === ['ea-php83'], 'only directories with a PHP binary count');
try {
    $installer->install('ea-php99');
    check(false, 'unknown version refused');
} catch (Refused $error) {
    check(str_contains($error->getMessage(), 'not an installed EA4 PHP version'), 'unknown version refused');
}
foreach (['ea-php83; id', '../ea-php83', 'php83'] as $bad) {
    try {
        $installer->install($bad);
        check(false, 'bad version refused');
    } catch (Refused) {
        check(true, 'bad version refused: ' . $bad);
    }
}

// --- Uninstall helpers --------------------------------------------------------------------------------------------------------------
[$box, $installer] = $world(['ea-php82', 'ea-php83'], ['ea-php82', 'ea-php83']);
$installer->install('ea-php83');
check($installer->ownInis() === ['ea-php83'], 'ownInis lists versions with our INI');
file_put_contents($box->ini('ea-php82'), "extension=/x.so\n");
$removed = $installer->removeInis();
check(array_column($removed['versions'], 'status', 'php') === ['ea-php82' => 'foreign', 'ea-php83' => 'removed'] && is_file($box->ini('ea-php82')), 'removeInis deletes only our files');

// --- Real php -n -i output parses (when a cPanel PHP is present) ------------------------------------------------------------------
foreach (glob('/opt/cpanel/ea-php[0-9][0-9]/root/usr/bin/php') ?: [] as $realPhp) {
    $run = new class implements CommandRunner {
        public function run(string $name, array $argv, int $timeout): array
        {
            $process = proc_open($argv, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
            $out = stream_get_contents($pipes[1]);
            $err = stream_get_contents($pipes[2]);
            return ['exit_code' => proc_close($process), 'stdout' => $out, 'stderr' => $err];
        }
    };
    $realRoot = dirname($realPhp, 4);
    $inst = new ExtensionInstaller($run, "$root/none", dirname($realRoot), "$root/real-state");
    $row = $inst->status()['versions'];
    $mine = array_values(array_filter($row, static fn(array $r): bool => $r['php'] === basename($realRoot)))[0];
    check(in_array($mine['status'], ['inactive', 'already_loaded', 'active', 'broken'], true) && ($mine['loaded'] || preg_match('/^[0-9.]+/', (string) $mine['php_version']) === 1),
        'real ' . basename($realRoot) . ' reports its build through php -n -i (' . ($mine['php_version'] ?? 'loaded') . ')');
    break;
}

// --- RV-31 item 16: the compile is unprivileged and sandboxed; root only installs dependencies and the final artifact -----
[$box, $installer] = $world(['ea-php84'], ['ea-php84']);
$box->abi['ea-php84'] = ['8.4.27', '20990101'];
$installer->install();
check($box->unsandboxed === [], 'tar, phpize, configure and make never run directly (as root)');
check(array_column($box->sandboxed, 'unit') === array_fill(0, 4, $box->sandboxed[0]['unit']) && str_starts_with($box->sandboxed[0]['unit'], 'ols-cpanel-ext-build-'),
    'the four build steps run as transient units of one build, under one name');
foreach ($box->sandboxed as $step) {
    foreach (['DynamicUser=yes', 'ProtectSystem=strict', 'PrivateNetwork=yes', 'NoNewPrivileges=yes', 'PrivateTmp=yes', 'CapabilityBoundingSet=', 'MemoryMax=2G',
        'TasksMax=256', 'StateDirectory=' . $step['unit'], 'ProtectHome=yes', 'RestrictAddressFamilies=AF_UNIX'] as $property) {
        check(in_array($property, $step['props'], true), "sandbox property $property");
    }
    check(count(array_filter($step['props'], static fn(string $p): bool => str_starts_with($p, 'RuntimeMaxSec='))) === 1, 'every step has a time limit');
}
$argv = array_values(array_filter($box->calls, static fn(array $c): bool => $c[0] === 'phpext-build-make'))[0][1];
check(array_slice($argv, 0, 6) === [$box->systemdRun, '--quiet', '--wait', '--pipe', '--collect', '--unit=' . $box->sandboxed[0]['unit']], 'systemd-run waits, pipes the output and collects the unit');
check($box->argvs('/usr/bin/dnf') !== [] && array_column($box->calls, 0)[0] !== 'phpext-build-untar', 'dependency installation (dnf) is the root step before the build');
check(array_diff(scandir($box->buildRoot), ['.', '..']) === [] && in_array('phpext-build-stop', array_column($box->calls, 0), true), 'the unit is stopped and the build directory removed afterwards');
check(file_exists("{$box->state}/redis/ea-php84/redis.so") && hash_file('sha256', "{$box->state}/redis/ea-php84/redis.so")
    === ExtensionBundle::load("{$box->state}/redis")->entry('ea-php84')['sha256'], 'the artifact is copied by root and recorded with its SHA-256');
// No systemd-run: refused, no fallback to a root build.
[$box, $installer] = $world(['ea-php84'], ['ea-php84']);
$box->abi['ea-php84'] = ['8.4.27', '20990101'];
unlink($box->systemdRun);
$report = $installer->install();
check($statuses($report) === ['ea-php84' => 'failed'] && str_contains($report['versions'][0]['message'], 'never compiled with root authority')
    && $box->unsandboxed === [] && $box->count('build-make') === 0, 'without systemd-run the build is refused, never run as root');
// A failing sandbox is a failed build, never retried unsandboxed.
[$box, $installer] = $world(['ea-php84'], ['ea-php84']);
$box->abi['ea-php84'] = ['8.4.27', '20990101'];
$box->sandboxFails = true;
$report = $installer->install();
check($statuses($report) === ['ea-php84' => 'failed'] && str_contains($report['versions'][0]['message'], 'build step untar failed') && $box->unsandboxed === [],
    'a sandbox that cannot start fails the build, with no unsandboxed fallback');
// What the build produced is not trusted: a symbolic link instead of redis.so is refused.
[$box, $installer] = $world(['ea-php84'], ['ea-php84']);
$box->abi['ea-php84'] = ['8.4.27', '20990101'];
file_put_contents("{$box->state}-secret", 'x');
$box->makeLink = "{$box->state}-secret";
$report = $installer->install();
check($statuses($report) === ['ea-php84' => 'failed'] && str_contains($report['versions'][0]['message'], 'produced no redis.so') && !file_exists("{$box->state}/redis/ea-php84/redis.so"),
    'a symbolic link as build output is refused and not copied');
// Leftovers of an interrupted build are pruned before the next one.
[$box, $installer] = $world(['ea-php84'], ['ea-php84']);
$box->abi['ea-php84'] = ['8.4.27', '20990101'];
mkdir("{$box->buildRoot}/ols-cpanel-ext-build-0123456789ab");
mkdir("{$box->buildRoot}/unrelated");
$installer->install();
check(!is_dir("{$box->buildRoot}/ols-cpanel-ext-build-0123456789ab") && is_dir("{$box->buildRoot}/unrelated"), 'an interrupted build is pruned, unrelated directories are left alone');

// --- RV-31: PHP older than 7.4 is unsupported for the object cache -----------------------------------------------------------
check(ExtensionInstaller::supported('ea-php74') && ExtensionInstaller::supported('ea-php83') && ExtensionInstaller::supported('ea-php100')
    && !ExtensionInstaller::supported('ea-php73') && !ExtensionInstaller::supported('ea-php56') && !ExtensionInstaller::supported('ea-php54'), 'the support gate: 7.4 and newer');
[$box, $installer] = $world(['ea-php56', 'ea-php73', 'ea-php74'], ['ea-php83']);
$status = $installer->status();
$rows = array_column($status['versions'], null, 'php');
check($rows['ea-php56']['status'] === 'unsupported' && $rows['ea-php73']['status'] === 'unsupported' && str_contains($rows['ea-php73']['message'], 'unsupported for the object cache')
    && $rows['ea-php74']['status'] === 'inactive', 'status: old versions say unsupported for the object cache; 7.4 is supported');
$report = $installer->install();
$st = $statuses($report);
check($st['ea-php56'] === 'unsupported' && $st['ea-php73'] === 'unsupported' && in_array($st['ea-php74'], ['activated'], true) && $report['result'] === 'activated'
    && !is_file($box->ini('ea-php56')) && !is_file($box->ini('ea-php73')), 'old PHP is neither built for nor activated; it is not a failure of the pass');
check(array_filter($box->sandboxed, static fn(array $s): bool => str_contains(implode(' ', $s['argv']), 'ea-php73') || str_contains(implode(' ', $s['argv']), 'ea-php56')) === []
    && $box->argvs('ea-php73-php-devel') === [], 'no build, no dnf for an unsupported version');
$report = $installer->install('ea-php73');
check($report['result'] === 'unchanged' && $statuses($report) === ['ea-php73' => 'unsupported'], 'a pass over only unsupported versions is unchanged, not failed');
// A redis that loads by other means in an old PHP is left alone and reported as it is.
[$box, $installer] = $world(['ea-php73'], ['ea-php83']);
$box->external['ea-php73'] = true;
check($statuses($installer->install()) === ['ea-php73' => 'already_loaded'], 'an old PHP that already loads redis keeps it');

// --- RV-31 item 8: a replaced managed redis.so marks the accounts of the version; php-ext remove restarts too --------------------
[$box, $installer] = $world(['ea-php83'], ['ea-php83']);
$box->vhosts = json_encode(['data' => ['versions' => [['account' => 'olscpa', 'version' => 'ea-php83'], ['account' => 'olscpb', 'version' => 'ea-php83'],
    ['account' => 'olscpc', 'version' => 'ea-php84']]]]);
$box->sync->install(null);
check($box->restarted === ['olscpa', 'olscpb'], 'activation restarts every account of the version');
$box->restarted = [];
$unchanged = $box->sync->sync();
check($unchanged['result'] === 'unchanged' && $box->restarted === [] && $installer->status()['versions'][0]['replaced'] === false, 'the same artifact marks nothing');
$so = "{$box->bundle}/ea-php83/redis.so";
file_put_contents($so, 'v2-' . file_get_contents($so));  // a package update replaced the managed redis.so (same ABI suffix: it still loads)
check($installer->status()['versions'][0]['replaced'] === true, 'status shows the replaced artifact');
$box->restartFails = ['olscpb' => true];
$report = $box->sync->sync();
check($report['changed'] === ['ea-php83'] && $statuses($report) === ['ea-php83' => 'replaced'] && $box->restarted === ['olscpa', 'olscpb'] && $report['result'] === 'failed'
    && $box->ledger->pending()['ea-php83']['accounts'] === ['olscpb' => 'redis:' . hash_file('sha256', $so)], 'a replaced redis.so (new sha256) marks the accounts; a failed restart stays pending with the new revision');
$box->restartFails = [];
$box->restarted = [];
$report = $box->sync->sync();
check($box->restarted === ['olscpb'] && $report['result'] === 'unchanged' && $box->ledger->pending() === [], 'the owed restart completes later');
$box->restarted = [];
$report = $box->sync->remove();
check($report['result'] === 'removed' && !is_file($box->ini('ea-php83')) && $box->restarted === ['olscpa', 'olscpb'] && $report['restart']['olscpa']['result'] === 'restarted',
    'php-ext remove restarts the accounts of the versions that lost the extension');
$box->restarted = [];
$box->sync->remove();
check($box->restarted === [], 'a second remove changes nothing and restarts nothing');
// A removal whose restart fails stays owed.
[$box, $installer] = $world(['ea-php83'], ['ea-php83']);
$box->vhosts = json_encode(['data' => ['versions' => [['account' => 'olscpa', 'version' => 'ea-php83']]]]);
$box->sync->install(null);
$box->restartFails = ['olscpa' => true];
$report = $box->sync->remove();
check($report['result'] === 'failed' && !is_file($box->ini('ea-php83')) && $box->ledger->pending()['ea-php83']['accounts'] === ['olscpa' => 'redis:removed'], 'a failed restart after remove stays pending');
// A ledger that cannot be written keeps the extension in place on remove (nothing is removed unrecorded).
[$box, $installer] = $world(['ea-php83'], ['ea-php83']);
$box->vhosts = json_encode(['data' => ['versions' => [['account' => 'olscpa', 'version' => 'ea-php83']]]]);
$box->sync->install(null);
$broken = new ExtensionInstaller($box, $box->bundle, $box->php, $box->state, null, $box->buildRoot, static function (): void {
    throw new Refused('cannot write the state');
}, $box->systemdRun);
$report = $broken->remove();
check(is_file($box->ini('ea-php83')) && $report['versions'][0]['status'] === 'failed', 'a removal whose restart cannot be recorded is not carried out');

// --- CLI ----------------------------------------------------------------------------------------------------------------------------------
$stub = new class implements ExtensionService {
    /** @var list<string> */
    public array $log = [];
    public string $result = 'unchanged';

    public function status(): array
    {
        $this->log[] = 'status';
        return ['result' => 'status'];
    }

    public function ensureForAccount(string $user, array $versions): array
    {
        return [];
    }

    public function ensureVersions(array $versions): array
    {
        return [];
    }

    public function sync(): array
    {
        $this->log[] = 'sync';
        return ['result' => $this->result];
    }

    public function install(?string $only): array
    {
        $this->log[] = 'install:' . ($only ?? '');
        return ['result' => $this->result];
    }

    public function remove(): array
    {
        $this->log[] = 'remove';
        return ['result' => 'removed'];
    }

    public function want(): void
    {
    }
};
$cli = static function (EngineContext $context, array $argv) use ($stub): array {
    $commands = array_map(static fn(string $action): PhpExtCommand => new PhpExtCommand($context, $action, static fn() => $stub), array_keys(PhpExtCommand::ACTIONS));
    $stdout = fopen('php://memory', 'w+');
    $stderr = fopen('php://memory', 'w+');
    $code = (new Application($commands))->run([...$argv, '--format=json'], new Output(true, $stdout, $stderr));
    rewind($stdout);
    return [$code, json_decode((string) stream_get_contents($stdout), true)];
};
$asRoot = new EngineContext(0, 'root');
[$code, $out] = $cli($asRoot, ['php-ext', 'status']);
check($code === 0 && $out['result'] === 'status', 'php-ext status');
[$code, $out] = $cli($asRoot, ['php-ext', 'install', '--php=ea-php83']);
check($code === 0 && end($stub->log) === 'install:ea-php83', 'php-ext install --php');
[$code] = $cli($asRoot, ['php-ext', 'install']);
check($code === 0 && end($stub->log) === 'install:', 'php-ext install');
[$code] = $cli($asRoot, ['php-ext', 'remove']);
check($code === 0 && end($stub->log) === 'remove', 'php-ext remove');
$stub->result = 'failed';
[$code, $out] = $cli($asRoot, ['php-ext', 'sync']);
check($code === 1 && $out['result'] === 'failed', 'a failed pass exits 1 (the watcher unit shows failed)');
[$code] = $cli($asRoot, ['php-ext', 'status', '--bogus']);
check($code === 64, 'unknown option is a usage error');
$stub->log = [];
[$code, $out] = $cli(new EngineContext(1001, 'olscpa'), ['php-ext', 'status']);
check($code !== 0 && $stub->log === [], 'not root: refused, nothing run');
check(count(PhpExtCommand::ACTIONS) === 4 && count(array_filter(Application::defaultCommands(), static fn($c): bool => $c instanceof PhpExtCommand)) === 4, 'wired into the application');

echo "$count assertions passed\n";
