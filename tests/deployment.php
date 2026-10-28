<?php
declare(strict_types=1);

// Deployment layer against a scripted fake host (no command reaches the real server): prepare (native, hybrid,
// refusals), cutover (success, failure at every step with recover.sh run, stale plan, approval), the return to
// Apache and its verification, hooks verify, uninstall (dry run and real), the local command runner; the lock
// order, digest binding, timer and cleanup rules of review RV-29 (concurrent recovery and reconcile passes
// simulated with the real deployment lock).
require dirname(__DIR__) . '/src/bootstrap.php';

use OlsCpanel\Cli\Application;
use OlsCpanel\Cli\Command\ApacheReturnCommand;
use OlsCpanel\Cli\Command\HooksCommand;
use OlsCpanel\Cli\Command\InstallCommand;
use OlsCpanel\Cli\Command\UninstallCommand;
use OlsCpanel\Cli\Output;
use OlsCpanel\Deployment\ApacheReturn;
use OlsCpanel\Deployment\Backup;
use OlsCpanel\Deployment\BuilderCompilation;
use OlsCpanel\Deployment\Compilation;
use OlsCpanel\Deployment\ConfigurationActivator;
use OlsCpanel\Deployment\Cutover;
use OlsCpanel\Deployment\DeploymentError;
use OlsCpanel\Deployment\CutoverPlan;
use OlsCpanel\Deployment\Ea4Profile;
use OlsCpanel\Deployment\Environment;
use OlsCpanel\Deployment\Hooks;
use OlsCpanel\Deployment\Host;
use OlsCpanel\Deployment\Http3Firewall;
use OlsCpanel\Deployment\HybridHost;
use OlsCpanel\Deployment\Plugins;
use OlsCpanel\Deployment\Profile;
use OlsCpanel\Deployment\RecoveryScript;
use OlsCpanel\Events\ReconcileBusy;
use OlsCpanel\Events\ReconcileRefused;
use OlsCpanel\Events\Reconciler;
use OlsCpanel\Ols\Generation\Engine;
use OlsCpanel\Infrastructure\Process\CommandRunner;
use OlsCpanel\Infrastructure\Process\LocalCommandRunner;
use OlsCpanel\Ols\Compiler\CompilationRefused;

$count = 0;
function check(bool $condition, string $name): void
{
    global $count;
    if (!$condition) {
        throw new RuntimeException('FAIL: ' . $name);
    }
    ++$count;
}

/** A cPanel server in memory: every command the deployment layer runs is answered from (and changes) this state. */
final class FakeHost implements CommandRunner
{
    public bool $apacheEnabled = true;
    public bool $apacheMonitored = true;
    public bool $apacheRunning = true;
    public bool $olsRunning = false;
    /** @var array<string,bool> */
    public array $active = [];
    /** @var list<string> directories created with install -d */
    public array $dirs = [];
    public bool $eaNginx = false;
    /** @var array<string,bool> */
    public array $enabled = [];
    public array $tweaks = ['apache_port' => '0.0.0.0:80', 'apache_ssl_port' => '0.0.0.0:443'];
    public bool $nft = false;
    public bool $suexec = true;
    /** Further `httpd -M` lines (mod_ruid2, MPM ITK). */
    public string $modules = '';
    public bool $olsInstalled = true;
    /** @var array<string,array{owner:string, content:string}> */
    public array $files = [];
    /** @var list<array<string,string>> */
    public array $hooks = [];
    /** @var array<string,string> request "<scheme>://<host>/" => status Apache gives */
    public array $apacheAnswers = [];
    /** @var array<string,string> overrides of what OLS answers */
    public array $olsAnswers = [];
    /** @var array<string,true> step names that fail */
    public array $fail = [];
    public int $recoverExit = 0;
    /** recover.sh leaves this behind (verification failure scenarios) */
    public ?string $recoverLeaves = null;
    /** @var list<array{0:string, 1:list<string>}> */
    public array $calls = [];
    /** @var array<string,true> units that stay active when stopped */
    public array $stuck = [];
    /** @var array<string,\Closure():void> run once before the first command of that name (concurrent actors) */
    public array $during = [];
    /** @var list<array<string,mixed>> recover.sh runs: held (run under the caller's lock), exit code */
    public array $recoveries = [];
    /** firewalld: null = not installed/running, else the ports open "<port>/udp" (permanent and runtime) */
    public ?array $firewalldPermanent = null;
    public array $firewalldRuntime = [];
    /** zones other than "public": "<zone>/p" (permanent) and "<zone>/r" (runtime) => ports */
    public array $firewalldOther = [];
    public string $firewalldDefaultZone = 'public';
    public int $firewalldReloads = 0;
    /** firewall-cmd calls that changed or queried a port without naming a zone */
    public int $firewalldZoneless = 0;
    public int $csfRestarts = 0;
    /** `ip -o addr show` output */
    public string $ipOutput = '';
    /** `nft list ruleset` output (null: nft answers nothing) */
    public ?string $nftRuleset = null;
    /** @var array<string,string> account => home (getent passwd) */
    public array $passwd = [];
    /** @var array<string,array{active:bool, options:array<string,string>, fail_set?:bool}> WordPress installation path => LiteSpeed Cache */
    public array $wp = [];

    /** @return array<int,string> the port list of a zone and state, by reference */
    public function &firewalldList(string $zone, bool $permanent): array
    {
        if ($zone === 'public') {
            if ($permanent) {
                return $this->firewalldPermanent;
            }
            return $this->firewalldRuntime;
        }
        $key = $zone . ($permanent ? '/p' : '/r');
        $this->firewalldOther[$key] ??= [];
        return $this->firewalldOther[$key];
    }

    public function __construct(public string $profilePath)
    {
        $this->files = ['/var/cpanel/cpanel.config' => ['owner' => 'root:root:644', 'content' => "apache_port=0.0.0.0:80\n"],
            HybridHost::HTTPD_CONF => ['owner' => 'root:root:644', 'content' => "Listen 0.0.0.0:80\n"],
            '/etc/chkserv.d/chkservd.conf' => ['owner' => 'root:root:644', 'content' => "httpd:1\n"]];
        $this->hooks = [['category' => 'Cpanel', 'event' => 'Api2::Park::park', 'stage' => 'post',
            'hook' => '/usr/local/cpanel/3rdparty/wp-toolkit/bin/handle-event', 'escalateprivs' => '1']];
    }

    public function names(): array
    {
        return array_column($this->calls, 0);
    }

    public function index(string $name): int
    {
        $found = array_search($name, $this->names(), true);
        return $found === false ? -1 : $found;
    }

    /** @return list<int> */
    public function apachePorts(): array
    {
        if (!$this->apacheRunning) {
            return [];
        }
        return array_map(static fn(string $v): int => (int) substr($v, strrpos($v, ':') + 1), array_values($this->tweaks));
    }

    public function run(string $name, array $argv, int $timeout): array
    {
        if (isset($this->during[$name])) {
            $actor = $this->during[$name];
            unset($this->during[$name]);
            $actor();
        }
        $this->calls[] = [$name, $argv];
        if (isset($this->fail[$name])) {
            return ['exit_code' => 1, 'stdout' => '', 'stderr' => "injected failure of $name"];
        }
        if (str_starts_with($name, 'plugin-')) {
            return ['exit_code' => 0, 'stdout' => '', 'stderr' => ''];
        }
        $ok = static fn(string $out = ''): array => ['exit_code' => 0, 'stdout' => $out, 'stderr' => ''];
        $no = static fn(int $code = 1): array => ['exit_code' => $code, 'stdout' => '', 'stderr' => ''];
        $api = static fn(string $command, array $data): array => ['exit_code' => 0, 'stderr' => '',
            'stdout' => json_encode(['metadata' => ['result' => 1, 'command' => $command], 'data' => $data])];
        $cmd = $argv[0];
        $args = array_slice($argv, 1);
        switch ($cmd) {
            case '/usr/local/cpanel/bin/whmapi1':
                $call = $args[1];
                $kv = [];
                foreach (array_slice($args, 2) as $pair) {
                    [$k, $v] = explode('=', $pair, 2);
                    $kv[$k] = $v;
                }
                if ($call === 'servicestatus') {
                    return $api($call, ['service' => [['name' => 'httpd', 'enabled' => (int) $this->apacheEnabled,
                        'monitored' => (int) $this->apacheMonitored, 'running' => (int) $this->apacheRunning]]]);
                }
                if ($call === 'get_tweaksetting') {
                    return $api($call, ['tweaksetting' => ['key' => $kv['key'], 'value' => $this->tweaks[$kv['key']]]]);
                }
                if ($call === 'set_tweaksetting') {
                    $this->tweaks[$kv['key']] = $kv['value'];
                    return $api($call, []);
                }
                if ($call === 'configureservice') {
                    $this->apacheEnabled = $kv['enabled'] === '1';
                    $this->apacheMonitored = $kv['monitored'] === '1';
                    $this->apacheRunning = $this->apacheEnabled;
                    return $api($call, []);
                }
                throw new LogicException("unexpected API call $call");
            case '/usr/sbin/ss':
                preg_match_all('/sport = :(\d+)/', $args[2], $m);
                $lines = [];
                foreach (array_map('intval', $m[1]) as $port) {
                    if (in_array($port, $this->apachePorts(), true)) {
                        $lines[] = "LISTEN 0 511 0.0.0.0:$port 0.0.0.0:* users:((\"httpd\",pid=10,fd=4),(\"httpd\",pid=11,fd=4))";
                    }
                    if ($this->olsRunning && in_array($port, [80, 443], true)) {
                        $lines[] = "LISTEN 0 511 *:$port *:* users:((\"litespeed\",pid=20,fd=9))";
                    }
                }
                return $ok(implode("\n", $lines) . ($lines === [] ? '' : "\n"));
            case '/usr/bin/systemctl':
                return $this->systemctl($args);
            case '/usr/bin/systemd-run':
                $unit = substr($args[0], strlen('--unit='));
                $this->active["$unit.timer"] = true;
                return $ok();
            case '/usr/bin/rpm':
                if ($args[0] === '-V') {
                    return $ok();
                }
                if ($args === ['-q', 'ea-nginx']) {
                    return $this->eaNginx ? $ok('ea-nginx-1.27.0-1.el9.x86_64') : $no();
                }
                return $this->olsInstalled ? $ok('1.9.3-1.olscp8.el9.x86_64') : $no();
            case '/usr/bin/curl':
                if (end($argv) === 'http://127.0.0.1/') {
                    return $ok(in_array(80, $this->apachePorts(), true) ? '200' : '000');
                }
                $url = end($argv);
                $port = str_starts_with($url, 'https') ? 443 : 80;
                if ($this->olsRunning && in_array($port, [80, 443], true)) {
                    return $ok($this->olsAnswers[$url] ?? $this->apacheAnswers[$url] ?? '200');
                }
                return $ok(in_array($port, $this->apachePorts(), true) ? ($this->apacheAnswers[$url] ?? '200') : '000');
            case '/usr/bin/stat':
                $path = end($argv);
                if ($args[1] === '%U:%G:%a') {
                    return $ok("u:u:750\n");
                }
                return isset($this->files[$path]) ? $ok('regular file|' . $this->files[$path]['owner'] . "\n") : $no();
            case '/usr/bin/test':
                return isset($this->files[$args[1]]) ? $ok() : $no();
            case '/usr/bin/sha256sum':
                $path = end($argv);
                return isset($this->files[$path]) ? $ok(hash('sha256', $this->files[$path]['content']) . "  $path\n") : $no();
            case '/usr/bin/cp':
                if ($args[0] === '--') {
                    // cp onto an existing file keeps its owner and mode.
                    $source = $argv[2];
                    $content = isset($this->files[$source]) ? $this->files[$source]['content'] : (string) @file_get_contents($source);
                    $this->files[$argv[3]] = ['owner' => $this->files[$argv[3]]['owner'] ?? 'root:root:644', 'content' => $content];
                    return $ok();
                }
                file_put_contents($argv[5], $this->files[$argv[4]]['content']);
                return $ok();
            case '/usr/bin/cat':
                return isset($this->files[end($argv)]) ? $ok($this->files[end($argv)]['content']) : $no();
            case '/usr/sbin/csf':
                ++$this->csfRestarts;
                return $ok();
            case '/usr/bin/firewall-cmd':
                if ($this->firewalldPermanent === null) {
                    return ['exit_code' => 252, 'stdout' => "not running\n", 'stderr' => ''];
                }
                if ($args === ['--state']) {
                    return $ok("running\n");
                }
                if ($args === ['--get-default-zone']) {
                    return $ok($this->firewalldDefaultZone . "\n");
                }
                if ($args === ['--reload']) {
                    ++$this->firewalldReloads;
                    $this->firewalldRuntime = $this->firewalldPermanent;
                    return $ok("success\n");
                }
                $permanent = in_array('--permanent', $args, true);
                $zone = null;
                $option = null;
                foreach ($args as $a) {
                    if (str_starts_with($a, '--zone=')) {
                        $zone = substr($a, 7);
                    } elseif ($a !== '--permanent') {
                        $option = $a;
                    }
                }
                if ($zone === null) {
                    ++$this->firewalldZoneless;
                    $zone = $this->firewalldDefaultZone;
                }
                preg_match('/^--(query|add|remove)-port=(\S+)$/', (string) $option, $m);
                $list = &$this->firewalldList($zone, $permanent);
                $has = in_array($m[2], $list, true);
                if ($m[1] === 'query') {
                    return $has ? $ok("yes\n") : $no();
                }
                $list = $m[1] === 'add' ? array_values(array_unique([...$list, $m[2]])) : array_values(array_diff($list, [$m[2]]));
                return $ok("success\n");
            case '/usr/bin/install':
                if (($args[0] ?? '') === '-d') {
                    $this->dirs[] = end($argv);
                    return $ok();
                }
                $this->files[end($argv)] = ['owner' => 'root:root:644', 'content' => file_get_contents($argv[count($argv) - 2])];
                return $ok();
            case '/usr/bin/rm':
                unset($this->files[end($argv)]);
                return $ok();
            case HybridHost::NFT:
                if ($args[0] === '-f') {
                    $this->nft = true;
                    return $ok();
                }
                if ($args[0] === 'delete') {
                    $this->nft = false;
                    return $ok();
                }
                if ($args === ['list', 'ruleset']) {
                    return $this->nftRuleset === null ? $no() : $ok($this->nftRuleset);
                }
                return $this->nft ? $ok("table inet ols_cpanel_hybrid {}\n") : $no();
            case '/usr/bin/grep':
                $port = substr($args[2], strlen('Listen 0.0.0.0:'));
                $ports = array_map(static fn(string $v): string => substr($v, strrpos($v, ':') + 1), $this->tweaks);
                return in_array($port, $ports, true) ? $ok("1\n") : ['exit_code' => 1, 'stdout' => "0\n", 'stderr' => ''];
            case '/usr/local/cpanel/scripts/restartsrv_httpd':
                $this->apacheRunning = true;
                return $ok();
            case '/usr/local/cpanel/scripts/rebuildhttpdconf':
            case '/usr/local/cpanel/scripts/enablefileprotect':
            case '/usr/bin/systemd-sysusers':
            case '/usr/bin/ln':
                return $ok();
            case '/usr/bin/openssl':
                // req -x509 ... -keyout <key> -out <cert>: the neutral default certificate.
                file_put_contents($args[array_search('-keyout', $args, true) + 1], "key\n");
                file_put_contents($args[array_search('-out', $args, true) + 1], "cert\n");
                return $ok();
            case HybridHost::IP:
                return $ok($this->ipOutput);
            case HybridHost::HTTPD:
                if ($args === ['-t']) {
                    return $ok();
                }
                return $ok("Loaded Modules:\n core_module (static)\n" . ($this->suexec ? " suexec_module (shared)\n" : '') . $this->modules);
            case Hooks::MANAGE:
                return $this->manageHooks($args);
            case '/bin/sh':
                return $this->recover($args[0], false);
            case '/usr/sbin/runuser':
                return $this->run($name, array_slice($argv, 4), $timeout);
            case '/usr/bin/getent':
                return isset($this->passwd[$args[1]]) ? $ok("{$args[1]}:x:1001:1001::{$this->passwd[$args[1]]}:/bin/bash\n") : $no(2);
            case '/usr/bin/head':
                return isset($this->files[end($argv)]) ? $ok($this->files[end($argv)]['content']) : $no();
            case '/usr/bin/env':
                if (str_starts_with($args[0], 'HOME=')) {
                    return $this->wpCli($args);
                }
                if ($args[0] !== RecoveryScript::DEPLOYMENT_LOCK_HELD . '=held' || $args[1] !== '/bin/sh') {
                    throw new LogicException('unexpected env command: ' . implode(' ', $argv));
                }
                return $this->recover($args[2], true);
        }
        throw new LogicException("unexpected command ($name): " . implode(' ', $argv));
    }

    /** wp-cli as the account: `plugin is-active`, `litespeed-option get|set` of the installation named by --path. */
    private function wpCli(array $args): array
    {
        $path = '';
        foreach ($args as $a) {
            if (str_starts_with($a, '--path=')) {
                $path = substr($a, 7);
            }
        }
        $rest = array_slice($args, (int) array_search('--skip-themes', $args, true) + 1);
        if (!isset($this->wp[$path])) {
            return ['exit_code' => 1, 'stdout' => '', 'stderr' => 'Error: not a WordPress installation'];
        }
        if ($rest[0] === 'plugin') {
            return ['exit_code' => $this->wp[$path]['active'] ? 0 : 1, 'stdout' => '', 'stderr' => ''];
        }
        if ($rest[1] === 'get') {
            return ['exit_code' => 0, 'stdout' => ($this->wp[$path]['options'][$rest[2]] ?? 'false') . "\n", 'stderr' => ''];
        }
        if ($this->wp[$path]['fail_set'] ?? false) {
            return ['exit_code' => 1, 'stdout' => '', 'stderr' => 'Error: cannot write the settings'];
        }
        $this->wp[$path]['options'][$rest[2]] = $rest[3];
        return ['exit_code' => 0, 'stdout' => '', 'stderr' => ''];
    }

    private function systemctl(array $args): array
    {
        $verb = $args[0];
        $units = array_values(array_filter(array_slice($args, 1), static fn(string $a): bool => $a !== '--now'));
        $now = in_array('--now', $args, true);
        foreach ($units as $unit) {
            match ($verb) {
                'is-active', 'is-enabled' => null,
                'start' => $this->active[$unit] = true,
                'stop' => $this->active[$unit] = isset($this->stuck[$unit]),
                'reset-failed' => null,
                'enable' => [$this->enabled[$unit] = true, $now ? $this->active[$unit] = true : null],
                'disable' => [$this->enabled[$unit] = false, $now ? $this->active[$unit] = isset($this->stuck[$unit]) : null],
            };
            if ($unit === 'ols-cpanel.service' && in_array($verb, ['start', 'stop', 'disable'], true) && ($verb !== 'disable' || $now)) {
                $this->olsRunning = $verb === 'start';
            }
        }
        if ($verb === 'is-active') {
            $on = $units[0] === 'ols-cpanel.service' ? $this->olsRunning : ($this->active[$units[0]] ?? false);
            return ['exit_code' => $on ? 0 : 3, 'stdout' => $on ? "active\n" : "inactive\n", 'stderr' => ''];
        }
        if ($verb === 'is-enabled') {
            $on = $this->enabled[$units[0]] ?? false;
            return ['exit_code' => $on ? 0 : 1, 'stdout' => $on ? "enabled\n" : "disabled\n", 'stderr' => ''];
        }
        return ['exit_code' => 0, 'stdout' => '', 'stderr' => ''];
    }

    private function manageHooks(array $args): array
    {
        if ($args[0] === 'list') {
            $grouped = [];
            foreach ($this->hooks as $h) {
                $grouped[$h['category']][$h['event']][] = $h;
            }
            $text = '';
            foreach ($grouped as $category => $events) {
                $text .= "$category:\n";
                foreach ($events as $event => $entries) {
                    $text .= "\t$event:\n";
                    foreach ($entries as $i => $h) {
                        $text .= ($i > 0 ? "\t\t--\n" : '') . "\t\tstage: {$h['stage']}\n\t\thook: {$h['hook']}\n\t\texectype: script\n"
                            . "\t\tweight: 100\n\t\tid: 00000000-0000-4000-8000-" . sprintf('%012d', $i) . "\n"
                            . ($h['escalateprivs'] === '1' ? "\t\tescalateprivs: 1\n" : '');
                    }
                }
            }
            return ['exit_code' => 0, 'stdout' => $text, 'stderr' => ''];
        }
        $opts = [];
        foreach ($args as $a) {
            if (preg_match('/^--(category|event|stage|escalateprivs)=(.*)$/', $a, $m)) {
                $opts[$m[1]] = $m[2];
            }
        }
        if ($args[0] === 'add') {
            $this->hooks[] = ['category' => $opts['category'], 'event' => $opts['event'], 'stage' => $opts['stage'],
                'hook' => $args[2], 'escalateprivs' => $opts['escalateprivs'] ?? '0'];
        } else {
            foreach ($this->hooks as $i => $h) {
                if ($h['hook'] === $args[2] && $h['category'] === $opts['category'] && $h['event'] === $opts['event']) {
                    unset($this->hooks[$i]);
                    $this->hooks = array_values($this->hooks);
                    break;
                }
            }
        }
        return ['exit_code' => 0, 'stdout' => '', 'stderr' => ''];
    }

    /**
     * What recover.sh does, read from the script itself (captured tweak values). Unless its caller holds the
     * deployment lock (held), it takes that lock as the script does; a held lock makes it give up (flock -w,
     * the wait shortened to nothing) without any change.
     */
    private function recover(string $script, bool $held): array
    {
        $text = (string) file_get_contents($script);
        $lock = null;
        if (!$held) {
            check(str_contains($text, 'exec 9>' . RecoveryScript::DEPLOYMENT_LOCK), 'recover.sh takes the deployment lock');
            $lock = fopen(dirname($this->profilePath) . '/deployment.lock', 'c');
            if (!flock($lock, LOCK_EX | LOCK_NB)) {
                fclose($lock);
                $this->recoveries[] = ['held' => false, 'exit_code' => 1];
                return ['exit_code' => 1, 'stdout' => '', 'stderr' => 'a deployment operation holds the deployment lock'];
            }
        }
        try {
            $result = $this->restore($text);
        } finally {
            if ($lock !== null) {
                fclose($lock);
            }
        }
        $this->recoveries[] = ['held' => $held, 'exit_code' => $result['exit_code']];
        return $result;
    }

    private function restore(string $text): array
    {
        if ($this->recoverExit !== 0) {
            return ['exit_code' => $this->recoverExit, 'stdout' => '', 'stderr' => 'recovery incomplete'];
        }
        $this->olsRunning = false;
        foreach (RecoveryScript::PRODUCT_UNITS as $unit) {
            $this->active[$unit] = false;
            $this->enabled[$unit] = false;
        }
        if (str_contains($text, 'rm -f ' . RecoveryScript::PRODUCT_PROFILE)) {
            @unlink($this->profilePath);
        }
        preg_match_all('/set_tweaksetting key=(\w+) value=(\S+) /', $text, $m, PREG_SET_ORDER);
        foreach ($m as [, $key, $value]) {
            $this->tweaks[$key] = $value;
        }
        unset($this->files[HybridHost::REMOTEIP_CONF]);
        // The firewall lines of recover.sh (FV-04), read from the script itself.
        if (preg_match('/^B=(\S+)$/m', $text, $b)
            && preg_match('/= ([0-9a-f]{64}) \]; then cat "\$B\/firewall\/csf\.conf" > (\S+); h=/', $text, $c)) {
            $current = $this->files[$c[2]]['content'] ?? null;
            if ($current !== null && hash('sha256', $current) === $c[1]) {
                $this->files[$c[2]]['content'] = (string) file_get_contents($b[1] . '/firewall/csf.conf');
                ++$this->csfRestarts;
            }
        }
        preg_match_all('/firewall-cmd (--permanent )?--zone=(\S+) --remove-port=443\/udp/', $text, $fw, PREG_SET_ORDER);
        foreach ($fw as [, $perm, $zone]) {
            $list = &$this->firewalldList($zone, $perm !== '');
            $list = array_values(array_diff($list, ['443/udp']));
            unset($list);
        }
        if (str_contains($text, 'firewall-cmd --reload')) {
            ++$this->firewalldReloads;
        }
        $this->nft = false;
        $this->apacheEnabled = $this->apacheMonitored = $this->apacheRunning = true;
        if ($this->recoverLeaves === 'nft') {
            $this->nft = true;
        } elseif ($this->recoverLeaves === 'tweak') {
            $this->tweaks['apache_ssl_port'] = '0.0.0.0:444';
        } elseif ($this->recoverLeaves === 'apache') {
            $this->apacheRunning = false;
        }
        return ['exit_code' => 0, 'stdout' => "recovered\n", 'stderr' => ''];
    }
}

final class FakeCompilation implements Compilation
{
    public string $config = "server config\n";
    public bool $blocked = false;
    /** a certificate the configuration references (its digest is part of the plan) */
    public ?string $cert = null;
    public int $calls = 0;

    public function compile(?array $hybridPorts): array
    {
        ++$this->calls;
        $plan = ['a.test' => ['ip' => '10.0.0.5', 'docroot' => '/home/a/public_html', 'php_handler' => 'fpm', 'mode' => 'native', 'user' => 'a'],
            'b.test' => ['ip' => '10.0.0.5', 'ipv6' => ['fd00::5'], 'docroot' => '/home/b/public_html', 'php_handler' => 'cgi',
                'mode' => 'native', 'user' => 'b']];
        $summary = ['hybrid_vhosts' => [], 'htaccess_blockers' => ['a.test' => [], 'b.test' => []]];
        if ($this->blocked) {
            if ($hybridPorts === null) {
                throw new CompilationRefused('untranslatable .htaccess in b.test (domain must stay on Apache)', ['b.test']);
            }
            $plan['b.test']['mode'] = 'apache';
            $summary = ['hybrid_vhosts' => ['b.test'], 'htaccess_blockers' => ['a.test' => [], 'b.test' => ['/: SetEnvIf']]];
        }
        $vhconf = ['a.test' => "vhost a\n" . ($this->cert === null ? '' : "  certFile {$this->cert}\n"),
            'b.test' => $this->blocked ? "proxy b\n" : "vhost b\n"];
        if ($this->blocked) {
            $vhconf['tls.b.test'] = "proxy tls b\n";
        }
        return ['config' => $this->config . ($hybridPorts === null ? '' : "hybrid\n"), 'vhconf' => $vhconf, 'plan' => $plan,
            'summary' => $summary];
    }
}

/** The reconciler's forced pass, faked: compiles again and, like Reconciler::activate, refuses another digest. */
final class FakeActivator implements ConfigurationActivator
{
    public ?string $failWith = null;
    public bool $profileSeen = false;
    public bool $olsStoppedBefore = false;
    public array $hybrid = [];
    public ?string $expected = null;

    public function __construct(private FakeHost $host, private FakeCompilation $compilation)
    {
    }

    public function activate(?string $expectedDigest = null): array
    {
        $this->profileSeen = file_exists($this->host->profilePath);
        $this->olsStoppedBefore = !$this->host->olsRunning;
        $this->expected = $expectedDigest;
        $profile = json_decode((string) file_get_contents($this->host->profilePath), true);
        $compiled = $this->compilation->compile($profile['hybrid_ports']);
        $files = OlsCpanel\Events\SourceDigest::referencedFiles($compiled, $this->host);
        if ($expectedDigest !== null && CutoverPlan::digest($compiled, $files) !== $expectedDigest) {
            throw new ReconcileRefused('the compiled configuration or a file it references differs from the approved plan');
        }
        if ($this->failWith !== null) {
            return ['action' => $this->failWith, 'reason' => 'health failed'];
        }
        $this->host->olsRunning = true;  // the activator's reload step starts the stopped unit
        return ['action' => 'committed', 'generation' => 'r20261022120000-abcdef', 'hybrid_vhosts' => $this->hybrid];
    }
}

/** A fresh state directory, fake host, compile and activator. */
function plugin_fixture(): string
{
    // The package's plugin trees as deploy() checks them (entry points are not read).
    $dir = sys_get_temp_dir() . '/ols-plugins-' . bin2hex(random_bytes(4));
    foreach (['whm', 'cpanel'] as $tree) {
        mkdir("$dir/$tree", 0755, true);
        file_put_contents("$dir/$tree/manifest.json", '{}');
        file_put_contents("$dir/$tree/" . ($tree === 'whm' ? 'index.cgi' : 'index.live.php'), 'entry');
    }
    // Removed when the run ends (runs had left thousands of these behind in /tmp).
    register_shutdown_function(static fn() => remove_tree($dir));
    return $dir;
}

function world(bool $blocked = false): array
{
    $state = sys_get_temp_dir() . '/ols-deploy-test-' . bin2hex(random_bytes(6));
    mkdir($state, 0755);
    $host = new FakeHost("$state/profile.json");
    $compilation = new FakeCompilation();
    $compilation->blocked = $blocked;
    $activator = new FakeActivator($host, $compilation);
    $activator->hybrid = $blocked ? ['b.test'] : [];
    $platform = json_decode((string) file_get_contents(__DIR__ . '/Fixtures/platform.json'), true)['observations'];
    $report = (new OlsCpanel\Cpanel\Discovery\PlatformInspector())->inspect($platform, ['architecture' => 'x86_64'], true);
    // The EA4 PHP root and the systemd unit directory of a world are temporary directories (never the real /opt/cpanel).
    mkdir("$state-opt", 0755);
    mkdir("$state-units", 0755);
    $env = new Environment($host, $state, $compilation, $activator, true, static fn(): array => $report,
        static function (float $s): void {
        }, pluginSource: plugin_fixture(), phpRoot: "$state-opt", unitDir: "$state-units");
    return ['state' => $state, 'host' => $host, 'compilation' => $compilation, 'activator' => $activator, 'env' => $env];
}

/**
 * Runs the CLI on a world: [exit code, decoded JSON result].
 * @param list<string> $argv
 */
function cli(array $w, array $argv, bool $tty = false, string $typed = ''): array
{
    $input = fopen('php://memory', 'w+');
    fwrite($input, $typed);
    rewind($input);
    $env = static fn(): Environment => $w['env'];
    $isTty = static fn(): bool => $tty;
    $app = new Application([new InstallCommand($env, $input, $isTty), new ApacheReturnCommand($env, $input, $isTty),
        new HooksCommand($env, $input, $isTty), new UninstallCommand($env, $input, $isTty)]);
    $stdout = fopen('php://memory', 'w+');
    $stderr = fopen('php://memory', 'w+');
    $code = $app->run([...$argv, '--format=json'], new Output(true, $stdout, $stderr));
    rewind($stdout);
    rewind($stderr);
    $text = stream_get_contents($stdout);
    $GLOBALS['stderr'] = stream_get_contents($stderr);
    return [$code, $text === '' ? null : json_decode($text, true, 64, JSON_THROW_ON_ERROR)];
}

function remove_tree(string $path): void
{
    if (is_dir($path) && !is_link($path)) {
        foreach (scandir($path) as $name) {
            if ($name !== '.' && $name !== '..') {
                remove_tree("$path/$name");
            }
        }
        rmdir($path);
    } elseif (file_exists($path) || is_link($path)) {
        unlink($path);
    }
}

/** Host restored to Apache after a recovery or return. */
function restored(array $w): bool
{
    $h = $w['host'];
    return $h->apacheEnabled && $h->apacheMonitored && $h->apacheRunning && !$h->olsRunning && !$h->nft
        && !isset($h->files[HybridHost::REMOTEIP_CONF]) && $h->tweaks === ['apache_port' => '0.0.0.0:80', 'apache_ssl_port' => '0.0.0.0:443']
        && !file_exists($w['state'] . '/profile.json')
        && array_filter($h->hooks, static fn(array $x): bool => $x['hook'] === Hooks::ENTRY) === [];
}

const CHANGING = ['configureservice', 'set_tweaksetting', 'systemd-run', '/usr/bin/install', '-f', 'add', 'del', 'restartsrv_httpd'];
function changed_host(FakeHost $h, int $from = 0): bool
{
    foreach (array_slice($h->calls, $from) as [$name, $argv]) {
        // Prepare deploys the product's own plugins (no Apache, port or tenant change).
        if (str_starts_with($name, 'plugin-')) {
            continue;
        }
        foreach ($argv as $a) {
            // Prepare may create its own directories (install -d); installing files is a host change.
            if ($argv[0] === '/usr/bin/install' && ($argv[1] ?? '') === '-d') {
                continue 2;
            }
            if (in_array($a, CHANGING, true) || str_ends_with($a, 'restartsrv_httpd')) {
                return true;
            }
        }
        if ($argv[0] === '/usr/bin/systemctl' && !in_array($argv[1], ['is-active', 'is-enabled'], true)
            && !($argv[1] === 'enable' && in_array($argv[3] ?? '', ['ols-cpanel-broker.service', 'ols-cpanel-hybrid-trust.timer', 'ols-cpanel-cache-clean.timer', 'ols-cpanel-objcache.timer', 'ols-cpanel-notify.timer', 'ols-cpanel-schedule.timer'], true))) {
            return true;
        }
    }
    return false;
}

// ---- prepare -------------------------------------------------------------------------------------------------
$w = world();
[$code, $out] = cli($w, ['install', '--prepare', '--native']);
check($code === 0 && $out['result'] === 'prepared' && $out['hybrid_vhosts'] === [] && $out['profile']['hybrid_ports'] === null,
    'prepare --native writes a native plan');
check(($w['host']->enabled['ols-cpanel-objcache.timer'] ?? false) === true, 'prepare enables the account-state fallback automatically');
check(!in_array('apache-suexec', array_column(json_decode((string) file_get_contents($w['state'] . "/plans/{$out['plan']}.json"), true)['checks'], 'name'), true),
    '--native does not need suEXEC');
// HR-D14: the default is the hybrid profile even when no vhost needs Apache today.
$d = world();
[$code, $o] = cli($d, ['install', '--prepare']);
check($code === 0 && $o['hybrid_vhosts'] === [] && $o['profile']['hybrid_ports'] === [81, 444]
    && str_contains(implode(' ', $o['host_changes']), 'Apache stays in standby behind OpenLiteSpeed for sites that need it')
    && $d['host']->index('httpd-modules') >= 0, 'prepare defaults to the hybrid profile (standby) with no hybrid vhost');
[$code, $o] = cli($d, ['install', '--prepare', '--hybrid']);
check($code === 0 && $o['profile']['hybrid_ports'] === [81, 444], '--hybrid stays accepted (same as the default)');
[$code, $o] = cli($d, ['install', '--prepare', '--hybrid', '--native']);
check($code === 64, '--hybrid with --native is a usage error');
[$code, $o] = cli($d, ['install', '--cutover', '--plan=x', '--native']);
check($code === 64, '--native with --cutover is a usage error');
$planPath = $w['state'] . "/plans/{$out['plan']}.json";
check(is_file($planPath) && (fileperms($planPath) & 0777) === 0600 && (fileperms($w['state'] . '/plans') & 0777) === 0700,
    'plan file root 0600 in a 0700 directory');
$plan = json_decode((string) file_get_contents($planPath), true);
check($plan['vhost_count'] === 2 && $plan['ols_package'] === 'ols-cpanel-openlitespeed-1.9.3-1.olscp8.el9.x86_64'
    && preg_match('/^[0-9a-f]{64}$/', $plan['compile_sha256']) === 1
    && in_array('apache-owner', array_column($plan['checks'], 'name'), true), 'plan records package, digest and checks');
check($plan['certification_blockers'] === [], 'the supported platform (AlmaLinux 9 x86_64) has no platform blockers');
check(is_file($w['state'] . '/tls/default.key') && is_file($w['state'] . '/tls/default.crt')
    && (fileperms($w['state'] . '/tls') & 0777) === 0700 && $w['host']->index('default-certificate') >= 0,
    'prepare creates the neutral default listener certificate');
check($w['host']->index('adopt-main-config') >= 0, 'prepare links the main configuration to the active generation');
$nginx = world();
$nginx['host']->eaNginx = true;
[$code, $out] = cli($nginx, ['install', '--prepare']);
check($code === 1 && str_contains((string) ($out['error'] ?? ''), 'ea-nginx') && !is_dir($nginx['state'] . '/plans/x'),
    'prepare refuses while ea-nginx is installed');
check($w['host']->index('plugin-whm-register') >= 0 && $w['host']->index('plugin-cpanel-register') >= 0
    && $w['host']->index('plugin-whm-validate') < $w['host']->index('plugin-whm-switch')
    && $w['host']->index('plugin-cpanel-validate') < $w['host']->index('plugin-whm-aside')
    && $w['host']->index('plugin-cpanel-switch') < $w['host']->index('plugin-whm-register'),
    'prepare stages and validates both plugin trees, switches them, then registers');
check(!changed_host($w['host']) && $w['host']->index('sysusers') >= 0 && $w['host']->index('broker-enable') >= 0,
    'prepare changes nothing a cutover changes; it sets up the engine user and the broker');
check(($w['host']->enabled['ols-cpanel-cache-clean.timer'] ?? false) === true && $w['host']->index('cache-clean-timer-enable') >= 0,
    'prepare enables the hourly LSCache cleanup timer');
check(($w['host']->enabled['ols-cpanel-notify.timer'] ?? false) === true && ($w['host']->enabled['ols-cpanel-schedule.timer'] ?? false) === true,
    'prepare enables the notification and maintenance-window timers (FV-07)');
foreach (['events', 'events/done', 'staging', 'backups'] as $dir) {
    check((fileperms($w['state'] . "/$dir") & 0777) === 0700, "prepared state directory $dir is 0700");
}
check(!file_exists($w['state'] . '/profile.json'), 'prepare writes no profile');

$w = world(true);
[$code, $out] = cli($w, ['install', '--prepare', '--native']);
check($code === 1 && $out['result'] === 'refused' && $out['blockers'][0]['vhost'] === 'b.test'
    && $out['blockers'][0]['reasons'] === ['/: SetEnvIf'] && !is_dir($w['state'] . '/plans'), 'prepare --native refuses with the blocker list');
[$code, $out] = cli($w, ['install', '--prepare']);
check($code === 0 && $out['hybrid_vhosts'][0]['vhost'] === 'b.test', 'default prepare moves the blocked vhost to Apache instead of refusing');
[$code, $out] = cli($w, ['install', '--prepare', '--hybrid']);
check($code === 0 && $out['hybrid_vhosts'] === [['vhost' => 'b.test', 'reasons' => ['/: SetEnvIf']]] && $out['profile']['hybrid_ports'] === [81, 444]
    && $w['host']->index('httpd-modules') >= 0, 'prepare --hybrid lists hybrid vhosts with reasons and checks suEXEC');
$w['host']->suexec = false;
[$code, $out] = cli($w, ['install', '--prepare', '--hybrid']);
check($code === 1 && str_contains($out['error'], 'suexec_module'), 'hybrid without suEXEC is refused');
foreach ([' ruid2_module (shared)' => 'mod_ruid2', ' mpm_itk_module (shared)' => 'MPM ITK'] as $line => $label) {
    $w['host']->modules = "$line\n";
    [$code, $out] = cli($w, ['install', '--prepare', '--hybrid']);
    check($code === 0 && $out['profile']['hybrid_ports'] === [81, 444], "hybrid with $label in place of suEXEC (CGI as the account) is prepared");
}
$w['host']->modules = '';

$refusals = [
    'not root' => fn(array $w): array => [new Environment($w['host'], $w['state'], $w['compilation'], $w['activator'], false), 1],
    'existing profile' => function (array $w): array {
        file_put_contents($w['state'] . '/profile.json', "{\"production\": true, \"hybrid_ports\": null}\n");
        return [$w['env'], 1];
    },
    'OLS running' => function (array $w): array {
        $w['host']->olsRunning = true;
        return [$w['env'], 1];
    },
    'Apache not owner' => function (array $w): array {
        $w['host']->apacheRunning = false;
        return [$w['env'], 1];
    },
    'OLS package missing' => function (array $w): array {
        $w['host']->olsInstalled = false;
        return [$w['env'], 1];
    },
    'unsupported platform' => fn(array $w): array => [new Environment($w['host'], $w['state'], $w['compilation'], $w['activator'], true,
        static fn(): array => ['observation_complete' => true, 'platform' => ['os' => ['value' => ['ID' => 'ubuntu', 'VERSION_ID' => '24.04']],
            'cpanel' => ['value' => '11.138.0.18']], 'runtime' => ['architecture' => 'x86_64']]), 2],
];
foreach ($refusals as $label => $setup) {
    $w = world();
    [$env, $expected] = $setup($w);
    $w['env'] = $env;
    [$code, $out] = cli($w, ['install', '--prepare']);
    check($code === $expected && in_array($out['result'], ['refused', 'unsupported'], true) && !is_dir($w['state'] . '/plans'),
        "prepare refused: $label");
}

// ---- cutover ------------------------------------------------------------------------------------------------
/** A prepared world and its plan id. */
function prepared(bool $hybrid = false): array
{
    $w = world($hybrid);
    [$code, $out] = cli($w, $hybrid ? ['install', '--prepare'] : ['install', '--prepare', '--native']);
    if ($code !== 0) {
        throw new RuntimeException('prepare failed: ' . json_encode($out));
    }
    $w['host']->calls = [];
    return [$w, $out['plan']];
}

[$w, $id] = prepared();
[$code, $out] = cli($w, ['install', '--cutover', "--plan=$id"]);
check($code === 1 && $out['result'] === 'refused' && str_contains($out['error'], '--yes') && $w['host']->calls === [],
    'cutover without a terminal and without --yes is refused before any command');
[$code, $out] = cli($w, ['install', '--cutover', "--plan=$id"], true, "wrong\n");
check($code === 1 && str_contains($out['error'], 'not approved') && $w['host']->calls === [] && str_contains($GLOBALS['stderr'], $id),
    'a wrong typed plan id cancels; the summary names the plan');
foreach (["y\n", "yes please\n", "no\n"] as $typed) {
    [$code] = cli($w, ['install', '--cutover', "--plan=$id"], true, $typed);
    check($code === 1 && $w['host']->calls === [], 'only "yes" (or the plan id) approves: ' . trim($typed) . ' cancels');
}
check(str_contains($GLOBALS['stderr'], 'Type yes and press Enter to approve the cutover'), 'the question asks for "yes"');
[$code, $out] = cli($w, ['install', '--cutover', "--plan=$id"], true, "Yes\n");
$h = $w['host'];
check($code === 0 && $out['result'] === 'cut_over', 'cutover (native) approved by typing yes');
check($w['activator']->profileSeen && $w['activator']->olsStoppedBefore, 'profile written before the activation, OLS started by the activation');
$order = ['arm-recovery', 'hook-add', 'disable-httpd', 'apache-released', 'start-ols', 'ols-listeners', 'enablefileprotect',
    'ols-http', 'enable-units', 'enable-reconciler', 'disarm-recovery'];
$positions = array_map(fn(string $n): int => $h->index($n), $order);
check(!in_array(-1, $positions, true) && $positions === array_values(array_unique($positions)) && $positions == array_values(
    (function (array $p): array {
        sort($p);
        return $p;
    })($positions)), 'cutover steps in order: ' . implode(', ', $order));
check($h->index('apache-http') < $h->index('arm-recovery'), 'Apache baseline before any change');
check($h->olsRunning && !$h->apacheEnabled && !$h->apacheMonitored && ($h->enabled['ols-cpanel.service'] ?? false)
    && ($h->enabled['ols-cpanel-reconciler.service'] ?? false) && ($h->active['ols-cpanel-reconciler.service'] ?? false)
    && !($h->active['ols-cpanel-recover-' . $out['backup'] . '.timer'] ?? true), 'OLS serving, Apache disabled, units enabled, timer disarmed');
check($w['env']->hooks()->verify()['ok'], 'hooks registered and verified');
check(file_get_contents($w['state'] . '/profile.json') === "{\"production\":true,\"hybrid_ports\":null}\n", 'native profile written');
$manifest = (new Backup($w['env']))->load($out['backup']);
check($manifest['intact'] && $manifest['plan'] === $id && (fileperms($manifest['dir']) & 0777) === 0700
    && (fileperms($manifest['dir'] . '/recover.sh') & 0777) === 0700 && $manifest['hybrid'] === false, 'backup with intact recover.sh (0700)');
check($manifest['files']['/var/cpanel/cpanel.config']['copy'] === 'files/0'
    && file_get_contents($manifest['dir'] . '/files/0') === "apache_port=0.0.0.0:80\n"
    && $manifest['files'][HybridHost::REMOTEIP_CONF]['state'] === 'absent', 'byte-exact copies and file states in the manifest');
check($manifest['docroot_ownership']['/home/a/public_html'] === 'u:u:750', 'docroot ownership recorded for the return path');
$script = file_get_contents($manifest['dir'] . '/recover.sh');
check($script === RecoveryScript::render($manifest['dir'], [], [], [], false, product: true), 'recover.sh is the product recovery script');
$timer = $h->calls[$h->index('arm-recovery')][1];
check($timer === ['/usr/bin/systemd-run', "--unit=ols-cpanel-recover-{$out['backup']}", '--on-active=45min',
    '--timer-property=AccuracySec=1s', '/bin/sh', $manifest['dir'] . '/recover.sh'], 'recovery timer armed as the lab did');
[$code, $out] = cli($w, ['install', '--cutover', "--plan=$id", '--yes']);
check($code === 1 && str_contains($out['error'], 'already cut over'), 'a second cutover is refused');

[$w, $id] = prepared(true);
[$code, $out] = cli($w, ['install', '--cutover', "--plan=$id", '--yes']);
$h = $w['host'];
check($code === 0 && $out['result'] === 'cut_over' && $out['hybrid_vhosts'] === ['b.test'], 'cutover (hybrid)');
check($h->tweaks === ['apache_port' => '0.0.0.0:81', 'apache_ssl_port' => '0.0.0.0:444'] && $h->nft && $h->apacheEnabled
    && $h->files[HybridHost::REMOTEIP_CONF]['content'] === HybridHost::remoteipConf(['127.0.0.1', '::1', '10.0.0.5', 'fd00::5']),
    'hybrid host changes: tweaks, firewall, include with the local addresses');
check($h->index('remoteip-conf') < $h->index('nft-hybrid') && $h->index('nft-hybrid') < $h->index('tweak-set-apache_port')
    && $h->index('httpd-conf-listen') < $h->index('restart-httpd') && $h->index('restart-httpd') < $h->index('apache-released'),
    'hybrid order: include, firewall, tweaks, Listen lines, explicit Apache restart');
$manifest = (new Backup($w['env']))->load($out['backup']);
check($manifest['tweaks'] === ['apache_port' => '0.0.0.0:80', 'apache_ssl_port' => '0.0.0.0:443']
    && str_contains(file_get_contents($manifest['dir'] . '/recover.sh'), "set_tweaksetting key=apache_ssl_port value=0.0.0.0:443"),
    'captured tweak values in the manifest and recover.sh');
check(in_array('https://b.test/', array_map(fn(array $c): string => end($c[1]), array_filter($h->calls,
    fn(array $c): bool => $c[0] === 'ols-https')), true), 'hybrid vhost checked through its TLS vhost (HTTPS) too');
check(file_get_contents($w['state'] . '/profile.json') === "{\"production\":true,\"hybrid_ports\":[81,444]}\n", 'hybrid profile written');

// HR-D14: the default installation has no hybrid vhost yet still performs every hybrid host change (standby).
$w = world();
[$code, $o] = cli($w, ['install', '--prepare']);
$w['host']->calls = [];
[$code, $out] = cli($w, ['install', '--cutover', '--plan=' . $o['plan'], '--yes']);
$h = $w['host'];
check($code === 0 && $out['result'] === 'cut_over' && $out['hybrid_vhosts'] === [] && $out['profile']['hybrid_ports'] === [81, 444]
    && $h->tweaks === ['apache_port' => '0.0.0.0:81', 'apache_ssl_port' => '0.0.0.0:444'] && $h->nft
    && isset($h->files[HybridHost::REMOTEIP_CONF]) && $h->index('restart-httpd') >= 0 && $h->index('backend-listeners') >= 0
    && file_get_contents($w['state'] . '/profile.json') === "{\"production\":true,\"hybrid_ports\":[81,444]}\n",
    'default cutover: Apache in standby on 81/444 (include, firewall, tweaks, restart, verified) with no hybrid vhost');
[$code, $out] = cli($w, ['apache-return', '--execute', '--yes']);
check($code === 0 && $out['result'] === 'returned' && $out['failed_checks'] === [] && restored($w)
    && ($out['checks']['nft_table_absent'] ?? false) && ($out['checks']['tweaks_restored'] ?? false), 'default (standby) cutover returns to Apache completely');
foreach (['remoteip-conf', 'restart-httpd', 'backend-listeners', 'activate'] as $step) {
    $w = world();
    [$code, $o] = cli($w, ['install', '--prepare']);
    $w['host']->calls = [];
    match ($step) {
        'activate' => $w['activator']->failWith = 'rolled_back',
        default => $w['host']->fail[$step] = true,
    };
    [$code, $out] = cli($w, ['install', '--cutover', '--plan=' . $o['plan'], '--yes']);
    check($code === 1 && restored($w), "default (standby) cutover failing at $step returns the host to Apache");
}

// Failure at every step: recover.sh runs synchronously, the host is Apache's again, hooks gone, timer disarmed.
$failures = [false => ['hook-add', 'disable-httpd', 'apache-released', 'activate', 'start-ols', 'ols-active', 'ols-listeners',
    'enablefileprotect', 'vhost-health', 'enable-units', 'enable-reconciler', 'recovery-disarmed'],
    true => ['remoteip-conf', 'nft-hybrid', 'nft-present', 'tweak-set-apache_port', 'httpd-conf-listen', 'restart-httpd', 'backend-listeners',
        'activate', 'vhost-health']];
foreach ($failures as $hybrid => $steps) {
    foreach ($steps as $step) {
        [$w, $id] = prepared((bool) $hybrid);
        $h = $w['host'];
        match ($step) {
            'activate' => $w['activator']->failWith = 'rolled_back',
            'vhost-health' => $h->olsAnswers['http://a.test/'] = '503',
            'recovery-disarmed' => null,
            default => $h->fail[$step] = true,
        };
        if ($step === 'recovery-disarmed') {
            // The timer stays active after the stop: the cutover must not leave it to fire later.
            $w['env'] = new Environment(new class($h) implements CommandRunner {
                public bool $stuck = true;

                public function __construct(private FakeHost $h)
                {
                }

                public function run(string $name, array $argv, int $timeout): array
                {
                    if ($name === 'recovery-disarmed' && $this->stuck) {
                        $this->stuck = false;
                        $this->h->calls[] = [$name, $argv];
                        return ['exit_code' => 0, 'stdout' => "active\n", 'stderr' => ''];
                    }
                    return $this->h->run($name, $argv, $timeout);
                }
            }, $w['state'], $w['compilation'], $w['activator'], true, (fn() => $this->platform)->call($w['env']),
                static function (float $s): void {
                });
        }
        [$code, $out] = cli($w, ['install', '--cutover', "--plan=$id", '--yes']);
        $label = ($hybrid ? 'hybrid' : 'native') . " cutover failing at $step";
        check($code === 1 && ($out['result'] ?? null) === 'failed' && $out['recovery']['recovered'] === true
            && $h->index('recovery-run') > $h->index('arm-recovery'), "$label runs recover.sh");
        check(restored($w) && $out['recovery']['timer_disarmed'] && $out['recovery']['hooks']['ok'], "$label leaves Apache serving, hooks removed");
        check(end($out['steps'])['ok'] === false && is_file($w['state'] . "/backups/{$out['backup']}/cutover.json"), "$label is recorded");
        check(array_column($h->recoveries, 'held') === [true], "$label runs recover.sh under its own deployment lock (held)");
    }
}
// recover.sh itself failing: reported, timer kept armed for the retry.
[$w, $id] = prepared();
$w['activator']->failWith = 'rolled_back';
$w['host']->recoverExit = 1;
[$code, $out] = cli($w, ['install', '--cutover', "--plan=$id", '--yes']);
check($code === 1 && $out['recovery']['recovered'] === false && $out['recovery']['timer_disarmed'] === false
    && $w['host']->index('disarm-recovery') === -1, 'a failed recovery is reported and the timer stays armed');

// Stale plan: the cPanel state changed after prepare.
[$w, $id] = prepared();
$w['compilation']->config = "server config changed\n";
[$code, $out] = cli($w, ['install', '--cutover', "--plan=$id", '--yes']);
check($code === 1 && str_contains($out['error'], 'run install --prepare again') && !changed_host($w['host'])
    && glob($w['state'] . '/backups/*') === [], 'a stale plan is refused before any change');
[$code, $out] = cli($w, ['install', '--cutover', '--plan=p20990101000000-000000', '--yes']);
check($code === 1 && str_contains($out['error'], 'no plan'), 'an unknown plan is refused');
[$code, $out] = cli($w, ['install', '--cutover', '--plan=../../etc/passwd', '--yes']);
check($code === 1 && str_contains($out['error'], 'invalid plan id'), 'a plan id is never a path');
// Collision: an include the product did not create.
[$w, $id] = prepared(true);
$w['host']->files[HybridHost::REMOTEIP_CONF] = ['owner' => 'root:root:644', 'content' => "admin's\n"];
[$code, $out] = cli($w, ['install', '--cutover', "--plan=$id", '--yes']);
check($code === 1 && str_contains($out['error'], 'refusing to take over') && $w['host']->index('arm-recovery') === -1
    && $w['host']->files[HybridHost::REMOTEIP_CONF]['content'] === "admin's\n", 'an existing include is refused, never overwritten');
// Busy.
[$w, $id] = prepared();
$held = fopen($w['state'] . '/deployment.lock', 'c');
flock($held, LOCK_EX);
[$code, $out] = cli($w, ['install', '--cutover', "--plan=$id", '--yes']);
check($code === 75 && $out['result'] === 'busy', 'busy while another operation holds the lock');
fclose($held);
// No activator in this installation.
$w['env'] = new Environment($w['host'], $w['state'], $w['compilation'], null, true, (fn() => $this->platform)->call($w['env']));
[$code, $out] = cli($w, ['install', '--cutover', "--plan=$id", '--yes']);
check($code === 1 && str_contains($out['error'], 'activator') && $w['host']->calls === [], 'no activator: refused before any command');

// ---- apache-return ----------------------------------------------------------------------------------------------
foreach ([false, true] as $hybrid) {
    [$w, $id] = prepared($hybrid);
    cli($w, ['install', '--cutover', "--plan=$id", '--yes']);
    [$code, $out] = cli($w, ['apache-return', '--prepare']);
    check($code === 0 && $out['intact'] && $out['cut_over'] && str_contains(implode("\n", $out['actions']), 'recover.sh'),
        'apache-return --prepare shows an intact backup and the actions' . ($hybrid ? ' (hybrid)' : ''));
    $w['host']->calls = [];
    [$code, $out] = cli($w, ['apache-return', '--execute', '--yes']);
    check($code === 0 && $out['result'] === 'returned' && $out['failed_checks'] === [] && restored($w)
        && $w['host']->index('stop-reconciler') < $w['host']->index('recovery-run'), 'apache-return --execute' . ($hybrid ? ' (hybrid)' : ''));
    check(($out['checks']['nft_table_absent'] ?? !$hybrid) && ($out['checks']['tweaks_restored'] ?? !$hybrid), 'hybrid checks present when hybrid');
    [$code, $out] = cli($w, ['apache-return', '--execute', '--yes']);
    check($code === 0 && $out['result'] === 'nothing_to_do', 'a second return finds nothing to do');
}
foreach (['nft' => 'nft_table_absent', 'tweak' => 'tweaks_restored', 'apache' => 'apache_owns_80_443'] as $leftover => $failed) {
    [$w, $id] = prepared(true);
    cli($w, ['install', '--cutover', "--plan=$id", '--yes']);
    $w['host']->recoverLeaves = $leftover;
    [$code, $out] = cli($w, ['apache-return', '--execute', '--yes']);
    check($code === 1 && $out['result'] === 'failed' && in_array($failed, $out['failed_checks'], true), "apache-return verification catches $leftover");
}
[$w, $id] = prepared();
[$code, $out] = cli($w, ['install', '--cutover', "--plan=$id", '--yes']);
file_put_contents($w['state'] . "/backups/{$out['backup']}/recover.sh", "#!/bin/sh\nrm -rf /\n");
[$code, $out] = cli($w, ['apache-return', '--prepare']);
check($code === 1 && !$out['intact'] && str_contains($out['problem'], 'sha256'), 'a modified recover.sh is detected');
$w['host']->calls = [];
[$code, $out] = cli($w, ['apache-return', '--execute', '--yes']);
check($code === 1 && $w['host']->index('recovery-run') === -1, 'a modified recover.sh is never run');
[$code, $out] = cli(world(), ['apache-return', '--prepare']);
check($code === 1 && str_contains($out['error'], 'no cutover backup'), 'no backup: refused');
[$w, $id] = prepared();
cli($w, ['install', '--cutover', "--plan=$id", '--yes']);
[$code, $out] = cli($w, ['apache-return', '--execute']);
check($code === 1 && str_contains($out['error'], '--yes') && file_exists($w['state'] . '/profile.json'), 'apache-return needs approval');

// ---- hooks ------------------------------------------------------------------------------------------------------
$w = world();
[$code, $out] = cli($w, ['hooks', 'verify']);
check($code === 1 && $out['result'] === 'mismatch' && count($out['missing']) === count(Hooks::EVENTS), 'hooks verify: nothing registered');
[$code, $out] = cli($w, ['hooks', 'install']);
check($code === 0 && $out['ok'] && $out['added'] === count(Hooks::EVENTS), 'hooks install');
$adds = array_filter($w['host']->calls, static fn(array $c): bool => $c[0] === 'hook-add');
$first = array_values($adds)[0][1];
check($first === [Hooks::MANAGE, 'add', 'script', Hooks::ENTRY, '--manual', '--category=Whostmgr', '--event=Accounts::Create', '--stage=post'],
    'manage_hooks add argv');
[$code, $out] = cli($w, ['hooks', 'install']);
check($code === 0 && $out['added'] === 0, 'hooks install is idempotent');
array_pop($w['host']->hooks);
$w['host']->hooks[] = ['category' => 'Whostmgr', 'event' => 'Accounts::Create', 'stage' => 'pre', 'hook' => Hooks::ENTRY, 'escalateprivs' => '0'];
foreach ($w['host']->hooks as $i => $hook) {
    if ($hook['event'] === 'UAPI::SSL::install_ssl') {
        $w['host']->hooks[$i]['escalateprivs'] = '0';
    }
}
[$code, $out] = cli($w, ['hooks', 'verify']);
check($code === 1 && $out['result'] === 'mismatch' && in_array('Cpanel::UAPI::Fileman::save_file_content post escalateprivs=1', $out['missing'], true)
    && in_array('Whostmgr::Accounts::Create pre escalateprivs=0', $out['unexpected'], true)
    && in_array('Cpanel::UAPI::SSL::install_ssl post escalateprivs=0', $out['unexpected'], true), 'hooks verify reports missing and unexpected');
[$code, $out] = cli($w, ['hooks', 'remove']);
check($code === 0 && array_column($w['host']->hooks, 'hook') === ['/usr/local/cpanel/3rdparty/wp-toolkit/bin/handle-event'],
    'hooks remove leaves foreign hooks alone');
$sample = "PkgAcct:\n\tCreate:\n\t\tstage: pre\n\t\thook: PodmanHooks::_do_backup\n\t\texectype: module\n\t\t--\n\t\tweight: 200\n"
    . "\t\thook: " . Hooks::ENTRY . "\n\t\tstage: post\nCpanel:\n\tApi2::Park::unpark:\n\t\tescalateprivs: 1\n\t\thook: " . Hooks::ENTRY
    . "\n\t\tstage: post\n";
$parsed = Hooks::parseList($sample);
check(count($parsed) === 3 && $parsed[1]['event'] === 'Create' && $parsed[1]['hook'] === Hooks::ENTRY && $parsed[2]['category'] === 'Cpanel'
    && $parsed[2]['escalateprivs'] === '1', 'manage_hooks list parsing (recorded format)');

// ---- uninstall -------------------------------------------------------------------------------------------------
[$w, $id] = prepared(true);
cli($w, ['install', '--cutover', "--plan=$id", '--yes']);
$w['host']->calls = [];
$ea4 = new Ea4Profile($w['state'] . '/ea4-profiles');
$ea4->write();
[$code, $out] = cli($w, ['uninstall', '--dry-run']);
check(in_array('remove the recommended EA4 profile ' . $ea4->path(), array_column($out['actions'], 'action'), true) && $ea4->present(),
    'uninstall --dry-run lists the recommended EA4 profile and keeps it');
check($code === 0 && $out['result'] === 'dry_run' && $out['actions'][0]['action'] === 'apache-return'
    && !changed_host($w['host']) && file_exists($w['state'] . '/profile.json') && is_dir($w['state'] . '/generations') === false
    && in_array('remove ' . $w['state'] . '/plans', array_column($out['actions'], 'action'), true), 'uninstall --dry-run only reads');
[$code, $out] = cli($w, ['uninstall']);
check($code === 0 && $out['result'] === 'uninstalled' && restored($w) && array_diff(scandir($w['state']), ['.', '..', 'backups', 'deployment.lock']) === []
    && glob($w['state'] . '/backups/c*/recover.sh') !== [] && !($w['host']->enabled['ols-cpanel-broker.service'] ?? true),
    'uninstall returns to Apache, removes hooks, units and state, keeps backups');
check(in_array('removed the recommended EA4 profile ' . $ea4->path(), array_column($out['actions'], 'action'), true)
    && in_array('disable and stop ols-cpanel-php.path', array_column($out['actions'], 'action'), true), 'uninstall removes the recommended EA4 profile and stops the PHP environment watcher');

// ---- uninstall leaves the server as before (RV-33): object cache setting, OPcache INI, drop-ins, packages ----------------
use OlsCpanel\ObjectCache\ObjectCacheManager;
use OlsCpanel\ObjectCache\ObjectCacheState;
use OlsCpanel\ObjectCache\ValkeyConfig;
use OlsCpanel\Php\OpcacheManager;

const PRODUCT_PACKAGES = ['ols-cpanel', 'ols-cpanel-openlitespeed', 'ols-cpanel-php-redis'];

/** One WordPress site of the fake host: LiteSpeed Cache with its drop-in and runtime configuration files. */
function wp_site(FakeHost $h, string $user, string $dir, string $host, bool $files = true, bool $active = true): string
{
    $path = "/home/$user/$dir";
    $h->passwd[$user] = "/home/$user";
    foreach (["$path/wp-config.php", '/opt/cpanel/ea-php83/root/usr/bin/php'] as $file) {
        $h->files[$file] = ['owner' => "$user:$user:644", 'content' => ''];
    }
    $h->files["$path/wp-content/plugins/litespeed-cache"] = ['owner' => "$user:$user:755", 'content' => ''];
    if ($files) {
        $h->files["$path/wp-content/object-cache.php"] = ['owner' => "$user:$user:644", 'content' => "<?php // https://litespeedtech.com\n"];
        $h->files["$path/wp-content/.litespeed_conf.php"] = ['owner' => "$user:$user:644", 'content' => "<?php exit;?>\n"
            . json_encode(['object-host' => $host, 'object-kind' => true, 'object-port' => 0, 'object' => true])];
    }
    $h->wp[$path] = ['active' => $active, 'options' => ['object' => 'true', 'object-kind' => '1', 'object-host' => $host, 'object-port' => '0']];
    return $path;
}

/** The wp-cli writes (path, option, value) the fake host saw. @return list<array{0:string, 1:string, 2:string}> */
function wp_writes(FakeHost $h): array
{
    $writes = [];
    foreach ($h->calls as [$name, $argv]) {
        if ($argv[0] === '/usr/bin/env' && str_starts_with($argv[1] ?? '', 'HOME=') && ($i = array_search('litespeed-option', $argv, true)) !== false
            && $argv[$i + 1] === 'set') {
            $writes[] = [substr((string) current(array_filter($argv, static fn(string $a): bool => str_starts_with($a, '--path='))), 7), $argv[$i + 2], $argv[$i + 3]];
        }
    }
    return $writes;
}

/** A cut-over world with the product's object cache sites, OPcache INI files and drop-ins in place. */
function leftover_world(): array
{
    [$w, $id] = prepared();
    cli($w, ['install', '--cutover', "--plan=$id", '--yes']);
    $h = $w['host'];
    $socket = static fn(string $user): string => ValkeyConfig::socket("/home/$user");
    $site = ['state' => 'automatic', 'product_set' => true, 'checked' => 1, 'php' => 'ea-php83', 'error' => null];
    $state = new ObjectCacheState();
    $state->wordpress = [
        'alice' => [wp_site($h, 'alice', 'public_html', $socket('alice')) => $site],                      // files say: ours
        'bob' => [wp_site($h, 'bob', 'public_html', '/home/bob/own-redis.sock') => $site],                // the administrator's host
        'carol' => [wp_site($h, 'carol', 'public_html', $socket('carol'), false) => $site],               // no files: wp-cli decides, ours
        'dave' => [wp_site($h, 'dave', 'public_html', '127.0.0.1', false) => $site],                      // wp-cli decides, not ours
        'erin' => [wp_site($h, 'erin', 'public_html', $socket('erin')) => $site],                         // ours, but wp-cli fails
        'frank' => [wp_site($h, 'frank', 'public_html', $socket('frank')) => ['product_set' => false] + $site],  // never set by the product
    ];
    $h->wp['/home/erin/public_html']['fail_set'] = true;
    $state->save($w['state'] . '/objcache.json');
    // OPcache INI: ours (two versions), another file of that name, a link of that name, and another INI that must stay.
    $opt = $w['env']->phpRoot;
    foreach (['ea-php74', 'ea-php82', 'ea-php83', 'ea-php84'] as $version) {
        mkdir("$opt/$version/root/etc/php.d", 0755, true);
    }
    file_put_contents("$opt/ea-php74/root/etc/php.d/" . OpcacheManager::INI, OpcacheManager::iniText('ea-php74'));
    file_put_contents("$opt/ea-php83/root/etc/php.d/" . OpcacheManager::INI, OpcacheManager::iniText('ea-php83'));
    file_put_contents("$opt/ea-php83/root/etc/php.d/10-opcache.ini", "zend_extension=opcache.so\n");
    file_put_contents("$opt/ea-php82/root/etc/php.d/" . OpcacheManager::INI, "; an administrator's own file\nopcache.enable=1\n");
    file_put_contents("$opt/target.ini", OpcacheManager::iniText('ea-php84'));
    symlink("$opt/target.ini", "$opt/ea-php84/root/etc/php.d/" . OpcacheManager::INI);
    // systemd drop-ins of the instances: ours, one with a foreign file, a link to a directory, and names that are not the product's.
    $units = $w['env']->unitDir;
    foreach (['alice', 'bob'] as $user) {
        mkdir("$units/ols-cpanel-objcache@$user.service.d", 0755);
        file_put_contents("$units/ols-cpanel-objcache@$user.service.d/50-account.conf", ValkeyConfig::dropIn("/home/$user", 64));
    }
    file_put_contents("$units/ols-cpanel-objcache@bob.service.d/99-local.conf", "[Service]\nNice=5\n");
    mkdir("$units/elsewhere", 0755);
    file_put_contents("$units/elsewhere/50-account.conf", "keep\n");
    symlink("$units/elsewhere", "$units/ols-cpanel-objcache@carol.service.d");
    mkdir("$units/ols-cpanel-objcache@.service.d", 0755);
    mkdir("$units/other.service.d", 0755);
    $h->calls = [];
    return $w;
}

$w = leftover_world();
$h = $w['host'];
$opt = $w['env']->phpRoot;
$units = $w['env']->unitDir;
$ini = '/root/etc/php.d/' . OpcacheManager::INI;
[$code, $out] = cli($w, ['uninstall', '--dry-run']);
$names = array_column($out['actions'], 'action');
$sites = array_values(array_filter($out['actions'], static fn(array $a): bool => str_starts_with($a['action'], 'turn off the object cache')));
check($code === 0 && $out['result'] === 'dry_run' && array_column($sites, 'action') === [
        'turn off the object cache of LiteSpeed Cache in alice:/home/alice/public_html',
        'turn off the object cache of LiteSpeed Cache in carol:/home/carol/public_html',
        'turn off the object cache of LiteSpeed Cache in dave:/home/dave/public_html',
        'turn off the object cache of LiteSpeed Cache in erin:/home/erin/public_html'],
    'uninstall --dry-run lists the sites whose object cache it would turn off (files say ours, or wp-cli has to decide); the administrator\'s and unset ones are not listed');
check(in_array('remove the OPcache INI of ea-php74, ea-php83', $names, true)
    && in_array('remove the systemd drop-in ' . "$units/ols-cpanel-objcache@alice.service.d", $names, true)
    && in_array('remove the packages ols-cpanel, ols-cpanel-openlitespeed, ols-cpanel-php-redis (dnf, in the unit ols-cpanel-remove-packages)', $names, true),
    'uninstall --dry-run lists the OPcache INI versions, the drop-ins and the package removal');
check(wp_writes($h) === [] && $h->index('remove-packages') < 0 && $h->index('daemon-reload') < 0 && !changed_host($h)
    && is_file("$opt/ea-php74$ini") && is_dir("$units/ols-cpanel-objcache@alice.service.d") && !file_exists($w['state'] . '/objcache.lock')
    , 'uninstall --dry-run writes nothing: no wp-cli write, no file removed, no package removal, no daemon-reload');

[$code, $out] = cli($w, ['uninstall']);
$names = array_column($out['actions'], 'action');
$by = array_column($out['actions'], null, 'action');
check($code === 0 && $out['result'] === 'uninstalled' && wp_writes($h) === [
        ['/home/alice/public_html', 'object', 'false'], ['/home/carol/public_html', 'object', 'false'], ['/home/erin/public_html', 'object', 'false']]
    && $h->wp['/home/alice/public_html']['options']['object'] === 'false' && $h->wp['/home/carol/public_html']['options']['object'] === 'false',
    'uninstall turns the object cache off on the product-configured sites whose host is still the product socket');
check($h->wp['/home/bob/public_html']['options']['object'] === 'true' && $h->wp['/home/dave/public_html']['options']['object'] === 'true'
    && $h->wp['/home/frank/public_html']['options']['object'] === 'true'
    && $h->wp['/home/bob/public_html']['options']['object-host'] === '/home/bob/own-redis.sock'
    && $h->wp['/home/dave/public_html']['options']['object-host'] === '127.0.0.1'
    && $h->wp['/home/alice/public_html']['options']['object-host'] === ValkeyConfig::socket('/home/alice'),
    'an administrator\'s own object cache host, and a site the product never set, are never touched');
$failed = $by['turned off the object cache of LiteSpeed Cache in erin:/home/erin/public_html'] ?? [];
check(($failed['ok'] ?? null) === false && $failed['result'] === 'error' && str_contains($failed['reason'], 'wp litespeed-option set object failed')
    && str_contains($failed['reason'], 'cannot write the settings'),
    'a wp-cli failure is reported with the site and the reason');
check($h->index('objcache-stop') > $h->index('objcache-as-user') && $h->index('objcache-stop') > $h->index('disable-unit')
    && ($by['turned off the object cache of LiteSpeed Cache in alice:/home/alice/public_html']['result'] ?? '') === 'reverted'
    && array_diff(scandir($w['state']), ['.', '..', 'backups', 'deployment.lock']) === [],
    'the failed site does not abort the uninstall: the object cache is turned off before the instances stop, the state is removed');
check(!file_exists("$opt/ea-php74$ini") && !file_exists("$opt/ea-php83$ini") && is_file("$opt/ea-php83/root/etc/php.d/10-opcache.ini")
    && is_file("$opt/ea-php82$ini") && is_link("$opt/ea-php84$ini") && is_file("$opt/target.ini")
    && in_array('removed the OPcache INI of ea-php74', $names, true) && in_array('removed the OPcache INI of ea-php83', $names, true)
    && !in_array('removed the OPcache INI of ea-php82', $names, true) && !in_array('removed the OPcache INI of ea-php84', $names, true),
    'only the OPcache INI files the product wrote are removed (another file of that name, a link and other INI files stay)');
$reloads = array_filter($h->calls, static fn(array $c): bool => $c[1] === ['/usr/bin/systemctl', 'daemon-reload']);
check(!file_exists("$units/ols-cpanel-objcache@alice.service.d") && count($reloads) === 1
    && is_file("$units/ols-cpanel-objcache@bob.service.d/99-local.conf") && is_file("$units/ols-cpanel-objcache@bob.service.d/50-account.conf")
    && is_link("$units/ols-cpanel-objcache@carol.service.d") && is_file("$units/elsewhere/50-account.conf")
    && is_dir("$units/ols-cpanel-objcache@.service.d") && is_dir("$units/other.service.d"),
    'the per-account drop-ins are removed (one daemon-reload); a link, a directory with a foreign file and other names stay');
$remove = $h->calls[$h->index('remove-packages')][1] ?? [];
check($remove === ['/usr/bin/systemd-run', '--unit=ols-cpanel-remove-packages', '--no-block', '--collect', '/usr/bin/dnf', '-y', 'remove', ...PRODUCT_PACKAGES]
    && $h->index('remove-packages') === count($h->calls) - 1 && str_contains($out['next'], 'ols-cpanel-remove-packages'),
    'the product packages are removed by a transient unit, as the last step');

// --keep-packages, a package that is not installed, and a failing start of the removal.
$w = leftover_world();
[$code, $out] = cli($w, ['uninstall', '--keep-packages']);
check($code === 0 && $out['result'] === 'uninstalled' && $w['host']->index('remove-packages') < 0
    && str_contains($out['next'], 'dnf remove ols-cpanel ols-cpanel-openlitespeed ols-cpanel-php-redis') && str_contains($out['next'], '--keep-packages'),
    'uninstall --keep-packages removes no package and says how');
$w = leftover_world();
[$code, $out] = cli($w, ['uninstall', '--dry-run', '--keep-packages']);
check($code === 0 && !str_contains(implode("\n", array_column($out['actions'], 'action')), 'remove the packages'), 'the dry run with --keep-packages lists no package removal');
$w = leftover_world();
$w['host']->fail['remove-packages'] = true;
[$code, $out] = cli($w, ['uninstall']);
check($code === 0 && $out['result'] === 'uninstalled' && str_starts_with($out['next'], 'dnf could not be started')
    && end($out['actions'])['ok'] === false, 'a package removal that cannot be started is reported, with the manual command');
$w = leftover_world();
$w['host']->olsInstalled = false;
[$code, $out] = cli($w, ['uninstall']);
check($code === 0 && $w['host']->index('remove-packages') < 0 && $out['next'] === 'no product package is installed',
    'nothing is removed when no product package is installed');

// ---- review RV-29: locks, digests, timers, cleanup ----------------------------------------------------------------
/** The only backup directory of a world. */
function backup_dir(array $w): string
{
    $dirs = glob($w['state'] . '/backups/c*') ?: [];
    if (count($dirs) !== 1) {
        throw new RuntimeException('expected one backup, found ' . count($dirs));
    }
    return $dirs[0];
}

// Finding 6: the deployment lock is root:olscpanel 0640, so only the reconciler service shares it.
[$w, $id] = prepared();
check((fileperms($w['state'] . '/deployment.lock') & 0777) === 0640, 'the deployment lock is 0640 (no other user may hold it)');
// A reconcile pass holds the lock shared: cutover and apache-return are busy, never beside it.
$shared = fopen($w['state'] . '/deployment.lock', 'r');
flock($shared, LOCK_SH);
[$code, $out] = cli($w, ['install', '--cutover', "--plan=$id", '--yes']);
check($code === 75 && $out['result'] === 'busy' && $w['host']->index('arm-recovery') === -1, 'cutover is busy while a reconcile pass shares the lock');
fclose($shared);
// The recovery timer fires during the cutover: its recover.sh waits for the deployment lock (here: gives up at
// once) and changes nothing; its service still waits when the cutover completes and is stopped and verified.
[$w, $id] = prepared();
$h = $w['host'];
$timerRun = null;
$h->during['enablefileprotect'] = function () use ($w, $h, &$timerRun): void {
    $timerRun = $h->run('timer-recovery', ['/bin/sh', backup_dir($w) . '/recover.sh'], 900);
    $timerRun['ols_running'] = $h->olsRunning;
    $h->active[Backup::unit(basename(backup_dir($w))) . '.service'] = true;  // still waiting for the lock
};
$h->during['disarm-recovery'] = function () use ($w, &$recordBeforeDisarm): void {
    $recordBeforeDisarm = json_decode((string) @file_get_contents(backup_dir($w) . '/cutover.json'), true);
};
[$code, $out] = cli($w, ['install', '--cutover', "--plan=$id", '--yes']);
$unit = Backup::unit($out['backup']);
check($timerRun['exit_code'] === 1 && $timerRun['ols_running'] && $h->recoveries === [['held' => false, 'exit_code' => 1]],
    'a recovery started during the cutover waits for the deployment lock and changes nothing');
check($code === 0 && $out['result'] === 'cut_over' && $h->olsRunning
    && $h->calls[$h->index('disarm-recovery')][1] === [Host::SYSTEMCTL, 'stop', "$unit.timer", "$unit.service"]
    && !$h->active["$unit.service"] && !$h->active["$unit.timer"] && $h->index('recovery-idle') > $h->index('disarm-recovery'),
    'cutover completes only with the timer and the waiting recovery service stopped and verified');
// Finding 15: the record is durable before the fallback goes, and completed afterwards.
check(($recordBeforeDisarm['result'] ?? null) === 'cut_over'
    && json_decode((string) file_get_contents(backup_dir($w) . '/cutover.json'), true)['steps'] === $out['steps']
    && end($out['steps'])['step'] === 'recovery-disarmed', 'cutover.json is written before the disarm and completed after it');
// After the cutover released the lock, the timer's recovery takes it and returns the host to Apache.
$run = $h->run('timer-recovery', ['/bin/sh', backup_dir($w) . '/recover.sh'], 900);
check($run['exit_code'] === 0 && !$h->olsRunning && $h->apacheRunning && $h->apacheEnabled && !file_exists($w['state'] . '/profile.json')
    && end($h->recoveries) === ['held' => false, 'exit_code' => 0],
    'a recovery outside any deployment operation takes the free lock and runs');
// A recovery service that cannot be stopped: the cutover is not complete; the host returns to Apache.
[$w, $id] = prepared();
$h = $w['host'];
$h->during['enablefileprotect'] = function () use ($w, $h): void {
    $service = Backup::unit(basename(backup_dir($w))) . '.service';
    $h->active[$service] = true;
    $h->stuck[$service] = true;
};
[$code, $out] = cli($w, ['install', '--cutover', "--plan=$id", '--yes']);
check($code === 1 && $out['result'] === 'failed' && str_contains($out['error'], 'recovery service') && $out['recovery']['recovered']
    && !$out['recovery']['timer_disarmed'] && restored($w), 'a running recovery service fails the cutover, which recovers');

// Reconcile passes: the deployment lock SHARED for each pass, never beside an exclusive holder; activate() runs
// under the cutover's exclusive hold; the digest of the approved plan.
final class LockProbeEngine implements Engine
{
    public array $log = [];
    /** set by the compile: the next status() is past the digest check and ends the pass */
    public bool $compiled = false;

    public function run(string $name, array $argv, int $timeout): array
    {
        $this->log[] = 'run';
        return ['exit_code' => 1, 'stdout' => '', 'stderr' => ''];
    }

    public function apply(string $generation, array $files, array $health, int $epoch, string $sourceSha256): array
    {
        $this->log[] = 'apply';
        throw new LogicException('nothing may be applied in these checks');
    }

    public function status(): array
    {
        $this->log[] = 'status';
        if ($this->compiled) {
            throw new RuntimeException('past the digest check');
        }
        return ['epoch' => 1, 'coherent' => true, 'source_sha256' => null];
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
        return [];
    }

    public function pendingEvents(): array
    {
        $this->log[] = 'events';
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
$state = sys_get_temp_dir() . '/ols-deploy-test-' . bin2hex(random_bytes(6));
mkdir($state, 0755);
$lockPath = "$state/deployment.lock";
$exclusiveDuringPass = null;
$compiled = ['config' => "server\n", 'vhconf' => ['a.test' => "vhost a\n"], 'plan' => [], 'summary' => []];
$compile = function (Profile $profile, Engine $engine) use ($lockPath, $compiled, &$exclusiveDuringPass): array {
    $probe = fopen($lockPath, 'c');
    $exclusiveDuringPass = flock($probe, LOCK_EX | LOCK_NB);
    fclose($probe);
    $engine->compiled = true;
    return $compiled;
};
$reconciler = static fn(LockProbeEngine $e): Reconciler => new Reconciler($e, $compile, null, new Profile(true, null), '/nonexistent',
    null, null, null, null, $lockPath);
$outcome = static function (Closure $pass): string {
    try {
        $pass();
        return 'returned';
    } catch (Throwable $error) {
        return get_class($error) . ': ' . $error->getMessage();
    }
};
$holder = fopen($lockPath, 'c');
flock($holder, LOCK_EX);  // a deployment operation or recover.sh
$engine = new LockProbeEngine();
check(str_starts_with($outcome(fn() => $reconciler($engine)->reconcile()), ReconcileBusy::class) && $engine->log === [],
    'a reconcile pass is busy while the deployment lock is held exclusively; nothing is read');
$engine = new LockProbeEngine();
check(str_contains($outcome(fn() => $reconciler($engine)->activate(CutoverPlan::digest($compiled, []))), 'past the digest check')
    && $exclusiveDuringPass === false, "the cutover's forced pass runs under the cutover's exclusive hold and accepts the approved digest");
$engine = new LockProbeEngine();
check(str_starts_with($outcome(fn() => $reconciler($engine)->activate(str_repeat('0', 64))), ReconcileRefused::class)
    && !in_array('apply', $engine->log, true) && $engine->compiled, 'the forced pass refuses a compile that differs from the approved plan');
fclose($holder);
$other = fopen($lockPath, 'r');
flock($other, LOCK_SH);  // another reconcile pass
$engine = new LockProbeEngine();
check(str_contains($outcome(fn() => $reconciler($engine)->reconcile()), 'past the digest check') && $exclusiveDuringPass === false,
    'passes share the lock with each other and hold it for the whole pass');
fclose($other);
$probe = fopen($lockPath, 'c');
check(flock($probe, LOCK_EX | LOCK_NB), 'the shared hold ends with the pass');
$context = new OlsCpanel\Cli\EngineContext(0, 'root', static fn(string $role): Engine => new LockProbeEngine(), null, $state, '/nonexistent');
check(str_starts_with($outcome(fn() => $context->reconciler($context->engine())->reconcile()), ReconcileBusy::class),
    'the CLI reconciler takes the deployment lock of the state directory');
fclose($probe);

// Findings 9 and 10: the plan is bound to the referenced files; changed inputs are refused before the first host
// change, and a change during the cutover is refused by the activation itself.
$cert = '/var/cpanel/ssl/apache_tls/a.test/combined';
$certWorld = function () use ($cert): array {
    $w = world();
    $w['compilation']->cert = $cert;
    $w['host']->files[$cert] = ['owner' => 'root:root:600', 'content' => "certificate 1\n"];
    [$code, $out] = cli($w, ['install', '--prepare', '--native']);
    $w['host']->calls = [];
    return [$w, $out['plan']];
};
[$w, $id] = $certWorld();
$plan = json_decode((string) file_get_contents($w['state'] . "/plans/$id.json"), true);
check($plan['schema_version'] === 2 && $plan['referenced_files'] === [$cert => hash('sha256', "certificate 1\n")]
    && $plan['compile_sha256'] === CutoverPlan::digest($w['compilation']->compile(null), [$cert => hash('sha256', "certificate 1\n")]),
    'the plan records the referenced file digests and binds its digest to them');
$w['host']->files[$cert]['content'] = "certificate 2\n";
[$code, $out] = cli($w, ['install', '--cutover', "--plan=$id", '--yes']);
check($code === 1 && str_contains($out['error'], 'run install --prepare again') && !changed_host($w['host'])
    && glob($w['state'] . '/backups/*') === [], 'a replaced certificate makes the plan stale');
[$w, $id] = $certWorld();
$w['host']->during['apache-http'] = function () use ($w, $cert): void {
    $w['host']->files[$cert]['content'] = "certificate 2\n";
};
[$code, $out] = cli($w, ['install', '--cutover', "--plan=$id", '--yes']);
check($code === 1 && str_contains($out['error'], 'run install --prepare again') && !changed_host($w['host'])
    && $w['host']->index('arm-recovery') === -1, 'the digest is checked again immediately before the first host change');
[$w, $id] = $certWorld();
$w['host']->during['hook-add'] = function () use ($w): void {
    $w['compilation']->config = "server config edited by a tenant\n";
};
[$code, $out] = cli($w, ['install', '--cutover', "--plan=$id", '--yes']);
check($code === 1 && $out['result'] === 'failed' && str_contains($out['error'], 'differs from the approved plan')
    && $w['activator']->expected === json_decode((string) file_get_contents($w['state'] . "/plans/$id.json"), true)['compile_sha256']
    && $out['recovery']['recovered'] && restored($w), 'a compile changed during the cutover is never activated; the host returns to Apache');
[$w, $id] = prepared();
$path = $w['state'] . "/plans/$id.json";
$old = json_decode((string) file_get_contents($path), true);
file_put_contents($path, json_encode(['schema_version' => 1] + $old));
[$code, $out] = cli($w, ['install', '--cutover', "--plan=$id", '--yes']);
check($code === 1 && str_contains($out['error'], 'earlier version'), 'a plan of the earlier format is refused');
// Finding 14 (cutover): the plan is read again under the lock and must be the approved one.
[$w, $id] = prepared();
$path = $w['state'] . "/plans/$id.json";
$error = $outcome(fn() => (new Cutover($w['env']))->run($id, function (array $plan) use ($path): bool {
    file_put_contents($path, json_encode(['created' => '2099-01-01T00:00:00+00:00'] + $plan));
    return true;
}));
check(str_contains($error, 'changed after it was shown') && !changed_host($w['host']), 'a plan changed during the approval is refused');

// Finding 15: an unwritable final record is a failed cutover with recovery; the timer goes only after it.
[$w, $id] = prepared();
$h = $w['host'];
$h->during['enable-reconciler'] = function () use ($w): void {
    mkdir(backup_dir($w) . '/cutover.json');
};
[$code, $out] = cli($w, ['install', '--cutover', "--plan=$id", '--yes']);
check($code === 1 && $out['result'] === 'failed' && end($out['steps'])['step'] === 'record' && isset($out['record_error'])
    && $out['recovery']['recovered'] && restored($w) && $h->index('disarm-recovery') > $h->index('recovery-run'),
    'a final record that cannot be written runs the recovery; the timer is disarmed only after it');

// Finding 7: a failed return keeps (re-arms) the recovery timer; only verified Apache service ends it.
foreach (['exit' => 'recovery exits 1', 'apache' => 'Apache does not run after recovery'] as $mode => $label) {
    [$w, $id] = prepared();
    cli($w, ['install', '--cutover', "--plan=$id", '--yes']);
    $h = $w['host'];
    $unit = Backup::unit(basename(backup_dir($w)));
    $h->calls = [];
    if ($mode === 'exit') {
        $h->recoverExit = 1;
    } else {
        $h->recoverLeaves = 'apache';
    }
    [$code, $out] = cli($w, ['apache-return', '--execute', '--yes']);
    check($code === 1 && $out['result'] === 'failed' && $out['recovery']['timer_disarmed'] === false && $out['recovery']['timer_armed']
        && $h->index('disarm-recovery') === -1 && $h->index('rearm-recovery') >= 0 && $h->active["$unit.timer"]
        && end($h->calls[$h->index('rearm-recovery')][1]) === backup_dir($w) . '/recover.sh',
        "apache-return: $label keeps the fallback armed");
}
[$w, $id] = prepared();
$w['activator']->failWith = 'rolled_back';
$w['host']->recoverLeaves = 'apache';
[$code, $out] = cli($w, ['install', '--cutover', "--plan=$id", '--yes']);
check($code === 1 && $out['recovery']['recovered'] === false && $out['recovery']['timer_armed'] && $w['host']->index('disarm-recovery') === -1,
    'cutover: a recovery that exits 0 without Apache serving keeps the timer');
[$w, $id] = prepared();
cli($w, ['install', '--cutover', "--plan=$id", '--yes']);
$w['host']->calls = [];
[$code, $out] = cli($w, ['apache-return', '--execute', '--yes']);
check($code === 0 && $out['recovery']['timer_disarmed'] && array_column($w['host']->recoveries, 'held') === [true],
    'apache-return runs recover.sh under its deployment lock and disarms after verified Apache service');

// Finding 14 (apache-return): the backup is chosen again under the lock and must be the approved one.
[$w, $id] = prepared();
cli($w, ['install', '--cutover', "--plan=$id", '--yes']);
$w['host']->calls = [];
$error = $outcome(fn() => (new ApacheReturn($w['env']))->execute(function (array $summary) use ($w): bool {
    $source = $w['state'] . "/backups/{$summary['backup']}";
    $newer = $w['state'] . '/backups/c20991231235959-ffffff';
    mkdir($newer, 0700);
    copy("$source/recover.sh", "$newer/recover.sh");
    chmod("$newer/recover.sh", 0700);
    $manifest = json_decode((string) file_get_contents("$source/manifest.json"), true);
    file_put_contents("$newer/manifest.json", json_encode(['id' => 'c20991231235959-ffffff', 'created' => '2099-12-31T23:59:59+00:00'] + $manifest));
    return true;
}));
check(str_contains($error, 'not the approved') && $w['host']->index('recovery-run') === -1, 'apache-return refuses a backup other than the approved one');
$held = fopen($w['state'] . '/deployment.lock', 'r');
flock($held, LOCK_SH);
[$code, $out] = cli($w, ['apache-return', '--execute', '--yes']);
check($code === 75 && $out['result'] === 'busy' && $w['host']->index('recovery-run') === -1, 'apache-return waits for a running pass, then reports busy');
fclose($held);

// Finding 8: uninstall needs verified Apache service, whatever profile.json says.
[$w, $id] = prepared();
cli($w, ['install', '--cutover', "--plan=$id", '--yes']);
unlink($w['state'] . '/profile.json');  // a recovery interrupted after it removed the profile
[$code, $out] = cli($w, ['uninstall']);
check($code === 0 && $out['result'] === 'uninstalled' && $out['actions'][0]['action'] === 'apache-return'
    && $out['actions'][0]['result'] === 'returned' && restored($w), 'uninstall without a profile but with OLS serving returns to Apache first');
$w = world();
cli($w, ['install', '--prepare', '--native']);
$w['host']->apacheRunning = false;
[$code, $out] = cli($w, ['uninstall']);
check($code === 1 && str_contains($out['error'], 'no cutover backup') && is_dir($w['state'] . '/plans'), 'uninstall without verified Apache and without a backup removes nothing');
[$w, $id] = prepared();
cli($w, ['install', '--cutover', "--plan=$id", '--yes']);
$w['host']->recoverExit = 1;
[$code, $out] = cli($w, ['uninstall']);
check($code === 1 && $out['result'] === 'failed' && is_dir($w['state'] . '/plans') && file_exists($w['state'] . '/profile.json')
    && $out['actions'][0]['recovery']['timer_armed'], 'uninstall with a failed recovery removes nothing and keeps the fallback');
check($w['host']->index('remove-packages') < 0 && $w['host']->index('package-installed') < 0, 'no package is removed after a failed return to Apache');
[$w, $id] = prepared();
cli($w, ['install', '--cutover', "--plan=$id", '--yes']);
$w['host']->stuck[CutoverPlan::BROKER_UNIT] = true;
$w['host']->active[CutoverPlan::BROKER_UNIT] = true;
[$code, $out] = cli($w, ['uninstall']);
check($code === 1 && $out['result'] === 'failed' && str_contains($out['error'], CutoverPlan::BROKER_UNIT) && is_dir($w['state'] . '/plans'),
    'a unit that does not stop aborts the cleanup');
check($w['host']->index('remove-packages') < 0 && $w['host']->index('package-installed') < 0, 'no package is removed after a unit that did not stop');

// ---- HTTP/3 firewall (FV-04): csf, firewalld, nftables/none, failures, restoration ----------------------------------
const CSF_ORIGINAL = "# csf\nTESTING = \"0\"\nTCP_IN = \"20,21,22,80,443,2083\"\nUDP_IN = \"20,21,53\"\nUDP6_IN = \"20,21,53\"\nUDP_OUT = \"20,113,123\"\n";
const CSF_OPENED = "# csf\nTESTING = \"0\"\nTCP_IN = \"20,21,22,80,443,2083\"\nUDP_IN = \"20,21,53,443\"\nUDP6_IN = \"20,21,53,443\"\nUDP_OUT = \"20,113,123\"\n";

/** Prepared world whose host has been set up (firewall, input file) before the plan. */
function fw_world(callable $setup, bool $hybrid = false): array
{
    $w = world($hybrid);
    $setup($w['host'], $w['state']);
    [$code, $out] = cli($w, $hybrid ? ['install', '--prepare'] : ['install', '--prepare', '--native']);
    if ($code !== 0) {
        throw new RuntimeException('prepare failed: ' . json_encode($out));
    }
    $w['host']->calls = [];
    return [$w, $out['plan'], $out];
}

function with_csf(FakeHost $h, string $conf = CSF_ORIGINAL): void
{
    $h->files['/usr/sbin/csf'] = ['owner' => 'root:root:755', 'content' => "#!/bin/sh\n"];
    $h->files['/etc/csf/csf.conf'] = ['owner' => 'root:root:600', 'content' => $conf];
}

/** @return array<string,mixed> the recorded step of a cutover outcome */
function step_of(array $out, string $name): array
{
    return array_values(array_filter($out['steps'], fn(array $s): bool => $s['step'] === $name))[0];
}

// The decisions themselves.
$plan = Http3Firewall::csfPlan(CSF_ORIGINAL);
check($plan['supported'] && $plan['changed'] && $plan['text'] === CSF_OPENED
    && $plan['keys'] === ['UDP_IN' => ['value' => '20,21,53', 'open' => false], 'UDP6_IN' => ['value' => '20,21,53', 'open' => false]],
    'csf plan: 443 appended to UDP_IN and UDP6_IN, nothing else changes');
foreach (['20,443,53', '3000:4000,443', '1:65535', '443', '400:500'] as $value) {
    check(!Http3Firewall::csfPlan("UDP_IN = \"$value\"\nUDP6_IN = \"$value\"\n")['changed'], "csf plan: $value already covers 443");
}
check(Http3Firewall::csfPlan("UDP_IN = \"500:600\"\n")['text'] === "UDP_IN = \"500:600,443\"\n", 'csf plan: a range that misses 443 gets it appended');
check(Http3Firewall::csfPlan("UDP_IN = \"\"\nUDP6_IN = \"20,\"\n")['text'] === "UDP_IN = \"443\"\nUDP6_IN = \"20,443\"\n", 'csf plan: empty and comma-terminated lists');
check(Http3Firewall::csfPlan("UDP_IN=\"53\" # note\n")['text'] === "UDP_IN=\"53,443\" # note\n", 'csf plan: only the quoted value changes');
check(!Http3Firewall::csfPlan("#UDP_IN = \"1\"\nTCP_IN = \"1\"\n")['supported'], 'csf plan: a commented or missing UDP_IN plans nothing');
check(!Http3Firewall::csfPlan("UDP_IN = \"1\"\nUDP_IN = \"2\"\n")['supported'], 'csf plan: a duplicated UDP_IN plans nothing');
check(Http3Firewall::nftInputDrop("table inet f {\n chain input {\n  type filter hook input priority filter; policy drop;\n }\n}\n")
    === ['input_policy_drop' => true, 'udp_443_mentioned' => false]
    && Http3Firewall::nftInputDrop("chain input { type filter hook input priority filter; policy drop;\n udp dport 443 accept\n}")
    === ['input_policy_drop' => true, 'udp_443_mentioned' => true], 'nftables: input policy drop and UDP 443 mention');

// csf: prepare shows it, the cutover changes it, the backup holds the original, apache-return restores it byte for byte.
[$w, $id, $prepared] = fw_world(fn(FakeHost $h) => with_csf($h));
$fw = $prepared['http3']['firewall'];
check($prepared['http3']['enabled'] === true && $fw['type'] === 'csf' && $fw['action'] === 'add' && !array_key_exists('new_text', $fw)
    && str_contains(implode("\n", $prepared['host_changes']), 'HTTP/3: csf'), 'prepare shows the csf change (never the csf.conf text)');
check($w['host']->files['/etc/csf/csf.conf']['content'] === CSF_ORIGINAL && $w['host']->csfRestarts === 0, 'prepare changes nothing in csf');
[$code, $out] = cli($w, ['install', '--cutover', "--plan=$id", '--yes']);
$h = $w['host'];
check($code === 0 && $out['result'] === 'cut_over' && $h->files['/etc/csf/csf.conf']['content'] === CSF_OPENED && $h->csfRestarts === 1
    && $h->files['/etc/csf/csf.conf']['owner'] === 'root:root:600', 'cutover opens UDP 443 in csf (owner and mode kept) and restarts csf');
$step = step_of($out, 'http3-firewall');
check($step['ok'] === true && str_starts_with($step['detail'], 'csf: append 443 to UDP_IN and UDP6_IN'), 'the cutover records the csf step');
$manifest = (new Backup($w['env']))->load($out['backup']);
check(file_get_contents($manifest['dir'] . '/firewall/csf.conf') === CSF_ORIGINAL
    && $manifest['http3']['firewall']['before_sha256'] === hash('sha256', CSF_ORIGINAL)
    && $manifest['http3']['firewall']['after_sha256'] === hash('sha256', CSF_OPENED)
    && $manifest['http3']['firewall']['backup'] === 'firewall/csf.conf' && $manifest['http3']['enabled'] === true,
    'the backup holds the byte-exact original csf.conf and both digests');
$script = file_get_contents($manifest['dir'] . '/recover.sh');
check($script === RecoveryScript::render($manifest['dir'], [], [], [], false, product: true,
    firewall: ['type' => 'csf', 'before_sha256' => hash('sha256', CSF_ORIGINAL), 'after_sha256' => hash('sha256', CSF_OPENED)]) && str_contains($script, 'csf -r')
    && $manifest['intact'], 'recover.sh undoes the csf change (manifest digest matches)');
check($h->index('csf-conf-write') < $h->index('csf-restart') && $h->index('ols-listeners') < $h->index('csf-conf-write'),
    'order: OLS serving, csf.conf written, csf restarted');
[$code, $ret] = cli($w, ['apache-return', '--prepare']);
check(str_contains(implode("\n", $ret['actions']), 'undo the UDP 443 change in csf'), 'apache-return --prepare names the firewall undo');
[$code, $ret] = cli($w, ['apache-return', '--execute', '--yes']);
check($code === 0 && $ret['result'] === 'returned' && $h->files['/etc/csf/csf.conf']['content'] === CSF_ORIGINAL && $h->csfRestarts === 2
    && $ret['http3_firewall_restored'] === true, 'apache-return restores csf.conf byte for byte and restarts csf');

// csf.conf edited by the administrator after the cutover: never overwritten, reported as not restored.
[$w, $id] = fw_world(fn(FakeHost $h) => with_csf($h));
$out = cli($w, ['install', '--cutover', "--plan=$id", '--yes'])[1];
$w['host']->files['/etc/csf/csf.conf']['content'] .= "# administrator edit\n";
$edited = $w['host']->files['/etc/csf/csf.conf']['content'];
$ret = cli($w, ['apache-return', '--execute', '--yes'])[1];
check($ret['result'] === 'returned' && $w['host']->files['/etc/csf/csf.conf']['content'] === $edited && $ret['http3_firewall_restored'] === false,
    'a csf.conf edited since the cutover is left alone and reported');

// csf already allowing UDP 443, an unusable csf.conf, csf disabled.
[$w, $id, $prepared] = fw_world(fn(FakeHost $h) => with_csf($h, str_replace('"20,21,53"', '"20,53,443"', CSF_ORIGINAL)));
$out = cli($w, ['install', '--cutover', "--plan=$id", '--yes'])[1];
$manifest = (new Backup($w['env']))->load($out['backup']);
check($prepared['http3']['firewall']['action'] === 'none' && $w['host']->csfRestarts === 0 && $manifest['http3']['firewall']['action'] === 'none'
    && !is_dir($manifest['dir'] . '/firewall') && !str_contains(file_get_contents($manifest['dir'] . '/recover.sh'), 'csf'),
    'csf that allows UDP 443 already: no change, no csf lines in recover.sh');
[$w, $id, $prepared] = fw_world(fn(FakeHost $h) => with_csf($h, "TCP_IN = \"80\"\n"));
$out = cli($w, ['install', '--cutover', "--plan=$id", '--yes'])[1];
check($out['result'] === 'cut_over' && $w['host']->files['/etc/csf/csf.conf']['content'] === "TCP_IN = \"80\"\n"
    && str_contains(implode(' ', $out['warnings']), 'no single UDP_IN'), 'csf without a UDP_IN line: nothing changed, a warning');
[$w, $id, $prepared] = fw_world(function (FakeHost $h): void {
    with_csf($h);
    $h->files['/etc/csf/csf.disable'] = ['owner' => 'root:root:644', 'content' => ''];
});
check($prepared['http3']['firewall']['type'] === 'none', 'csf.disable: csf is not the firewall (falls through)');

// csf failures: the cutover still completes, the partial change is undone, the administrator is told.
foreach (['csf-restart', 'csf-conf-write'] as $failing) {
    [$w, $id] = fw_world(fn(FakeHost $h) => with_csf($h));
    $w['host']->fail[$failing] = true;
    $out = cli($w, ['install', '--cutover', "--plan=$id", '--yes'])[1];
    $step = step_of($out, 'http3-firewall');
    check($out['result'] === 'cut_over' && $step['ok'] === false && str_contains($step['detail'], '; undone')
        && $w['host']->files['/etc/csf/csf.conf']['content'] === CSF_ORIGINAL
        && str_contains(implode(' ', $out['warnings']), 'UDP 443 could not be opened in csf'),
        "csf failing at $failing: cutover completes, csf.conf restored, warning");
}
// A cutover that fails after the firewall change: recover.sh restores csf.conf.
[$w, $id] = fw_world(fn(FakeHost $h) => with_csf($h));
$w['host']->olsAnswers['http://a.test/'] = '503';
$out = cli($w, ['install', '--cutover', "--plan=$id", '--yes'])[1];
check($out['result'] === 'failed' && $out['recovery']['recovered'] === true && $w['host']->files['/etc/csf/csf.conf']['content'] === CSF_ORIGINAL
    && $w['host']->csfRestarts === 2, 'a failed cutover: recover.sh restores csf.conf byte for byte and restarts csf');
// csf.conf changed between the backup and the change: refused (the step fails, nothing guessed).
[$w, $id] = fw_world(fn(FakeHost $h) => with_csf($h));
$w['host']->during['ols-listeners'] = function () use ($w): void {
    $w['host']->files['/etc/csf/csf.conf']['content'] .= "# edit\n";
};
$out = cli($w, ['install', '--cutover', "--plan=$id", '--yes'])[1];
$step = step_of($out, 'http3-firewall');
check($out['result'] === 'cut_over' && $step['ok'] === false && str_contains($step['detail'], 'changed since the backup')
    && str_ends_with($w['host']->files['/etc/csf/csf.conf']['content'], "# edit\n") && $w['host']->csfRestarts === 0,
    'csf.conf edited after the backup: the change is refused and nothing is overwritten');

// firewalld.
[$w, $id, $prepared] = fw_world(function (FakeHost $h): void {
    $h->firewalldPermanent = ['22/tcp'];
    $h->firewalldRuntime = ['22/tcp'];
});
check($prepared['http3']['firewall']['type'] === 'firewalld' && $prepared['http3']['firewall']['action'] === 'add', 'prepare shows the firewalld change');
$out = cli($w, ['install', '--cutover', "--plan=$id", '--yes'])[1];
$h = $w['host'];
check($out['result'] === 'cut_over' && $h->firewalldPermanent === ['22/tcp', '443/udp'] && $h->firewalldRuntime === ['22/tcp', '443/udp']
    && $h->firewalldReloads === 0, 'firewalld: 443/udp added at runtime and permanently, no reload');
$argvs = array_map(fn(array $c): array => $c[1], array_filter($h->calls, fn(array $c): bool => str_starts_with($c[0], 'firewalld-')));
check(in_array(['/usr/bin/firewall-cmd', '--zone=public', '--add-port=443/udp'], $argvs, true)
    && in_array(['/usr/bin/firewall-cmd', '--permanent', '--zone=public', '--add-port=443/udp'], $argvs, true)
    && !in_array(['/usr/bin/firewall-cmd', '--reload'], $argvs, true) && $h->firewalldZoneless === 0,
    'firewalld commands are fixed argv, always with --zone=, never a global --reload');
$manifest = (new Backup($w['env']))->load($out['backup']);
$fwr = $manifest['http3']['firewall'];
$recover = file_get_contents($manifest['dir'] . '/recover.sh');
check($fwr['type'] === 'firewalld' && $fwr['zone'] === 'public' && $fwr['add_runtime'] === true && $fwr['add_permanent'] === true
    && str_contains($recover, 'firewall-cmd --zone=public --remove-port=443/udp')
    && str_contains($recover, 'firewall-cmd --permanent --zone=public --remove-port=443/udp') && !str_contains($recover, '--reload'),
    'the backup records zone and ownership; recover.sh removes both states in that zone, no reload');
$ret = cli($w, ['apache-return', '--execute', '--yes'])[1];
check($ret['result'] === 'returned' && $h->firewalldPermanent === ['22/tcp'] && $h->firewalldRuntime === ['22/tcp']
    && $ret['http3_firewall_restored'] === true && $h->firewalldReloads === 0, 'apache-return removes the firewalld port again, no reload');

// Runtime and permanent state are separate facts (RV-31 item 4): permanent yes + runtime no adds the runtime port only;
// runtime yes + permanent no adds the permanent one only; each is removed again only where the product added it.
[$w, $id, $prepared] = fw_world(function (FakeHost $h): void {
    $h->firewalldPermanent = ['443/udp'];
    $h->firewalldRuntime = [];
});
$fw = $prepared['http3']['firewall'];
check($fw['action'] === 'add' && $fw['add_runtime'] === true && $fw['add_permanent'] === false && $fw['permanent_open'] === true,
    'firewalld permanent yes, runtime no: the plan adds the runtime port only');
$out = cli($w, ['install', '--cutover', "--plan=$id", '--yes'])[1];
$h = $w['host'];
check($out['result'] === 'cut_over' && $h->firewalldRuntime === ['443/udp'] && $h->firewalldPermanent === ['443/udp']
    && $h->index('firewalld-add-port') >= 0 && $h->index('firewalld-add-port-permanent') === -1 && $h->firewalldReloads === 0,
    'firewalld permanent yes, runtime no: only the runtime port is added');
$ret = cli($w, ['apache-return', '--execute', '--yes'])[1];
check($ret['result'] === 'returned' && $h->firewalldRuntime === [] && $h->firewalldPermanent === ['443/udp'] && $ret['http3_firewall_restored'] === true,
    'apache-return removes only the runtime port the product added; the administrator\'s permanent port stays');
[$w, $id, $prepared] = fw_world(function (FakeHost $h): void {
    $h->firewalldPermanent = [];
    $h->firewalldRuntime = ['443/udp'];
});
$fw = $prepared['http3']['firewall'];
check($fw['action'] === 'add' && $fw['add_runtime'] === false && $fw['add_permanent'] === true, 'firewalld runtime yes, permanent no: the plan adds the permanent port only');
$out = cli($w, ['install', '--cutover', "--plan=$id", '--yes'])[1];
$h = $w['host'];
check($out['result'] === 'cut_over' && $h->firewalldPermanent === ['443/udp'] && $h->index('firewalld-add-port') === -1 && $h->firewalldReloads === 0,
    'firewalld runtime yes, permanent no: only the permanent port is added');
cli($w, ['apache-return', '--execute', '--yes']);
check($h->firewalldPermanent === [] && $h->firewalldRuntime === ['443/udp'], 'apache-return removes only the permanent port the product added');
[$w, $id, $prepared] = fw_world(function (FakeHost $h): void {
    $h->firewalldPermanent = ['443/udp'];
    $h->firewalldRuntime = ['443/udp'];
});
$out = cli($w, ['install', '--cutover', "--plan=$id", '--yes'])[1];
check($prepared['http3']['firewall']['action'] === 'none' && $w['host']->index('firewalld-add-port') === -1
    && $w['host']->index('firewalld-add-port-permanent') === -1, 'firewalld with UDP 443 open in both states: nothing changed, nothing removed later');

// The zone is resolved once and recorded (RV-31 item 5): a default zone changed before recovery does not redirect the undo,
// and an administrator's runtime-only rule survives (no reload).
[$w, $id] = fw_world(function (FakeHost $h): void {
    $h->firewalldPermanent = ['22/tcp'];
    $h->firewalldRuntime = ['22/tcp', '9999/tcp'];
});
$out = cli($w, ['install', '--cutover', "--plan=$id", '--yes'])[1];
$h = $w['host'];
$h->firewalldDefaultZone = 'dmz';
$h->firewalldOther['dmz/p'] = ['443/udp'];
$h->firewalldOther['dmz/r'] = ['443/udp'];
$ret = cli($w, ['apache-return', '--execute', '--yes'])[1];
check($ret['result'] === 'returned' && $h->firewalldPermanent === ['22/tcp'] && $h->firewalldRuntime === ['22/tcp', '9999/tcp']
    && $h->firewalldOther['dmz/p'] === ['443/udp'] && $h->firewalldOther['dmz/r'] === ['443/udp'] && $h->firewalldReloads === 0
    && $ret['http3_firewall_restored'] === true, 'a changed default zone: the undo targets the recorded zone, other zones and runtime-only rules stay, no reload');
// The default zone cannot be resolved: nothing is planned, a warning says why (never "open").
[$w, $id, $prepared] = fw_world(function (FakeHost $h): void {
    $h->firewalldPermanent = [];
    $h->firewalldRuntime = [];
    $h->firewalldDefaultZone = 'bad zone!';
});
check($prepared['http3']['firewall']['action'] === 'none' && str_contains(implode(' ', $prepared['http3']['firewall']['warnings']), 'firewalld cannot be inspected'),
    'an unreadable firewalld default zone plans nothing and warns');
// A failing permanent add after the runtime add: the cutover completes, the runtime port is removed again, warning.
[$w, $id] = fw_world(function (FakeHost $h): void {
    $h->firewalldPermanent = [];
    $h->firewalldRuntime = [];
});
$w['host']->fail['firewalld-add-port-permanent'] = true;
$out = cli($w, ['install', '--cutover', "--plan=$id", '--yes'])[1];
check($out['result'] === 'cut_over' && $w['host']->firewalldPermanent === [] && $w['host']->firewalldRuntime === []
    && str_contains(implode(' ', $out['warnings']), 'firewalld'), 'firewalld permanent add failing: cutover completes, the runtime port is removed again, warning');
[$w, $id] = fw_world(function (FakeHost $h): void {
    $h->firewalldPermanent = [];
    $h->firewalldRuntime = [];
});
$w['activator']->failWith = 'rolled_back';
$out = cli($w, ['install', '--cutover', "--plan=$id", '--yes'])[1];
check($out['result'] === 'failed' && $w['host']->firewalldPermanent === [] && $w['host']->index('firewalld-add-port') === -1,
    'a cutover failing before the firewall step changes no firewall');

// csf: file restored and firewall applied are separate (RV-31 item 6): undo() retries the restart while the original file is in place.
[$w, $id] = fw_world(fn(FakeHost $h) => with_csf($h));
$out = cli($w, ['install', '--cutover', "--plan=$id", '--yes'])[1];
$h = $w['host'];
$manifest = (new Backup($w['env']))->load($out['backup']);
$record = $manifest['http3']['firewall'];
$h->fail['csf-restart-undo'] = true;
$firewall = new Http3Firewall($w['env']->host);
$first = $firewall->undo($record, $manifest['dir']);
check($first['restored'] === false && $first['file_restored'] === true && $first['firewall_applied'] === false
    && $h->files['/etc/csf/csf.conf']['content'] === CSF_ORIGINAL, 'csf undo: the file is restored but csf did not restart: not undone');
unset($h->fail['csf-restart-undo']);
$restarts = $h->csfRestarts;
$second = $firewall->undo($record, $manifest['dir']);
check($second['restored'] === true && $second['firewall_applied'] === true && $h->csfRestarts === $restarts + 1,
    'csf undo: the next attempt finds the original file and retries the restart');

// nftables and none: nothing changed.
$ruleset = "table inet filter {\n chain input {\n  type filter hook input priority filter; policy drop;\n  tcp dport 22 accept\n }\n}\n";
[$w, $id, $prepared] = fw_world(fn(FakeHost $h) => $h->nftRuleset = $ruleset);
$out = cli($w, ['install', '--cutover', "--plan=$id", '--yes'])[1];
check($prepared['http3']['firewall']['type'] === 'nftables' && $prepared['http3']['firewall']['action'] === 'none'
    && $out['result'] === 'cut_over' && str_contains(implode(' ', $out['warnings']), 'allow UDP 443'), 'nftables input drop: nothing changed, a warning');
[$w, $id, $prepared] = fw_world(fn(FakeHost $h) => $h->nftRuleset = str_replace('tcp dport 22 accept', "tcp dport 22 accept\n  udp dport 443 accept", $ruleset));
$out = cli($w, ['install', '--cutover', "--plan=$id", '--yes'])[1];
check($out['result'] === 'cut_over' && !isset($out['warnings']), 'nftables that allows UDP 443: no warning');
[$w, $id, $prepared] = fw_world(fn(FakeHost $h) => null);
$out = cli($w, ['install', '--cutover', "--plan=$id", '--yes'])[1];
check($prepared['http3']['firewall']['type'] === 'none' && $out['result'] === 'cut_over' && !isset($out['warnings'])
    && $w['host']->index('csf-conf-write') === -1, 'no firewall: nothing changed');

// The operator opt-out: no firewall inspection at all, nothing recorded as changed; a broken file refuses.
[$w, $id, $prepared] = fw_world(function (FakeHost $h, string $state): void {
    with_csf($h);
    file_put_contents("$state/http3.json", "{\"enabled\": false}\n");
});
$out = cli($w, ['install', '--cutover', "--plan=$id", '--yes'])[1];
$manifest = (new Backup($w['env']))->load($out['backup']);
check($prepared['http3'] === ['enabled' => false, 'input' => $w['state'] . '/http3.json', 'firewall' => null] && $out['result'] === 'cut_over'
    && $w['host']->files['/etc/csf/csf.conf']['content'] === CSF_ORIGINAL && $manifest['http3'] === ['enabled' => false, 'firewall' => null]
    && $w['host']->index('csf-conf-read') === -1 && $w['host']->index('firewalld-state') === -1,
    'http3.json {"enabled": false}: no firewall inspection or change');
$world = world();
file_put_contents($world['state'] . '/http3.json', '{"enabled": "no"}');
[$code, $out] = cli($world, ['install', '--prepare']);
check($code === 1 && str_contains($out['error'], '"enabled" must be true or false'), 'a malformed http3.json refuses the prepare');
file_put_contents($world['state'] . '/http3.json', '{}');
chmod($world['state'] . '/http3.json', 0666);
[$code, $out] = cli($world, ['install', '--prepare']);
check($code === 1 && str_contains($out['error'], 'writable by no one else'), 'a group- or world-writable http3.json is refused');

// ---- plugin deployment: staged trees, atomic switch, rollback (RV-31 item 14), on a real directory tree ----------
{
    $root = sys_get_temp_dir() . '/ols-plugin-swap-' . bin2hex(random_bytes(4));
    mkdir($root . '/state', 0700, true);
    mkdir($root . '/live/cgi', 0755, true);
    mkdir($root . '/live/addon', 0755, true);
    mkdir($root . '/live/jupiter', 0755, true);
    $dest = ['whm' => "$root/live/cgi/ols-cpanel", 'cpanel' => "$root/live/jupiter/ols_cpanel", 'icon' => "$root/live/addon/ols-cpanel.svg"];
    $source = plugin_fixture();
    file_put_contents("$source/whm/ols-cpanel.svg", '<svg/>');
    file_put_contents("$source/whm/ols-cpanel.conf", 'conf');
    foreach (['install.json', 'ols_cpanel.svg', 'ols_cpanel_group.svg', 'ols_cpanel_cache.svg', 'ols_cpanel_php.svg', 'ols_cpanel_objcache.svg', 'ols_cpanel_speed.svg', 'ols_cpanel_logs.svg', 'ols_cpanel_traffic.svg', 'ols_cpanel_purge.svg'] as $f) {
        file_put_contents("$source/cpanel/$f", $f);
    }
    // Runs everything for real except cPanel's registration tools, which can be made to fail.
    $runner = new class implements CommandRunner {
        public array $fail = [];
        /** @var array<string,int> the umask cPanel's registration tools ran with */
        public array $umasks = [];
        public function run(string $name, array $argv, int $timeout): array
        {
            if (in_array($name, $this->fail, true)) {
                return ['exit_code' => 1, 'stdout' => '', 'stderr' => "injected $name"];
            }
            if (in_array($name, ['plugin-whm-register', 'plugin-cpanel-register'], true)) {
                $this->umasks[$name] = umask();
                return ['exit_code' => 0, 'stdout' => '', 'stderr' => ''];
            }
            return (new LocalCommandRunner())->run($name, $argv, $timeout);
        }
    };
    $plugins = static fn(): Plugins => new Plugins(new Host($runner), "$root/state", $source, $dest);
    $tree = static function (string $dir): array {
        $out = [];
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS));
        foreach ($it as $file) {
            $out[substr($file->getPathname(), strlen($dir))] = file_get_contents($file->getPathname());
        }
        ksort($out);
        return $out;
    };
    $leftovers = static fn(): array => glob("$root/live/*/*.ols-*") ?: [];
    $snapshot = static fn(): array => [$tree($dest['whm']), $tree($dest['cpanel']), file_get_contents($dest['icon'])];

    // First deployment: complete trees, entry mode, icon, nothing staged left behind. It runs under the installer's
    // umask 077, yet cPanel's registration tools get 022 (their files are read by every account), and the caller's
    // umask is restored afterwards.
    $callerUmask = umask(0077);
    $plugins()->deploy();
    check($runner->umasks === ['plugin-whm-register' => 0022, 'plugin-cpanel-register' => 0022] && umask() === 0077,
        'plugin registration runs with umask 022 whatever the caller\'s umask, which is restored');
    umask($callerUmask);
    check(is_file("{$dest['whm']}/manifest.json") && is_file("{$dest['cpanel']}/index.live.php") && is_file($dest['icon'])
        && (fileperms("{$dest['whm']}/index.cgi") & 0777) === 0755 && $leftovers() === [], 'plugin deploy: complete trees in place, no staging leftovers');

    // A new package version replaces the trees as a whole (a removed file never lingers).
    file_put_contents("$source/whm/new.txt", 'v2');
    file_put_contents($dest['whm'] . '/stale.txt', 'old');
    file_put_contents("$source/whm/index.cgi", 'entry2');
    $plugins()->deploy();
    check(is_file("{$dest['whm']}/new.txt") && !file_exists("{$dest['whm']}/stale.txt") && file_get_contents("{$dest['whm']}/index.cgi") === 'entry2'
        && $leftovers() === [], 'plugin deploy: replacement is whole, the previous tree is removed after registration');

    // Registration fails: both previous trees and the icon are back byte for byte, nothing staged remains.
    $before = $snapshot();
    file_put_contents("$source/whm/new.txt", 'v3');
    file_put_contents("$source/cpanel/index.live.php", 'entry3');
    file_put_contents("$source/whm/ols-cpanel.svg", '<svg v3/>');
    foreach (['plugin-whm-register', 'plugin-cpanel-register'] as $failing) {
        $runner->fail = [$failing];
        try {
            $plugins()->deploy();
            check(false, "deploy must fail when $failing fails");
        } catch (DeploymentError) {
            check($snapshot() === $before && $leftovers() === [], "plugin deploy: a failing $failing restores the previous trees and icon");
        }
    }
    // A copy or validation failure before the switch changes nothing live.
    foreach (['plugin-cpanel-stage', 'plugin-cpanel-validate', 'plugin-icon-stage'] as $failing) {
        $runner->fail = [$failing];
        try {
            $plugins()->deploy();
            check(false, "deploy must fail when $failing fails");
        } catch (DeploymentError) {
            check($snapshot() === $before, "plugin deploy: a failing $failing leaves the live plugin untouched");
        }
    }
    // A failure in the middle of the switch (the cPanel tree cannot go aside) rolls the WHM switch back.
    $runner->fail = ['plugin-cpanel-aside'];
    try {
        $plugins()->deploy();
        check(false, 'deploy must fail when the switch fails');
    } catch (DeploymentError) {
        check($snapshot() === $before && $leftovers() === [], 'plugin deploy: a failed switch restores the trees already switched');
    }
    // A tree without its entry point is refused before any live path is touched.
    $runner->fail = [];
    unlink("$source/cpanel/index.live.php");
    try {
        $plugins()->deploy();
        check(false, 'a tree without its entry point must be refused');
    } catch (DeploymentError) {
        check($tree($dest['whm']) === $before[0], 'plugin deploy: a package tree without its entry point is refused');
    }
    // An interrupted switch (live path gone, previous tree present) is put back before the next deployment starts.
    file_put_contents("$source/cpanel/index.live.php", 'entry4');
    rename($dest['cpanel'], $dest['cpanel'] . '.ols-old');
    $plugins()->deploy();
    check(file_get_contents("{$dest['cpanel']}/index.live.php") === 'entry4' && $leftovers() === [], 'plugin deploy: recovers from an interrupted switch');
    remove_tree($root);
    remove_tree($source);
}

// ---- local runner and compilation ---------------------------------------------------------------------------------
$local = new LocalCommandRunner();
$r = $local->run('echo', ['/bin/sh', '-c', 'printf "%s|%s" "$PATH" "$LC_ALL"; echo err >&2; exit 3'], 10);
check($r === ['exit_code' => 3, 'stdout' => '/usr/bin:/bin:/usr/sbin|C', 'stderr' => "err\n"], 'local runner: argv, fixed environment, exit code');
$started = microtime(true);
$r = $local->run('sleep', ['/bin/sleep', '5'], 1);
check($r['exit_code'] === 124 && microtime(true) - $started < 4, 'local runner: timeout kills');
try {
    $local->run('relative', ['sh', '-c', 'true'], 1);
    check(false, 'relative executable must be refused');
} catch (InvalidArgumentException) {
    check(true, 'local runner refuses a relative executable');
}
$listaccts = new class implements CommandRunner {
    public function run(string $name, array $argv, int $timeout): array
    {
        return ['exit_code' => 0, 'stdout' => json_encode(['metadata' => ['result' => 1, 'command' => 'listaccts'],
            'data' => ['acct' => [['user' => 'b', 'domain' => 'b.test'], ['user' => 'a', 'domain' => 'a.test']]]])];
    }
};
check((new BuilderCompilation($listaccts))->tenants() === ['a' => 'a.test', 'b' => 'b.test'], 'compile tenants from listaccts');

$emptyList = new class implements CommandRunner {
    public array $data = ['acct' => []];
    public function run(string $name, array $argv, int $timeout): array {
        return ['exit_code' => 0, 'stdout' => json_encode(['metadata' => ['result' => 1, 'command' => 'listaccts'], 'data' => $this->data])];
    }
};
check((new BuilderCompilation($emptyList))->tenants() === [], 'an explicit successful empty account list removes the final tenant');
$emptyList->data = [];
try {
    (new BuilderCompilation($emptyList))->tenants();
    check(false, 'missing account data must refuse');
} catch (OlsCpanel\Ols\Compiler\CompilationRefused) {
    check(true, 'missing account data is never an authoritative empty list');
}
check(in_array(['Whostmgr', 'Accounts::SiteIP::set'], Hooks::EVENTS, true)
    && in_array(['PkgAcct', 'Restore'], Hooks::EVENTS, true)
    && in_array(['Whostmgr', 'Transfers::Session'], Hooks::EVENTS, true), 'verified site IP, restore and transfer hooks are registered');

// HR-D14: the hybrid include trusts every local address, refreshed without an operator.
$ipText = "1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever\n"
    . "1: lo    inet6 ::1/128 scope host \\       valid_lft forever\n"
    . "2: eth0    inet 10.0.0.9/24 brd 10.0.0.255 scope global eth0\\       valid_lft forever\n"
    . "2: eth0    inet 10.0.0.5/24 scope global secondary eth0\\       valid_lft forever\n"
    . "2: eth0    inet 10.0.0.5/32 scope global eth0\\       valid_lft forever\n"
    . "2: eth0    inet6 FD00::5/64 scope global \\       valid_lft forever\n"
    . "2: eth0    inet6 fe80::1/64 scope link \\       valid_lft forever\n";
check(HybridHost::localAddresses($ipText) === ['127.0.0.1', '::1', '10.0.0.5', '10.0.0.9', 'fd00::5'],
    'local addresses: loopback first, IPv4 and global IPv6, prefixes stripped, sorted, deduplicated, link-local dropped');
check(HybridHost::localAddresses('') === ['127.0.0.1', '::1'], 'no addresses: loopback only');
check(HybridHost::trustedIn(HybridHost::remoteipConf(['127.0.0.1', '::1', '10.0.0.5'])) === ['127.0.0.1', '::1', '10.0.0.5'],
    'trusted list read back from the include');

$h = new FakeHost('/nonexistent/profile.json');
$h->ipOutput = $ipText;
$stage = sys_get_temp_dir() . '/ols-deploy-test-trust-' . bin2hex(random_bytes(4));
$trust = new HybridHost(new Host($h, static function (float $s): void {
}));
check($trust->refreshTrust($stage) === ['result' => 'not-hybrid'] && $h->index('local-addresses') < 0, 'refresh-trust without the include does nothing');
$old = HybridHost::remoteipConf(['127.0.0.1', '::1', '10.0.0.5']);
$h->files[HybridHost::REMOTEIP_CONF] = ['owner' => 'root:root:644', 'content' => $old];
$want = HybridHost::remoteipConf(['127.0.0.1', '::1', '10.0.0.5', '10.0.0.9', 'fd00::5']);
$h->calls = [];
$out = $trust->refreshTrust($stage);
check($out['result'] === 'updated' && $h->files[HybridHost::REMOTEIP_CONF]['content'] === $want
    && $h->index('remoteip-conf') < $h->index('httpd-configtest') && $h->index('httpd-configtest') < $h->index('reload-httpd')
    && in_array(['reload-httpd', ['/usr/local/cpanel/scripts/restartsrv_httpd', '--graceful']], $h->calls, true),
    'a changed address list is installed, tested and Apache reloaded gracefully');
$h->calls = [];
check($trust->refreshTrust($stage)['result'] === 'unchanged' && $h->index('remoteip-conf') < 0 && $h->index('reload-httpd') < 0,
    'an unchanged list changes nothing and reloads nothing');
$h->files[HybridHost::REMOTEIP_CONF]['content'] = $old;
$h->fail['httpd-configtest'] = true;
$h->calls = [];
$out = $trust->refreshTrust($stage);
check($out['result'] === 'failed' && str_contains($out['error'], 'restored') && $h->files[HybridHost::REMOTEIP_CONF]['content'] === $old
    && $h->index('reload-httpd') < 0, 'a failed configuration test restores the previous include and reloads nothing');
remove_tree($stage);

remove_tree(sys_get_temp_dir() . '/ols-deploy-test-none');
foreach (glob(sys_get_temp_dir() . '/ols-deploy-test-*') ?: [] as $dir) {
    remove_tree($dir);
}
echo "Deployment layer: $count assertions passed.\n";
