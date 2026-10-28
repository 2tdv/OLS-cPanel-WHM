<?php
declare(strict_types=1);

// Replays every command the lab compiler (compile_lab, production=True) ran on the real lab server
// through the product ServerConfigurationBuilder: the server configuration and every vhconf must be
// byte-identical to what the lab compiler produced, and mutated cPanel state must fail closed.
require dirname(__DIR__) . '/src/bootstrap.php';

use OlsCpanel\Deployment\BuilderCompilation;
use OlsCpanel\Deployment\SecurityInput;
use OlsCpanel\Events\SourceDigest;
use OlsCpanel\Infrastructure\Process\CommandRunner;
use OlsCpanel\Ols\Compiler\CompilationRefused;
use OlsCpanel\Ols\Compiler\CpanelSurface;
use OlsCpanel\Ols\Compiler\ServerConfigurationBuilder;

/** A command the fixture never recorded: the port diverged from the lab compiler. Never caught. */
final class ReplayMiss extends LogicException
{
}

/** Answers each command with the recorded result of the same argv; anything else is a ReplayMiss. */
final class ReplayRunner implements CommandRunner
{
    /** @var array<string,array{exit_code:int, stdout:string}> */
    private array $calls = [];
    /** @var array<string,true> */
    private array $used = [];

    /** @param list<array{name:string, argv:list<string>, exit_code:int, stdout:string}> $calls */
    public function __construct(array $calls)
    {
        foreach ($calls as $call) {
            $key = self::key($call['argv']);
            $result = ['exit_code' => $call['exit_code'], 'stdout' => $call['stdout']];
            if (isset($this->calls[$key]) && $this->calls[$key] !== $result) {
                throw new LogicException("the fixture records different results for $key");
            }
            $this->calls[$key] = $result;
        }
    }

    public function run(string $name, array $argv, int $timeout): array
    {
        $key = self::key($argv);
        if (!isset($this->calls[$key])) {
            throw new ReplayMiss("unrecorded command ($name): $key");
        }
        $this->used[$key] = true;
        return $this->calls[$key];
    }

    /** @return list<string> recorded commands never requested */
    public function unused(): array
    {
        return array_values(array_diff(array_keys($this->calls), array_keys($this->used)));
    }

    /** @param list<string> $argv */
    public static function key(array $argv): string
    {
        return json_encode($argv, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    }
}

$fixture = json_decode(file_get_contents(__DIR__ . '/Fixtures/lab-snapshot/compile-production.json'), true, 64,
    JSON_THROW_ON_ERROR);
// The lab accounts (build/vm-qualification/tenant_fixtures.py TENANTS) and the lab error log directory.
const TENANTS = ['olscpa' => 'olstest1.example.test', 'olscpb' => 'olstest2.example.test'];
const LOG_DIR = '/var/lib/ols-cpanel-lab/logs';
const A = 'olstest1.example.test';
const B = 'olstest2.example.test';
const A_VHOSTS = ['blog.olstest1.example.test', 'olscpc.olstest1.example.test', A, 'secure.olstest1.example.test'];
$template = file_get_contents(dirname(__DIR__) . '/build/vm-qualification/ols-lab/ownership_httpd_config.conf');
if (!$fixture['production'] || $template === false) {
    throw new RuntimeException('FAIL: the replay needs the production fixture and the server template');
}
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

/** @return array{0:array<string,mixed>, 1:ReplayRunner} */
function compile_with(array $calls, string $template, array $tenants = TENANTS, ?array $hybridPorts = null, mixed $security = null,
                      bool $http3 = true): array
{
    $runner = new ReplayRunner($calls);
    return [(new ServerConfigurationBuilder($runner, $tenants, $template, LOG_DIR, null, null, null, null, null, null,
        $hybridPorts, $security, null, http3: $http3))->compile(), $runner];
}

/**
 * The recorded calls with one command's result replaced; the command must exist in the fixture, so a
 * drifting fixture can never make a negative case vacuous.
 * @param callable(string):string|null $stdout
 */
function replaced(array $calls, array $argv, ?int $exit = null, ?callable $stdout = null): array
{
    $hits = 0;
    foreach ($calls as $i => $call) {
        if ($call['argv'] === $argv) {
            ++$hits;
            $calls[$i]['exit_code'] = $exit ?? $call['exit_code'];
            $calls[$i]['stdout'] = $stdout === null ? $call['stdout'] : $stdout($call['stdout']);
        }
    }
    if ($hits === 0) {
        throw new RuntimeException('FAIL: the fixture has no call ' . ReplayRunner::key($argv));
    }
    return $calls;
}

/**
 * Compilation must refuse (CompilationRefused only; a ReplayMiss or any other error propagates) and
 * name every vhost in $names, and none in $others.
 * @param list<string> $names
 * @param list<string> $others
 */
function refused(array $calls, string $template, array $names, string $text, array $others = []): bool
{
    try {
        compile_with($calls, $template);
    } catch (CompilationRefused $refusal) {
        $message = $refusal->getMessage();
        foreach ($names as $name) {
            if (!str_contains($message, $name) || ($refusal->vhosts() !== [] && !in_array($name, $refusal->vhosts(), true))) {
                echo "refusal does not name $name: $message\n";
                return false;
            }
        }
        foreach ($others as $other) {
            if (in_array($other, $refusal->vhosts(), true) || str_contains($message, "\"$other\"")) {
                echo "refusal names $other: $message\n";
                return false;
            }
        }
        if (!str_contains($message, $text)) {
            echo "unexpected refusal: $message\n";
        }
        return str_contains($message, $text);
    }
    return false;
}

/**
 * A whole compile through the production wiring (Deployment\BuilderCompilation: the product template, the account
 * list from listaccts, the security file) over the recorded calls. $security null = no security file.
 * @return array<string,mixed>
 */
function compile_production(array $calls, string $template, ?string $security, ?array $hybridPorts = null): array
{
    $dir = sys_get_temp_dir() . '/ols-replay-' . bin2hex(random_bytes(6));
    mkdir($dir, 0700);
    try {
        file_put_contents("$dir/template.conf", $template);
        file_put_contents("$dir/security.json", $security ?? '');
        if ($security === null) {
            unlink("$dir/security.json");
        } else {
            chmod("$dir/security.json", 0644);
        }
        $runner = new class(new ReplayRunner($calls)) implements CommandRunner {
            public function __construct(private ReplayRunner $replay)
            {
            }
            public function run(string $name, array $argv, int $timeout): array
            {
                if ($argv === ['/usr/local/cpanel/bin/whmapi1', '--output=json', 'listaccts']) {
                    $rows = [];
                    foreach (TENANTS as $user => $domain) {
                        $rows[] = ['user' => $user, 'domain' => $domain];
                    }
                    return ['exit_code' => 0, 'stdout' => json_encode(['metadata' => ['result' => 1, 'command' => 'listaccts'],
                        'data' => ['acct' => $rows]]), 'stderr' => ''];
                }
                return $this->replay->run($name, $argv, $timeout);
            }
        };
        return (new BuilderCompilation($runner, "$dir/template.conf", LOG_DIR, null, "$dir/security.json"))->compile($hybridPorts);
    } finally {
        exec('/usr/bin/rm -rf -- ' . escapeshellarg($dir));
    }
}

/** Recursively key-sorted, so summaries compare independently of key order. */
function canonical(mixed $value): mixed
{
    if (!is_array($value)) {
        return $value;
    }
    $value = array_map('canonical', $value);
    if (!array_is_list($value)) {
        ksort($value, SORT_STRING);
    }
    return $value;
}

/** The lab summary's (address, port) keys as the product writes them: "address|port", "" = any port. */
function endpoint(string $python): string
{
    $colon = strrpos($python, ':');
    $port = substr($python, $colon + 1);
    return substr($python, 0, $colon) . '|' . ($port === 'None' ? '' : $port);
}

/**
 * The product compiler on recorded inputs equals the lab compiler's recorded output: server configuration,
 * every vhconf and the summary. Returns the product result.
 * @return array<string,mixed>
 */
function equivalent(array $fixture, string $template, string $label = ''): array
{
    $expected = $fixture['compiled'];
    [$result, $runner] = compile_with($fixture['calls'], $template, TENANTS, $fixture['hybrid_ports'] ?? null, $fixture['security'] ?? null);
    check($result['config'] === $expected['config'], "{$label}server configuration byte-identical to the lab compiler");
    $names = array_keys($result['vhconf']);
    $expectedNames = array_keys($expected['vhconf']);
    sort($names);
    sort($expectedNames);
    check($names === $expectedNames, "{$label}the same " . count($expectedNames) . ' OLS vhosts as the lab compiler');
    foreach ($expected['vhconf'] as $name => $text) {
        check(($result['vhconf'][$name] ?? null) === $text, "{$label}vhconf $name byte-identical");
    }
    $unused = $runner->unused();
    check($unused !== [] && array_filter($unused, static fn(string $k): bool => !str_starts_with($k, '["/usr/bin/curl",')) === [],
        "{$label}every recorded cPanel input is read; only the lab-only Apache PHP check is skipped");
    $labSummary = $fixture['summary'];
    $labSummary['apache_defaults'] = array_combine(array_map('endpoint', array_keys($labSummary['apache_defaults'])),
        $labSummary['apache_defaults']);
    $labSummary['apache_proxy_endpoints'] = array_map('endpoint', $labSummary['apache_proxy_endpoints']);
    $summary = json_decode(json_encode($result['summary'], JSON_THROW_ON_ERROR), true, 64, JSON_THROW_ON_ERROR);
    check(canonical($summary) === canonical($labSummary), "{$label}summary equals the lab summary");
    return $result;
}

// Hybrid scenarios (tests/compile_replay_hybrid.py) and WAF and security scenarios (FV-02,
// tests/compile_replay_security.py): the lab compiler's output, or its refusal, on edited inputs.
if (isset($argv[1])) {
    foreach (json_decode(file_get_contents($argv[1]), true, 128, JSON_THROW_ON_ERROR) as $label => $scenario) {
        if (array_key_exists('security', $scenario)) {
            if (isset($scenario['refused'])) {
                try {
                    compile_with($scenario['calls'], $template, TENANTS, $scenario['hybrid_ports'] ?? null, $scenario['security']);
                    check(false, "security $label: refused");
                } catch (CompilationRefused $refusal) {
                    check($refusal->getMessage() === $scenario['refused'], "security $label: refused like the lab compiler");
                }
            } else {
                $result = equivalent($scenario, $template, "security $label: ");
                // Production wiring: the same compile through BuilderCompilation with the security file on disk.
                $ports = $scenario['hybrid_ports'] ?? null;
                $wired = compile_production($scenario['calls'], $template, json_encode($scenario['security'] ?: new stdClass()), $ports);
                check($wired['config'] === $result['config'] && $wired['vhconf'] === $result['vhconf'] && canonical($wired['summary']) === canonical($result['summary']),
                    "security $label: production wiring with security.json equals the builder compile");
                if ($scenario['security'] === []) {
                    $absent = compile_production($scenario['calls'], $template, null, $ports);
                    check($absent['config'] === $result['config'] && $absent['vhconf'] === $result['vhconf'],
                        "security $label: absent security.json compiles like {}");
                }
                // The digests: every ModSecurity file the compile read is part of the source digest.
                $files = SourceDigest::referencedFiles($wired, new class implements CommandRunner {
                    public function run(string $name, array $argv, int $timeout): array
                    {
                        return ['exit_code' => 1, 'stdout' => '', 'stderr' => ''];
                    }
                });
                $inputs = $wired['summary']['waf']['inputs'] ?? [];
                check(array_diff(array_column($inputs, 'path'), array_keys($files)) === []
                    && array_filter($inputs, static fn(array $i): bool => ($files[$i['path']] ?? null) !== $i['sha256']) === [],
                    "security $label: source digest covers " . count($inputs) . ' ModSecurity files');
                if ($inputs !== []) {
                    $changed = $wired;
                    $changed['summary']['waf']['inputs'][count($inputs) - 1]['sha256'] = str_repeat('0', 64);
                    $changedFiles = SourceDigest::referencedFiles($changed, new class implements CommandRunner {
                        public function run(string $name, array $argv, int $timeout): array
                        {
                            return ['exit_code' => 1, 'stdout' => '', 'stderr' => ''];
                        }
                    });
                    check(SourceDigest::source($wired, 1, $files) !== SourceDigest::source($changed, 1, $changedFiles),
                        "security $label: a changed rule or data file changes the source digest");
                }
            }
            continue;
        }
        $hybridResult = equivalent($scenario, $template, "hybrid $label: ");
        if (isset($scenario['summary']['held_vhosts'])) {
            // HR-D14: with an active generation the held vhost keeps its configuration; the other vhosts are unchanged.
            $heldName = array_key_first($scenario['summary']['held_vhosts']);
            $kept = (new ServerConfigurationBuilder(new ReplayRunner($scenario['calls']), TENANTS, $template, LOG_DIR, null, null, null, null, null,
                null, $scenario['hybrid_ports'], null, null, null, previousVhost: static fn(string $v): ?string => "# previous $v\n"))->compile();
            check($kept['vhconf'][$heldName] === "# previous $heldName\n" && !in_array($heldName, $kept['summary']['hybrid_vhosts'], true)
                && isset($kept['summary']['held_vhosts'][$heldName]) && !str_contains($kept['config'], "apache-http-$heldName"),
                "hybrid $label: a held vhost keeps the previous configuration and no Apache backend");
        }
        check($hybridResult['summary']['hybrid_vhosts'] === $scenario['summary']['hybrid_vhosts']
            && ($scenario['summary']['hybrid_vhosts'] !== [] || isset($scenario['summary']['held_vhosts'])), "hybrid $label: Apache keeps " . implode(', ', $scenario['summary']['hybrid_vhosts']));
    }
    // Production wiring, malformed security.json: the compile is refused before anything is compiled.
    foreach (['{bad', '[]x', '{"unknown": 1}', '{"exceptions": [{"vhost": "x.test", "engine": "off"}]}'] as $text) {
        try {
            compile_production($fixture['calls'], $template, $text);
            check(false, "malformed security.json $text refused");
        } catch (CompilationRefused $refusal) {
            check(str_contains($refusal->getMessage(), 'security input'), "malformed security.json refuses the compile: $text");
        }
    }
    echo "$count scenario compile replay checks passed.\n";
    exit(0);
}

$calls = $fixture['calls'];
$expected = $fixture['compiled'];
$result = equivalent($fixture, $template);
// HTTP/3 (FV-04): QUIC is on in the recorded compile (the template default); the operator input turns it off through
// the production wiring (the lab compiler's http3=False output is compared in tests/compiler_equivalence.py).
check(str_contains($expected['config'], "    quicEnable           1\n") && substr_count($expected['config'], "    enableQuic           1\n")
    === substr_count($expected['config'], "    secure               1\n") && !str_contains($expected['config'], '/dev/shm')
    && str_contains($expected['config'], "    quicShmDir           /run/ols-cpanel/shm/\n"), 'HTTP/3 on by default: quicEnable, enableQuic per HTTPS listener, state under /run');
$off = compile_with($calls, $template, http3: false)[0];
check($off['config'] === str_replace(["    quicEnable           1\n", "    enableQuic           1\n"],
    ["    quicEnable           0\n", "    enableQuic           0\n"], $expected['config'])
    && canonical($off['vhconf']) === canonical($expected['vhconf']) && !str_contains($off['config'], 'enableQuic           1'),
    'HTTP/3 off: server quicEnable 0 and enableQuic 0 on every HTTPS listener, nothing else differs');
// The production wiring reads the operator input (absent: enabled) and hands it to the builder; a malformed file refuses.
$http3File = sys_get_temp_dir() . '/ols-http3-' . bin2hex(random_bytes(6)) . '.json';
$seenHttp3 = [];
$wired = static function (string $path) use (&$seenHttp3): BuilderCompilation { return new BuilderCompilation(new class implements CommandRunner {
    public function run(string $name, array $argv, int $timeout): array
    {
        return ['exit_code' => 0, 'stdout' => json_encode(['metadata' => ['result' => 1, 'command' => 'listaccts'],
            'data' => ['acct' => [['user' => 'olscpa', 'domain' => A]]]]), 'stderr' => ''];
    }
}, dirname(__DIR__)
    . '/build/vm-qualification/ols-lab/ownership_httpd_config.conf', LOG_DIR, static function ($r, $t, $tpl, $l, $ports, $security, $limits, $http3) use (&$seenHttp3) {
        $seenHttp3[] = $http3;
        throw new CompilationRefused('stop after the wiring');
    }, '/nonexistent/security.json', '/nonexistent/php-limits.json', $path);
};
foreach (['' => true, '{}' => true, '{"enabled": true}' => true, '{"enabled": false}' => false] as $text => $want) {
    @unlink($http3File);
    if ($text !== '') {
        file_put_contents($http3File, $text);
        chmod($http3File, 0644);
    }
    $seenHttp3 = [];
    try {
        $wired($http3File)->compile(null);
    } catch (CompilationRefused $stop) {
        check($stop->getMessage() === 'stop after the wiring' && $seenHttp3 === [$want], 'production wiring hands the http3 input to the builder: '
            . var_export($text, true));
    }
}
foreach (['{"enabled": 1}', '{"enabled": false, "x": 1}', '[]', '[false]', '{bad', '"off"'] as $text) {
    file_put_contents($http3File, $text);
    chmod($http3File, 0644);
    try {
        $wired($http3File)->compile(null);
        check(false, "malformed http3.json $text refused");
    } catch (CompilationRefused $refusal) {
        check(str_contains($refusal->getMessage(), 'http3 input'), "malformed http3.json refuses the compile: $text");
    }
}
chmod($http3File, 0666);
try {
    $wired($http3File)->compile(null);
    check(false, 'a writable http3.json is refused');
} catch (CompilationRefused $refusal) {
    check(str_contains($refusal->getMessage(), 'writable by no one else'), 'a group- or world-writable http3.json is refused');
}
unlink($http3File);
check($result['summary']['hybrid_vhosts'] === [], 'no hybrid vhost without the hybrid profile');
check(array_keys($result['plan']) === [...A_VHOSTS, B] && array_filter($result['plan'], static fn(array $v): bool => $v['suspended']) === [],
    'plan holds the five lab vhosts, none suspended');

$surface = new CpanelSurface();
$rules = "    rules                <<<END_rules\n";
$purge = "RewriteCond %{REQUEST_METHOD} ^(PURGE|REFRESH)\$ [NC]\nRewriteRule ^ - [F]\n";
// Suspended accounts: every vhost of that account (only) leads its rules with cPanel's suspended page.
foreach (['olscpa' => A_VHOSTS, 'olscpb' => [B]] as $user => $vhosts) {
    [$suspended] = compile_with(replaced($calls, ['/usr/bin/test', '-e', "/var/cpanel/suspended/$user"], 0), $template);
    $ok = $suspended['config'] === $expected['config'] && $suspended['summary']['suspended_accounts'] === [$user];
    foreach ($expected['vhconf'] as $name => $text) {
        // LSCache (FV-01): a suspended vhost keeps its own store but never looks entries up (module off; no
        // PURGE refusal is needed where the module never answers PURGE).
        $want = in_array($name, $vhosts, true)
            ? str_replace([$rules . $purge, "module cache {\n    ls_enabled           1\n"],
                [$rules . $surface->suspensionRules($result['summary']['missing_alias_dirs'][$name]),
                    "module cache {\n    ls_enabled           0\n"], $text) : $text;
        $ok = $ok && $suspended['vhconf'][$name] === $want && ($want === $text || (substr_count($text, $rules . $purge) === 1
            && substr_count($text, 'ls_enabled           1') === 1));
        if (isset($result['summary']['cache'][$name])) {
            $ok = $ok && $suspended['summary']['cache'][$name]['enabled'] === !in_array($name, $vhosts, true)
                && $suspended['summary']['cache'][$name]['storage'] === $result['summary']['cache'][$name]['storage'];
        }
    }
    check($ok, "suspended $user: suspended-page rules and cache lookups off on its " . count($vhosts) . ' vhost(s) only');
}
// A recorded call that is not in the fixture fails loudly instead of being taken as an empty answer.
try {
    (new ReplayRunner($calls))->run('probe', ['/usr/bin/cat', '/etc/shadow'], 1);
    check(false, 'unknown argv fails the replay');
} catch (ReplayMiss) {
    check(true, 'unknown argv fails the replay');
}
// Internal backends through tenant rewrites are blockers that stop compilation.
$proxy = static fn(): string => "RewriteEngine On\nRewriteRule ^ http://cpsrvd2082/ [P]\n";
$readB = static fn(string $path): array => ['/usr/sbin/runuser', '-u', 'olscpb', '--', '/usr/bin/cat', "/home/olscpb/public_html/$path"];
$readA = static fn(string $path): array => ['/usr/sbin/runuser', '-u', 'olscpa', '--', '/usr/bin/cat', "/home/olscpa/public_html/$path"];
check(refused(replaced($calls, $readB('app/.htaccess'), null, $proxy), $template, [B], 'untranslatable .htaccess', A_VHOSTS),
    'proxy rewrite to cpsrvd refused (tenant B only)');
// A nested vhost's .htaccess also lies in the parent vhost's tree: both stay on Apache.
check(refused(replaced($calls, $readA('blog/.htaccess'), null, $proxy), $template, ['blog.olstest1.example.test', A],
    'untranslatable .htaccess', [B, 'secure.olstest1.example.test']), 'proxy rewrite in a nested docroot blocks both vhosts');
check(refused(replaced($calls, $readB('sub-noindex/.htaccess'), 1, static fn(): string => ''), $template, [B], '.htaccess unreadable'),
    'unreadable .htaccess refused');
$listB = ['/usr/sbin/runuser', '-u', 'olscpb', '--', '/usr/bin/find', '-H', '/home/olscpb/public_html', '-name', '.htaccess',
    '(', '-type', 'f', '-o', '-type', 'l', ')', '-printf', '%y%p\0'];
check(refused(replaced($calls, $listB, 1), $template, [B], '.htaccess scan incomplete'), 'incomplete .htaccess scan refused');
check(refused(replaced($calls, $listB, null, static fn(string $s): string => str_replace("f/home/olscpb/public_html/app/",
    "l/home/olscpb/public_html/app/", $s)), $template, [B], '/app/: .htaccess is a symlink'), 'symlinked .htaccess refused');
// HR-D14: with the hybrid profile a read failure of one account moves only that vhost to Apache (fail safe: Apache applies
// the account's real rules); the other vhosts stay native and nothing refuses. The next compile without the cause returns it.
$poolBlog = ['/usr/bin/cat', '/opt/cpanel/ea-php83/root/etc/php-fpm.d/blog.olstest1.example.test.conf'];
foreach ([
    '.htaccess unreadable' => [replaced($calls, $readB('sub-noindex/.htaccess'), 1, static fn(): string => ''), '.htaccess unreadable'],
    '.htaccess scan incomplete' => [replaced($calls, $listB, 1), '.htaccess scan incomplete'],
    'symlinked .htaccess' => [replaced($calls, $listB, null, static fn(string $s): string => str_replace("f/home/olscpb/public_html/app/",
        "l/home/olscpb/public_html/app/", $s)), '.htaccess is a symlink'],
] as $label => [$broken, $reason]) {
    [$fallback] = compile_with($broken, $template, TENANTS, [81, 444]);
    check($fallback['summary']['hybrid_vhosts'] === [B] && str_contains(json_encode($fallback['summary']['htaccess_blockers'][B]), $reason)
        && $fallback['plan'][B]['mode'] === 'apache' && $fallback['plan'][A]['mode'] === 'native',
        "hybrid: $label moves only that vhost to Apache, with the reason");
    [$healed] = compile_with($calls, $template, TENANTS, [81, 444]);
    check($healed['summary']['hybrid_vhosts'] === [] && $healed['plan'][B]['mode'] === 'native',
        "hybrid: $label gone, the vhost returns to OLS on the next compile");
}
// After the cutover cPanel binds Apache's vhosts to the backend ports; the compile must equal the approved plan's, which was made
// while Apache still had 80/443 (lab 2026-10-28: a fresh install's cutover refused because the two differed).
[$planned] = compile_with($calls, $template, TENANTS, [81, 444]);
$moved = replaced($calls, ['/usr/bin/cat', '/etc/apache2/conf/httpd.conf'], null,
    static fn(string $s): string => preg_replace(['/:80>/', '/:443>/', '/^Listen (.*):80$/m', '/^Listen (.*):443$/m', '/^Listen 80$/m', '/^Listen 443$/m'],
        [':81>', ':444>', 'Listen $1:81', 'Listen $1:444', 'Listen 81', 'Listen 444'], $s));
[$afterMove] = compile_with($moved, $template, TENANTS, [81, 444]);
check($afterMove['config'] === $planned['config'] && $afterMove['vhconf'] === $planned['vhconf']
    && $afterMove['summary']['apache_defaults'] === $planned['summary']['apache_defaults']
    && $afterMove['summary']['apache_proxy_endpoints'] === $planned['summary']['apache_proxy_endpoints'],
    'hybrid: Apache moved to 81/444 compiles exactly the plan made while Apache had 80/443');
[$fallback] = compile_with(replaced($calls, $poolBlog, 1), $template, TENANTS, [81, 444]);
check($fallback['summary']['hybrid_vhosts'] === ['blog.olstest1.example.test']
    && $fallback['summary']['hybrid_reasons'] === ['blog.olstest1.example.test' => ['PHP-FPM pool unreadable']],
    'hybrid: an unreadable FPM pool moves only that vhost to Apache, with the reason');
check(refused(replaced($calls, $poolBlog, 1), $template, ['blog.olstest1.example.test'], 'pool'), 'native: the same unreadable FPM pool still refuses');
check(refused(replaced($calls, $readA('secure/.htaccess'), null, static fn(string $s): string => $s . "Action x /cgi-bin/x\n"),
    $template, ['secure.olstest1.example.test', A], 'untranslatable .htaccess'), 'unknown directive refused');
// PHP handlers. API answers are edited as JSON: cPanel's key order differs between recordings.
/** @param callable(array<string,mixed>):array<string,mixed> $edit applied to each row of data.$list */
function api_rows(string $list, callable $edit): callable
{
    return static function (string $json) use ($list, $edit): string {
        $data = json_decode($json, true, 64, JSON_THROW_ON_ERROR);
        $data['data'][$list] = array_map($edit, $data['data'][$list]);
        return json_encode($data, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    };
}
$handlers = ['/usr/local/cpanel/bin/whmapi1', '--output=json', 'php_get_handlers'];
$handler = static fn(string $h): callable => api_rows('version_handlers',
    static fn(array $row): array => $row['version'] === 'ea-php82' ? ['current_handler' => $h] + $row : $row);
check(refused(replaced($calls, $handlers, null, $handler('lsapi')), $template, [B],
    "unsupported PHP handler 'lsapi'"), 'unsupported PHP handler refused');
check(refused(replaced($calls, $handlers, null, static fn(string $s): string => str_replace('"result":1', '"result":0', $s)),
    $template, [], 'API semantic failure'), 'failed whmapi1 answer refused');
$suphp = replaced($calls, $handlers, null, $handler('suphp'));
[$suphpResult] = compile_with($suphp, $template);
check(str_contains($suphpResult['vhconf'][B], "    env                  PHP_INI_SCAN_DIR=/opt/cpanel/ea-php82/root/etc:"
    . "/opt/cpanel/ea-php82/root/etc/php.d:/home/olscpb/public_html\n") && $suphpResult['vhconf'][A] === $expected['vhconf'][A],
    'suPHP vhost gets the INI scan environment');
$versions = ['/usr/local/cpanel/bin/whmapi1', '--output=json', 'php_get_vhost_versions'];
check(refused(replaced($calls, $versions, null, api_rows('versions',
    static fn(array $row): array => $row['vhost'] === B ? ['php_fpm' => 1] + $row : $row)), $template, [B], 'PHP-FPM pool'),
    'PHP-FPM vhost without a readable pool refused');
// Malformed cPanel state.
$userdataB = ['/usr/bin/cat', '/var/cpanel/userdata/olscpb/olstest2.example.test'];
check(refused(replaced($calls, $userdataB, null, static fn(string $s): string => str_replace('servername: olstest2.example.test',
    'servername: other.example', $s)), $template, [B], 'servername mismatch'), 'userdata servername mismatch refused');
check(refused(replaced($calls, $userdataB, null, static fn(string $s): string => preg_replace('/^documentroot: .*$/m',
    'documentroot: /home/olscpa/public_html', $s)), $template, [B], 'unsafe document root'), 'foreign document root refused');
check(refused(replaced($calls, $userdataB, null, static fn(string $s): string => preg_replace('/^phpversion: .*$/m',
    'phpversion: ../../../tmp/x', $s)), $template, [B], 'invalid PHP version'), 'unsafe PHP version refused before any read');
// A new account before cPanel writes its version (about two minutes, lab 2026-10-28): no phpversion in the userdata, an empty
// userdatadomains field. OLS takes cPanel's resolved version (php_get_vhost_versions) like Apache, never refuses the server.
$udd = ['/usr/bin/cat', '/etc/userdatadomains'];
$noVersion = replaced(replaced($calls, $userdataB, null, static fn(string $s): string => preg_replace('/^phpversion: .*\n/m', '', $s)),
    $udd, null, static fn(string $s): string => str_replace('====0==ea-php82', '====0==', $s));
[$newAccount] = compile_with($noVersion, $template);
check($newAccount['plan'][B]['php'] === 'ea-php82' && $newAccount['config'] === $expected['config'] && $newAccount['vhconf'][B] === $expected['vhconf'][B],
    'a new account without a PHP version of its own is compiled with the version cPanel resolves (system default)');
check(refused(replaced($noVersion, $versions, null, api_rows('versions',
    static fn(array $row): array => $row['vhost'] === B ? ['version' => ''] + $row : $row)), $template, [B], 'invalid PHP version'),
    'no version from the userdata nor from cPanel: refused');
// cPanel's Force HTTPS Redirect (userdata ssl_redirect: '1', lab 2026-10-28: the cutover's comparison found Apache 301, OLS 200).
$forced = replaced($calls, $userdataB, null, static fn(string $s): string => $s . "ssl_redirect: '1'\n");
[$redirected] = compile_with($forced, $template);
$dcv = "RewriteRule ^ - [L]\n";
$redirect = "RewriteCond %{HTTP:X-Forwarded-Proto} !https\nRewriteCond %{HTTPS} !^on$\nRewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]\n";
$pos = strpos($expected['vhconf'][B], 'RewriteCond %{REQUEST_URI} ' . CpanelSurface::DCV . "\n" . $dcv);
check($pos !== false && $redirected['vhconf'][B] === substr_replace($expected['vhconf'][B], $redirect,
        $pos + strlen('RewriteCond %{REQUEST_URI} ' . CpanelSurface::DCV . "\n" . $dcv), 0)
    && $redirected['vhconf'][A] === $expected['vhconf'][A] && $redirected['config'] === $expected['config'],
    'Force HTTPS Redirect: the vhost answers plain HTTP with 301 to https right after the DCV exemption, nothing else changes');
check(refused(replaced($calls, ['/usr/bin/cat', '/etc/userdatadomains'], null, static fn(string $s): string => $s . "bad line\n"),
    $template, [], 'unexpected userdatadomains line'), 'malformed userdatadomains refused');
check(refused(replaced($calls, ['/usr/bin/cat', '/etc/apache2/conf/httpd.conf'], 1, static fn(): string => ''), $template, [],
    'unable to read /etc/apache2/conf/httpd.conf'), 'unreadable httpd.conf refused');
// Certificates follow cPanel's state.
[$noServiceCert] = compile_with(replaced($calls, ['/usr/bin/test', '-f', CpanelSurface::SERVICE_CERTS[0]], 1), $template);
$ok = $noServiceCert['config'] === $expected['config'];
foreach ($expected['vhconf'] as $name => $text) {
    $want = in_array($name, [CpanelSurface::PROXY_VHOST, CpanelSurface::DEFAULT_VHOST], true)
        ? str_replace(CpanelSurface::SERVICE_CERTS[0], CpanelSurface::SERVICE_CERTS[1], $text) : $text;
    $ok = $ok && $noServiceCert['vhconf'][$name] === $want;
}
check($ok && $noServiceCert['summary']['service_cert'] === CpanelSurface::SERVICE_CERTS[1],
    'self-signed service certificate until cPanel installs mycpanel.pem');
[$noTls] = compile_with(replaced($calls, ['/usr/bin/test', '-f', ServerConfigurationBuilder::TLS_DIR . '/' . B . '/combined'], 1), $template);
check(!str_contains($noTls['vhconf'][B], 'vhssl') && !str_contains($noTls['vhconf']['svc.' . B], 'vhssl')
    && $noTls['vhconf'][A] === $expected['vhconf'][A], 'vhost without an installed certificate gets no vhssl');
// cPanel's current names and addresses replace the previous account configuration on the next compile.
foreach ([['olscpa' => 'renamed', A => 'newmain.test'], ['172.16.0.4' => '192.0.2.99']] as $changes) {
    $changedCalls = array_map(static function (array $call) use ($changes): array {
        if (isset($changes['172.16.0.4'])) {
            if ($call['argv'] === ['/usr/bin/cat', '/etc/userdatadomains']) {
                $call['stdout'] = implode("\n", array_map(static fn(string $line): string => str_contains($line, ': olscpa==')
                    ? strtr($line, $changes) : $line, explode("\n", $call['stdout'])));
            } elseif (str_contains(implode(' ', $call['argv']), '/userdata/olscpa/')) {
                $call['stdout'] = strtr($call['stdout'], $changes);
            }
        } else {
            $call['argv'] = array_map(static fn(string $arg): string => strtr($arg, $changes), $call['argv']);
            $call['stdout'] = strtr($call['stdout'], $changes);
        }
        return $call;
    }, $calls);
    $tenants = isset($changes['olscpa']) ? ['renamed' => 'newmain.test', 'olscpb' => B] : TENANTS;
    [$changed] = compile_with($changedCalls, $template, $tenants);
    if (isset($changes['olscpa'])) {
        check(!isset($changed['plan'][A]) && $changed['plan']['newmain.test']['user'] === 'renamed'
            && str_contains($changed['vhconf']['newmain.test'], '/home/renamed/')
            && !str_contains($changed['config'], A), 'account and main-domain renames replace old vhosts and home paths');
    } else {
        check(str_contains($changed['config'], '192.0.2.99:80') && str_contains($changed['config'], '172.16.0.4:80'),
            'an account IP change replaces listener addresses from cPanel state');
    }
}
// An authoritative empty cPanel account set must remove the final tenant, keeping the cPanel service surface.
[$empty] = compile_with($calls, $template, []);
check($empty['plan'] === [] && $empty['summary']['vhosts'] === [] && $empty['summary']['cache'] === []
    && isset($empty['vhconf'][CpanelSurface::PROXY_VHOST], $empty['vhconf'][CpanelSurface::DEFAULT_VHOST])
    && !str_contains($empty['config'], A) && !str_contains($empty['config'], B),
    'the final account removal compiles an empty tenant set without retaining old domains');
echo "$count compile replay checks passed.\n";
