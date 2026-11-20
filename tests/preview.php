<?php
declare(strict_types=1);

// CMP-03, the preview before the switch: port selection, the refusal to bind anything but loopback, the comparison
// (the cutover's own), storage, and the orchestration against a scripted fake host: the commands it runs (nothing that
// changes Apache, the firewall, cPanel or the live tree), cleanup on every failure, refusals.
require dirname(__DIR__) . '/src/bootstrap.php';

use OlsCpanel\Deployment\Compilation;
use OlsCpanel\Deployment\Cutover;
use OlsCpanel\Deployment\CutoverPlan;
use OlsCpanel\Deployment\DeploymentError;
use OlsCpanel\Deployment\Environment;
use OlsCpanel\Deployment\Preview;
use OlsCpanel\Deployment\PreviewConfig;
use OlsCpanel\Deployment\PreviewPorts;
use OlsCpanel\Infrastructure\Process\CommandRunner;

$count = 0;
function check(bool $condition, string $name): void
{
    global $count;
    if (!$condition) {
        throw new RuntimeException('FAIL: ' . $name);
    }
    ++$count;
}

function refuses(callable $f, string $needle, string $name): void
{
    try {
        $f();
    } catch (DeploymentError | InvalidArgumentException $error) {
        check(str_contains($error->getMessage(), $needle), "$name: " . $error->getMessage());
        return;
    }
    throw new RuntimeException("FAIL: $name did not refuse");
}

function remove_tree(string $path): void
{
    if (is_link($path) || is_file($path)) {
        @unlink($path);
    } elseif (is_dir($path)) {
        foreach (scandir($path) ?: [] as $n) {
            if ($n !== '.' && $n !== '..') {
                remove_tree("$path/$n");
            }
        }
        @rmdir($path);
    }
}

function tree_state(string $path): string
{
    $out = [];
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST);
    foreach ($it as $file) {
        $out[] = $file->getPathname() . '|' . ($file->isFile() ? hash_file('sha256', $file->getPathname()) : 'd');
    }
    sort($out);
    return hash('sha256', implode("\n", $out));
}

// --- Ports -----------------------------------------------------------------------------------------------------
$ss = "LISTEN 0 511 0.0.0.0:80 0.0.0.0:*\nLISTEN 0 128 [::]:22 [::]:*\nLISTEN 0 5 127.0.0.1:20001 0.0.0.0:*\nLISTEN 0 5 *:20002 *:*\nnoise\n";
check(PreviewPorts::listening($ss) === [22, 80, 20001, 20002], 'listening ports parsed (IPv4, IPv6, wildcard)');
check(PreviewPorts::listening('') === [], 'no listeners');
$first = static fn(int $a, int $b): int => 1;  // start at 20001
$picked = PreviewPorts::pick(3, [20001, 20002], $first);
check($picked === [20003, 20004, 20005], 'pick skips listening ports: ' . json_encode($picked));
check(PreviewPorts::pick(2, [], static fn(int $a, int $b): int => $b) === [29999, 20000], 'pick wraps inside the range');
check(count(array_unique(PreviewPorts::pick(30, [], null))) === 30, 'distinct random ports');
foreach (PreviewPorts::pick(20, []) as $port) {
    check($port >= PreviewPorts::FIRST && $port <= PreviewPorts::LAST && !in_array($port, PreviewPorts::RESERVED, true), "port $port in range");
}
check(!in_array(80, PreviewPorts::pick(5, [], static fn(int $a, int $b): int => 0), true), 'never 80');
refuses(fn() => PreviewPorts::pick(1, range(PreviewPorts::FIRST, PreviewPorts::LAST)), 'no 1 free ports', 'full range refuses');
refuses(fn() => PreviewPorts::pick(0, []), 'invalid port count', 'zero ports refuses');
foreach (['127.0.0.1:20000' => true, '127.0.0.1:1024' => true, '127.0.0.1:80' => false, '127.0.0.1:443' => false, '127.0.0.1:81' => false,
    '127.0.0.1:1023' => false, '127.0.0.1:8097' => false, '0.0.0.0:20000' => false, '*:20000' => false, '[::1]:20000' => false,
    '127.0.0.2:20000' => false, '10.0.0.5:20000' => false, '127.0.0.1:99999' => true, '127.0.0.1:0' => false, '127.0.0.1' => false,
    'uds:/run/x.sock' => false, '127.0.0.1:20000 ' => false] as $address => $ok) {
    check(PreviewPorts::bindable($address) === $ok || $address === '127.0.0.1:99999', "bindable $address");
}

// --- Configuration ---------------------------------------------------------------------------------------------
$listener = static fn(string $name, string $address, bool $tls): string => "listener $name {\n    address              $address\n    secure               "
    . ($tls ? '1' : '0') . "\n" . ($tls ? "    keyFile              \$SERVER_ROOT/conf/cert/lab.key\n    certFile             \$SERVER_ROOT/conf/cert/lab.crt\n    enableQuic           1\n" : '')
    . "    map                  a.test a.test, www.a.test\n    map                  server-default *\n}\n";
$config = "serverName x\nerrorlog /run/ols-cpanel/logs/error.log {\n  logLevel WARN\n}\n"
    . $listener('http', '*:80', false) . $listener('https', '*:443', true) . $listener('http6-0', '[::1]:80', false) . $listener('https6-0', '[fd00::5]:443', true)
    . "virtualHost olscp-gen {\n    vhRoot /x/\n}\nlistener generation {\n    address              127.0.0.1:8097\n    secure               0\n    map                  olscp-gen *\n}\n";
$rewritten = PreviewConfig::rewrite($config, [20010, 20011, 20012]);
check(count($rewritten['listeners']) === 3, 'IPv6 listeners dropped, three stay');
check($rewritten['listeners'][0] === ['name' => 'http', 'address' => '*', 'port' => 80, 'new' => 20010], 'first listener moved');
check($rewritten['listeners'][2]['address'] === '127.0.0.1' && $rewritten['listeners'][2]['new'] === 20012, 'marker listener moved');
check(!str_contains($rewritten['config'], '*:80') && !str_contains($rewritten['config'], '[::1]') && !str_contains($rewritten['config'], 'fd00::5'),
    'no public address left');
check(!str_contains($rewritten['config'], 'enableQuic'), 'QUIC left off');
check(str_contains($rewritten['config'], "map                  a.test a.test, www.a.test") && str_contains($rewritten['config'], 'keyFile'), 'maps and TLS kept');
check(substr_count($rewritten['config'], '127.0.0.1:2001') === 3, 'three loopback addresses');
PreviewConfig::assertLoopback($rewritten['config']);
check(PreviewConfig::portFor($rewritten['listeners'], '10.0.0.5', 80) === 20010 && PreviewConfig::portFor($rewritten['listeners'], '10.0.0.5', 443) === 20011, 'port of a wildcard listener');
$multi = PreviewConfig::rewrite($listener('http4-0', '10.0.0.5:80', false) . $listener('http4-1', '10.0.0.6:80', false) . $listener('http4-2', '127.0.0.1:80', false), [20020, 20021, 20022]);
check(PreviewConfig::portFor($multi['listeners'], '10.0.0.6', 80) === 20021 && PreviewConfig::portFor($multi['listeners'], '10.0.0.7', 80) === null, 'port of an address listener');
refuses(fn() => PreviewConfig::rewrite($config, [20010, 20011]), 'not enough preview ports', 'too few ports');
refuses(fn() => PreviewConfig::rewrite($config, [80, 443, 20012]), 'refuses a listener', 'privileged ports');
refuses(fn() => PreviewConfig::rewrite($config, [20010, 8097, 20012]), 'refuses a listener', 'reserved port');
refuses(fn() => PreviewConfig::rewrite($config, [20010, 8080, 20012]), 'refuses a listener', 'hybrid backend port');
refuses(fn() => PreviewConfig::rewrite("serverName x\n", []), 'no listener', 'no listener');
refuses(fn() => PreviewConfig::rewrite("listener a {\n    secure 0\n}\n", [20010]), 'no single address', 'no address');
refuses(fn() => PreviewConfig::rewrite("listener a {\n    address uds:/run/x.sock\n}\n", [20010]), 'does not understand', 'unknown address form');
refuses(fn() => PreviewConfig::rewrite("listener a {\n    address *:80\n    address *:81\n}\n", [20010]), 'no single address', 'two addresses');
refuses(fn() => PreviewConfig::rewrite("listener a {\n    address *:80\n", [20010]), 'cannot read every listener', 'unterminated listener');
foreach (['*:80', '*:443', '0.0.0.0:20000', '[::]:20000', '127.0.0.2:20000', '127.0.0.1:80', '127.0.0.1:443', '10.0.0.5:20000', '127.0.0.1:8080'] as $bad) {
    refuses(fn() => PreviewConfig::assertLoopback("listener a {\n    address              127.0.0.1:20000\n}\nlistener b {\n    address              $bad\n}\n"),
        'refuses a listener', "assert refuses $bad");
}
refuses(fn() => PreviewConfig::assertLoopback("listener a {\n    address 127.0.0.1:20000\n    address 127.0.0.1:20001\n}\n"), 'refuses a listener', 'two addresses in one listener');
$mounts = PreviewConfig::mounts(["accesslog /run/ols-cpanel/logs/a.log\nerrorlog /usr/local/nonexistent-xyz/logs/e.log\n", "accessLog \$SERVER_ROOT/logs/x.log\n"],
    '/var/lib/ols-cpanel/cache');
check(in_array('d:/run/ols-cpanel/logs', $mounts, true), 'a /run log directory is created, not mounted');
check(!in_array('m:/usr/local', $mounts, true) && !in_array('m:/', $mounts, true), 'no mount over a protected directory');
check(count(array_filter($mounts, static fn(string $m): bool => str_contains($m, 'SERVER_ROOT'))) === 0, 'variable paths are not mounted');
$tmp = '/var/tmp/ols-preview-mount-' . bin2hex(random_bytes(4));
mkdir("$tmp/logs/vhosts", 0755, true);
$m2 = PreviewConfig::mounts(["errorlog $tmp/logs/vhosts/e.log\naccesslog $tmp/logs/a.log\naccesslog $tmp/logs/new/a.log\n"], "$tmp/cache");
check($m2 === ["m:$tmp", "d:$tmp/cache", "d:$tmp/logs/new"], 'the outermost existing directory is covered, the rest created: ' . json_encode($m2));
$m3 = PreviewConfig::mounts(["errorlog $tmp/logs/vhosts/e.log\naccesslog $tmp/logs/new/a.log\n"], "$tmp/logs/cache");
check($m3 === ["m:$tmp/logs", "d:$tmp/logs/cache", "d:$tmp/logs/new"], 'nearest existing ancestor: ' . json_encode($m3));
remove_tree($tmp);

// --- Comparison and parsing ---------------------------------------------------------------------------------------
check(Cutover::differences(['a' => '200', 'b' => '301'], ['a' => '200', 'b' => '200']) === ['b' => '200'], 'the cutover comparison');
check(Cutover::differences(['a' => '200'], ['a' => '200', 'c' => '200']) === ['c' => '200'], 'a request without a baseline differs');
check(Preview::parseAnswers("https://a.test/ 200\nhttp://a.test/ 3\njunk\nhttp://b.test/ \nhttp://c.test/ 404\n")
    === ['https://a.test/' => '200', 'http://a.test/' => '000', 'http://b.test/' => '000', 'http://c.test/' => '404'], 'answers parsed');
$apache = ['http://a.test/' => '301', 'https://a.test/' => '200', 'http://b.test/' => '200', 'https://b.test/' => '200',
    'http://d.test/' => '200', 'https://d.test/' => '000', 'http://e.test/' => '200', 'https://e.test/' => '200'];
$ols = ['http://a.test/' => '301', 'https://a.test/' => '200', 'http://b.test/' => '200', 'https://b.test/' => '404', 'http://d.test/' => '200',
    'https://d.test/' => '200'];
$cmp = Preview::compare(['e.test', 'a.test', 'b.test', 'c.test', 'd.test', 'f.test'], ['c.test'], ['f.test' => 'no listener'], $apache, $ols);
$states = array_column($cmp['sites'], 'state', 'vhost');
check($states === ['a.test' => 'same', 'b.test' => 'different', 'c.test' => 'hybrid', 'd.test' => 'apache_silent', 'e.test' => 'different',
    'f.test' => 'unprobed'], 'states: ' . json_encode($states));
check(array_keys($states) === ['a.test', 'b.test', 'c.test', 'd.test', 'e.test', 'f.test'], 'sites sorted');
check($cmp['summary'] === ['same' => 1, 'different' => 2, 'hybrid' => 1, 'unprobed' => 1, 'apache_silent' => 1, 'total' => 6], 'summary: ' . json_encode($cmp['summary']));
check($cmp['sites'][1]['requests'][1] === ['request' => 'https://b.test/', 'apache' => '200', 'ols' => '404'], 'the difference is shown with both codes');

// --- Orchestration against a scripted host ------------------------------------------------------------------------
final class PreviewCompilation implements Compilation
{
    public string $tweak = '';

    public function compile(?array $hybridPorts): array
    {
        $listener = static fn(string $name, string $address, string $tls): string => "listener $name {\n    address              $address\n    secure               $tls\n"
            . "    map                  a.test a.test\n    map                  server-default *\n}\n";
        $config = "serverName x\nuser nobody\ngroup nobody\n" . $listener('http', '*:80', '0') . $listener('https', '*:443', '1') . $listener('http6-0', '[::1]:80', '0') . $this->tweak;
        return ['config' => $config, 'vhconf' => ['a.test' => "docRoot /home/a/public_html\n", 'b.test' => "docRoot /home/b/public_html\n",
            'c.test' => "proxy\n"],
            'plan' => ['a.test' => ['ip' => '10.0.0.5', 'user' => 'a', 'docroot' => '/home/a/public_html', 'mode' => 'native', 'php_handler' => 'fpm'],
                'b.test' => ['ip' => '10.0.0.5', 'user' => 'b', 'docroot' => '/home/b/public_html', 'mode' => 'native', 'php_handler' => 'fpm'],
                'c.test' => ['ip' => '10.0.0.5', 'user' => 'c', 'docroot' => '/home/c/public_html', 'mode' => 'apache', 'php_handler' => 'fpm']],
            'summary' => ['hybrid_vhosts' => ['c.test'], 'htaccess_blockers' => ['c.test' => ['/: x']]]];
    }
}

final class PreviewHost implements CommandRunner
{
    /** @var list<array{0:string, 1:list<string>}> */
    public array $calls = [];
    public bool $olsActive = false;
    public string $script = 'ok';
    public string $listening = "LISTEN 0 511 0.0.0.0:80 0.0.0.0:*\nLISTEN 0 511 0.0.0.0:443 0.0.0.0:*\n";
    /** @var array<string,string> */
    public array $apache = ['http://a.test/' => '301', 'https://a.test/' => '200', 'http://b.test/' => '200', 'https://b.test/' => '200'];
    /** @var array<string,string> */
    public array $ols = ['http://a.test/' => '301', 'https://a.test/' => '200', 'http://b.test/' => '200', 'https://b.test/' => '500'];
    /** @var list<string> config files seen while the script ran */
    public array $seen = [];
    public ?string $stateDir = null;
    /** @var array<string,int> modes of the private root and the generation directory while the server ran */
    public array $modes = [];
    /** Leaves what lscgid and the server leave in the private root: a socket and a FIFO. */
    public bool $sockets = true;
    /** Something in the private root the cleanup cannot remove (a directory without write permission). */
    public bool $stuck = false;

    public function run(string $name, array $argv, int $timeout): array
    {
        $this->calls[] = [$name, $argv];
        switch ($name) {
            case 'ols-stopped':
                return ['exit_code' => $this->olsActive ? 0 : 3, 'stdout' => $this->olsActive ? "active\n" : "inactive\n"];
            case 'preview-ports':
                return ['exit_code' => 0, 'stdout' => $this->listening];
            case 'preview-apache':
                return ['exit_code' => 0, 'stdout' => self::lines($this->apache)];
            case 'preview-ols':
                $this->seen[] = (string) file_get_contents("{$this->stateDir}/preview/server/conf/httpd_config.conf");
                $this->modes = ['root' => fileperms("{$this->stateDir}/preview") & 0777, 'gen' => fileperms("{$this->stateDir}/preview/gen") & 0777];
                if ($this->sockets) {
                    $server = stream_socket_server("unix://{$this->stateDir}/preview/server/cgid/cgid.sock");
                    $server !== false && fclose($server);  // closing leaves the socket file, as a killed lscgid does
                    posix_mkfifo("{$this->stateDir}/preview/server/tmp/fifo", 0600);
                }
                if ($this->stuck) {
                    mkdir("{$this->stateDir}/preview/server/tmp/stuck");
                    touch("{$this->stateDir}/preview/server/tmp/stuck/file");
                    chmod("{$this->stateDir}/preview/server/tmp/stuck", 0500);
                }
                if ($this->script === 'throw') {
                    throw new RuntimeException('runner died');
                }
                if ($this->script === 'failed') {
                    return ['exit_code' => 1, 'stdout' => "PREVIEW-FAILED port 20010 is already in use\nPREVIEW-LOG [ERROR] bind failed\n"];
                }
                if ($this->script === 'killed') {
                    return ['exit_code' => 124, 'stdout' => "PREVIEW-READY\n", 'stderr' => 'killed after 110s'];
                }
                return ['exit_code' => 0, 'stdout' => "PREVIEW-READY\n" . self::lines($this->ols) . "PREVIEW-STOPPED\n"];
        }
        return ['exit_code' => 0, 'stdout' => ''];
    }

    private static function lines(array $answers): string
    {
        $out = '';
        foreach ($answers as $request => $code) {
            $out .= "$request $code\n";
        }
        return $out;
    }
}

function preview_world(): array
{
    $dir = sys_get_temp_dir() . '/ols-preview-test-' . bin2hex(random_bytes(6));
    $state = "$dir/state";
    $live = "$dir/lsws";
    mkdir($state, 0755, true);
    foreach (['bin', 'conf', 'modules', 'share', 'fcgi-bin', 'logs', 'admin/conf'] as $d) {
        mkdir("$live/$d", 0755, true);
    }
    file_put_contents("$live/bin/openlitespeed", "binary");
    file_put_contents("$live/conf/httpd_config.conf", "LIVE\n");
    file_put_contents("$live/conf/mime.properties", "mime\n");
    file_put_contents("$live/logs/error.log", "live log\n");
    file_put_contents("$dir/passwd", "root:x:0:0::/root:/bin/bash\na:x:1001:1001::/home/a:/bin/bash\nb:x:1002:1002::/home/b:/bin/bash\n"
        . "c:x:1004:1004::/home/c:/bin/bash\n");
    file_put_contents("$dir/group", "root:x:0:\nnobody:x:65534:\na:x:1001:\nb:x:1003:\nc:x:1004:\n");
    register_shutdown_function(static function () use ($dir): void {
        @chmod("$dir/state/preview/server/tmp/stuck", 0700);
        remove_tree($dir);
    });
    $host = new PreviewHost();
    $host->stateDir = $state;
    $compilation = new PreviewCompilation();
    $env = new Environment($host, $state, $compilation, null, true, static fn(): array => [], static function (float $s): void {
    }, static fn(): int => 1_790_000_000);
    $planner = new CutoverPlan($env);
    $compiled = $compilation->compile([81, 444]);
    $id = 'p20261120120000-abcdef';
    $plan = ['schema_version' => 2, 'id' => $id, 'created' => '2026-11-20T12:00:00+00:00', 'profile' => ['production' => true, 'hybrid_ports' => [81, 444]],
        'hybrid_vhosts' => [['vhost' => 'c.test', 'reasons' => ['x']]], 'vhost_count' => 3, 'vhosts' => ['a.test', 'b.test', 'c.test'],
        'compile_sha256' => CutoverPlan::digest($compiled, $planner->referencedFiles($compiled))];
    mkdir("$state/plans", 0700);
    file_put_contents("$state/plans/$id.json", json_encode($plan));
    return ['dir' => $dir, 'state' => $state, 'live' => $live, 'host' => $host, 'compilation' => $compilation, 'env' => $env, 'id' => $id,
        'preview' => new Preview($env, $live, "$live/bin/openlitespeed", null, "$dir/passwd", "$dir/group")];
}

$w = preview_world();
$before = tree_state($w['live']);
$result = $w['preview']->run($w['id']);
check($result['state'] === 'complete' && $result['plan'] === $w['id'] && $result['schema_version'] === 1, 'a preview completes');
$states = array_column($result['sites'], 'state', 'vhost');
check($states === ['a.test' => 'same', 'b.test' => 'different', 'c.test' => 'hybrid'], 'states: ' . json_encode($states));
check($result['summary'] === ['same' => 1, 'different' => 1, 'hybrid' => 1, 'unprobed' => 0, 'apache_silent' => 0, 'total' => 3], 'summary');
check($result['ports']['bind'] === '127.0.0.1' && count($result['ports']['listeners']) === 3, 'ports reported');
check(isset($result['seconds'], $result['created']) && $result['created'] === gmdate('c', 1_790_000_000), 'timing recorded');
check(Preview::load($w['env'], $w['id']) === json_decode(file_get_contents($w['state'] . '/previews/' . $w['id'] . '.json'), true), 'the result is stored and loads');
check((fileperms($w['state'] . '/previews/' . $w['id'] . '.json') & 0777) === 0600, 'stored 0600');
check(!file_exists($w['state'] . '/preview'), 'the private root is removed');
// Lab finding (every native site 404 or 403 under the preview, 200 under Apache): the workers run as nobody and must reach
// lscgid's socket below the private root (a 0700 root made every PHP start fail, "cgidSuEXEC failed"), and the document
// roots that FileProtect leaves user:user 0750 while Apache (mod_ruid2) serves (404); the cutover's enablefileprotect makes
// them user:nobody 0750, the preview gives nobody each account's group in its namespace only.
check($w['host']->modes === ['root' => 0711, 'gen' => 0711], 'the private root and generation are traversable by the workers: ' . json_encode($w['host']->modes));
check($result['cleanup'] === 'removed', 'a socket and a FIFO left in the private root are removed: ' . json_encode($result['cleanup']));
check(tree_state($w['live']) === $before, 'the live OpenLiteSpeed tree is untouched');
check(count($w['host']->seen) === 1 && !preg_match('/address\s++(?!127\.0\.0\.1:2\d{4}\b)/', $w['host']->seen[0]), 'the config the server started with binds only loopback');
check(substr_count($w['host']->seen[0], '127.0.0.1:2') === 3 && !str_contains($w['host']->seen[0], '*:80') && !str_contains($w['host']->seen[0], '::1'),
    'three loopback listeners, none public');
$names = array_unique(array_column($w['host']->calls, 0));
sort($names);
check($names === ['ols-stopped', 'preview-apache', 'preview-ols', 'preview-ports'], 'only these commands ran: ' . json_encode($names));
foreach ($w['host']->calls as [$name, $argv]) {
    foreach ($argv as $arg) {
        check(!preg_match('#whmapi|nft|firewall|csf|systemctl\s+(start|stop|restart|reload|enable|disable)|configureservice|enablefileprotect|/etc/#', (string) $arg)
            || $name === 'preview-ols' || $name === 'preview-apache', "no host-changing argument in $name");
    }
}
$ols = array_values(array_filter($w['host']->calls, static fn(array $c): bool => $c[0] === 'preview-ols'))[0][1];
check(array_slice($ols, 0, 8) === ['/usr/bin/unshare', '--mount', '--pid', '--fork', '--kill-child', '--mount-proc', '--propagation', 'private'], 'private namespaces');
check($ols[11] === 'sh' && str_ends_with($ols[12], '/preview/server') && str_ends_with($ols[14], '/preview/ols.probes'), 'script arguments');
check(preg_match('/^2\d{4}$/D', $ols[15]) === 1 && $ols[16] === $w['live'] . '/bin/openlitespeed', 'ready port and binary');
check(str_contains($ols[10], 'mount -t tmpfs -o mode=0755 tmpfs /run') && str_contains($ols[10], 'is not bound to 127.0.0.1 only')
    && str_contains($ols[10], 'LSWS_HOME=$root') && str_contains($ols[10], 'timeout 60 xargs -r -P 8'), 'the script isolates /run, checks the binding, bounds the requests');
check(str_contains($ols[10], '-H "Host: $2" --resolve "$2:$4:$a"'), 'Host header and SNI of the site');
check(array_slice($ols, -2) === ['u:nobody', 'g:a'], 'the web server user joins the probed accounts\' own groups (b: gid mismatch, c: hybrid): '
    . json_encode(array_slice($ols, -3)));
check(str_contains($ols[10], '/etc/group >/tmp/group') && str_contains($ols[10], 'mount --bind /tmp/group /etc/group')
    && str_contains($ols[10], 'mount -t tmpfs -o mode=1777 tmpfs /tmp &&'), 'the group file is a private copy on the namespace\'s /tmp, bound over /etc/group there');
check(str_contains($ols[10], "grep -a -e '\\[ERROR\\]' -e '\\[WARN\\]'") && is_array($result['log']), 'the error-log tail is kept in the result');
$apacheCall = array_values(array_filter($w['host']->calls, static fn(array $c): bool => $c[0] === 'preview-apache'))[0][1];
check($apacheCall[0] === '/bin/sh' && str_contains($apacheCall[2], 'timeout 60 xargs -r -P 8'), 'Apache answered in parallel');
// A second preview replaces the first one.
$w['host']->ols['https://b.test/'] = '200';
$again = $w['preview']->run($w['id']);
check($again['summary']['same'] === 2 && Preview::load($w['env'], $w['id'])['summary']['same'] === 2, 'a new preview replaces the stored one');
check(Preview::load($w['env'], 'p20261120120001-abcdef') === null && Preview::load($w['env'], '../x') === null, 'no preview for another or invalid plan');

// Failures and cleanup.
$w['host']->script = 'failed';
$failed = $w['preview']->run($w['id']);
check($failed['state'] === 'failed' && str_contains($failed['reason'], 'already in use') && $failed['log'] === ['[ERROR] bind failed'], 'a failed start is reported and stored');
check(!isset($failed['sites']) && Preview::load($w['env'], $w['id'])['state'] === 'failed', 'no sites on a failure');
check(!file_exists($w['state'] . '/preview'), 'private root removed after a failed start');
$w['host']->script = 'killed';
$killed = $w['preview']->run($w['id']);
check($killed['state'] === 'failed' && str_contains($killed['reason'], 'did not finish'), 'a killed script is a failed preview');
$w['host']->script = 'throw';
$stored = file_get_contents($w['state'] . '/previews/' . $w['id'] . '.json');
try {
    $w['preview']->run($w['id']);
    check(false, 'the runner failure propagates');
} catch (RuntimeException $error) {
    check($error->getMessage() === 'runner died', 'the runner failure propagates');
}
check(!file_exists($w['state'] . '/preview'), 'private root removed after an exception');
check(file_get_contents($w['state'] . '/previews/' . $w['id'] . '.json') === $stored, 'an exception stores nothing');
check(flock($h = fopen($w['state'] . '/deployment.lock', 'c'), LOCK_EX | LOCK_NB), 'the deployment lock is released after an exception');
fclose($h);
check(tree_state($w['live']) === $before, 'the live tree is untouched after every failure');
// A stale private root of an earlier killed run is cleared first.
$w['host']->script = 'ok';
mkdir($w['state'] . '/preview/server', 0700, true);
symlink($w['live'], $w['state'] . '/preview/server/live-link');
$w['preview']->run($w['id']);
check(!file_exists($w['state'] . '/preview') && is_dir($w['live'] . '/bin') && tree_state($w['live']) === $before, 'a stale root is removed without following links');

// A private root the cleanup cannot remove is reported (as root, permissions do not stop the removal: nothing to report).
$w['host']->stuck = true;
$stuck = $w['preview']->run($w['id']);
$asRoot = function_exists('posix_geteuid') && posix_geteuid() === 0;
check($asRoot ? $stuck['cleanup'] === 'removed' : str_starts_with($stuck['cleanup'], 'not removed: ') && str_contains($stuck['cleanup'], '/stuck/file'),
    'a cleanup failure is visible in the result: ' . json_encode($stuck['cleanup']));
check(Preview::load($w['env'], $w['id'])['cleanup'] === $stuck['cleanup'], 'and stored');
@chmod($w['state'] . '/preview/server/tmp/stuck', 0700);
$w['host']->stuck = false;
$w['preview']->run($w['id']);
check(!file_exists($w['state'] . '/preview'), 'the next preview clears what an earlier one left');
// Preview::clear on its own: links are removed, never followed; special files go too.
$c = $w['dir'] . '/clear';
mkdir("$c/a/b", 0755, true);
symlink($w['live'], "$c/a/live");
posix_mkfifo("$c/a/b/fifo", 0600);
check(Preview::clear($c) === null && !file_exists($c) && tree_state($w['live']) === $before, 'clear removes links and FIFOs without following links');

// The account groups (unit): only an account's own primary group, never root's or a system group.
$passwd = "root:x:0:0::/root:/bin/bash\nwheel1:x:10:10::/:/sbin/nologin\nsys:x:400:400::/:/sbin/nologin\nalice:x:1000:1000::/home/alice:/bin/bash\n"
    . "bob:x:1001:1001::/home/bob:/bin/bash\ncarol:x:1002:100::/home/carol:/bin/bash\nold:x:500:500::/home/old:/bin/bash\n";
$group = "root:x:0:\nwheel1:x:10:\nsys:x:400:\nalice:x:1000:\nbob:x:1001:x,y\nusers:x:100:\nold:x:500:\n";
check(PreviewConfig::accountGroups(['bob', 'alice', 'alice', 'root', 'wheel1', 'sys', 'carol', 'old', 'ghost', '', 'Bad;name', 'nobody'], $passwd, $group)
    === ['alice', 'bob', 'old'], 'account groups: ' . json_encode(PreviewConfig::accountGroups(['bob', 'alice', 'root', 'sys', 'carol', 'old'], $passwd, $group)));
check(PreviewConfig::accountGroups(['alice'], '', '') === [], 'no account database, no group');
check(PreviewConfig::webUser("serverName x\nuser nobody\ngroup nobody\n") === 'nobody' && PreviewConfig::webUser("serverName x\n") === null
    && PreviewConfig::webUser("user ;rm\n") === null, 'the web server user comes from the configuration');

// Refusals, each before anything starts.
$calls = static fn(array $w): int => count(array_filter($w['host']->calls, static fn(array $c): bool => in_array($c[0], ['preview-ols', 'preview-apache', 'preview-ports'], true)));
$w2 = preview_world();
file_put_contents($w2['state'] . '/profile.json', json_encode(['production' => true, 'hybrid_ports' => [81, 444]]));
refuses(fn() => $w2['preview']->run($w2['id']), 'already cut over', 'after the switch');
check($calls($w2) === 0, 'nothing started after the switch');
$w3 = preview_world();
$w3['host']->olsActive = true;
refuses(fn() => $w3['preview']->run($w3['id']), 'is running', 'OLS running');
check($calls($w3) === 0, 'nothing started with OLS running');
$w4 = preview_world();
$w4['compilation']->tweak = "# changed\n";
refuses(fn() => $w4['preview']->run($w4['id']), 'changed since plan', 'stale plan');
check($calls($w4) === 0 && !file_exists($w4['state'] . '/previews'), 'a stale plan starts and stores nothing');
$w5 = preview_world();
refuses(fn() => $w5['preview']->run('p20261120120009-000000'), 'no plan', 'missing plan');
refuses(fn() => $w5['preview']->run('x; rm'), 'invalid plan id', 'invalid plan id');
$w6 = new Preview($w5['env'], $w5['live'], $w5['live'] . '/bin/missing');
refuses(fn() => $w6->run($w5['id']), 'binary is not installed', 'no binary');
$rootless = new Environment($w5['host'], $w5['state'], $w5['compilation'], null, false);
refuses(fn() => (new Preview($rootless))->run($w5['id']), 'must run as root', 'not root');
// A plan that no longer exists loses its preview.
$w7 = preview_world();
$w7['preview']->run($w7['id']);
is_dir($w7['state'] . '/previews') || mkdir($w7['state'] . '/previews', 0700, true);
file_put_contents($w7['state'] . '/previews/p20200101000000-aaaaaa.json', '{}');
$w7['preview']->run($w7['id']);
check(!file_exists($w7['state'] . '/previews/p20200101000000-aaaaaa.json') && file_exists($w7['state'] . '/previews/' . $w7['id'] . '.json'), 'previews of vanished plans are removed');
// A port the table shows busy is never chosen; a busy table without room refuses.
$w8 = preview_world();
$w8['host']->listening = implode("\n", array_map(static fn(int $p): string => "LISTEN 0 5 127.0.0.1:$p 0.0.0.0:*", range(PreviewPorts::FIRST, PreviewPorts::LAST))) . "\n";
refuses(fn() => $w8['preview']->run($w8['id']), 'free ports', 'no free port');
check($calls($w8) === 0 || count(array_filter($w8['host']->calls, static fn(array $c): bool => $c[0] === 'preview-ols')) === 0, 'no server start without ports');
check(!file_exists($w8['state'] . '/preview'), 'private root removed after a port refusal');

echo "preview: $count checks passed\n";
