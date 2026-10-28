<?php
declare(strict_types=1);

// Engine runtime unit tests (fakes and temporary directories only; nothing on the host is touched):
// LocalCommandRunner, LocalEngine, BrokerEngine (against a canned socket server), Reconciler decisions,
// the paced enforcement of the service loop, HookEntry and CLI dispatch with exit codes.
require dirname(__DIR__) . '/src/bootstrap.php';

use OlsCpanel\Broker\BrokerClient;
use OlsCpanel\Broker\BrokerEngine;
use OlsCpanel\Cli\Application;
use OlsCpanel\Cli\Command;
use OlsCpanel\Cli\EngineContext;
use OlsCpanel\Cli\Output;
use OlsCpanel\Deployment\BuilderCompilation;
use OlsCpanel\Deployment\CutoverPlan;
use OlsCpanel\Deployment\Profile;
use OlsCpanel\Deployment\SecurityInput;
use OlsCpanel\Events\HookEntry;
use OlsCpanel\Events\PacedEngine;
use OlsCpanel\Events\ReconcileBusy;
use OlsCpanel\Events\Reconciler;
use OlsCpanel\Events\ReconcileRefused;
use OlsCpanel\Events\SourceDigest;
use OlsCpanel\Infrastructure\Process\CommandFailed;
use OlsCpanel\Infrastructure\Process\CommandRunner;
use OlsCpanel\Infrastructure\Process\LocalCommandRunner;
use OlsCpanel\Ols\Compiler\CompilationRefused;
use OlsCpanel\Ols\Compiler\ServerConfigurationBuilder;
use OlsCpanel\Ols\Generation\Engine;
use OlsCpanel\Ols\Generation\EngineError;
use OlsCpanel\Ols\Generation\GenerationTree;
use OlsCpanel\Ols\Generation\LocalEngine;

const PHP = PHP_BINARY;
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

/** @param callable():mixed $call */
function throws(callable $call, string $class, string $text = ''): bool
{
    try {
        $call();
    } catch (Throwable $error) {
        if (!$error instanceof $class || !str_contains($error->getMessage(), $text)) {
            echo 'unexpected ' . get_class($error) . ': ' . $error->getMessage() . "\n";
            return false;
        }
        return true;
    }
    return false;
}

function temp_dir(): string
{
    $dir = sys_get_temp_dir() . '/ols-engine-test-' . bin2hex(random_bytes(6));
    mkdir($dir, 0700);
    register_shutdown_function(static fn() => exec('/usr/bin/rm -rf -- ' . escapeshellarg($dir)));
    return $dir;
}

$fixture = json_decode(file_get_contents(__DIR__ . '/Fixtures/lab-snapshot/compile-production.json'), true, 64, JSON_THROW_ON_ERROR);
$template = file_get_contents(dirname(__DIR__) . '/build/vm-qualification/ols-lab/ownership_httpd_config.conf');
const TENANTS = ['olscpa' => 'olstest1.example.test', 'olscpb' => 'olstest2.example.test'];

/** The privileged half, faked: recorded cPanel inputs, a scripted activator and a spool in memory. */
class FakeEngine implements Engine
{
    /** @var list<string> */
    public array $log = [];
    /** @var array<string,mixed> */
    public array $state = ['pointer' => 'r20260101000000-aaaaaa', 'served' => 'r20260101000000-aaaaaa',
        'committed' => 'r20260101000000-aaaaaa', 'epoch' => 2, 'active_epoch' => 2, 'coherent' => true, 'source_sha256' => null];
    public array $failing = [];
    public ?array $afterRecover = null;
    public array $validation = ['valid' => true];
    public string $activation = 'committed';
    /** @var list<array{name:string, event:array<string,mixed>}> */
    public array $events = [];
    public array $applied = [];
    /** @var list<string> quarantined spool entries */
    public array $quarantined = [];
    public bool $quarantineFails = false;
    /** @var list<string> restriction intents not yet folded */
    public array $intents = [];
    /** @var array<string,array{exit_code:int, stdout:string}> */
    private array $calls = [];
    public array $digests = [];

    public function __construct(array $calls)
    {
        foreach ($calls as $call) {
            $this->calls[json_encode($call['argv'], JSON_UNESCAPED_SLASHES)] ??= ['exit_code' => $call['exit_code'], 'stdout' => $call['stdout']];
        }
    }

    public function run(string $name, array $argv, int $timeout): array
    {
        if ($name === 'referenced-digest') {
            $this->log[] = 'digest';
            $path = $argv[count($argv) - 1];
            return ['exit_code' => 0, 'stdout' => ($this->digests[$path] ?? hash('sha256', $path)) . "  $path\n"];
        }
        $this->log[] = 'run';
        return $this->calls[json_encode($argv, JSON_UNESCAPED_SLASHES)] ?? throw new LogicException("unrecorded $name");
    }

    public function apply(string $generation, array $files, array $health, int $epoch, string $sourceSha256): array
    {
        $this->log[] = 'apply';
        LocalEngine::checkTree($generation, $files, $health, $epoch, $sourceSha256);
        $this->applied[] = compact('generation', 'epoch', 'sourceSha256') + ['targets' => count($health)];
        return LocalEngine::outcome($generation, $this->validation, fn(): array => ['result' => $this->activation]
            + ($this->activation === 'committed' ? [] : ['reason' => 'scripted']));
    }

    public function status(): array
    {
        $this->log[] = 'status';
        return $this->state;
    }

    public function health(int $seconds): array
    {
        $this->log[] = "health $seconds";
        return ['generation' => $this->state['pointer'], 'failing' => $this->failing];
    }

    public function enforce(int $grace): array
    {
        $this->log[] = "enforce $grace";
        return ['result' => 'within-grace'];
    }

    public function recover(int $grace): array
    {
        $this->log[] = "recover $grace";
        if ($this->afterRecover !== null) {
            $this->state = $this->afterRecover;
        }
        return ['actions' => [['action' => 'enforce', 'result' => 'within-grace']]] + $this->state;
    }

    public function pendingEvents(): array
    {
        $this->log[] = 'events';
        return $this->events;
    }

    public function eventsDone(array $names): array
    {
        $this->log[] = 'done ' . implode(',', $names);
        if (array_diff($names, array_column($this->events, 'name')) !== []) {
            throw new EngineError('NOT_FOUND', 'no spool entry');
        }
        $this->events = array_values(array_filter($this->events, static fn(array $e): bool => !in_array($e['name'], $names, true)));
        return $names;
    }

    public function eventsQuarantine(array $names): array
    {
        $this->log[] = 'quarantine ' . implode(',', $names);
        if ($this->quarantineFails) {
            throw new EngineError('UNKNOWN_OPERATION', 'operation not available on this socket');
        }
        $this->quarantined = [...$this->quarantined, ...$names];
        $this->events = array_values(array_filter($this->events, static fn(array $e): bool => !in_array($e['name'], $names, true)));
        return $names;
    }

    public function foldRestrictions(): array
    {
        $this->log[] = 'fold';
        $folded = $this->intents;
        if ($folded === []) {
            return ['folded' => [], 'epoch' => null];
        }
        $this->state['epoch'] += count($folded);
        $this->intents = [];
        return ['folded' => $folded, 'epoch' => $this->state['epoch']];
    }
}

$builders = static fn(Profile $profile, Engine $engine): array => (new ServerConfigurationBuilder($engine, TENANTS,
    $template, '/var/lib/ols-cpanel-lab/logs', null, null, null, null, null, null, $profile->hybridPorts))->compile();
$production = new Profile(true, null);
$reconciler = static fn(FakeEngine $engine, ?Profile $profile = null, string $profilePath = '/nonexistent/profile.json',
    ?string $lock = null): Reconciler => new Reconciler($engine, $builders, null, $profile, $profilePath, $lock, null, null,
    static fn(): string => 'r20261022120000-0a1b2c');
$events = [['name' => '1761134400000000000-' . str_repeat('a', 32) . '.json', 'event' => ['event' => 'Accounts::suspendacct']]];

// --- Reconciler decisions -----------------------------------------------------------------------------
$engine = new FakeEngine($fixture['calls']);
$engine->events = $events;
$first = $reconciler($engine, $production)->reconcile();
check($first['action'] === 'committed' && $first['generation'] === 'r20261022120000-0a1b2c' && $engine->events === []
    && $first['epoch'] === 2 && $first['events'] === 1, 'changed configuration: new generation committed, events done');
check(array_search('status', $engine->log, true) < array_search('run', $engine->log, true),
    'restriction epoch read before compiling');
check($engine->applied[0]['targets'] === 10 && $engine->applied[0]['epoch'] === 2, 'apply carries every health target and the epoch');
$source = $engine->applied[0]['sourceSha256'];
$engine->state['source_sha256'] = $source;
$engine->log = [];
$engine->events = $events;
$unchanged = $reconciler($engine, $production)->reconcile();
check($unchanged['action'] === 'unchanged' && !in_array('apply', $engine->log, true) && $engine->events === []
    && in_array('health 5', $engine->log, true), 'unchanged and healthy: no activation, events done');
$engine->log = [];
$forced = $reconciler($engine, $production)->activate();
check($forced['action'] === 'committed' && in_array('apply', $engine->log, true), 'activate() (cutover) forces a new generation');
$engine->failing = [['vhost' => 'olstest2.example.test', 'got' => 'error: HTTP 404']];
$engine->log = [];
check($reconciler($engine, $production)->reconcile()['action'] === 'committed' && in_array('apply', $engine->log, true),
    'unchanged but an unhealthy vhost: new generation');
$engine->failing = [];
$engine->digests['/var/cpanel/ssl/apache_tls/olstest2.example.test/combined'] = str_repeat('0', 64);
$engine->log = [];
check($reconciler($engine, $production)->reconcile()['action'] === 'committed', 'a renewed certificate (same text) changes the source digest');
unset($engine->digests['/var/cpanel/ssl/apache_tls/olstest2.example.test/combined']);
$engine->state['epoch'] = 3;
check($reconciler($engine, $production)->reconcile()['action'] === 'committed', 'a raised restriction epoch changes the source digest');
$engine->state['epoch'] = 2;
// Incoherent runtime: recover with HR-D11's grace first, then decide on the recovered state.
$engine->state['coherent'] = false;
$engine->afterRecover = ['coherent' => true, 'source_sha256' => $source, 'epoch' => 2] + $engine->state;
$engine->log = [];
$recovered = $reconciler($engine, $production)->reconcile();
check(in_array('recover 300', $engine->log, true) && $recovered['action'] === 'unchanged' && isset($recovered['recovered']),
    'incoherent: recover with grace 300, then unchanged');
$engine->state['coherent'] = false;
$engine->afterRecover = null;
$engine->log = [];
check($reconciler($engine, $production)->reconcile()['action'] === 'committed' && !in_array('health 5', $engine->log, true),
    'still incoherent after recovery: new generation without a health check');
$engine->state['coherent'] = true;
// Invalid or failed activations keep the events pending.
foreach ([['valid' => false, 'report' => 'line 3: Not support [x]'], ['valid' => true]] as $i => $validation) {
    $engine->validation = $validation;
    $engine->activation = $i === 0 ? 'committed' : 'rolled_back';
    $engine->events = $events;
    $engine->state['source_sha256'] = null;
    $failed = $reconciler($engine, $production)->reconcile();
    check($failed['action'] === ($i === 0 ? 'invalid' : 'rolled_back') && $engine->events === $events && $failed['reason'] !== null,
        ($i === 0 ? 'invalid' : 'rolled back') . ' generation: events stay pending, reason reported');
}
$engine->validation = ['valid' => true];
$engine->activation = 'committed';
// Profiles: absent = not cut over, malformed refuses, non-production refuses; nothing is compiled.
$dir = temp_dir();
$engine->log = [];
check(throws(fn() => $reconciler($engine, null, "$dir/profile.json")->reconcile(), ReconcileRefused::class, 'not cut over')
    && !in_array('run', $engine->log, true) && !in_array('apply', $engine->log, true), 'no profile: refused, nothing compiled');
file_put_contents("$dir/profile.json", '{"production": true, "hybrid_ports": [80, 444]}');
check(throws(fn() => $reconciler($engine, null, "$dir/profile.json")->reconcile(), ReconcileRefused::class, 'malformed'),
    'malformed profile: refused');
file_put_contents("$dir/profile.json", '{"production": false, "hybrid_ports": null}');
check(throws(fn() => $reconciler($engine, null, "$dir/profile.json")->reconcile(), ReconcileRefused::class, 'production'),
    'non-production profile: refused');
(new Profile(true, null))->save("$dir/profile.json");
$engine->state['source_sha256'] = null;
check($reconciler($engine, null, "$dir/profile.json")->reconcile()['action'] === 'committed', 'profile.json read on every pass');
$engine->state['epoch'] = null;
check(throws(fn() => $reconciler($engine, $production)->reconcile(), ReconcileRefused::class, 'epoch'), 'unknown epoch: refused');
$engine->state['epoch'] = 2;
// Compilation refusals propagate (fail closed); hybrid profile carries the hybrid vhosts.
$broken = new FakeEngine(array_map(static fn(array $c): array => $c['argv'] === ['/usr/bin/cat', '/etc/apache2/conf/httpd.conf']
    ? ['exit_code' => 1, 'stdout' => ''] + $c : $c, $fixture['calls']));
check(throws(fn() => $reconciler($broken, $production)->reconcile(), CompilationRefused::class, 'httpd.conf')
    && !in_array('apply', $broken->log, true), 'compilation refused: nothing applied');
// HR-D14: with the hybrid profile one account's unreadable .htaccess moves only that vhost to Apache (the pass commits,
// the result says which vhost and why); without it the compile refuses; the cause gone, the vhost returns on the next pass.
$unreadable = ['/usr/sbin/runuser', '-u', 'olscpb', '--', '/usr/bin/cat', '/home/olscpb/public_html/sub-noindex/.htaccess'];
$hybridProfile = new Profile(true, [81, 444]);
$damaged = array_map(static fn(array $c): array => $c['argv'] === $unreadable ? ['exit_code' => 1, 'stdout' => ''] + $c : $c, $fixture['calls']);
check(array_filter($damaged, static fn(array $c): bool => $c['argv'] === $unreadable && $c['exit_code'] === 1) !== [], 'the damaged fixture has the failing read');
$onlyB = new FakeEngine($damaged);
check(throws(fn() => $reconciler($onlyB, $production)->reconcile(), CompilationRefused::class, 'unreadable') && !in_array('apply', $onlyB->log, true),
    'native profile: an unreadable .htaccess refuses the compile');
$moved = $reconciler($onlyB, $hybridProfile)->reconcile();
check($moved['action'] === 'committed' && $moved['hybrid_vhosts'] === ['olstest2.example.test']
    && str_contains(json_encode($moved['hybrid_reasons']), 'unreadable'), 'hybrid profile: only that vhost moves to Apache, with the reason');
$healed = new FakeEngine($fixture['calls']);
$returned = $reconciler($healed, $hybridProfile)->reconcile();
check($returned['action'] === 'committed' && $returned['hybrid_vhosts'] === [] && !isset($returned['hybrid_reasons']),
    'hybrid profile: the cause gone, the vhost is native again on the next pass');
check($onlyB->applied[0]['sourceSha256'] !== $healed->applied[0]['sourceSha256'], 'the move and the return are different generations');
// Busy: a second pass while the lock is held.
$lockFile = "$dir/reconcile.lock";
$held = fopen($lockFile, 'c');
flock($held, LOCK_EX);
$code = 0;
exec(escapeshellarg(PHP) . ' -n -r ' . escapeshellarg('require "' . dirname(__DIR__) . '/src/bootstrap.php"; $h = fopen("'
    . $lockFile . '", "c"); exit(flock($h, LOCK_EX | LOCK_NB) ? 0 : 3);'), $ignored, $code);
check($code === 3, 'reconcile lock is exclusive across processes');
flock($held, LOCK_UN);
$other = fopen($lockFile, 'c');
flock($other, LOCK_EX);
check(throws(fn() => $reconciler($engine, $production, '/nonexistent', $lockFile)->reconcile(), ReconcileBusy::class),
    'lock held: ReconcileBusy');
flock($other, LOCK_UN);
// Referenced files: certificates as root and password files as the tenant through sha256sum; anything else null, no command.
$probe = new class implements CommandRunner {
    public array $argv = [];
    public function run(string $name, array $argv, int $timeout): array
    {
        $this->argv[] = $argv;
        return str_ends_with($argv[count($argv) - 1], 'missing') ? ['exit_code' => 1, 'stdout' => '']
            : ['exit_code' => 0, 'stdout' => '\\' . str_repeat('ab', 32) . "  x\n"];
    }
};
check(SourceDigest::digest('/var/cpanel/ssl/apache_tls/a.example/combined', $probe) === str_repeat('ab', 32)
    && SourceDigest::digest('/home2/olscpa/.htpasswds/public_html/x/passwd', $probe) === str_repeat('ab', 32)
    && SourceDigest::digest('/home/olscpa/private/users.key', $probe) === null
    && SourceDigest::digest('/home/root/.htpasswds/x', $probe) === null
    && SourceDigest::digest('/var/cpanel/ssl/missing', $probe) === null
    && SourceDigest::digest('/etc/pki/tls/private/x.key', $probe) === null
    && SourceDigest::digest('/var/cpanel/ssl/../../etc/shadow', $probe) === null
    && $probe->argv === [['/usr/bin/sha256sum', '/var/cpanel/ssl/apache_tls/a.example/combined'],
        ['/usr/sbin/runuser', '-u', 'olscpa', '--', '/usr/bin/sha256sum', '/home2/olscpa/.htpasswds/public_html/x/passwd'],
        ['/usr/bin/sha256sum', '/var/cpanel/ssl/missing']], 'referenced file digests through the allowlisted digest commands only');

// Malformed spool entries are reported and quarantined at once, whatever the outcome (review RV-29, finding 16);
// valid entries are consumed independently of them; a concurrent consumer is tolerated.
$engine = new FakeEngine($fixture['calls']);
$bad = ['name' => '1761134400000000005-' . str_repeat('e', 32) . '.json', 'error' => 'malformed spool entry'];
$odd = ['name' => 'stray.json', 'error' => 'not a spool file name'];
$engine->events = [...$events, $bad, $odd];
$withBad = $reconciler($engine, $production)->reconcile();
check($withBad['action'] === 'committed' && $withBad['malformed_events'] === [$bad, $odd] && $engine->events === []
    && $engine->quarantined === [$bad['name'], 'stray.json'] && $withBad['events'] === 1
    && in_array('done ' . $events[0]['name'], $engine->log, true),
    'malformed spool entries: reported and quarantined; only the valid entry is marked done');
$engine = new FakeEngine($fixture['calls']);
$engine->events = [...$events, $bad];
$engine->validation = ['valid' => false, 'report' => 'bad'];
$failedWithBad = $reconciler($engine, $production)->reconcile();
check($failedWithBad['action'] === 'invalid' && $engine->quarantined === [$bad['name']] && $engine->events === $events,
    'a failed pass still quarantines malformed entries; the valid events stay pending');
$engine = new FakeEngine($fixture['calls']);
$engine->events = [...$events, $bad];
$engine->quarantineFails = true;
$noQuarantine = $reconciler($engine, $production)->reconcile();
check($noQuarantine['action'] === 'committed' && str_contains($noQuarantine['quarantine_error'], 'not available')
    && $engine->events === [$bad] && !str_contains(implode(' ', $engine->log), 'done ' . $bad['name']),
    'quarantine unavailable: reported, the valid events are still consumed, the malformed one is never marked done');
// Restriction intents are folded into the epoch before the epoch is read and before anything is compiled (finding 5).
$engine = new FakeEngine($fixture['calls']);
$engine->intents = ['1761134400000000007-' . str_repeat('7', 32) . '.json'];
$foldedPass = $reconciler($engine, $production)->reconcile();
check($foldedPass['restrictions_folded'] === ['1761134400000000007-' . str_repeat('7', 32) . '.json'] && $foldedPass['epoch'] === 3
    && $engine->applied[0]['epoch'] === 3 && $engine->log[0] === 'fold' && array_search('status', $engine->log, true) > 0,
    'restriction intents folded first: the pass compiles against the raised epoch');
$racing = new class($fixture['calls']) extends FakeEngine {
    public bool $raced = false;
    public function eventsDone(array $names): array
    {
        if (!$this->raced) {
            $this->raced = true;
            array_shift($this->events);  // another pass consumed the oldest entry meanwhile
        }
        return parent::eventsDone($names);
    }
};
$racing->events = [...$events, ['name' => '1761134400000000006-' . str_repeat('f', 32) . '.json', 'event' => []]];
check($reconciler($racing, $production)->reconcile()['action'] === 'committed' && $racing->events === [],
    'events consumed by a concurrent pass (NOT_FOUND): the rest are still moved');

// --- Service loop: enforcement every 5 s, interleaved with the pass -----------------------------------
$now = 0.0;
$clock = static function () use (&$now): float {
    return $now;
};
$engine = new FakeEngine($fixture['calls']);
$engine->state['source_sha256'] = $source;
$lines = [];
$emit = static function (array $line) use (&$lines): void {
    $lines[] = $line;
};
$paced = new PacedEngine($engine, $emit, $clock);
// Each compile command takes 2 s of the fake clock: enforcement must still run every 5 s during the pass.
$timed = new class($paced, $now) implements Engine {
    public function __construct(private PacedEngine $inner, private float &$now)
    {
    }
    public function run(string $name, array $argv, int $timeout): array
    {
        $this->now += 2.0;
        return $this->inner->run($name, $argv, $timeout);
    }
    public function apply(string $g, array $f, array $h, int $e, string $s): array
    {
        return $this->inner->apply($g, $f, $h, $e, $s);
    }
    public function status(): array
    {
        return $this->inner->status();
    }
    public function health(int $seconds): array
    {
        return $this->inner->health($seconds);
    }
    public function enforce(int $grace): array
    {
        return $this->inner->enforce($grace);
    }
    public function recover(int $grace): array
    {
        return $this->inner->recover($grace);
    }
    public function pendingEvents(): array
    {
        return $this->inner->pendingEvents();
    }
    public function eventsDone(array $names): array
    {
        return $this->inner->eventsDone($names);
    }
    public function eventsQuarantine(array $names): array
    {
        return $this->inner->eventsQuarantine($names);
    }
    public function foldRestrictions(): array
    {
        return $this->inner->foldRestrictions();
    }
};
$pass = new Reconciler($timed, $builders, null, $production, '/nonexistent', null, $clock);
$engine->log = [];
$pass->reconcile();
$runs = count(array_filter($engine->log, static fn(string $l): bool => $l === 'run'));
$enforcements = count(array_filter($engine->log, static fn(string $l): bool => $l === 'enforce 300'));
check($runs > 50 && $enforcements >= intdiv($runs * 2, 5) - 1, "enforcement during a pass: $enforcements enforcements over {$runs} commands of 2 s");
$gap = 0;
$since = 0;
foreach ($engine->log as $entry) {
    $since = $entry === 'enforce 300' ? 0 : $since + ($entry === 'run' ? 2 : 0);
    $gap = max($gap, $since);
}
check($gap <= 6, "longest gap without enforcement is one operation past 5 s ({$gap} s)");
$now = 0.0;
$engine->log = [];
$sleeper = static function (int $seconds) use (&$now): void {
    $now += $seconds;
};
$paced = new PacedEngine($engine, $emit, $clock);  // a fresh clock origin
$loop = new Reconciler($paced, $builders, null, $production, '/nonexistent', null, $clock, $sleeper);
$loop->watch(60, $emit, 130);
$passes = count(array_filter($lines, static fn(array $l): bool => isset($l['action'])));
$enforced = count(array_filter($engine->log, static fn(string $l): bool => $l === 'enforce 300'));
check($passes === 3 && $enforced >= 26, "watch: a pass every 60 s ($passes in 130 s) and enforcement every 5 s ($enforced)");
$engine->events = $events;
$lines = [];
$loop->watch(60, $emit, 2);
check(isset($lines[0]['action']) && $engine->events === [], 'watch: pending events trigger a pass at once');
check(throws(fn() => (new Reconciler($engine, $builders))->watch(60, $emit, 1), LogicException::class), 'watch needs the paced engine');
$engine->events = $events;
$engine->validation = ['valid' => false, 'report' => 'bad'];
$engine->state['source_sha256'] = null;
$lines = [];
$now = 0.0;
(new Reconciler(new PacedEngine($engine, $emit, $clock), $builders, null, $production, '/nonexistent', null, $clock, $sleeper))
    ->watch(3600, $emit, 40);
$failedPasses = count(array_filter($lines, static fn(array $l): bool => ($l['action'] ?? null) === 'invalid'));
check($failedPasses === 3 && $engine->events === $events,
    "watch: after a failed pass pending events retry every " . Reconciler::RETRY_SECONDS . " s, not every second ($failedPasses passes in 40 s)");
$engine->validation = ['valid' => true];
$errors = [];
$broken = new FakeEngine([]);
(new Reconciler(new PacedEngine($broken, $emit, $clock), $builders, null, $production, '/nonexistent', null, $clock, $sleeper))
    ->watch(60, static function (array $l) use (&$errors): void {
        $errors[] = $l;
    }, 1);
check(isset($errors[0]['error']) && str_contains($errors[0]['error'], 'unrecorded'), 'watch: a failing pass is logged, the loop continues');

// --- LocalCommandRunner ------------------------------------------------------------------------------
$runner = new LocalCommandRunner();
$env = $runner->run('env', ['/usr/bin/env'], 10);
check($env['stdout'] === "PATH=/usr/bin:/bin:/usr/sbin\nLANG=C\nLC_ALL=C\n" && $env['exit_code'] === 0, 'fixed environment only');
$echo = $runner->run('echo', ['/usr/bin/echo', '$(id)', ';', '|', '*'], 10);
check($echo['stdout'] === "\$(id) ; | *\n", 'arguments are never interpreted by a shell');
$big = $runner->run('big', ['/usr/bin/python3', '-c', 'import sys; sys.stdout.write("o" * 3000000); sys.stderr.write("e" * 3000000); sys.exit(4)'], 30);
check($big['exit_code'] === 4 && strlen($big['stdout']) === 3000000 && strlen($big['stderr']) === 3000000,
    'large stdout and stderr together without deadlock; exit status kept');
$strict = new LocalCommandRunner(LocalCommandRunner::MAX_OUTPUT, true);
$started = microtime(true);
$timedOut = $runner->run('sleep', ['/usr/bin/sleep', '30'], 1);
check($timedOut['exit_code'] === 124 && str_contains($timedOut['stderr'], 'killed after 1s') && microtime(true) - $started < 5,
    'deployment mode: timeout kills the command, exit 124');
check(throws(fn() => $strict->run('sleep', ['/usr/bin/sleep', '30'], 1), CommandFailed::class, 'timed out'),
    'strict mode (engine): timeout is CommandFailed TIMEOUT');
$failure = null;
try {
    (new LocalCommandRunner(1000))->run('big', ['/usr/bin/head', '-c', '5000', '/dev/zero'], 10);
} catch (CommandFailed $failure) {
}
check($failure?->errorCode === CommandFailed::OUTPUT_TOO_LARGE, 'output above the limit is refused (OUTPUT_TOO_LARGE), not truncated');
check(throws(fn() => $runner->run('rel', ['echo', 'x'], 1), InvalidArgumentException::class)
    && $runner->run('missing', ['/nonexistent/binary'], 1)['exit_code'] === 127
    && throws(fn() => $strict->run('missing', ['/nonexistent/binary'], 1), CommandFailed::class, 'cannot start'),
    'relative executables refused; a missing one is exit 127, or SPAWN_FAILED in strict mode');
$bytes = $runner->run('bytes', ['/usr/bin/printf', '%b', 'ok \\xe2\\x82\\xac \\xff\\xfe \\xe2\\x82 \\xf0\\x9f\\x98\\x80 \\xed\\xa0\\x80 \\xc0\\xaf end'], 10);
check($bytes['stdout'] === "ok \u{20AC} \u{FFFD}\u{FFFD} \u{FFFD} \u{1F600} \u{FFFD}\u{FFFD}\u{FFFD} \u{FFFD}\u{FFFD} end",
    'invalid UTF-8 output: each invalid sequence becomes U+FFFD (as the broker decodes it), valid text unchanged');
$python = $runner->run('python', ['/usr/bin/python3', '-c', 'import sys; sys.stdout.write(bytes(range(256)).decode("utf-8", "replace"))'], 10);
check(LocalCommandRunner::text(implode('', array_map('chr', range(0, 255)))) === $python['stdout'], 'decoding equals Python errors="replace"');
check($runner->run('signal', ['/usr/bin/python3', '-c', 'import os, signal; os.kill(os.getpid(), signal.SIGTERM)'], 10)['exit_code'] === -15,
    'a signal ends as -signal (like Python)');
// Finding 13: each command leads its own session and process group; timeout and overflow kill the whole group.
$ids = $runner->run('ids', ['/usr/bin/python3', '-c', 'import os; print(os.getpid(), os.getpgid(0), os.getsid(0))'], 10);
[$pid, $pgid, $sid] = array_map('intval', explode(' ', trim($ids['stdout'])));
check($pid > 1 && $pid === $pgid && $pid === $sid && $pgid !== (int) getmypid(), 'the command leads its own session and process group');
$alive = static function (string $pidFile): bool {
    $pid = (int) trim((string) @file_get_contents($pidFile));
    for ($i = 0; $i < 100; ++$i) {  // the killed descendant is reaped by init shortly after
        $stat = @file_get_contents("/proc/$pid/stat");
        if ($stat === false || preg_match('/^\d+ \(.*\) Z /', $stat) === 1) {
            return false;
        }
        usleep(20000);
    }
    return $pid > 0;
};
$groupDir = temp_dir();
$descendant = "sleep 60 & echo \$! > $groupDir/%s; wait";
$started = microtime(true);
$killed = $runner->run('tree', ['/usr/bin/sh', '-c', sprintf($descendant, 'timeout.pid')], 1);
check($killed['exit_code'] === 124 && microtime(true) - $started < 5 && !$alive("$groupDir/timeout.pid"),
    'timeout: the descendant (a background child of the shell) is killed with the command');
check(throws(fn() => $strict->run('tree', ['/usr/bin/sh', '-c', sprintf($descendant, 'strict.pid')], 1), CommandFailed::class, 'timed out')
    && !$alive("$groupDir/strict.pid"), 'strict timeout: the whole group is killed too');
$overflow = null;
try {
    (new LocalCommandRunner(1000))->run('tree', ['/usr/bin/sh', '-c', "sleep 60 & echo \$! > $groupDir/overflow.pid; head -c 5000 /dev/zero; wait"], 30);
} catch (CommandFailed $overflow) {
}
check($overflow?->errorCode === CommandFailed::OUTPUT_TOO_LARGE && !$alive("$groupDir/overflow.pid"),
    'output overflow: the whole group is killed');
$started = microtime(true);
$detached = $runner->run('detached', ['/usr/bin/sh', '-c', "sleep 60 & echo \$! > $groupDir/held.pid; exit 0"], 1);
check($detached['exit_code'] === 124 && !$alive("$groupDir/held.pid") && microtime(true) - $started < 5,
    'a descendant holding the output pipes after the command ended is killed at the time limit');
// Finding 17: a program's own exit 127 is a result; only a failed start is SPAWN_FAILED.
$own = $strict->run('own127', ['/usr/bin/sh', '-c', 'echo out; echo err >&2; exit 127'], 10);
check($own === ['exit_code' => 127, 'stdout' => "out\n", 'stderr' => "err\n"], "strict mode: the program's own exit 127 is its result");
file_put_contents("$groupDir/broken-interpreter", "#!/nonexistent/interpreter\n");
chmod("$groupDir/broken-interpreter", 0755);
file_put_contents("$groupDir/not-executable", "#!/usr/bin/sh\n");
chmod("$groupDir/not-executable", 0644);
check(throws(fn() => $strict->run('x', ["$groupDir/broken-interpreter"], 5), CommandFailed::class, 'cannot start')
    && throws(fn() => $strict->run('x', ["$groupDir/not-executable"], 5), CommandFailed::class, 'cannot start')
    && throws(fn() => $strict->run('x', [$groupDir], 5), CommandFailed::class, 'cannot start')
    && $runner->run('x', ["$groupDir/broken-interpreter"], 5)['exit_code'] === 127
    && throws(fn() => (new LocalCommandRunner(LocalCommandRunner::MAX_OUTPUT, true, '/nonexistent/setsid'))->run('x', ['/usr/bin/true'], 5),
        CommandFailed::class, 'cannot start'),
    'strict mode: an exec failure (missing interpreter, not executable, a directory, no setsid) is SPAWN_FAILED; exit 127 otherwise');

// --- LocalEngine -------------------------------------------------------------------------------------
$activator = new class implements CommandRunner {
    public array $calls = [];
    public array $staged = [];
    public bool $valid = true;
    public function run(string $name, array $argv, int $timeout): array
    {
        $this->calls[] = array_slice($argv, 1);
        $out = match ($argv[1]) {
            'stage' => ['generation' => $argv[2], 'files' => count($this->staged = self::files($argv[3]))],
            'validate' => ['valid' => $this->valid, 'report' => $this->valid ? '' : 'Not support [x]', 'stderr' => ''],
            'activate' => ['result' => 'committed', 'generation' => $argv[2]],
            'status' => ['pointer' => 'r20260101000000-aaaaaa', 'served' => 'r20260101000000-aaaaaa', 'coherent' => true, 'epoch' => 1],
            'enforce' => ['result' => null],
            'recover' => ['actions' => [], 'coherent' => true],
            'health' => ['generation' => 'r20260101000000-aaaaaa', 'failing' => []],
            default => null,
        };
        return $out === null ? ['exit_code' => 1, 'stdout' => '', 'stderr' => "usage\n"]
            : ['exit_code' => 0, 'stdout' => json_encode($out) . "\n", 'stderr' => ''];
    }
    private static function files(string $dir): array
    {
        $out = [];
        foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS)) as $path => $info) {
            $out[substr($path, strlen($dir) + 1)] = file_get_contents($path);
        }
        ksort($out);
        return $out;
    }
};
$state = temp_dir();
mkdir("$state/generations/r20260101000000-aaaaaa", 0755, true);
file_put_contents("$state/generations/r20260101000000-aaaaaa/SOURCE_SHA256", str_repeat('c', 64) . "\n");
$local = new LocalEngine($activator, $state, '/opt/activator');
$tree = (new GenerationTree())->arguments(['config' => $fixture['compiled']['config'], 'vhconf' => $fixture['compiled']['vhconf'],
    'plan' => [], 'summary' => $fixture['summary']], 'r20261022120000-0a1b2c', 4, str_repeat('d', 64));
$applied = $local->apply($tree['generation'], $tree['files'], $tree['health'], 4, str_repeat('d', 64));
check($applied === ['generation' => 'r20261022120000-0a1b2c', 'valid' => true, 'result' => 'committed', 'reason' => null]
    && array_column($activator->calls, 0) === ['stage', 'validate', 'activate']
    && $activator->calls[0][2] === "$state/staging/r20261022120000-0a1b2c", 'apply: stage, validate, activate through the activator');
check($activator->staged['EPOCH'] === "4\n" && $activator->staged['SOURCE_SHA256'] === str_repeat('d', 64) . "\n"
    && isset($activator->staged['health.json'], $activator->staged['marker/generation'], $activator->staged['httpd_config.conf'],
        $activator->staged['summary.json'])
    && !file_exists("$state/staging/r20261022120000-0a1b2c") && (fileperms("$state/staging") & 0777) === 0700,
    'staged tree has health.json, EPOCH and SOURCE_SHA256; the staging copy is removed');
mkdir("$state/generations/r20261022120000-0a1b2c");
check(throws(fn() => $local->apply('r20261022120000-0a1b2c', $tree['files'], [['vhost' => 'a.b', 'host' => 'a.b',
    'url' => 'http://1.2.3.4:80/.ols-cpanel-generation/id']], 4, str_repeat('d', 64)), EngineError::class, 'immutable'),
    'an existing generation id is refused');
$activator->valid = false;
$activator->calls = [];
$invalid = $local->apply('r20261022120001-0a1b2c', $tree['files'], [['vhost' => 'a.b', 'host' => 'a.b',
    'url' => 'http://1.2.3.4:80/.ols-cpanel-generation/id']], 4, str_repeat('d', 64));
check($invalid['result'] === 'invalid' && $invalid['valid'] === false && str_contains((string) $invalid['reason'], 'Not support')
    && array_column($activator->calls, 0) === ['stage', 'validate'], 'invalid generation: never activated');
$target = [['vhost' => 'a.b', 'host' => 'a.b', 'url' => 'http://1.2.3.4:80/.ols-cpanel-generation/id']];
foreach ([['../../etc/x' => 'x'], ['vhosts/../x/vhconf.conf' => 'x'], ['vhosts/Bad_Name/vhconf.conf' => 'x'], ['health.json' => '[]'],
          ['EPOCH' => '9'], ['vhosts/a.b/other.conf' => 'x']] as $bad) {
    check(throws(fn() => LocalEngine::checkTree('r20261022120000-0a1b2c', $bad + $tree['files'], $target, 1, str_repeat('d', 64)),
        EngineError::class, 'not allowed'), 'apply refuses the path ' . array_key_first($bad));
}
// Finding 12: HTTPS health targets on 443 only (hybrid tls.<domain>); plain HTTP on 80 or loopback.
foreach (['https://172.16.0.4:443/.ols-cpanel-generation/id' => true, 'https://127.0.0.1:443/.ols-cpanel-generation/id' => true,
          'http://172.16.0.4:80/.ols-cpanel-generation/id' => true, 'http://127.0.0.1:8097/.ols-cpanel-generation/id' => true,
          'https://172.16.0.4:8443/.ols-cpanel-generation/id' => false, 'https://172.16.0.4:80/.ols-cpanel-generation/id' => false,
          'http://172.16.0.4:443/.ols-cpanel-generation/id' => false, 'https://a.example:443/.ols-cpanel-generation/id' => false,
          'https://[::1]:443/.ols-cpanel-generation/id' => false, 'ftp://172.16.0.4:443/.ols-cpanel-generation/id' => false,
          'https://172.16.0.4:443/.ols-cpanel-generation/.x' => false] as $url => $valid) {
    check(GenerationTree::validHealthUrl($url) === $valid, "health URL $url " . ($valid ? 'accepted' : 'refused'));
}
check(GenerationTree::targetAddress('https://172.16.0.4:443/.ols-cpanel-generation/id') === '172.16.0.4'
    && GenerationTree::targetAddress('http://127.0.0.1:80/.ols-cpanel-generation/id') === '127.0.0.1', 'target address of a health URL');
LocalEngine::checkTree('r20261022120000-0a1b2c', $tree['files'], [['vhost' => 'tls.a.example', 'host' => 'a.example',
    'url' => 'https://172.16.0.4:443/.ols-cpanel-generation/id']], 1, str_repeat('d', 64));
check(throws(fn() => LocalEngine::checkTree('20261022-x', $tree['files'], $target, 1, str_repeat('d', 64)), EngineError::class)
    && throws(fn() => LocalEngine::checkTree('r20261022120000-0a1b2c', $tree['files'], [['vhost' => 'a.b', 'host' => 'a.b',
        'url' => 'http://evil.example:80/x']], 1, str_repeat('d', 64)), EngineError::class, 'health'),
    'apply refuses malformed ids and health targets');
check($local->status()['source_sha256'] === str_repeat('c', 64) && $local->health(5)['failing'] === []
    && $local->enforce(300) === ['result' => null] && end($activator->calls) === ['enforce', '--grace', '300'],
    'status adds the active SOURCE_SHA256; health and enforce are activator commands');
mkdir("$state/events");
$names = ['1761134400000000002-' . str_repeat('b', 32) . '.json', '1761134400000000001-' . str_repeat('a', 32) . '.json'];
foreach ($names as $name) {
    file_put_contents("$state/events/$name", '{"event": "Accounts::Remove"}');
}
file_put_contents("$state/events/stray.tmp-x", 'x');
$pending = $local->pendingEvents();
check(array_column($pending, 'name') === array_reverse($names) && $pending[0]['event']['event'] === 'Accounts::Remove',
    'spool: entries oldest first, temporary files ignored');
file_put_contents("$state/events/1761134400000000003-" . str_repeat('c', 32) . '.json', '{"event": ');
check(($local->pendingEvents()[2]['error'] ?? null) === 'malformed spool entry' && !isset($local->pendingEvents()[2]['event']),
    'spool: a malformed entry is listed with an error');
unlink("$state/events/1761134400000000003-" . str_repeat('c', 32) . '.json');
check(throws(fn() => $local->eventsDone([$names[1], $names[1]]), EngineError::class, 'repeated')
    && throws(fn() => $local->eventsDone(['../profile.json']), EngineError::class)
    && throws(fn() => $local->eventsDone([$names[1], '1761134400000000009-' . str_repeat('f', 32) . '.json']), EngineError::class, 'no spool entry')
    && count($local->pendingEvents()) === 2, 'events done: malformed, repeated or unknown names refused, nothing moved');
check($local->eventsDone([$names[1]]) === [$names[1]] && is_file("$state/events/done/{$names[1]}") && count($local->pendingEvents()) === 1,
    'events done moves the named spool entries');
check(throws(fn() => $local->recover(0) && (new LocalEngine($activator, $state, '/opt/activator'))->activateExisting('x/../y'),
    EngineError::class), 'activateExisting validates the id');
// Quarantine (finding 16): every *.json entry is listed, an entry that is not a spool name as malformed; quarantine
// moves exactly the named entries (links as links), all or nothing, never replacing an earlier quarantined one.
file_put_contents("$state/events/stray.json", '{}');
file_put_contents("$state/events/1761134400000000004-" . str_repeat('d', 32) . '.json', '[1]');
symlink('/etc/passwd', "$state/events/1761134400000000005-" . str_repeat('e', 32) . '.json');
$listed = $local->pendingEvents();
$errors = array_column(array_filter($listed, static fn(array $e): bool => isset($e['error'])), 'error', 'name');
check($errors === ['stray.json' => 'not a spool file name', '1761134400000000004-' . str_repeat('d', 32) . '.json' => 'malformed spool entry',
    '1761134400000000005-' . str_repeat('e', 32) . '.json' => 'unreadable spool entry'], 'spool: malformed, misnamed and linked entries listed with an error');
check(throws(fn() => $local->eventsQuarantine(['../profile.json']), EngineError::class, 'not a spool entry')
    && throws(fn() => $local->eventsQuarantine(['done']), EngineError::class)
    && throws(fn() => $local->eventsQuarantine(['stray.json', 'absent.json']), EngineError::class, 'no spool entry')
    && is_file("$state/events/stray.json"), 'quarantine: paths, non-entries and unknown names refused, nothing moved');
check($local->eventsQuarantine(array_keys($errors)) === array_keys($errors) && is_link("$state/events/quarantine/1761134400000000005-"
    . str_repeat('e', 32) . '.json') && is_file("$state/events/quarantine/stray.json") && (fileperms("$state/events/quarantine") & 0777) === 0700
    && array_column($local->pendingEvents(), 'name') === [$names[0]], 'quarantine moves the malformed entries, the valid one stays');
file_put_contents("$state/events/stray.json", '{"again": 1}');
$local->eventsQuarantine(['stray.json']);
check(count(glob("$state/events/quarantine/stray.json*")) === 2, 'a second entry of the same name never replaces the first');
// Restriction intents (finding 5): oldest first, each removed only after the activator returned the raised epoch.
$restricter = new class implements CommandRunner {
    public array $reasons = [];
    public int $epoch = 4;
    public bool $fail = false;
    public function run(string $name, array $argv, int $timeout): array
    {
        $this->reasons[] = $argv[2];
        return $this->fail ? ['exit_code' => 1, 'stdout' => '', 'stderr' => "EpochError: epoch record unreadable
"]
            : ['exit_code' => 0, 'stdout' => json_encode(['epoch' => ++$this->epoch, 'reason' => $argv[2]]), 'stderr' => ''];
    }
};
$intentState = temp_dir();
$folder = new LocalEngine($restricter, $intentState, '/opt/activator');
check($folder->foldRestrictions() === ['folded' => [], 'epoch' => null] && $restricter->reasons === [], 'no intents: nothing raised');
mkdir("$intentState/restrictions", 0700);
$intentNames = ['1761134400000000010-' . str_repeat('1', 32) . '.json', '176113440000000009-' . str_repeat('2', 32) . '.json'];
file_put_contents("$intentState/restrictions/{$intentNames[0]}", '{"event": "Accounts::Remove", "reason": "Accounts::Remove root", "time": 5.0, "user": "root"}');
file_put_contents("$intentState/restrictions/{$intentNames[1]}", '{broken');
file_put_contents("$intentState/restrictions/x.json.tmp-1", '{}');
$restricter->fail = true;
check(throws(fn() => $folder->foldRestrictions(), EngineError::class, 'restrict failed') && count(glob("$intentState/restrictions/*.json")) === 2,
    'epoch not raised: no intent is removed');
$restricter->fail = false;
$restricter->reasons = [];
check($folder->foldRestrictions() === ['folded' => [$intentNames[1], $intentNames[0]], 'epoch' => 6]
    && $restricter->reasons === ["restriction intent {$intentNames[1]} (malformed)", 'Accounts::Remove root']
    && glob("$intentState/restrictions/*.json") === [] && is_file("$intentState/restrictions/x.json.tmp-1"),
    'intents folded oldest first (a malformed one still restricts), then removed');

// --- BrokerEngine over a canned engine.sock ----------------------------------------------------------
$socketDir = temp_dir();
$socket = "$socketDir/engine.sock";
$server = <<<'PHP'
$server = stream_socket_server('unix://' . $argv[1]);
$replies = json_decode($argv[2], true);
foreach ($replies as $reply) {
    $conn = stream_socket_accept($server, 10);
    $request = json_decode(fgets($conn), true);
    $answer = $reply === 'echo' ? ['ok' => true, 'result' => ['exit_code' => 0, 'stdout' => str_repeat('x', 5000000) . json_encode($request['args'], JSON_UNESCAPED_SLASHES),
        'stderr' => '']] : (isset($reply['op']) && $reply['op'] !== $request['op'] . ' ' . json_encode($request['args'] ?? null)
        ? ['ok' => false, 'error' => ['code' => 'BAD_ARGS', 'message' => 'unexpected ' . $request['op']]] : $reply);
    unset($answer['op']);
    fwrite($conn, json_encode(['v' => 1, 'id' => $request['id']] + $answer) . "\n");
    fclose($conn);
}
PHP;
$replies = ['echo', ['ok' => false, 'error' => ['code' => 'FORBIDDEN', 'message' => 'argv not allowed']],
    ['ok' => true, 'result' => ['generation' => 'r20261022120000-0a1b2c', 'valid' => true, 'result' => 'committed', 'reason' => null]],
    ['ok' => true, 'result' => ['pending' => [['name' => 'n.json', 'event' => ['event' => 'x']]]]],
    ['ok' => true, 'result' => ['generation' => null, 'failing' => []]],
    ['op' => 'engine.events_quarantine {"names":["stray.json"]}', 'ok' => true, 'result' => ['quarantined' => ['stray.json']]],
    ['op' => 'engine.restrictions_fold null', 'ok' => true, 'result' => ['folded' => ['1-' . str_repeat('a', 32) . '.json'], 'epoch' => 9]],
    ['ok' => true, 'result' => ['folded' => 'x']]];
$process = proc_open([PHP, '-n', '-r', $server, $socket, json_encode($replies)], [0 => ['file', '/dev/null', 'r']], $pipes);
for ($i = 0; $i < 100 && !file_exists($socket); ++$i) {
    usleep(20000);
}
$broker = new BrokerEngine(new BrokerClient($socket, 20.0, BrokerClient::MAX_ENGINE_REPLY));
$ran = $broker->run('userdatadomains', ['/usr/bin/cat', '/etc/userdatadomains'], 120);
check(strlen($ran['stdout']) > 5000000 && str_ends_with($ran['stdout'], '{"name":"userdatadomains","argv":["/usr/bin/cat","/etc/userdatadomains"]}'),
    'engine.run: envelope with name and argv, a reply above the 4 MiB default limit');
check(throws(fn() => $broker->run('x', ['/usr/bin/cat', '/etc/shadow'], 1), EngineError::class, 'argv not allowed'),
    'engine.run FORBIDDEN becomes EngineError');
check($broker->apply('r20261022120000-0a1b2c', ['httpd_config.conf' => str_repeat('#', 200000)], $target, 1, str_repeat('d', 64))['result']
    === 'committed', 'engine.apply with a request far above one socket write');
check($broker->pendingEvents() === [['name' => 'n.json', 'event' => ['event' => 'x']]] && $broker->health(5)['failing'] === [],
    'engine.events and engine.health');
check($broker->eventsQuarantine(['stray.json']) === ['stray.json']
    && $broker->foldRestrictions() === ['folded' => ['1-' . str_repeat('a', 32) . '.json'], 'epoch' => 9]
    && throws(fn() => $broker->foldRestrictions(), EngineError::class, 'no fold result'),
    'engine.events_quarantine and engine.restrictions_fold, malformed replies refused');
proc_close($process);
check(throws(fn() => (new BrokerEngine(new BrokerClient("$socketDir/absent.sock")))->status(), EngineError::class, 'not available'),
    'broker unavailable: EngineError');

// --- HookEntry ---------------------------------------------------------------------------------------
$hookState = temp_dir();
$spool = "$hookState/events";
$intents = "$hookState/restrictions";
$restrictor = new class($spool) implements CommandRunner {
    public array $calls = [];
    public bool $fail = false;
    public function __construct(private string $spool)
    {
    }
    public function run(string $name, array $argv, int $timeout): array
    {
        // The epoch must be raised before the event is recorded (before cPanel's operation is acknowledged).
        $this->calls[] = [$argv, count(glob($this->spool . '/*.json') ?: [])];
        return $this->fail ? ['exit_code' => 1, 'stdout' => '', 'stderr' => "EpochError\n"]
            : ['exit_code' => 0, 'stdout' => '{"epoch": 7, "reason": "x"}' . "\n", 'stderr' => ''];
    }
};
$hook = new HookEntry($spool, $restrictor, '/opt/activator', $intents);
$answer = static function (string $input) use ($hook): array {
    $out = fopen('php://memory', 'w+');
    $err = fopen('php://memory', 'w+');
    $hook->handle($input, $out, $err);
    rewind($out);
    rewind($err);
    return [stream_get_contents($out), stream_get_contents($err)];
};
$suspend = json_encode(['context' => ['category' => 'Whostmgr', 'event' => 'Accounts::suspendacct', 'stage' => 'post', 'user' => 'root'],
    'data' => ['user' => 'olscpb']]);
check($answer($suspend)[0] === '1' && $restrictor->calls[0] === [['/opt/activator', 'restrict', 'Accounts::suspendacct root'], 0],
    'restricting event: epoch raised through the activator before anything is spooled; answers exactly 1');
$records = array_map(static fn(string $p): array => json_decode(file_get_contents($p), true), glob("$spool/*.json"));
check(count($records) === 1 && $records[0]['epoch'] === 7 && $records[0]['user'] === 'root' && $records[0]['event'] === 'Accounts::suspendacct'
    && preg_match(LocalEngine::EVENT_NAME, basename(glob("$spool/*.json")[0])) === 1 && (fileperms($spool) & 0777) === 0700,
    'event spooled with its epoch under a spool name');
$install = json_encode(['context' => ['event' => 'UAPI::SSL::install_ssl', 'user' => ''], 'data' => ['username' => 'olscpa']]);
check($answer($install)[0] === '1' && count($restrictor->calls) === 1 && count(glob("$spool/*.json")) === 2,
    'other events are only recorded');
$user = array_values(array_filter(array_map(static fn(string $p): array => json_decode(file_get_contents($p), true), glob("$spool/*.json")),
    static fn(array $r): bool => $r['event'] === 'UAPI::SSL::install_ssl'))[0]['user'];
check($user === 'olscpa', 'user falls back to data.username like the lab hook');
foreach (['', '{}', 'not json', '[]', '{"context": "bad"}', '{"context": []}', str_repeat('[', 5000)] as $raw) {
    check($answer($raw) === ['1', ''] && count(glob("$spool/*.json")) === 2, 'malformed or empty input: nothing recorded, exactly 1 (' . substr($raw, 0, 12) . ')');
}
$restrictor->fail = true;
[$printed, $stderr] = $answer($suspend);
check($printed === '1' && str_contains($stderr, 'restriction epoch not raised') && count(glob("$spool/*.json")) === 3,
    'failed epoch raise: still exactly 1, reported, event spooled for the reconciler');
// Finding 5: the restriction is kept as a durable root 0600 intent before "1" is printed.
$intentFiles = glob("$intents/*.json");
$intent = json_decode(file_get_contents($intentFiles[0]), true);
check(count($intentFiles) === 1 && preg_match(LocalEngine::EVENT_NAME, basename($intentFiles[0])) === 1
    && array_keys($intent) === ['event', 'reason', 'time', 'user'] && $intent['event'] === 'Accounts::suspendacct'
    && $intent['reason'] === 'Accounts::suspendacct root' && $intent['user'] === 'root' && is_float($intent['time'])
    && (fileperms($intentFiles[0]) & 0777) === 0600 && (fileperms($intents) & 0777) === 0700 && str_contains($stderr, 'durable intent'),
    'failed epoch raise: durable restriction intent {event, reason, time, user}, file 0600 in a 0700 directory');
check(LocalEngine::intentReason($intentFiles[0], basename($intentFiles[0])) === 'Accounts::suspendacct root',
    'the engine folds the intent with the reason the hook would have recorded');
$noSpool = new HookEntry('/proc/ols-cpanel-no-spool', $restrictor, '/opt/activator', $intents);
$out = fopen('php://memory', 'w+');
$err = fopen('php://memory', 'w+');
$noSpool->handle($suspend, $out, $err);
rewind($out);
check(stream_get_contents($out) === '1' && count(glob("$intents/*.json")) === 2,
    'spool directory impossible: the restriction intent is still recorded first; exactly 1');
$nowhere = new HookEntry('/proc/ols-cpanel-no-spool', $restrictor, '/opt/activator', '/proc/ols-cpanel-no-intents');
$out = fopen('php://memory', 'w+');
$err = fopen('php://memory', 'w+');
$nowhere->handle($suspend, $out, $err);
rewind($out);
rewind($err);
check(stream_get_contents($out) === '1' && str_contains(stream_get_contents($err), 'restriction intent not recorded'),
    'unwritable spool and intent directory: still exactly 1, reported');

// --- CLI dispatch and exit codes ---------------------------------------------------------------------
$run = static function (Application $app, array $argv, $stdin = null): array {
    $out = fopen('php://memory', 'w+');
    $err = fopen('php://memory', 'w+');
    $code = $app->run($argv, new Output(in_array('--format=json', $argv, true), $out, $err));
    rewind($out);
    rewind($err);
    return [$code, stream_get_contents($out), stream_get_contents($err)];
};
$commands = static fn(EngineContext $context, $stdin = null): array => [
    new OlsCpanel\Cli\Command\StatusCommand($context), new OlsCpanel\Cli\Command\SyncCommand($context),
    new OlsCpanel\Cli\Command\HookCommand($context, $stdin), new OlsCpanel\Cli\Command\GenerationListCommand($context),
    new OlsCpanel\Cli\Command\GenerationInspectCommand($context), new OlsCpanel\Cli\Command\RollbackCommand($context),
    new OlsCpanel\Cli\Command\RecoverCommand($context)];
$names = array_map(static fn(Command $c): string => implode(' ', $c->words()), Application::defaultCommands());
check(array_diff(['status', 'sync', 'hook', 'generation list', 'generation inspect', 'rollback', 'recover'], $names) === [],
    'commands registered in the application');
$stranger = new Application($commands(new EngineContext(1000, 'someone')));
foreach ([['status'], ['sync'], ['recover'], ['generation', 'list'], ['rollback']] as $argv) {
    [$code, $stdout] = $run($stranger, [...$argv, '--format=json']);
    check($code === 1 && json_decode($stdout, true)['result'] === 'refused', implode(' ', $argv) . ': other users refused (exit 1, JSON reason)');
}
$fake = new FakeEngine($fixture['calls']);
$fake->state['source_sha256'] = $source;
$state = temp_dir();
mkdir("$state/events");
$engineRole = new EngineContext(990, 'olscpanel', static fn(string $role): Engine => $role === 'engine' ? $fake : throw new LogicException(),
    static fn(Engine $e, ?string $lock): Reconciler => new Reconciler($e, $builders, null, $production, '/nonexistent', $lock), $state,
    "$state/profile.json", "$state/no-proc");
$app = new Application($commands($engineRole));
[$code, $stdout] = $run($app, ['sync', '--format=json']);
check($code === 0 && json_decode($stdout, true)['action'] === 'unchanged', 'olscpanel: sync through the broker engine, unchanged: exit 0');
$fake->validation = ['valid' => false];
$fake->state['source_sha256'] = null;
[$code, $stdout] = $run($app, ['sync', '--format=json']);
check($code === 1 && json_decode($stdout, true)['action'] === 'invalid', 'sync with an invalid generation: exit 1');
[$code, $stdout] = $run($app, ['generation', 'list', '--format=json']);
check($code === 1 && str_contains($stdout, 'root only'), 'olscpanel: generation list is root only');
[$code, $stdout] = $run($app, ['status', '--format=json']);
$status = json_decode($stdout, true);
check($code === 0 && $status['role'] === 'engine' && $status['cut_over'] === false && $status['activator']['epoch'] === 2
    && $status['pending_events'] === 0 && $status['ports'] === ['80' => [], '443' => []], 'status as olscpanel');
foreach ([['sync', '--interval=5'], ['sync', '--watch', '--force'], ['sync', '--watch', '--interval=0'], ['sync', '--bogus'],
          ['generation', 'inspect'], ['recover', '--grace=-1'], ['status', 'extra']] as $argv) {
    [$code, $stdout] = $run($app, $argv);
    check($code === 64 && $stdout === '', implode(' ', $argv) . ': usage error, exit 64');
}
// Finding 17: with --format=json every exit prints exactly one JSON object {result, code, error}.
foreach ([[[], 'usage'], [['bogus'], 'usage'], [['sync', '--bogus'], 'usage'], [['status', 'extra'], 'usage']] as [$argv, $kind]) {
    [$code, $stdout] = $run($app, [...$argv, '--format=json']);
    $object = json_decode($stdout, true);
    check($code === 64 && is_array($object) && $object['result'] === $kind && $object['code'] === 64 && is_string($object['error'])
        && $stdout === json_encode($object, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n",
        implode(' ', $argv) . ' --format=json: one JSON usage object, exit 64');
}
$crashing = new class implements Command {
    public function words(): array
    {
        return ['crash'];
    }
    public function summary(): string
    {
        return 'test';
    }
    public function run(array $argv, Output $out): int
    {
        throw new LogicException("secret\0path");
    }
};
[$code, $stdout, $stderr] = $run(new Application([$crashing]), ['crash', '--format=json']);
$object = json_decode($stdout, true);
check($code === 70 && $object['result'] === 'internal' && $object['code'] === 70 && str_contains($object['error'], 'LogicException')
    && !str_contains($stdout, "\0") && str_contains($stderr, 'Internal error'), 'internal error --format=json: one JSON object, exit 70');
[$code, $stdout] = $run(new Application([$crashing]), ['crash']);
check($code === 70 && $stdout === '', 'internal error in text mode: nothing on stdout');
[$code, $stdout] = $run(new Application([$crashing]), ['--help', '--format=json']);
check($code === 0 && json_decode($stdout, true)['commands'] === ['crash'], 'help --format=json: one JSON object, exit 0');
[$code, $stdout, $stderr] = $run($app, ['hook']);
check($code === 1 && $stdout === '1' && str_contains($stderr, 'root only'), 'hook as olscpanel: exactly 1, exit 1');
[$code, $stdout] = $run($app, ['hook', '--format=json']);
check($stdout === '1', 'hook --format=json: still exactly 1 (cPanel parses it)');
$busyLock = "$state/reconcile.lock";
$holder = fopen($busyLock, 'c');
flock($holder, LOCK_EX);
$root = new EngineContext(0, 'root', static fn(string $role): Engine => $fake,
    static fn(Engine $e, ?string $lock): Reconciler => new Reconciler($e, $builders, null, $production, '/nonexistent', $lock), $state);
[$code, $stdout] = $run(new Application($commands($root)), ['sync', '--format=json']);
check($code === 75 && json_decode($stdout, true)['result'] === 'busy', 'root sync while another pass holds the lock: exit 75');
flock($holder, LOCK_UN);
$unprofiled = new EngineContext(0, 'root', static fn(string $role): Engine => $fake, null, $state, "$state/profile.json");
[$code, $stdout] = $run(new Application($commands($unprofiled)), ['sync', '--format=json']);
$refusal = json_decode($stdout, true);
check($code === 1 && str_contains($refusal['error'], 'not cut over') && $refusal['code'] === 1 && $refusal['class'] === 'ReconcileRefused',
    'sync before cutover: refused, exit 1, JSON {result, code, error}');
// Root operator commands on a local engine with a scripted activator and a real state layout.
$state = temp_dir();
foreach (['r20260101000000-aaaaaa' => 1, 'r20260102000000-bbbbbb' => 1, 'r20260103000000-cccccc' => 2] as $gen => $epoch) {
    mkdir("$state/generations/$gen", 0755, true);
    file_put_contents("$state/generations/$gen/EPOCH", "$epoch\n");
    file_put_contents("$state/generations/$gen/httpd_config.conf", $gen === 'r20260103000000-cccccc'
        ? "extProcessor apache-http-olstest2.example.test {\n}\n" : '');
}
symlink("$state/generations/r20260103000000-cccccc", "$state/active");
mkdir("$state/journal");
mkdir("$state/validations");
foreach ([['r20260101000000-aaaaaa', 1], ['r20260102000000-bbbbbb', 2], ['r20260103000000-cccccc', 3]] as [$gen, $seq]) {
    file_put_contents("$state/journal/t$seq.json", json_encode(['id' => "t$seq", 'seq' => $seq, 'new' => $gen, 'state' => 'committed']));
    file_put_contents("$state/validations/$gen.json", json_encode(['generation' => $gen, 'valid' => true]));
}
$rollbackRunner = new class implements CommandRunner {
    public array $activated = [];
    public function run(string $name, array $argv, int $timeout): array
    {
        $this->activated[] = $argv[2] ?? $argv[1];
        $out = $argv[2] === 'r20260102000000-bbbbbb'
            ? ['result' => 'refused', 'generation' => $argv[2], 'reason' => 'generation epoch 1 predates restriction epoch 2']
            : ['result' => 'committed', 'generation' => $argv[2]];
        return ['exit_code' => 0, 'stdout' => json_encode($out), 'stderr' => ''];
    }
};
$operator = new EngineContext(0, 'root', static fn(string $role): Engine => new LocalEngine($rollbackRunner, $state, '/opt/activator'), null, $state);
$app = new Application($commands($operator));
[$code, $stdout] = $run($app, ['generation', 'list', '--format=json']);
$list = json_decode($stdout, true);
check($code === 0 && $list['active'] === 'r20260103000000-cccccc' && count($list['generations']) === 3
    && $list['generations'][2]['active'] && $list['generations'][0]['valid'] === true && $list['generations'][2]['epoch'] === 2,
    'generation list (root)');
[$code, $stdout] = $run($app, ['generation', 'inspect', 'r20260103000000-cccccc', '--format=json']);
$view = json_decode($stdout, true);
check($code === 0 && $view['hybrid_vhosts'] === ['olstest2.example.test'] && count($view['transactions']) === 1, 'generation inspect (root)');
[$code] = $run($app, ['generation', 'inspect', '../etc']);
check($code === 1, 'generation inspect of an unknown id: exit 1');
[$code, $stdout] = $run($app, ['rollback', '--format=json']);
$rolled = json_decode($stdout, true);
check($code === 0 && $rolled['generation'] === 'r20260101000000-aaaaaa' && $rollbackRunner->activated === ['r20260102000000-bbbbbb', 'r20260101000000-aaaaaa']
    && $rolled['attempts'][0]['result'] === 'refused', 'rollback skips a candidate the activator refuses (older epoch) and activates the next');
unlink("$state/journal/t1.json");
$rollbackRunner->activated = [];
[$code, $stdout] = $run($app, ['rollback', '--format=json']);
check($code === 1 && json_decode($stdout, true)['action'] === 'none', 'rollback without an acceptable candidate: exit 1');
// Hook as root: the real HookEntry with the context's spool.
$stdin = fopen('php://memory', 'w+');
fwrite($stdin, json_encode(['context' => ['event' => 'Accounts::unsuspendacct', 'user' => 'olscpb']]));
rewind($stdin);
[$code, $stdout] = $run(new Application($commands($operator, $stdin)), ['hook']);
check($code === 0 && $stdout === '1' && count(glob("$state/events/*.json")) === 1, 'hook as root: spooled, exactly 1');
// --- FV-02: security input, WAF digests and the waf commands -----------------------------------------------
$wafInputs = static fn(string $sha): array => [
    ['path' => '/etc/apache2/conf.d/modsec2.conf', 'sha256' => str_repeat('1', 64)],
    ['path' => '/etc/apache2/conf.d/modsec_vendor_configs/OWASP3/rules/a.conf', 'sha256' => $sha],
    ['path' => '/etc/apache2/conf.d/modsec_vendor_configs/OWASP3/rules/a.data', 'sha256' => str_repeat('2', 64)]];
$wafSummary = static fn(string $sha): array => ['summary' => ['waf' => ['state' => 'translated', 'inputs' => $wafInputs($sha)]]];
$base = ['config' => "x\n", 'vhconf' => ['a' => "y\n"]];
$one = $base + $wafSummary(str_repeat('a', 64));
$two = $base + $wafSummary(str_repeat('b', 64));
$noop = new class implements CommandRunner {
    public function run(string $name, array $argv, int $timeout): array
    {
        throw new LogicException('no command expected');
    }
};
$filesOne = SourceDigest::referencedFiles($one, $noop);
$filesTwo = SourceDigest::referencedFiles($two, $noop);
check(count($filesOne) === 3 && $filesOne['/etc/apache2/conf.d/modsec_vendor_configs/OWASP3/rules/a.conf'] === str_repeat('a', 64)
    && SourceDigest::referencedFiles($base, $noop) === [], 'source digest files include every ModSecurity input of the summary (no command run)');
check(SourceDigest::source($one, 3, $filesOne) !== SourceDigest::source($two, 3, $filesTwo)
    && SourceDigest::source($one, 3, $filesOne) === SourceDigest::source($one, 3, SourceDigest::referencedFiles($one, $noop)),
    'a changed vendor rule file changes the source digest');
check(CutoverPlan::digest($one, $filesOne) !== CutoverPlan::digest($two, $filesTwo)
    && CutoverPlan::digest($one, $filesOne) === CutoverPlan::digest($one, SourceDigest::referencedFiles($one, $noop)),
    'a changed vendor rule file changes the plan digest');

$secDir = temp_dir();
$secFile = static function (?string $text, int $mode = 0644) use ($secDir): string {
    $path = $secDir . '/security-' . bin2hex(random_bytes(4)) . '.json';
    if ($text !== null) {
        file_put_contents($path, $text);
        chmod($path, $mode);
    }
    return $path;
};
$refusal = static function (callable $call): string {
    try {
        $call();
    } catch (CompilationRefused $error) {
        return $error->getMessage();
    }
    return '';
};
check(SecurityInput::load($secFile(null)) === [] && SecurityInput::load($secFile('{}')) === []
    && SecurityInput::load($secFile('{"ip_block": ["198.51.100.0/24"], "exceptions": [{"vhost": "a.test", "rule_ids": [941100], "reason": "x"}]}'))['ip_block'] === ['198.51.100.0/24'],
    'security input: absent is {}, a valid file is returned');
foreach ([['not json', 'not valid JSON'], ['[1]', 'must be a JSON object'], ['"x"', 'must be a JSON object'], ['{"bogus": 1}', 'unknown security input keys'],
          ['{"exceptions": [{"vhost": "a.test", "reason": "x"}]}', 'exactly one of engine and rule_ids'],
          ['{"ip_allow": ["not an address"]}', 'invalid address'], ['{"accept_differences": ["nope"]}', 'invalid accept_differences'],
          [str_repeat(' ', SecurityInput::MAX_BYTES) . '{}', 'larger than']] as [$text, $message]) {
    $path = $secFile($text);
    check(str_contains($refusal(static fn() => SecurityInput::load($path)), $message), "security input refused: $message");
}
check($refusal(fn() => SecurityInput::load($secFile('{}', 0666))) !== '' && $refusal(fn() => SecurityInput::load($secFile('{}', 0664))) !== '',
    'security input writable by group or others refused');
$linked = "$secDir/linked.json";
symlink($secFile('{}'), $linked);
check($refusal(fn() => SecurityInput::load($linked)) !== '', 'security input symlink refused');

// BuilderCompilation hands the file (or {}) to the builder; a malformed file refuses before any builder runs.
$accounts = new class implements CommandRunner {
    public function run(string $name, array $argv, int $timeout): array
    {
        return ['exit_code' => 0, 'stdout' => json_encode(['metadata' => ['result' => 1, 'command' => 'listaccts'],
            'data' => ['acct' => [['user' => 'olscpa', 'domain' => 'olstest1.example.test']]]]), 'stderr' => ''];
    }
};
$templateFile = $secDir . '/template.conf';
file_put_contents($templateFile, "x\n");
$seen = [];
$capture = static function (string $path) use ($accounts, $templateFile, &$seen): BuilderCompilation {
    return new BuilderCompilation($accounts, $templateFile, '/logs', static function ($r, $t, $tpl, $l, $ports, $security) use (&$seen) {
        $seen[] = $security;
        throw new CompilationRefused('stop after capture');
    }, $path);
};
foreach ([null, '{}', '{"ip_block": ["198.51.100.0/24"]}'] as $text) {
    $refusal(static fn() => $capture($secFile($text))->compile(null));
}
check($seen === [[], [], ['ip_block' => ['198.51.100.0/24']]], 'production wiring: BuilderCompilation hands the security file (absent: {}) to the builder');
$seen = [];
check(str_contains($refusal(static fn() => $capture($secFile('{"bogus": 1}'))->compile(null)), 'unknown security input keys') && $seen === [],
    'production wiring: a malformed security file refuses the compile before the builder runs');
check(array_diff(['waf status', 'waf blocked'], array_map(static fn(Command $c): string => implode(' ', $c->words()), Application::defaultCommands())) === [],
    'waf commands registered in the application');

// waf status / waf blocked (root) on a state directory and an audit log.
$wafState = temp_dir();
mkdir("$wafState/generations/g1", 0755, true);
symlink("$wafState/generations/g1", "$wafState/active");
file_put_contents("$wafState/generations/g1/summary.json", json_encode(['waf' => ['state' => 'translated', 'engine' => 'On',
    'audit_log' => '/usr/local/lsws/logs/modsec_audit.log', 'inputs' => $wafInputs(str_repeat('a', 64)),
    'rule_files' => ['/etc/apache2/conf.d/modsec_vendor_configs/OWASP3/rules/a.conf'],
    'data_files' => ['/etc/apache2/conf.d/modsec_vendor_configs/OWASP3/rules/a.data'], 'rules' => 8, 'disabled_rules' => [920350],
    'differences' => [], 'exceptions' => [['vhost' => 'a.test', 'source' => 'cpanel', 'engine' => 'off', 'rule_ids' => [], 'reason' => 'x']]]]));
$wafContext = new EngineContext(0, 'root', static fn(string $role): Engine => throw new LogicException(), null, $wafState);
$auditCopy = $secDir . '/audit.log';
copy(__DIR__ . '/Fixtures/modsec/audit-serial.log', $auditCopy);
$securityJson = $secFile('{"exceptions": [{"vhost": "b.test", "engine": "off", "reason": "legacy app"}]}');
$wafApp = new Application([new Command\WafStatusCommand($wafContext, $securityJson), new Command\WafBlockedCommand($wafContext, $auditCopy)]);
[$code, $stdout] = $run($wafApp, ['waf', 'status', '--format=json']);
$status = json_decode($stdout, true);
check($code === 0 && $status['state'] === 'translated' && $status['engine'] === 'On' && $status['vendors'] === ['OWASP3']
    && $status['rule_files'][0]['sha256'] === str_repeat('a', 64) && $status['data_files'][0]['sha256'] === str_repeat('2', 64)
    && $status['disabled_rules'] === [920350] && $status['domain_disables'][0]['vhost'] === 'a.test'
    && $status['security_json']['present'] === true && $status['security_json']['exceptions'][0]['vhost'] === 'b.test',
    'waf status: engine, vendors, rule files with digests, disables and security.json exceptions');
[$code, $stdout] = $run(new Application([new Command\WafStatusCommand($wafContext, $secFile('{"bogus": 1}'))]), ['waf', 'status', '--format=json']);
check($code === 0 && str_contains(json_decode($stdout, true)['security_json']['error'], 'unknown security input keys'),
    'waf status reports a malformed security.json');
[$code, $stdout] = $run($wafApp, ['waf', 'status']);
check($code === 0 && str_contains($stdout, 'state: translated'), 'waf status text output');
[$code, $stdout] = $run($wafApp, ['waf', 'blocked', '--format=json']);
$blocked = json_decode($stdout, true);
$times = array_column($blocked['records'], 'time');
$descending = $times;
rsort($descending);
check($code === 0 && $blocked['available'] === true && count($times) >= 2 && $times === $descending
    && !str_contains($stdout, 'secret-value-never-reported'), 'waf blocked: parsed records, newest first, no headers beyond Host');
[$code, $stdout] = $run($wafApp, ['waf', 'blocked', '--limit=1', '--format=json']);
check($code === 0 && count(json_decode($stdout, true)['records']) === 1, 'waf blocked --limit=1 bounds the output');
foreach ([['--limit=0'], ['--limit=1001'], ['--limit=x'], ['--limit'], ['extra']] as $bad) {
    [$code, $stdout] = $run($wafApp, ['waf', 'blocked', ...$bad]);
    check($code === 64 && $stdout === '', 'waf blocked ' . $bad[0] . ': usage error');
}
[$code, $stdout] = $run(new Application([new Command\WafBlockedCommand($wafContext, "$secDir/missing.log")]), ['waf', 'blocked', '--format=json']);
check($code === 0 && json_decode($stdout, true)['available'] === false && json_decode($stdout, true)['records'] === [],
    'waf blocked without a log: empty');
$stranger = new EngineContext(1000, 'someone', null, null, $wafState);
foreach ([new Command\WafStatusCommand($stranger, $securityJson), new Command\WafBlockedCommand($stranger, $auditCopy)] as $command) {
    [$code, $stdout] = $run(new Application([$command]), [...$command->words(), '--format=json']);
    check($code === 1 && json_decode($stdout, true)['result'] === 'refused', implode(' ', $command->words()) . ': root only');
}

// http3 status (FV-04, root): the operator input, the firewall inspection and the protocol share of the active generation's vhosts.
check(in_array('http3 status', array_map(static fn(Command $c): string => implode(' ', $c->words()), Application::defaultCommands()), true),
    'http3 status registered in the application');
$h3State = temp_dir();
mkdir("$h3State/generations/g1", 0755, true);
symlink("$h3State/generations/g1", "$h3State/active");
file_put_contents("$h3State/generations/g1/summary.json", json_encode(['vhosts' => ['a.test' => [], 'b.test' => [], 'not a domain' => []]]));
$h3Logs = temp_dir();
$h3Line = static fn(string $request): string => '203.0.113.5 - - [27/Oct/2026:12:00:00 +0000] "' . $request . '" 200 1 "-" "-"';
file_put_contents("$h3Logs/a.test", $h3Line('GET / HTTP/1.1') . "\n" . $h3Line('GET / HTTP/1.1') . "\n");
file_put_contents("$h3Logs/a.test-ssl_log", $h3Line('GET / HTTP/2') . "\n" . $h3Line('GET / HTTP/3') . "\n" . $h3Line('GET /x HTTP/3') . "\n");
$h3Context = new EngineContext(0, 'root', static fn(string $role): Engine => throw new LogicException(), null, $h3State);
$h3Input = $secDir . '/http3-absent.json';
$h3Firewall = static fn(): array => ['type' => 'csf', 'action' => 'add', 'detail' => 'append 443', 'new_text' => 'never printed', 'warnings' => []];
$h3App = new Application([new Command\Http3StatusCommand($h3Context, $h3Input, $h3Logs, $h3Firewall)]);
[$code, $stdout] = $run($h3App, ['http3', 'status', '--format=json']);
$h3 = json_decode($stdout, true);
$shares = array_column($h3['protocol_share'], null, 'vhost');
check($code === 0 && $h3['enabled'] === true && $h3['input']['present'] === false && $h3['firewall']['type'] === 'csf'
    && !str_contains($stdout, 'never printed') && array_keys($shares) === ['a.test', 'b.test'] && $shares['a.test']['h1'] === 2
    && $shares['a.test']['h2'] === 1 && $shares['a.test']['h3'] === 2 && $shares['a.test']['share_bp'] === ['h1' => 4000, 'h2' => 2000, 'h3' => 4000]
    && $shares['b.test']['lines'] === 0, 'http3 status: input, firewall (no file text) and the share per vhost of the active generation');
[$code, $stdout] = $run($h3App, ['http3', 'status', '--lines=1', '--format=json']);
check($code === 0 && json_decode($stdout, true)['protocol_share'][0]['lines'] === 2, 'http3 status --lines bounds each log file');
file_put_contents($h3Input, '{"enabled": false}');
chmod($h3Input, 0644);
[$code, $stdout] = $run($h3App, ['http3', 'status', '--format=json']);
$h3 = json_decode($stdout, true);
check($code === 0 && $h3['enabled'] === false && $h3['firewall'] === null, 'http3 status: opted out, no firewall inspection');
file_put_contents($h3Input, '{"enabled": 1}');
[$code, $stdout] = $run($h3App, ['http3', 'status', '--format=json']);
$h3 = json_decode($stdout, true);
check($code === 0 && $h3['enabled'] === null && str_contains($h3['input']['error'], '"enabled" must be true or false'), 'http3 status reports a malformed input');
foreach ([['--lines=0'], ['--lines=20001'], ['--lines=x'], ['--lines'], ['extra']] as $bad) {
    [$code, $stdout] = $run($h3App, ['http3', 'status', ...$bad]);
    check($code === 64 && $stdout === '', 'http3 status ' . $bad[0] . ': usage error');
}
[$code, $stdout] = $run(new Application([new Command\Http3StatusCommand($stranger, $h3Input, $h3Logs, $h3Firewall)]), ['http3', 'status', '--format=json']);
check($code === 1 && json_decode($stdout, true)['result'] === 'refused', 'http3 status: root only');
// A refused validation names its findings, which the report's tail (only the last output lines) loses.
$tailOnly = str_repeat('2026-10-28 [WARN] Uid of /home/u is 0, smaller than minimum requirement 100, use server uid!' . "\n", 30);
$invalid = LocalEngine::outcome('g9', ['valid' => false, 'report' => $tailOnly, 'stderr' => '',
    'findings' => ['[WARN] [config:server:vhosts:vhost:x] path of SSL key file is invalid', 7]], fn(): array => []);
check($invalid['result'] === 'invalid' && $invalid['reason'] === 'validation findings: [WARN] [config:server:vhosts:vhost:x] path of SSL key file is invalid',
    'a refused validation reports its findings, not the report tail');
$reason = \OlsCpanel\Deployment\Cutover::activationReason(['result' => 'invalid', 'reason' => $invalid['reason']]);
check($reason === $invalid['reason'], 'cutover names a warning finding whole');
$old = LocalEngine::outcome('g9', ['valid' => false, 'report' => 'x', 'stderr' => 'y'], fn(): array => []);
check($old['reason'] === "x\ny", 'without findings the report tail is kept');
echo "$count engine runtime checks passed.\n";
