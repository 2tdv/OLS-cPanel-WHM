<?php
declare(strict_types=1);

namespace OlsCpanel\Events;

use OlsCpanel\Deployment\ConfigurationActivator;
use OlsCpanel\Deployment\CutoverPlan;
use OlsCpanel\Deployment\Profile;
use OlsCpanel\Deployment\BuilderCompilation;
use OlsCpanel\Ols\Generation\Engine;
use OlsCpanel\Ols\Generation\EngineError;
use OlsCpanel\Ols\Generation\GenerationTree;
use OlsCpanel\Php\LsphpGuard;

/**
 * One reconciliation (port of ols_events.reconcile) and the service loop (port of ols_events.watch):
 * compile the current cPanel state with the deployment profile through the engine; when it differs from
 * the active generation (configuration, vhosts, restriction epoch or a referenced certificate/key/password
 * file: SourceDigest) or the active generation is not coherent and healthy, stage, validate and activate a
 * new generation; mark the spooled events done only once a configuration that includes them is active: after
 * a committed activation, or after a pass that found the active generation equal to the compiled state and
 * healthy ("unchanged"), so a failed pass is retried with the same events. An incoherent runtime is recovered
 * first with HR-D11's grace (300 s): one suspension must not stop every site before its replacement is ready.
 *
 * Every pass first folds the hook's durable restriction intents into the epoch (Engine::foldRestrictions;
 * review RV-29, finding 5): a restriction the hook could not record is never left out of what is compiled
 * and compared. The restriction epoch is then read before compiling: a restriction raised during
 * compilation makes this generation stale, and the activator refuses it (the next pass compiles again).
 * Without profile.json the server is not cut over and nothing is compiled, unless a profile is given
 * explicitly (cutover activates the first generation through activate() right after writing it).
 * The root CLI serializes passes with STATE/reconcile.lock; the reconciler service (one instance, as
 * `olscpanel`) has no writable state and relies on the activator's own activation lock. A spool entry
 * already consumed by a concurrent pass is skipped when marking done.
 * Malformed spool entries (`{"name", "error"}`) cannot say what changed, but every pass compiles the
 * complete cPanel state anyway: they are reported ("malformed_events") and moved to events/quarantine/ at
 * once (Engine::eventsQuarantine; review RV-29, finding 16), whatever the pass's outcome, so they never block
 * the valid entries' consumption or keep the service loop busy; a failed quarantine is reported
 * ("quarantine_error") and retried by the next pass.
 * Every activation carries an invalid generation's validator report or the activator's reason in "reason";
 * anything but "committed" keeps the events pending.
 * Lock order (review RV-29): every reconcile() pass holds the deployment lock SHARED (busy while a deployment
 * operation or recover.sh holds it), then the reconcile lock; activate() runs under the cutover's exclusive hold
 * and takes only the reconcile lock. activate() with an expected digest refuses a compile whose
 * CutoverPlan::digest differs from the approved plan's (review RV-29 findings 9 and 10).
 */
final class Reconciler implements ConfigurationActivator
{
    public const LOCK = '/var/lib/ols-cpanel/reconcile.lock';
    public const RECOVER_GRACE = 300;
    public const HEALTH_SECONDS = 5;
    public const DEFAULT_INTERVAL = 60;
    /** After a failed pass, pending events retrigger a pass only after this many seconds (no busy loop). */
    public const RETRY_SECONDS = 15;

    /** @var \Closure(Profile, Engine):array<string,mixed> */
    private \Closure $compile;
    private GenerationTree $tree;
    /** @var \Closure():float */
    private \Closure $clock;
    /** @var \Closure(int):void */
    private \Closure $sleep;
    /** @var \Closure():string */
    private \Closure $ids;

    /**
     * @param (\Closure(Profile, Engine):array<string,mixed>)|null $compile the compile for a profile, reading cPanel through the engine
     *        (default: Deployment\BuilderCompilation, every account with the product template)
     * @param Profile|null $profile a fixed profile (cutover, tests); null reads $profilePath on every pass
     * @param string|null $lockPath reconcile lock (root CLI), or null
     * @param (\Closure():float)|null $clock wall-clock seconds
     * @param (\Closure(int):void)|null $sleep
     * @param (\Closure():string)|null $ids new generation ids
     * @param string|null $deploymentLockPath the deployment lock, held shared by every reconcile() pass, or null
     * @param (\Closure(array<string,array<string,mixed>>):void)|null $planSeen called with every compiled plan (never failing the pass),
     *        e.g. to ask the hybrid trust service to run when a vhost address is not trusted by Apache yet (HR-D14)
     * @param LsphpGuard|null $php keeps the earlier configuration of a vhost whose PHP version has no usable lsphp (FV-10); null: no check
     */
    public function __construct(private readonly Engine $engine, ?\Closure $compile = null, ?GenerationTree $tree = null,
                                private readonly ?Profile $profile = null, private readonly string $profilePath = Profile::PATH,
                                private readonly ?string $lockPath = null, ?\Closure $clock = null, ?\Closure $sleep = null,
                                ?\Closure $ids = null, private readonly ?string $deploymentLockPath = null,
                                private readonly ?LsphpGuard $php = null, private readonly ?\Closure $planSeen = null)
    {
        $this->compile = $compile ?? static fn(Profile $profile, Engine $engine): array
            => (new BuilderCompilation($engine))->compile($profile->hybridPorts);
        $this->tree = $tree ?? new GenerationTree();
        $this->clock = $clock ?? static fn(): float => microtime(true);
        $this->sleep = $sleep ?? static function (int $seconds): void {
            sleep($seconds);
        };
        $this->ids = $ids ?? static fn(): string => GenerationTree::newId();
    }

    /**
     * The forced pass of cutover (ConfigurationActivator), under the deployment lock the cutover holds
     * exclusively (so not taken shared here); refused before any activation when $expectedDigest is given and
     * this compile's CutoverPlan::digest differs from it.
     */
    public function activate(?string $expectedDigest = null): array
    {
        return $this->serialized(true, $expectedDigest);
    }

    /**
     * One reconciliation; returns what it did ("action": unchanged | committed | invalid | refused |
     * rolled_back | ...). Throws ReconcileRefused (not cut over, malformed profile, unknown epoch),
     * ReconcileBusy (lock held), CompilationRefused and engine errors.
     * @return array<string,mixed>
     */
    public function reconcile(bool $force = false): array
    {
        $shared = $this->sharedDeploymentLock();
        try {
            return $this->serialized($force, null);
        } finally {
            if ($shared !== null) {
                flock($shared, LOCK_UN);
                fclose($shared);
            }
        }
    }

    /** @return array<string,mixed> one pass under the reconcile lock */
    private function serialized(bool $force, ?string $expectedDigest): array
    {
        $lock = $this->lock();
        try {
            return $this->pass($force, $expectedDigest);
        } finally {
            if ($lock !== null) {
                flock($lock, LOCK_UN);
                fclose($lock);
            }
        }
    }

    /**
     * The service loop: reconcile when events are pending, otherwise every $interval seconds (the fallback
     * for changes without a hook, e.g. edited .htaccess files), with the deadline enforcement of
     * PacedEngine interleaved (the reconciler's engine must be a PacedEngine). One JSON object per pass,
     * enforcement action or error goes to $emit; errors never end the loop.
     * @param \Closure(array<string,mixed>):void $emit
     */
    public function watch(int $interval, \Closure $emit, ?int $rounds = null): void
    {
        if (!$this->engine instanceof PacedEngine) {
            throw new \LogicException('the service loop needs the paced engine (deadline enforcement)');
        }
        $last = -INF;
        $failed = false;
        for ($round = 0; $rounds === null || $round < $rounds; ++$round) {
            $this->engine->enforceIfDue();
            try {
                $pending = $this->engine->pendingEvents() !== [];
            } catch (\Throwable $error) {
                $emit(['time' => ($this->clock)(), 'error' => self::describe($error)]);
                $pending = false;
            }
            $since = ($this->clock)() - $last;
            if ($since >= $interval || ($pending && (!$failed || $since >= self::RETRY_SECONDS))) {
                try {
                    $result = $this->reconcile();
                    $failed = !in_array($result['action'] ?? null, ['unchanged', 'committed'], true);
                    $emit(['time' => ($this->clock)(), ...$result]);
                } catch (\Throwable $error) {
                    $failed = true;
                    $emit(['time' => ($this->clock)(), 'error' => self::describe($error)]);
                }
                $last = ($this->clock)();
            }
            ($this->sleep)(1);
        }
    }

    /** @return array<string,mixed> */
    private function pass(bool $force, ?string $expectedDigest = null): array
    {
        $folded = $this->engine->foldRestrictions()['folded'];  // before the epoch is read: see the class comment
        $events = $this->engine->pendingEvents();
        // Malformed entries go to quarantine whatever this pass's outcome; only valid ones wait for consumption.
        $malformed = array_values(array_filter($events, static fn(array $e): bool => array_key_exists('error', $e)));
        $events = array_values(array_filter($events, static fn(array $e): bool => !array_key_exists('error', $e)));
        $quarantineError = null;
        if ($malformed !== []) {
            try {
                $this->engine->eventsQuarantine(array_column($malformed, 'name'));
            } catch (EngineError $error) {
                $quarantineError = self::describe($error);
            }
        }
        $started = ($this->clock)();
        $epoch = $this->engine->status()['epoch'] ?? null;  // first: see the class comment
        if (!is_int($epoch) || $epoch < 0) {
            throw new ReconcileRefused('restriction epoch unknown (damaged epoch record): nothing is current');
        }
        $profile = $this->profile();
        $compiled = ($this->compile)($profile, $this->engine);
        // FV-10: never a configuration whose lsphp does not exist; the vhost keeps its working configuration meanwhile.
        $phpKept = [];
        if ($this->php !== null) {
            [$compiled, $phpKept] = $this->php->apply($compiled);
        }
        if ($this->planSeen !== null) {
            try {
                ($this->planSeen)($compiled['plan']);
            } catch (\Throwable) {
                // Only a trigger; the timer runs the hybrid trust refresh anyway.
            }
        }
        $files = SourceDigest::referencedFiles($compiled, $this->engine);
        if ($expectedDigest !== null && !hash_equals($expectedDigest, CutoverPlan::digest($compiled, $files))) {
            throw new ReconcileRefused('the compiled configuration or a file it references differs from the approved plan; nothing was activated');
        }
        $source = SourceDigest::source($compiled, $epoch, $files);
        $result = ['events' => count($events), 'epoch' => $epoch, 'compile_seconds' => round(($this->clock)() - $started, 1),
            'hybrid_vhosts' => $compiled['summary']['hybrid_vhosts'] ?? []];
        // HR-D14: with a hybrid profile a blocker of one vhost moves only that vhost to Apache; why, in the result.
        $reasons = [];
        foreach (CutoverPlan::hybridVhosts($compiled) as $row) {
            $reasons[$row['vhost']] = $row['reasons'];
        }
        if ($reasons !== []) {
            $result['hybrid_reasons'] = $reasons;
        }
        if (($compiled['summary']['held_vhosts'] ?? []) !== []) {
            $result['held_vhosts'] = $compiled['summary']['held_vhosts'];
        }
        if ($phpKept !== []) {
            $result['php_kept'] = $phpKept;
        }
        if ($folded !== []) {
            $result['restrictions_folded'] = $folded;
        }
        if ($malformed !== []) {
            $result['malformed_events'] = $malformed;
        }
        if ($quarantineError !== null) {
            $result['quarantine_error'] = $quarantineError;
        }
        $state = $this->engine->status();
        if (($state['coherent'] ?? false) !== true) {
            // Repair an interrupted switch or a stopped server before trusting the pointer, keeping the grace
            // for the replacement compiled above.
            $result['recovered'] = $this->engine->recover(self::RECOVER_GRACE)['actions'] ?? [];
            $state = $this->engine->status();
        }
        $healthy = ($state['coherent'] ?? false) === true && $this->engine->health(self::HEALTH_SECONDS)['failing'] === [];
        if (!$force && $healthy && $source === ($state['source_sha256'] ?? null)) {
            $result['action'] = 'unchanged';
        } else {
            $arguments = $this->tree->arguments($compiled, ($this->ids)(), $epoch, $source);
            $outcome = $this->engine->apply($arguments['generation'], $arguments['files'], $arguments['health'], $arguments['epoch'],
                $arguments['source_sha256']);
            $result += ['generation' => $arguments['generation'], 'valid' => $outcome['valid'], 'action' => $outcome['result']];
            if ($arguments['unprobed'] !== []) {
                $result['unprobed'] = $arguments['unprobed'];
            }
            if ($outcome['result'] !== 'committed') {
                $result['reason'] = $outcome['reason'];
                return $result;  // events stay pending; the next pass retries
            }
        }
        if ($events !== []) {
            $this->done(array_column($events, 'name'));
        }
        $result['seconds'] = round(($this->clock)() - $started, 1);
        return $result;
    }

    /** @param list<string> $names */
    private function done(array $names): void
    {
        try {
            $this->engine->eventsDone($names);
        } catch (EngineError $error) {
            if ($error->errorCode !== 'NOT_FOUND') {
                throw $error;
            }
            // A concurrent pass (root CLI beside the service) consumed some: move the rest.
            $left = array_values(array_intersect($names, array_column($this->engine->pendingEvents(), 'name')));
            if ($left !== []) {
                $this->engine->eventsDone($left);
            }
        }
    }

    private function profile(): Profile
    {
        if ($this->profile !== null) {
            $profile = $this->profile;
        } else {
            try {
                $profile = Profile::load($this->profilePath);
            } catch (\RuntimeException $error) {
                throw new ReconcileRefused($error->getMessage() . ': every compile refuses until it is fixed');
            }
            if ($profile === null) {
                throw new ReconcileRefused('not cut over (no deployment profile ' . $this->profilePath . '): nothing to reconcile');
            }
        }
        if (!$profile->production) {
            throw new ReconcileRefused('the deployment profile is not a production profile; the product compiles production listeners only');
        }
        return $profile;
    }

    /** @return resource|null */
    private function lock()
    {
        if ($this->lockPath === null) {
            return null;
        }
        $lock = @fopen($this->lockPath, 'c');
        if ($lock === false) {
            throw new ReconcileRefused("cannot open the reconcile lock {$this->lockPath}");
        }
        if (!flock($lock, LOCK_EX | LOCK_NB)) {
            fclose($lock);
            throw new ReconcileBusy('another reconciliation is running');
        }
        return $lock;
    }

    /**
     * The deployment lock held shared for one pass (root opens or creates it; the reconciler service, in its
     * group, opens it read-only). ReconcileBusy while a deployment operation or recover.sh holds it.
     * @return resource|null
     */
    private function sharedDeploymentLock()
    {
        if ($this->deploymentLockPath === null) {
            return null;
        }
        $lock = @fopen($this->deploymentLockPath, 'c') ?: @fopen($this->deploymentLockPath, 'r');
        if ($lock === false) {
            throw new ReconcileRefused("cannot open the deployment lock {$this->deploymentLockPath}");
        }
        if (!flock($lock, LOCK_SH | LOCK_NB)) {
            fclose($lock);
            throw new ReconcileBusy('a deployment operation or a recovery holds the deployment lock');
        }
        return $lock;
    }

    public static function describe(\Throwable $error): string
    {
        return substr((new \ReflectionClass($error))->getShortName() . ': ' . preg_replace('/[^\x20-\x7e]/', '?', $error->getMessage()), 0, 500);
    }
}
