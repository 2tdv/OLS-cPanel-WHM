<?php
declare(strict_types=1);

namespace OlsCpanel\Cli;

use OlsCpanel\Broker\BrokerEngine;
use OlsCpanel\Deployment\Profile;
use OlsCpanel\Events\HookEntry;
use OlsCpanel\Events\Reconciler;
use OlsCpanel\Infrastructure\System\PortOwners;
use OlsCpanel\Ols\Cache\CacheCleaner;
use OlsCpanel\Ols\Cache\CacheLimits;
use OlsCpanel\Ols\Cache\CacheManager;
use OlsCpanel\Ols\Cache\CacheStorage;
use OlsCpanel\Ols\Compiler\CachePolicy;
use OlsCpanel\Ols\Generation\Engine;
use OlsCpanel\Ols\Generation\GenerationStore;
use OlsCpanel\Ols\Generation\LocalEngine;
use OlsCpanel\Deployment\HybridHost;
use OlsCpanel\Php\LsphpGuard;

/**
 * Who runs the engine commands and through what: root works directly (LocalEngine), the engine user
 * `olscpanel` (the reconciler service) through engine.sock (BrokerEngine); anyone else is refused.
 * Activator views and operator operations (generation list/inspect, rollback) read root-only state and
 * are root only. Every collaborator is injectable for tests.
 */
final class EngineContext
{
    public const ENGINE_USER = 'olscpanel';

    private ?Engine $engine = null;
    /** @var \Closure(string):Engine */
    private \Closure $engines;

    /**
     * @param (\Closure(string):Engine)|null $engines engine for a role ("root" | "engine")
     * @param (\Closure(Engine, ?string):Reconciler)|null $reconcilers reconciler over an engine with the lock path
     */
    public function __construct(private readonly ?int $uid = null, private readonly ?string $user = null, ?\Closure $engines = null,
                                private readonly ?\Closure $reconcilers = null, private readonly string $state = LocalEngine::STATE,
                                private readonly string $profilePath = Profile::PATH, private readonly string $proc = '/proc',
                                private readonly string $cacheRoot = CachePolicy::CACHE_ROOT, private readonly int $cacheOwner = 0,
                                private readonly ?\Closure $cacheWorker = null, private readonly ?\Closure $trimWorker = null)
    {
        $this->engines = $engines ?? static fn(string $role): Engine => $role === 'root' ? new LocalEngine() : new BrokerEngine();
    }

    /** "root" or "engine"; Refused for anyone else. */
    public function role(): string
    {
        $uid = $this->uid ?? self::effectiveUid();
        if ($uid === 0) {
            return 'root';
        }
        if (($this->user ?? self::userName($uid)) === self::ENGINE_USER) {
            return 'engine';
        }
        throw new Refused('this command runs as root or as the engine user ' . self::ENGINE_USER);
    }

    public function engine(): Engine
    {
        return $this->engine ??= ($this->engines)($this->role());
    }

    /** The local engine (root only): operator operations on the activator. */
    public function local(): LocalEngine
    {
        $this->root();
        $engine = $this->engine();
        if (!$engine instanceof LocalEngine) {
            throw new Refused('this operation needs the local engine');
        }
        return $engine;
    }

    public function root(): void
    {
        try {
            $role = $this->role();
        } catch (Refused) {
            $role = null;
        }
        if ($role !== 'root') {
            throw new Refused('this command runs as root only');
        }
    }

    /** For the confined helpers that must never hold root. */
    public function unprivileged(): void
    {
        if (($this->uid ?? self::effectiveUid()) === 0) {
            throw new Refused('this command never runs as root: it is the unprivileged helper of a root operation');
        }
    }

    public function store(): GenerationStore
    {
        return new GenerationStore($this->state);
    }

    /** LSCache statistics and purge over the cache tree and the active generation's summary (root only). */
    public function cache(): CacheManager
    {
        $this->root();
        return new CacheManager($this->state, new CacheStorage($this->cacheRoot, $this->cacheOwner, null, $this->cacheWorker), $this->cacheRoot);
    }

    /** The automatic LSCache cleanup and its limits (root only). */
    public function cacheCleaner(): CacheCleaner
    {
        $this->root();
        return new CacheCleaner($this->state, new CacheStorage($this->cacheRoot, $this->cacheOwner, null, $this->cacheWorker), $this->cacheRoot, $this->trimWorker);
    }

    public function cacheLimits(): CacheLimits
    {
        $this->root();
        return new CacheLimits($this->state);
    }

    public function ports(): PortOwners
    {
        return new PortOwners($this->proc);
    }

    public function profilePath(): string
    {
        return $this->profilePath;
    }

    public function hook(): HookEntry
    {
        return new HookEntry("{$this->state}/events", null, LocalEngine::ACTIVATOR, "{$this->state}/" . LocalEngine::RESTRICTIONS,
            "{$this->state}/objcache.json");
    }

    /**
     * A reconciler over $engine; root passes are serialized by the reconcile lock, and every pass holds the
     * deployment lock shared (review RV-29 lock order).
     */
    public function reconciler(Engine $engine): Reconciler
    {
        $lock = $this->role() === 'root' ? "{$this->state}/reconcile.lock" : null;
        return $this->reconcilers !== null ? ($this->reconcilers)($engine, $lock)
            : new Reconciler($engine, null, null, null, $this->profilePath, $lock, deploymentLockPath: "{$this->state}/deployment.lock",
                php: new LsphpGuard(stateRoot: $this->state, trigger: self::phpEnvironmentTrigger($engine)),
                planSeen: self::hybridTrustTrigger($engine));
    }

    /**
     * Asks the root PHP environment service to run now (a version without usable lsphp was met), through the engine's
     * allowlisted `systemctl start --no-block`; at most once every two minutes, never failing the pass.
     * @return \Closure(list<string>):void
     */
    private static function phpEnvironmentTrigger(Engine $engine): \Closure
    {
        $last = 0.0;
        return static function (array $versions) use ($engine, &$last): void {
            if (microtime(true) - $last < 120.0) {
                return;
            }
            $last = microtime(true);
            try {
                $engine->run('php-env-trigger', ['/usr/bin/systemctl', 'start', '--no-block', 'ols-cpanel-php.service'], 30);
            } catch (\Throwable) {
                // The timer and the package-transaction watcher run the service anyway.
            }
        };
    }

    /**
     * Asks the root hybrid trust service to run now when a compiled vhost address is not trusted by the installed
     * mod_remoteip include (HR-D14: a new server IP or an account moved to a new IP), through the engine's allowlisted
     * `systemctl start --no-block`; at most once every two minutes, never failing the pass. Without the include
     * (no hybrid profile) nothing is asked.
     * @return \Closure(array<string,array<string,mixed>>):void
     */
    private static function hybridTrustTrigger(Engine $engine): \Closure
    {
        $last = 0.0;
        return static function (array $plan) use ($engine, &$last): void {
            $conf = @file_get_contents(HybridHost::REMOTEIP_CONF, false, null, 0, 1 << 20);
            if ($conf === false || microtime(true) - $last < 120.0
                || array_diff(HybridHost::proxies($plan), HybridHost::trustedIn($conf)) === []) {
                return;
            }
            $last = microtime(true);
            try {
                $engine->run('hybrid-trust-trigger', ['/usr/bin/systemctl', 'start', '--no-block', 'ols-cpanel-hybrid-trust.service'], 30);
            } catch (\Throwable) {
                // The timer runs the service anyway.
            }
        };
    }

    private static function effectiveUid(): int
    {
        if (function_exists('posix_geteuid')) {
            return posix_geteuid();
        }
        // Without the posix extension: /proc/self belongs to the effective user.
        $owner = @fileowner('/proc/self');
        return $owner === false ? -1 : $owner;
    }

    private static function userName(int $uid): ?string
    {
        if (function_exists('posix_getpwuid')) {
            $entry = posix_getpwuid($uid);
            return is_array($entry) ? $entry['name'] : null;
        }
        foreach (@file('/etc/passwd', FILE_IGNORE_NEW_LINES) ?: [] as $line) {
            $fields = explode(':', $line);
            if (count($fields) > 2 && $fields[2] === (string) $uid) {
                return $fields[0];
            }
        }
        return null;
    }
}
