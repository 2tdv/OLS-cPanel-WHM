<?php
declare(strict_types=1);

namespace OlsCpanel\Ols\Cache;

use OlsCpanel\Ols\Compiler\CachePolicy;

/**
 * Automatic LSCache cleanup (FV-01), run hourly by ols-cpanel-cache-clean.timer as `ols-cpanel cache clean` (root). OLS leaves an
 * expired entry file until the same URL is cached again, so sites with many URLs (query strings, crawlers, variants) would grow
 * without bound and could fill the disk. Per store:
 *  1. entries older (mtime) than CachePolicy::maxEntryAge() are removed (expired);
 *  2. a store above the per-site cap loses its oldest entries until it fits;
 * then, over all stores,
 *  3. above the server-wide cap (server_percent of the filesystem, at most server_max_gb) the oldest entries of the whole server go.
 * When the filesystem has less than 5% free space every cap is halved (emergency). An entry modified in the last 60 s is never
 * removed, control files (.cacheman.*) and links are never touched.
 *
 * Root never deletes: every removal is done by the confined helper (CacheStorage::trimStore through `cache clean-store`, as the
 * store's owner without capabilities), like a purge. Root only reads (the inventory behind the server-wide cut-off). The result
 * of every run is recorded in `<state>/cache-clean.json` (root 0600): when, the caps used, files and bytes removed per store.
 */
final class CacheCleaner
{
    public const STATE_FILE = 'cache-clean.json';
    public const EMERGENCY_FREE_PERCENT = 5;
    /** The activator's lock file in the state directory (flock). */
    public const ACTIVATION_LOCK = 'activation.lock';
    private const BUCKET = 60;

    /** @var \Closure():int */
    private \Closure $clock;
    /** @var \Closure(string):array{0:int,1:int} total and free bytes of the filesystem holding the path */
    private \Closure $disk;
    /** @var \Closure(string,string,int,int,int,int,int):array<string,mixed> */
    private \Closure $worker;

    /**
     * @param (\Closure():int)|null $clock unix time
     * @param (\Closure(string):array{0:int,1:int})|null $disk total and free bytes of the cache's filesystem
     * @param (\Closure(string,string,int,int,int,int,int):array<string,mixed>)|null $worker (root, store, uid, gid, cutoff, cap, now) => counts
     */
    public function __construct(private readonly string $state, private readonly CacheStorage $storage,
                                private readonly string $cacheRoot = CachePolicy::CACHE_ROOT, ?\Closure $worker = null,
                                ?\Closure $clock = null, ?\Closure $disk = null)
    {
        $this->clock = $clock ?? static fn(): int => time();
        $this->disk = $disk ?? static fn(string $path): array => [(int) (@disk_total_space($path) ?: 0), (int) (@disk_free_space($path) ?: 0)];
        $this->worker = $worker ?? CacheStorage::confinedTrimHelper(new \OlsCpanel\Infrastructure\Process\LocalCommandRunner());
    }

    /** @return array<string,mixed> */
    public function clean(): array
    {
        $now = ($this->clock)();
        $plan = $this->plan($now);
        $stores = [];
        [$retired, $retirementSkipped] = $this->retireObsolete();
        $names = is_dir($this->cacheRoot) && !is_link($this->cacheRoot) ? $this->storage->storeNames() : [];
        foreach ($names as $name) {
            $stores[$name] = $this->trim($name, $plan['expiry_cutoff'], $plan['per_site_bytes'], $now);
        }
        // Server-wide cap, over what is left: the cut-off time is found from the read-only inventory of every store.
        $over = false;
        $inventory = [];
        $remaining = 0;
        $buckets = [];
        foreach ($names as $name) {
            $inventory[$name] = $this->storage->inventory($name, $now);
            $remaining += $inventory[$name]['bytes'];
            foreach ($inventory[$name]['buckets'] as $bucket => $bytes) {
                $buckets[$bucket] = ($buckets[$bucket] ?? 0) + $bytes;
            }
        }
        if ($remaining > $plan['server_bytes']) {
            ksort($buckets);
            $need = $remaining - $plan['server_bytes'];
            $cutoff = null;
            foreach ($buckets as $bucket => $bytes) {
                $need -= $bytes;
                $cutoff = $bucket + self::BUCKET;
                if ($need <= 0) {
                    break;
                }
            }
            $over = $need > 0; // what remains is younger than a minute: it cannot be removed now
            if ($cutoff !== null) {
                foreach ($names as $name) {
                    if (($inventory[$name]['buckets'] !== []) && array_key_first($inventory[$name]['buckets']) < $cutoff) {
                        $stores[$name] = $this->merge($stores[$name], $this->trim($name, $cutoff, PHP_INT_MAX, $now));
                    }
                }
            }
        }
        $totals = ['stores' => count($stores), 'files' => 0, 'bytes' => 0, 'failed' => 0, 'remaining_bytes' => 0];
        foreach ($stores as $row) {
            $totals['files'] += $row['files'];
            $totals['bytes'] += $row['bytes'];
            $totals['failed'] += $row['failed'];
            $totals['remaining_bytes'] += $row['remaining_bytes'];
        }
        foreach ($retired as $row) {
            $totals['failed'] += $row['failed'] ?? 1;
        }
        $report = ['retired_stores' => $retired, 'retirement_skipped' => $retirementSkipped, 'result' => $totals['failed'] > 0 ? 'partial' : 'cleaned', 'last_run' => $now, 'emergency' => $plan['emergency'],
            'over_server_cap' => $over, 'limits' => $plan['limits'], 'limits_problem' => $plan['problem'],
            'per_site_bytes' => $plan['per_site_bytes'], 'server_bytes' => $plan['server_bytes'],
            'filesystem' => $plan['filesystem'], 'totals' => $totals, 'stores' => $stores];
        $this->record($report);
        return $report;
    }

    /**
     * Retires the stores of vhosts that are not in the active generation. The decision and the retirement both happen while
     * the activation lock (state/activation.lock, the activator's flock) is held, so an activation cannot add a vhost between
     * the moment its store is judged obsolete and the moment it is removed. The lock is only tried (a busy lock means an
     * activation, or another holder, is at work): retirement is then skipped and the next run decides again. Lock order: the
     * cleaner takes no other lock, so the documented order deployment.lock, reconcile.lock, activation.lock cannot be inverted;
     * the lock is held for the retirement only, which is bounded, and an activation waits for it meanwhile.
     * @return array{0:array<string,mixed>,1:?string} the retired stores and the reason retirement was skipped, if it was
     */
    private function retireObsolete(): array
    {
        if (!is_dir($this->cacheRoot) || is_link($this->cacheRoot)) {
            return [[], null];
        }
        $path = $this->state . '/' . self::ACTIVATION_LOCK;
        if (!is_dir($this->state) || is_link($path)) {
            return [[], 'the activation lock is not usable'];
        }
        $previous = umask(0077);
        try {
            $handle = @fopen($path, 'cb');
        } finally {
            umask($previous);
        }
        if ($handle === false) {
            return [[], 'the activation lock cannot be opened'];
        }
        try {
            if (!flock($handle, LOCK_EX | LOCK_NB)) {
                return [[], 'an activation is in progress; retirement is tried again by the next run'];
            }
            $keep = $this->activeStores();
            return [$keep === null ? [] : $this->storage->retireUnused($keep), null];
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
    }

    /** A missing or malformed active summary cannot establish which stores are obsolete. */
    private function activeStores(): ?array
    {
        $text = @file_get_contents($this->state . '/active/summary.json', false, null, 0, 64 * 1024 * 1024);
        $summary = is_string($text) ? json_decode($text, true) : null;
        if (!is_array($summary) || !is_array($summary['vhosts'] ?? null) || !is_array($summary['cache'] ?? null)) {
            return null;
        }
        if (array_diff_key($summary['cache'], $summary['vhosts']) !== []
            || array_diff_key($summary['vhosts'], $summary['cache']) !== []) {
            return null;
        }
        $keep = [];
        foreach ($summary['vhosts'] as $name => $vhost) {
            if (!is_array($vhost) || !is_string($vhost['user'] ?? null)
                || !array_key_exists($name, $summary['cache'])) {
                return null;
            }
            // Keep every extant vhost's store, including suspended and temporarily hybrid vhosts.
            try {
                $keep[] = (new CachePolicy())->storeName($vhost['user'], (string) $name);
            } catch (\InvalidArgumentException) {
                return null;
            }
        }
        return $keep;
    }

    /**
     * The limits in force, the filesystem and the last cleanup (what `cache limits` shows).
     * @return array<string,mixed>
     */
    public function status(): array
    {
        $now = ($this->clock)();
        $plan = $this->plan($now);
        $last = $this->last();
        return ['observed_at' => $now, 'limits' => $plan['limits'], 'defaults' => CacheLimits::DEFAULTS, 'bounds' => CacheLimits::BOUNDS,
            'problem' => $plan['problem'], 'per_site_bytes' => $plan['per_site_bytes'], 'server_bytes' => $plan['server_bytes'],
            'emergency' => $plan['emergency'], 'filesystem' => $plan['filesystem'], 'max_entry_age' => CachePolicy::maxEntryAge(),
            'last_clean' => $last === null ? null : ['last_run' => $last['last_run'], 'result' => $last['result'], 'emergency' => $last['emergency'],
                'totals' => $last['totals']], 'stores' => $last['stores'] ?? []];
    }

    /** @return array<string,mixed>|null the last recorded run */
    public function last(): ?array
    {
        $path = $this->state . '/' . self::STATE_FILE;
        $info = @lstat($path);
        if ($info === false || ($info['mode'] & 0170000) !== 0100000 || $info['size'] > 8 * 1024 * 1024) {
            return null;
        }
        $text = @file_get_contents($path);
        $data = is_string($text) ? json_decode($text, true) : null;
        return is_array($data) && is_int($data['last_run'] ?? null) && is_array($data['totals'] ?? null) ? $data : null;
    }

    /** @return array<string,mixed> */
    private function plan(int $now): array
    {
        $loaded = (new CacheLimits($this->state))->load();
        $limits = $loaded['limits'];
        [$total, $free] = is_dir($this->cacheRoot) ? ($this->disk)($this->cacheRoot) : [0, 0];
        $emergency = $total > 0 && $free * 100 < $total * self::EMERGENCY_FREE_PERCENT;
        $server = $limits['server_max_gb'] * 1024 ** 3;
        if ($total > 0) {
            $server = min($server, intdiv($total * $limits['server_percent'], 100));
        }
        $perSite = $limits['per_site_mb'] * 1024 ** 2;
        if ($emergency) {
            $perSite = intdiv($perSite, 2);
            $server = intdiv($server, 2);
        }
        return ['limits' => $limits, 'problem' => $loaded['problem'], 'emergency' => $emergency, 'per_site_bytes' => $perSite,
            'server_bytes' => $server, 'expiry_cutoff' => $now - CachePolicy::maxEntryAge(),
            'filesystem' => ['total_bytes' => $total, 'free_bytes' => $free,
                'free_percent' => $total > 0 ? round($free * 100 / $total, 1) : null]];
    }

    /** @return array<string,mixed> */
    private function trim(string $name, int $cutoff, int $cap, int $now): array
    {
        $owner = $this->storage->storeOwner($name);
        if ($owner === null) {
            return ['files' => 0, 'bytes' => 0, 'failed' => 0, 'remaining_files' => 0, 'remaining_bytes' => 0, 'present' => false];
        }
        $row = ($this->worker)($this->cacheRoot, $name, $owner[0], $owner[1], $cutoff, $cap, $now);
        return $row;
    }

    /**
     * @param array<string,mixed> $first
     * @param array<string,mixed> $second the later pass: its remaining counts are the ones that stand
     * @return array<string,mixed>
     */
    private function merge(array $first, array $second): array
    {
        $second['files'] += $first['files'];
        $second['bytes'] += $first['bytes'];
        $second['failed'] += $first['failed'];
        if (isset($first['error']) && !isset($second['error'])) {
            $second['error'] = $first['error'];
        }
        return $second;
    }

    /** @param array<string,mixed> $report */
    private function record(array $report): void
    {
        if (!is_dir($this->state)) {
            return;
        }
        $path = $this->state . '/' . self::STATE_FILE;
        $tmp = $path . '.tmp-' . bin2hex(random_bytes(8));
        $handle = @fopen($tmp, 'xb');
        if ($handle === false) {
            return;
        }
        @chmod($tmp, 0600);
        $ok = fwrite($handle, json_encode($report, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n") !== false;
        $ok = fclose($handle) && $ok;
        if (!$ok || !@rename($tmp, $path)) {
            @unlink($tmp);
        }
    }
}
