<?php
declare(strict_types=1);

namespace OlsCpanel\Ols\Cache;

use OlsCpanel\Ols\Compiler\CachePolicy;

/**
 * The operator's view of LSCache (FV-01): per-store statistics and purge selected by account, domain or the
 * whole server. A domain is mapped to its vhost (and the vhost to its store) through the active generation's
 * summary.json (vhosts, their aliases and the `cache` section); unknown accounts and domains are refused, as is
 * a domain whose vhost has no store (hybrid pass-through). The storage work is CacheStorage's (links never
 * followed, only hash directories and entries touched). Each purge is recorded per store in
 * `<state>/cache-purges.json` (root 0600) so the interfaces can show the last purge; only a store emptied without a failed
 * removal is recorded (a partial or failed purge is reported as such and does not advance `last_purge`).
 */
final class CacheManager
{
    public const LEDGER = 'cache-purges.json';
    private const SUMMARY_LIMIT = 64 * 1024 * 1024;

    /** @var \Closure():int */
    private \Closure $clock;

    /** @param \Closure():int|null $clock unix time */
    public function __construct(private readonly string $state, private readonly CacheStorage $storage,
                                private readonly string $cacheRoot = CachePolicy::CACHE_ROOT, ?\Closure $clock = null,
                                private readonly CachePolicy $policy = new CachePolicy())
    {
        $this->clock = $clock ?? static fn(): int => time();
    }

    /**
     * @return array<string,mixed>
     * @throws \InvalidArgumentException unknown account or domain, or a domain without a store
     */
    public function stats(?string $account, ?string $domain): array
    {
        [$disk, $stores, $generation] = $this->select($account, $domain, false);
        return ['scope' => $this->scope($account, $domain), 'observed_at' => ($this->clock)(), 'generation' => $generation]
            + $this->report($disk, $stores);
    }

    /**
     * What was removed, per store (RV-31 item 12). `result` is "purged" when every selected store was emptied without a
     * failed removal, "partial" when some removals failed but something was removed, "failed" when nothing could be
     * removed. `last_purge` and the ledger are written only for stores that were purged completely, and `purged_at`
     * is null unless every store was.
     * @return array<string,mixed>
     * @throws \InvalidArgumentException
     */
    public function purge(?string $account, ?string $domain): array
    {
        [$removed, $stores, $generation] = $this->select($account, $domain, true);
        $report = $this->report($removed, $stores);
        $now = ($this->clock)();
        $complete = array_keys(array_filter($removed, static fn(array $c): bool => $c['present'] && ($c['failed'] ?? 0) === 0 && !isset($c['error'])));
        $this->record($complete, $now);
        $failed = 0;
        foreach ($report['stores'] as &$row) {
            $counts = $removed[$row['store']];
            $row['failed'] = (int) ($counts['failed'] ?? 0);
            if (isset($counts['error'])) {
                $row['error'] = (string) $counts['error'];
            }
            $failed += $row['failed'];
            if (in_array($row['store'], $complete, true)) {
                $row['last_purge'] = $now;
            }
        }
        unset($row);
        $incomplete = array_filter($removed, static fn(array $c): bool => $c['present'] && (($c['failed'] ?? 0) > 0 || isset($c['error'])));
        $result = $incomplete === [] ? 'purged' : ($complete !== [] || $report['totals']['entries'] > 0 ? 'partial' : 'failed');
        $report['totals']['failed'] = $failed;
        $error = $result === 'purged' ? null : "the purge is $result: " . max($failed, count($incomplete)) . ' removal(s) failed in ' . count($incomplete)
            . ' store(s) (' . implode(', ', array_keys($incomplete)) . '); the entries that remain were not recorded as purged';
        return ['result' => $result, 'error' => $error, 'scope' => $this->scope($account, $domain),
            'purged_at' => $result === 'purged' ? $now : null, 'generation' => $generation] + $report;
    }

    /** @return array{0:array<string,array<string,mixed>>, 1:array<string,array<string,mixed>>, 2:?string} */
    private function select(?string $account, ?string $domain, bool $remove): array
    {
        if ($account !== null && preg_match(CachePolicy::USER, $account) !== 1) {
            throw new \InvalidArgumentException('invalid account name');
        }
        if ($domain !== null && preg_match(CachePolicy::DOMAIN, $domain) !== 1) {
            throw new \InvalidArgumentException('invalid domain name');
        }
        $summary = $this->summary();
        $known = $summary === null ? [] : $this->known($summary);
        $generation = $summary === null ? null : (($t = @readlink($this->state . '/active')) === false ? null : basename($t));
        $vhost = null;
        if ($domain !== null) {
            if ($summary === null) {
                throw new \InvalidArgumentException('there is no active generation to map the domain to its vhost');
            }
            $vhost = $this->vhostOf($summary, $domain);
            if ($vhost === null) {
                throw new \InvalidArgumentException("unknown domain $domain");
            }
            $owner = (string) $summary['vhosts'][$vhost]['user'];
            if ($account !== null && $account !== $owner) {
                throw new \InvalidArgumentException("domain $domain does not belong to account $account");
            }
            $account = $owner;
            $name = $this->nameFor($summary, $vhost);
            if ($name === null) {
                throw new \InvalidArgumentException("domain $domain is served by Apache and has no cache store");
            }
        } elseif ($account !== null && !$this->accountKnown($account, $known)) {
            throw new \InvalidArgumentException("unknown account $account");
        }
        $disk = [];
        if (is_dir($this->cacheRoot) && !is_link($this->cacheRoot)) {
            try {
                $disk = $vhost !== null ? ($remove ? $this->storage->purge($account, $vhost) : $this->storage->stats($account, $vhost))
                    : ($remove ? $this->storage->purge($account) : $this->storage->stats($account));
            } catch (\InvalidArgumentException $error) {
                throw new \InvalidArgumentException('cache tree: ' . $error->getMessage(), 0, $error);
            }
        }
        $wanted = $vhost !== null ? [$name => $known[$name]] : array_filter($known, static fn(array $k): bool => $account === null || $k['account'] === $account);
        $zero = ['public_entries' => 0, 'public_bytes' => 0, 'private_entries' => 0, 'private_bytes' => 0, 'present' => false];
        foreach ($wanted as $storeName => $_) {
            $disk[$storeName] ??= $zero;
        }
        ksort($disk, SORT_STRING);
        return [$disk, $known, $generation];
    }

    /**
     * @param array<string,array<string,mixed>> $disk
     * @param array<string,array<string,mixed>> $known
     * @return array{stores:list<array<string,mixed>>, totals:array<string,int>}
     */
    private function report(array $disk, array $known): array
    {
        $ledger = $this->ledger();
        $rows = [];
        $totals = ['stores' => 0, 'entries' => 0, 'bytes' => 0, 'private_entries' => 0, 'private_bytes' => 0];
        foreach ($disk as $name => $counts) {
            $meta = $known[$name] ?? $this->parse($name);
            $entries = $counts['public_entries'] + $counts['private_entries'];
            $bytes = $counts['public_bytes'] + $counts['private_bytes'];
            $rows[] = ['store' => $name, 'account' => $meta['account'], 'vhost' => $meta['vhost'], 'domains' => $meta['domains'],
                'enabled' => $meta['enabled'], 'present' => $counts['present'],
                'public_entries' => $counts['public_entries'], 'public_bytes' => $counts['public_bytes'],
                'private_entries' => $counts['private_entries'], 'private_bytes' => $counts['private_bytes'],
                'entries' => $entries, 'bytes' => $bytes, 'last_purge' => $ledger[$name] ?? null];
            $totals['stores'] += $counts['present'] ? 1 : 0;
            $totals['entries'] += $entries;
            $totals['bytes'] += $bytes;
            $totals['private_entries'] += $counts['private_entries'];
            $totals['private_bytes'] += $counts['private_bytes'];
        }
        return ['stores' => $rows, 'totals' => $totals];
    }

    /** @return array{account:?string, vhost:?string, domains:list<string>, enabled:?bool} */
    private function parse(string $name): array
    {
        if ($name === CachePolicy::SERVER_STORE) {
            return ['account' => null, 'vhost' => null, 'domains' => [], 'enabled' => false];
        }
        // A store no active vhost names (a removed account's, or a hashed name of an older generation).
        [$account, $vhost] = explode('@', $name, 2) + [null, null];
        $vhost = is_string($vhost) && !str_starts_with($vhost, 'h-') ? $vhost : null;
        return ['account' => $account, 'vhost' => $vhost, 'domains' => $vhost === null ? [] : [$vhost], 'enabled' => null];
    }

    /** @return array{scope:string, account:?string, domain:?string} */
    private function scope(?string $account, ?string $domain): array
    {
        return ['scope' => $domain !== null ? 'domain' : ($account !== null ? 'account' : 'server'), 'account' => $account, 'domain' => $domain];
    }

    /** @return array<string,mixed>|null the active generation's summary.json */
    private function summary(): ?array
    {
        $path = $this->state . '/active/summary.json';
        $info = @stat($path);
        if ($info === false || $info['size'] > self::SUMMARY_LIMIT) {
            return null;
        }
        $text = @file_get_contents($path);
        $data = is_string($text) ? json_decode($text, true) : null;
        return is_array($data) && is_array($data['vhosts'] ?? null) ? $data : null;
    }

    /**
     * Stores of native vhosts: store name => account, vhost, domains (vhost then aliases), enabled.
     * @param array<string,mixed> $summary
     * @return array<string,array{account:?string, vhost:?string, domains:list<string>, enabled:?bool}>
     */
    private function known(array $summary): array
    {
        $out = [];
        foreach ($summary['vhosts'] as $vhost => $v) {
            $name = is_array($v) ? $this->nameFor($summary, (string) $vhost) : null;
            if ($name === null) {
                continue;
            }
            $aliases = array_values(array_filter((array) ($v['aliases'] ?? []), 'is_string'));
            $out[$name] = ['account' => (string) $v['user'], 'vhost' => (string) $vhost, 'domains' => [(string) $vhost, ...$aliases],
                'enabled' => (bool) ($summary['cache'][$vhost]['enabled'] ?? false)];
        }
        return $out;
    }

    /** The store name of a vhost, null for a vhost with no store (hybrid). @param array<string,mixed> $summary */
    private function nameFor(array $summary, string $vhost): ?string
    {
        $v = $summary['vhosts'][$vhost] ?? null;
        if (!is_array($v) || !is_string($v['user'] ?? null)) {
            return null;
        }
        if (is_array($summary['cache'] ?? null) && array_key_exists($vhost, $summary['cache'])
            && ($summary['cache'][$vhost]['storage'] ?? null) === null) {
            return null;
        }
        try {
            return $this->policy->storeName($v['user'], $vhost);
        } catch (\InvalidArgumentException) {
            return null;
        }
    }

    /** @param array<string,mixed> $summary */
    private function vhostOf(array $summary, string $domain): ?string
    {
        if (isset($summary['vhosts'][$domain]) && is_array($summary['vhosts'][$domain])) {
            return $domain;
        }
        foreach ($summary['vhosts'] as $vhost => $v) {
            if (is_array($v) && in_array($domain, (array) ($v['aliases'] ?? []), true)) {
                return (string) $vhost;
            }
        }
        return null;
    }

    /** @param array<string,array<string,mixed>> $known */
    private function accountKnown(string $account, array $known): bool
    {
        foreach ($known as $k) {
            if ($k['account'] === $account) {
                return true;
            }
        }
        if (!is_dir($this->cacheRoot) || is_link($this->cacheRoot)) {
            return false;
        }
        try {
            return $this->storage->stats($account) !== [];
        } catch (\InvalidArgumentException) {
            return false;
        }
    }

    /** @return array<string,int> store => last purge time */
    private function ledger(): array
    {
        $path = $this->state . '/' . self::LEDGER;
        $text = is_file($path) && !is_link($path) && (int) @filesize($path) <= 4 * 1024 * 1024 ? @file_get_contents($path) : false;
        $data = is_string($text) ? json_decode($text, true) : null;
        $out = [];
        foreach (is_array($data) ? $data : [] as $store => $time) {
            if (is_string($store) && is_int($time)) {
                $out[$store] = $time;
            }
        }
        return $out;
    }

    /** @param list<string> $stores */
    private function record(array $stores, int $time): void
    {
        if ($stores === [] || !is_dir($this->state)) {
            return;
        }
        $ledger = $this->ledger();
        foreach ($stores as $store) {
            $ledger[$store] = $time;
        }
        ksort($ledger, SORT_STRING);
        $path = $this->state . '/' . self::LEDGER;
        $tmp = $path . '.tmp-' . bin2hex(random_bytes(8));
        $handle = @fopen($tmp, 'xb');
        if ($handle === false) {
            return;
        }
        @chmod($tmp, 0600);
        $ok = fwrite($handle, json_encode($ledger, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n") !== false;
        $ok = fclose($handle) && $ok;
        if (!$ok || !@rename($tmp, $path)) {
            @unlink($tmp);
        }
    }
}
