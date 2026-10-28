<?php
declare(strict_types=1);

namespace OlsCpanel\Ols\Cache;

use OlsCpanel\Ols\Compiler\CachePolicy;

/**
 * LSCache storage primitives (FV-01): statistics and purge of one vhost's store, every store of an account,
 * or every store, inside the root-owned cache tree the compiler names (CachePolicy). Port of
 * build/vm-qualification/lscache.py stats/purge with equal results (tests/lscache.py).
 *
 * Layout (OLS 1.9.3 cachestore.cpp getCacheDirPath): <store>/<h>/<h>/<h>/<16 hex>[.S|.tmp] for public entries
 * and <store>/priv/<h>/<h>/<h>/<16 hex> for private ones; the shared-memory index (.cacheman.*) and anything
 * else in a store is never touched. Deleting an entry file is a miss on the next lookup.
 *
 * Symbolic links are never followed: every path is checked with lstat before it is opened, links and other
 * non-directories are unlinked as such. PHP has no openat(), so a directory swapped for a link between the check
 * and the use is a race; RV-31 item 15 therefore keeps every deletion away from root: statistics only read, and a
 * purge hands each store to a confined unprivileged helper (purgeStore() run by `cache purge-store` after
 * setpriv dropped to the store directory's owner, the OLS server user, with no capabilities and no new privileges).
 * The stores are that user's own (nobody:nobody 2770), so whatever a compromised OLS worker redirects the helper
 * to is something that user could already delete: no privilege is crossed. Root never traverses a store to delete.
 *
 * A purge counts only what it removed (RV-31 item 12): an entry counts once its unlink succeeded, an entry that
 * vanished meanwhile (a concurrent purge or OLS itself) is neither removed nor a failure, and every other failed
 * unlink or rmdir is reported under "failed" for the store.
 */
final class CacheStorage
{
    private const ENTRY = '/^[0-9a-f]{16}(\.S)?$/D';
    private const HASH_DIR = '/^[0-9a-f]$/D';
    private const STORE = '/^([a-z0-9][a-z0-9_.-]*)@([a-z0-9][a-z0-9.-]*)$/D';
    private const TMP = '/^[0-9a-f]{16}\.tmp$/D';
    private const PRIVATE_DIR = 'priv';
    /** Entries modified within this many seconds are never removed by a cleanup (OLS may be writing or just wrote them). */
    public const YOUNG = 60;

    /** The product CLI, run unprivileged by the purge helper (the wrapper that selects cPanel's PHP). */
    public const HELPER_CLI = '/usr/local/ols-cpanel/bin/ols-cpanel';
    public const SETPRIV = '/usr/bin/setpriv';
    private const HELPER_TIMEOUT = 900;

    private string $root;
    private int $owner;
    private CachePolicy $policy;
    /** @var \Closure(string,string,int,int):array<string,mixed> */
    private \Closure $worker;

    /**
     * @param int $owner uid that must own the root (0 in production)
     * @param (\Closure(string,string,int,int):array<string,mixed>)|null $worker purges one store as its owner:
     *        (root, store name, uid, gid) => counts of that store. Default: the confined helper process.
     */
    public function __construct(string $root = CachePolicy::CACHE_ROOT, int $owner = 0, ?CachePolicy $policy = null, ?\Closure $worker = null)
    {
        $this->root = rtrim($root, '/');
        $this->owner = $owner;
        $this->policy = $policy ?? new CachePolicy();
        $this->worker = $worker ?? self::confinedHelper(new \OlsCpanel\Infrastructure\Process\LocalCommandRunner());
    }

    /**
     * The production helper: setpriv drops to the store's owner (never root), clears supplementary groups, all capabilities
     * and the ability to gain privileges, then the product CLI purges that one store. Anything but a complete JSON answer is
     * a failed store (a purge is never assumed to have worked).
     * @return \Closure(string,string,int,int):array<string,mixed>
     */
    public static function confinedHelper(\OlsCpanel\Infrastructure\Process\CommandRunner $runner, string $cli = self::HELPER_CLI): \Closure
    {
        return static function (string $root, string $store, int $uid, int $gid, bool $retire = false) use ($runner, $cli): array {
            $failed = ['public_entries' => 0, 'public_bytes' => 0, 'private_entries' => 0, 'private_bytes' => 0, 'failed' => 1, 'present' => true];
            if ($uid <= 0 || $gid < 0) {
                return $failed + ['error' => "cache store $store is owned by uid $uid: it is not purged as root"];
            }
            $argv = [self::SETPRIV, "--reuid=$uid", "--regid=$gid", '--clear-groups', '--no-new-privs', '--inh-caps=-all', '--bounding-set=-all',
                $cli, 'cache', 'purge-store', "--root=$root", "--store=$store", '--format=json'];
            if ($retire) {
                $argv[] = '--retire';
            }
            $answer = $runner->run('cache-purge-store', $argv, self::HELPER_TIMEOUT);
            $data = $answer['exit_code'] === 0 ? json_decode($answer['stdout'], true) : null;
            if (!is_array($data)) {
                return $failed + ['error' => "the purge helper for $store failed (exit {$answer['exit_code']})"];
            }
            $counts = [];
            foreach (['public_entries', 'public_bytes', 'private_entries', 'private_bytes', 'failed'] as $key) {
                if (!is_int($data[$key] ?? null) || $data[$key] < 0) {
                    return $failed + ['error' => "the purge helper for $store answered unusably"];
                }
                $counts[$key] = $data[$key];
            }
            return $counts + ['present' => ($data['present'] ?? true) === true];
        };
    }

    /**
     * The production helper of the automatic cleanup: like confinedHelper(), `cache clean-store` as the store's owner. Anything but
     * a complete JSON answer is a failed store.
     * @return \Closure(string,string,int,int,int,int,int):array<string,mixed> (root, store, uid, gid, cutoff, cap bytes, now)
     */
    public static function confinedTrimHelper(\OlsCpanel\Infrastructure\Process\CommandRunner $runner, string $cli = self::HELPER_CLI): \Closure
    {
        return static function (string $root, string $store, int $uid, int $gid, int $cutoff, int $cap, int $now) use ($runner, $cli): array {
            $failed = ['files' => 0, 'bytes' => 0, 'failed' => 1, 'remaining_files' => 0, 'remaining_bytes' => 0, 'present' => true];
            if ($uid <= 0 || $gid < 0) {
                return $failed + ['error' => "cache store $store is owned by uid $uid: it is not cleaned as root"];
            }
            $argv = [self::SETPRIV, "--reuid=$uid", "--regid=$gid", '--clear-groups', '--no-new-privs', '--inh-caps=-all', '--bounding-set=-all',
                $cli, 'cache', 'clean-store', "--root=$root", "--store=$store", "--cutoff=$cutoff", "--cap=$cap", "--now=$now", '--format=json'];
            $answer = $runner->run('cache-clean-store', $argv, self::HELPER_TIMEOUT);
            $data = $answer['exit_code'] === 0 ? json_decode($answer['stdout'], true) : null;
            if (!is_array($data)) {
                return $failed + ['error' => "the cleanup helper for $store failed (exit {$answer['exit_code']})"];
            }
            $counts = [];
            foreach (['files', 'bytes', 'failed', 'remaining_files', 'remaining_bytes'] as $key) {
                if (!is_int($data[$key] ?? null) || $data[$key] < 0) {
                    return $failed + ['error' => "the cleanup helper for $store answered unusably"];
                }
                $counts[$key] = $data[$key];
            }
            return $counts + ['present' => ($data['present'] ?? true) === true];
        };
    }

    /**
     * Entries and bytes per store (entries being written, ".tmp", are not counted).
     * @return array<string,array{public_entries:int, public_bytes:int, private_entries:int, private_bytes:int, present:bool}>
     */
    public function stats(?string $account = null, ?string $vhost = null): array
    {
        return $this->run($account, $vhost, false);
    }

    /**
     * Deletes every entry of the selected stores; returns what was removed (and "failed": removals that did not happen, "error"
     * when a store could not be handled at all). Stores and their index stay.
     * @return array<string,array<string,mixed>>
     */
    public function purge(?string $account = null, ?string $vhost = null): array
    {
        return $this->run($account, $vhost, true);
    }

    private function run(?string $account, ?string $vhost, bool $remove): array
    {
        $this->checkRoot();
        $out = [];
        foreach ($this->selected($account, $vhost) as $name) {
            $out[$name] = $remove ? $this->purgeViaHelper($name) : $this->store($name, false);
        }
        return $out;
    }

    /** One store purged by the helper as the store's owner; root only looks at the directory's owner. */
    private function purgeViaHelper(string $name): array
    {
        $info = @lstat("{$this->root}/$name");
        if ($info === false) {
            return ['public_entries' => 0, 'public_bytes' => 0, 'private_entries' => 0, 'private_bytes' => 0, 'failed' => 0, 'present' => false];
        }
        if (($info['mode'] & 0170000) !== 0040000) {
            throw new \InvalidArgumentException("cache store $name is not a directory");
        }
        return ($this->worker)($this->root, $name, $info['uid'], $info['gid']);
    }

    /**
     * Purges one store with the privileges of the calling process: the body of the confined helper (`cache purge-store`),
     * never run as root. The root directory itself was checked by the privileged caller.
     * @return array<string,mixed>
     */
    public function purgeStore(string $name, bool $retire = false): array
    {
        if (preg_match(self::STORE, $name) !== 1 && $name !== CachePolicy::SERVER_STORE) {
            throw new \InvalidArgumentException("invalid cache store name '$name'");
        }
        $counts = $this->store($name, true);
        if ($retire) {
            // Obsolete stores have no live index. Run only in the confined helper, never as root.
            $path = "{$this->root}/$name";
            foreach ($this->listing($path) as $child) {
                $target = "$path/$child";
                if ($this->isDirectory($target)) {
                    $this->walk($target, false, $counts, true);
                    $this->removeDirectory($target, $counts);
                } else {
                    $this->remove($target, $counts);
                }
            }
        }
        return $counts;
    }

    /** Purge obsolete stores as their owner, then remove only the empty top-level directory as root. */
    public function retireUnused(array $keep): array
    {
        $out = [];
        foreach ($this->storeNames() as $name) {
            if ($name === CachePolicy::SERVER_STORE || in_array($name, $keep, true)) {
                continue;
            }
            $owner = $this->storeOwner($name);
            if ($owner === null) {
                continue;
            }
            $counts = ($this->worker)($this->root, $name, $owner[0], $owner[1], true);
            if (($counts['failed'] ?? 1) === 0 && !isset($counts['error'])) {
                if (!@rmdir("{$this->root}/$name") && @lstat("{$this->root}/$name") !== false) {
                    ++$counts['failed'];
                }
            }
            $out[$name] = $counts;
        }
        return $out;
    }

    /**
     * Cleanup of one store (the body of the confined helper `cache clean-store`, run with the store owner's privileges, never as
     * root; the twin of lscache.py trim_store, equal results). Considers the entry files (".S" stale copies and stale ".tmp" files
     * included) below the hash directories and "priv"; links, control files (.cacheman.*) and any other name are never touched.
     * 1. Entries with mtime < $cutoff are removed (expired). 2. If the store still holds more than $capBytes, the oldest entries
     * (mtime, then path) go until it fits. An entry modified in the last YOUNG seconds before $now is never removed. Emptied
     * directories below the store are removed. Counts only what this call removed; "failed" counts removals that did not happen.
     * @return array{files:int, bytes:int, failed:int, remaining_files:int, remaining_bytes:int, present:bool}
     */
    public function trimStore(string $name, int $cutoff, int $capBytes, int $now): array
    {
        if (preg_match(self::STORE, $name) !== 1 && $name !== CachePolicy::SERVER_STORE) {
            throw new \InvalidArgumentException("invalid cache store name '$name'");
        }
        $result = ['files' => 0, 'bytes' => 0, 'failed' => 0, 'remaining_files' => 0, 'remaining_bytes' => 0, 'present' => false];
        $path = "{$this->root}/$name";
        $info = @lstat($path);
        if ($info === false) {
            return $result;
        }
        if (($info['mode'] & 0170000) !== 0040000) {
            throw new \InvalidArgumentException("cache store $name is not a directory");
        }
        $result['present'] = true;
        $young = $now - self::YOUNG;
        $found = [];
        $dirs = [];
        $this->collect($path, $found, $dirs);
        $keep = [];
        foreach ($found as $rel => [$mtime, $size]) {
            if ($mtime < $cutoff && $mtime <= $young && $this->unlinkCounted("$path/$rel", $size, $result)) {
                continue;
            }
            $keep[$rel] = [$mtime, $size];
        }
        $total = array_sum(array_column($keep, 1));
        if ($total > $capBytes) {
            $order = array_keys($keep);
            usort($order, static fn(string $a, string $b): int => [$keep[$a][0], $a] <=> [$keep[$b][0], $b]);
            foreach ($order as $rel) {
                if ($total <= $capBytes) {
                    break;
                }
                if ($keep[$rel][0] <= $young && $this->unlinkCounted("$path/$rel", $keep[$rel][1], $result)) {
                    $total -= $keep[$rel][1];
                    unset($keep[$rel]);
                }
            }
        }
        $result['remaining_files'] = count($keep);
        $result['remaining_bytes'] = (int) array_sum(array_column($keep, 1));
        // Directories this call emptied, deepest first (rmdir refuses a non-empty one; an entry written meanwhile keeps it).
        $touched = [];
        foreach (array_diff_key($found, $keep) as $rel => $_) {
            for ($dir = dirname($rel); $dir !== '.'; $dir = dirname($dir)) {
                $touched[$dir] = true;
            }
        }
        $touched = array_keys($touched);
        usort($touched, static fn(string $a, string $b): int => strlen($b) <=> strlen($a) ?: strcmp($a, $b));
        foreach ($touched as $dir) {
            if (count(@scandir("$path/$dir") ?: []) <= 2) {
                @rmdir("$path/$dir");
            }
        }
        return $result;
    }

    /**
     * What a cleanup could still remove from one store, read only (root may call it; nothing is changed): entry bytes and their
     * modification times grouped by minute, young entries left out (they are never removed).
     * @return array{present:bool, bytes:int, files:int, buckets:array<int,int>}
     */
    public function inventory(string $name, int $now): array
    {
        if (preg_match(self::STORE, $name) !== 1 && $name !== CachePolicy::SERVER_STORE) {
            throw new \InvalidArgumentException("invalid cache store name '$name'");
        }
        $path = "{$this->root}/$name";
        $info = @lstat($path);
        if ($info === false || ($info['mode'] & 0170000) !== 0040000) {
            return ['present' => false, 'bytes' => 0, 'files' => 0, 'buckets' => []];
        }
        $found = [];
        $dirs = [];
        $this->collect($path, $found, $dirs);
        $out = ['present' => true, 'bytes' => 0, 'files' => count($found), 'buckets' => []];
        foreach ($found as [$mtime, $size]) {
            $out['bytes'] += $size;
            if ($mtime <= $now - self::YOUNG) {
                $bucket = intdiv($mtime, 60) * 60;
                $out['buckets'][$bucket] = ($out['buckets'][$bucket] ?? 0) + $size;
            }
        }
        ksort($out['buckets']);
        return $out;
    }

    /**
     * Entry files below a store: relative path => [mtime, size]; "dirs" gets the relative paths of the directories (hash and priv
     * levels). Only the hash directories and "priv" are entered; links and other non-regular files are skipped, never followed.
     * @param array<string,array{0:int,1:int}> $found
     * @param list<string> $dirs
     */
    private function collect(string $store, array &$found, array &$dirs): void
    {
        foreach ($this->listing($store) as $child) {
            if (!preg_match(self::HASH_DIR, $child) && $child !== self::PRIVATE_DIR) {
                continue;
            }
            if ($this->isDirectory("$store/$child")) {
                $this->collectBelow($store, $child, $found, $dirs);
            }
        }
    }

    /** @param array<string,array{0:int,1:int}> $found @param list<string> $dirs */
    private function collectBelow(string $store, string $rel, array &$found, array &$dirs): void
    {
        $dirs[] = $rel;
        foreach ($this->listing("$store/$rel") as $name) {
            $info = @lstat("$store/$rel/$name");
            if ($info === false) {
                continue;
            }
            $type = $info['mode'] & 0170000;
            if ($type === 0040000) {
                $this->collectBelow($store, "$rel/$name", $found, $dirs);
            } elseif ($type === 0100000 && (preg_match(self::ENTRY, $name) === 1 || preg_match(self::TMP, $name) === 1)) {
                $found["$rel/$name"] = [$info['mtime'], $info['size']];
            }
        }
    }

    /** @param array<string,int> $result */
    private function unlinkCounted(string $path, int $size, array &$result): bool
    {
        if (@unlink($path)) {
            ++$result['files'];
            $result['bytes'] += $size;
            return true;
        }
        if (@lstat($path) === false) {
            return true; // gone already (OLS or a purge): not ours to count, not a failure
        }
        ++$result['failed'];
        return false;
    }

    /** Names of the stores below the root (links and non-stores excluded), sorted. @return list<string> */
    public function storeNames(): array
    {
        $this->checkRoot();
        return $this->selected(null, null);
    }

    /** uid and gid of a store directory (what the cleanup helper runs as); null when it is gone. @return array{0:int,1:int}|null */
    public function storeOwner(string $name): ?array
    {
        $info = @lstat("{$this->root}/$name");
        if ($info === false) {
            return null;
        }
        if (($info['mode'] & 0170000) !== 0040000) {
            throw new \InvalidArgumentException("cache store $name is not a directory");
        }
        return [$info['uid'], $info['gid']];
    }

    private function checkRoot(): void
    {
        $info = @lstat($this->root);
        if ($info === false || ($info['mode'] & 0170000) !== 0040000) {
            throw new \InvalidArgumentException("{$this->root} is not a directory");
        }
        if ($info['uid'] !== $this->owner || ($info['mode'] & 0022) !== 0) {
            throw new \InvalidArgumentException("{$this->root} must be owned by uid {$this->owner} and not group/other writable");
        }
    }

    /** @return list<string> */
    private function selected(?string $account, ?string $vhost): array
    {
        if ($vhost !== null) {
            if ($account === null) {
                throw new \InvalidArgumentException('a vhost store needs its account');
            }
            return [$this->policy->storeName($account, $vhost)];
        }
        if ($account !== null && !preg_match(CachePolicy::USER, $account)) {
            throw new \InvalidArgumentException("invalid account '$account'");
        }
        $names = [];
        foreach ($this->listing($this->root) as $name) {
            if ((preg_match(self::STORE, $name, $m) && ($account === null || $m[1] === $account))
                || ($account === null && $name === CachePolicy::SERVER_STORE)) {
                $names[] = $name;
            }
        }
        sort($names, SORT_STRING);
        return $names;
    }

    private function store(string $name, bool $remove): array
    {
        $counts = ['public_entries' => 0, 'public_bytes' => 0, 'private_entries' => 0, 'private_bytes' => 0];
        if ($remove) {
            $counts['failed'] = 0;
        }
        $path = "{$this->root}/$name";
        $info = @lstat($path);
        if ($info === false) {
            return $counts + ['present' => false];
        }
        if (($info['mode'] & 0170000) !== 0040000) {
            throw new \InvalidArgumentException("cache store $name is not a directory");
        }
        $children = $this->listing($path);
        sort($children, SORT_STRING);
        foreach ($children as $child) {
            if (!preg_match(self::HASH_DIR, $child) && $child !== self::PRIVATE_DIR) {
                continue;
            }
            $childPath = "$path/$child";
            if (!$this->isDirectory($childPath)) {
                if ($remove) {
                    $this->remove($childPath, $counts);
                }
                continue;
            }
            $this->walk($childPath, $child === self::PRIVATE_DIR, $counts, $remove);
            if ($remove) {
                $this->removeDirectory($childPath, $counts);
            }
        }
        return $counts + ['present' => true];
    }

    /** @param array<string,int> $counts */
    private function walk(string $directory, bool $private, array &$counts, bool $remove): void
    {
        foreach ($this->listing($directory) as $name) {
            $path = "$directory/$name";
            $info = @lstat($path);
            if ($info === false) {
                continue;
            }
            $type = $info['mode'] & 0170000;
            if ($type === 0040000) {
                $this->walk($path, $private, $counts, $remove);
                if ($remove) {
                    $this->removeDirectory($path, $counts);
                }
                continue;
            }
            // With a removal an entry counts only once it is gone by our unlink.
            if ($remove && !$this->remove($path, $counts)) {
                continue;
            }
            if ($type === 0100000 && preg_match(self::ENTRY, $name)) {
                $key = $private ? 'private' : 'public';
                ++$counts[$key . '_entries'];
                $counts[$key . '_bytes'] += $info['size'];
            }
        }
    }

    /**
     * Unlinks a path. True when this call removed it; false when it was gone already (not a failure) or could not be
     * removed (counted in "failed").
     * @param array<string,int> $counts
     */
    private function remove(string $path, array &$counts): bool
    {
        if (@unlink($path)) {
            return true;
        }
        if (@lstat($path) !== false) {
            ++$counts['failed'];
        }
        return false;
    }

    /** rmdir; "gone already" and "not empty" (an entry written meanwhile, or a failure below that was counted) are no failure. @param array<string,int> $counts */
    private function removeDirectory(string $path, array &$counts): void
    {
        if (@rmdir($path) || @lstat($path) === false) {
            return;
        }
        $names = @scandir($path);
        if ($names === false || count($names) <= 2) {
            ++$counts['failed'];
        }
    }

    private function isDirectory(string $path): bool
    {
        $info = @lstat($path);
        return $info !== false && ($info['mode'] & 0170000) === 0040000;
    }

    /** @return list<string> names in a directory that is not a link */
    private function listing(string $directory): array
    {
        if (!$this->isDirectory($directory)) {
            return [];
        }
        $names = @scandir($directory);
        return $names === false ? [] : array_values(array_diff($names, ['.', '..']));
    }
}
