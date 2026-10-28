<?php
declare(strict_types=1);

namespace OlsCpanel\Php;

/**
 * Per-account PHP limits (FV-03), the optional operator input /var/lib/ols-cpanel/php-limits.json (root, 0644):
 *
 *   {"defaults": {...}, "accounts": {"olscpa": {"children": 10, "mem_hard_mb": 1024}}, "runaway": {...}}
 *
 * Every limit field is optional. Precedence: built-in values (what the compiler always produced: BUILTIN),
 * then "defaults", then the account's own entry. Without the file the compiler output is unchanged.
 * Fields: children (PHP_LSAPI_CHILDREN, 1-256), max_conns (OLS maxConns, 1-1024, never below children,
 * equal to children unless set), mem_soft_mb / mem_hard_mb (OLS memSoftLimit/memHardLimit; 0 = unlimited,
 * otherwise 64-2047, the ceiling of OLS's limit value, hard not below soft) and proc_soft / proc_hard
 * (procSoftLimit/procHardLimit, 1-65535, soft not below children, hard not below soft). "runaway" holds the
 * detection thresholds of `php processes`: cpu_seconds, rss_mb and min_age_seconds. Anything else, or a
 * value of the wrong type or range, is refused: a broken limits file never reaches a configuration.
 */
final class PhpLimits
{
    public const PATH = '/var/lib/ols-cpanel/php-limits.json';
    public const MAX_BYTES = 65536;
    private const ACCOUNT = '/^[a-z][a-z0-9_-]{0,31}$/D';
    /** What ServerCompiler::vhostConfig emits without an input (memory in bytes). */
    public const BUILTIN = ['children' => 5, 'max_conns' => 5, 'mem_soft' => 0, 'mem_hard' => 0, 'proc_soft' => 400, 'proc_hard' => 500];
    /** Runaway thresholds without an input: cumulative CPU seconds, RSS in MB, minimum process age in seconds. */
    public const RUNAWAY = ['cpu_seconds' => 900, 'rss_mb' => 1024, 'min_age_seconds' => 120];
    private const RANGES = ['children' => [1, 256], 'max_conns' => [1, 1024], 'proc_soft' => [1, 65535], 'proc_hard' => [1, 65535]];
    private const MEMORY_MB = [64, 2047];
    private const RUNAWAY_RANGES = ['cpu_seconds' => [1, 1000000], 'rss_mb' => [16, 1048576], 'min_age_seconds' => [0, 86400]];
    private const FIELDS = ['children', 'max_conns', 'mem_soft_mb', 'mem_hard_mb', 'proc_soft', 'proc_hard'];

    /** @var array<string,int> raw fields of "defaults" */
    private array $defaults = [];
    /** @var array<string,array<string,int>> raw fields per account */
    private array $accounts = [];
    /** @var array{cpu_seconds:int, rss_mb:int, min_age_seconds:int} */
    private array $runaway = self::RUNAWAY;

    /**
     * @param array<string,mixed> $data decoded document
     * @throws \InvalidArgumentException
     */
    public static function fromArray(array $data): self
    {
        $self = new self();
        foreach (array_keys($data) as $key) {
            if (!in_array($key, ['defaults', 'accounts', 'runaway'], true)) {
                throw new \InvalidArgumentException("unknown key $key");
            }
        }
        $self->defaults = self::fields($data['defaults'] ?? [], 'defaults');
        $self->resolve($self->defaults, 'defaults');
        $accounts = $data['accounts'] ?? [];
        if (!is_array($accounts) || ($accounts !== [] && array_is_list($accounts))) {
            throw new \InvalidArgumentException('accounts must be an object');
        }
        foreach ($accounts as $user => $entry) {
            if (preg_match(self::ACCOUNT, (string) $user) !== 1) {
                throw new \InvalidArgumentException('invalid account name ' . substr(preg_replace('/[^\x20-\x7e]/', '?', (string) $user) ?? '', 0, 40));
            }
            $self->accounts[(string) $user] = self::fields($entry, "accounts.$user");
            $self->resolve($self->accounts[(string) $user], "accounts.$user");
        }
        $runaway = $data['runaway'] ?? [];
        if (!is_array($runaway) || ($runaway !== [] && array_is_list($runaway))) {
            throw new \InvalidArgumentException('runaway must be an object');
        }
        foreach ($runaway as $key => $value) {
            if (!isset(self::RUNAWAY_RANGES[$key])) {
                throw new \InvalidArgumentException("unknown runaway field $key");
            }
            [$low, $high] = self::RUNAWAY_RANGES[$key];
            if (!is_int($value) || $value < $low || $value > $high) {
                throw new \InvalidArgumentException("runaway.$key must be a whole number from $low to $high");
            }
            $self->runaway[$key] = $value;
        }
        return $self;
    }

    /**
     * The file at $path; absent means no overrides. Must be a regular file owned by root (or the running user)
     * that no one else can write.
     * @throws \InvalidArgumentException
     */
    public static function load(string $path = self::PATH): self
    {
        if (!file_exists($path) && !is_link($path)) {
            return new self();
        }
        $stat = @lstat($path);
        if ($stat === false || ($stat['mode'] & 0170000) !== 0100000) {
            throw new \InvalidArgumentException("$path is not a regular file");
        }
        $euid = function_exists('posix_geteuid') ? posix_geteuid() : 0;
        if (($stat['mode'] & 0022) !== 0 || !in_array($stat['uid'], [0, $euid], true)) {
            throw new \InvalidArgumentException("$path must be owned by root and writable by no one else");
        }
        $text = @file_get_contents($path, false, null, 0, self::MAX_BYTES + 1);
        if ($text === false || strlen($text) > self::MAX_BYTES) {
            throw new \InvalidArgumentException("$path is unreadable or larger than " . self::MAX_BYTES . ' bytes');
        }
        try {
            $data = json_decode($text, true, 8, JSON_THROW_ON_ERROR);
        } catch (\JsonException $error) {
            throw new \InvalidArgumentException("$path is not valid JSON: " . $error->getMessage());
        }
        if (!is_array($data) || ($data !== [] && array_is_list($data))) {
            throw new \InvalidArgumentException("$path must be a JSON object");
        }
        try {
            return self::fromArray($data);
        } catch (\InvalidArgumentException $error) {
            throw new \InvalidArgumentException("$path is invalid: " . $error->getMessage(), 0, $error);
        }
    }

    /** Root lifecycle pass, serialized by objcache.lock. Only an authoritative account list may prune overrides. */
    public static function reconcileAccounts(string $path, array $users, ?string $old = null, ?string $new = null): void
    {
        if (!file_exists($path) && !is_link($path)) {
            return;
        }
        $limits = self::load($path);
        $before = $limits->accounts;
        if ($old !== null && $new !== null && isset($limits->accounts[$old])) {
            $limits->accounts[$new] ??= $limits->accounts[$old];
            unset($limits->accounts[$old]);
        }
        // Prune only after every queued rename has moved its entries, including intermediate names.
        if ($old === null) {
            $limits->accounts = array_intersect_key($limits->accounts, array_fill_keys($users, true));
        }
        if ($limits->accounts !== $before) {
            self::fromArray(['defaults' => $limits->defaults, 'accounts' => $limits->accounts, 'runaway' => $limits->runaway]);
            \OlsCpanel\Events\HookEntry::writeDurable($path, json_encode([
                'defaults' => (object) $limits->defaults, 'accounts' => (object) $limits->accounts,
                'runaway' => $limits->runaway,
            ], JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR) . "\n", 0644);
        }
    }

    /**
     * For read-only views: a broken file gives the built-in set and the reason (the compiler refuses instead).
     * @return array{0:self, 1:?string}
     */
    public static function loadLenient(string $path = self::PATH): array
    {
        try {
            return [self::load($path), null];
        } catch (\InvalidArgumentException $error) {
            return [new self(), $error->getMessage()];
        }
    }

    /** The configured fields as the file spells them (memory in MB), for display. @return array<string,mixed> */
    public function describe(): array
    {
        $accounts = [];
        foreach ($this->accountsWithOverrides() as $user) {
            $accounts[$user] = $this->forAccount($user);
        }
        return ['builtin' => self::BUILTIN, 'overrides' => $this->overrides(), 'accounts' => (object) $accounts, 'runaway' => $this->runaway];
    }

    /**
     * The limits an account's vhosts compile with (memory in bytes).
     * @return array{children:int, max_conns:int, mem_soft:int, mem_hard:int, proc_soft:int, proc_hard:int}
     */
    public function forAccount(string $user): array
    {
        return $this->resolve($this->accounts[$user] ?? [], "accounts.$user");
    }

    /** @return array{cpu_seconds:int, rss_mb:int, min_age_seconds:int} */
    public function runaway(): array
    {
        return $this->runaway;
    }

    /** @return list<string> accounts with their own entry */
    public function accountsWithOverrides(): array
    {
        $names = array_keys($this->accounts);
        sort($names, SORT_STRING);
        return $names;
    }

    /** Whether any limit differs from the built-in values. */
    public function overrides(): bool
    {
        return $this->defaults !== [] || $this->accounts !== [];
    }

    /**
     * @param mixed $entry
     * @return array<string,int>
     */
    private static function fields(mixed $entry, string $where): array
    {
        if (!is_array($entry) || ($entry !== [] && array_is_list($entry))) {
            throw new \InvalidArgumentException("$where must be an object");
        }
        $out = [];
        foreach ($entry as $key => $value) {
            if (!in_array($key, self::FIELDS, true)) {
                throw new \InvalidArgumentException("$where: unknown field $key");
            }
            $memory = str_ends_with($key, '_mb');
            [$low, $high] = $memory ? self::MEMORY_MB : self::RANGES[$key];
            if (!is_int($value) || !(($memory && $value === 0) || ($value >= $low && $value <= $high))) {
                throw new \InvalidArgumentException("$where.$key must be a whole number from $low to $high" . ($memory ? ' or 0 (unlimited)' : ''));
            }
            $out[$key] = $value;
        }
        return $out;
    }

    /**
     * Built-in values, then defaults, then the entry; cross-checked.
     * @param array<string,int> $entry
     * @return array{children:int, max_conns:int, mem_soft:int, mem_hard:int, proc_soft:int, proc_hard:int}
     */
    private function resolve(array $entry, string $where): array
    {
        $merged = $entry + $this->defaults;
        $children = $merged['children'] ?? self::BUILTIN['children'];
        $limits = ['children' => $children, 'max_conns' => $merged['max_conns'] ?? $children,
            'mem_soft' => ($merged['mem_soft_mb'] ?? 0) * 1048576, 'mem_hard' => ($merged['mem_hard_mb'] ?? 0) * 1048576,
            'proc_soft' => $merged['proc_soft'] ?? self::BUILTIN['proc_soft'], 'proc_hard' => $merged['proc_hard'] ?? self::BUILTIN['proc_hard']];
        if ($limits['max_conns'] < $children) {
            throw new \InvalidArgumentException("$where: max_conns must not be below children");
        }
        if ($limits['mem_soft'] !== 0 && $limits['mem_hard'] !== 0 && $limits['mem_hard'] < $limits['mem_soft']) {
            throw new \InvalidArgumentException("$where: mem_hard_mb must not be below mem_soft_mb");
        }
        if ($limits['proc_soft'] < $children || $limits['proc_hard'] < $limits['proc_soft']) {
            throw new \InvalidArgumentException("$where: proc_soft must not be below children and proc_hard not below proc_soft");
        }
        return $limits;
    }
}
