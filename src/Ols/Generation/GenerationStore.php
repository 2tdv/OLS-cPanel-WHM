<?php
declare(strict_types=1);

namespace OlsCpanel\Ols\Generation;

/**
 * Read-only views of the activator state for the root CLI (`generation list|inspect`, `rollback`): the
 * generations, their validation records and the activation journal (formats of ols_generation.py).
 * Nothing here changes state; activations always go through the activator.
 */
final class GenerationStore
{
    public const NAME = '/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/D';

    public function __construct(private readonly string $state = LocalEngine::STATE)
    {
    }

    /** The generation the active pointer selects, or null. */
    public function pointer(): ?string
    {
        $target = @readlink("{$this->state}/active");
        return $target === false ? null : basename($target);
    }

    /** @return list<array<string,mixed>> every generation, oldest first */
    public function list(): array
    {
        $names = @scandir("{$this->state}/generations") ?: [];
        $names = array_values(array_filter($names, static fn(string $n): bool => (bool) preg_match(self::NAME, $n)));
        sort($names, SORT_STRING);
        $pointer = $this->pointer();
        $committed = array_column(array_filter($this->transactions(), static fn(array $t): bool => ($t['state'] ?? null) === 'committed'), 'new');
        return array_map(fn(string $name): array => [
            'generation' => $name,
            'active' => $name === $pointer,
            'committed' => in_array($name, $committed, true),
            'epoch' => $this->epoch($name),
            'valid' => $this->validation($name)['valid'] ?? null,
            'source_sha256' => $this->text("generations/$name/SOURCE_SHA256"),
        ], $names);
    }

    /** @return array<string,mixed>|null one generation in detail, null when it does not exist */
    public function inspect(string $name): ?array
    {
        if (!preg_match(self::NAME, $name) || !is_dir("{$this->state}/generations/$name")) {
            return null;
        }
        $health = json_decode((string) $this->text("generations/$name/health.json", 16 * 1024 * 1024), true, 8);
        $manifest = json_decode((string) $this->text("generations/$name/MANIFEST.json", 64 * 1024 * 1024), true, 8);
        $config = (string) $this->text("generations/$name/httpd_config.conf", 64 * 1024 * 1024);
        preg_match_all('/^extProcessor apache-http-(\S+) \{$/m', $config, $hybrid);
        return [
            'generation' => $name,
            'active' => $name === $this->pointer(),
            'epoch' => $this->epoch($name),
            'source_sha256' => $this->text("generations/$name/SOURCE_SHA256"),
            'files' => is_array($manifest['files'] ?? null) ? count($manifest['files']) : null,
            'health_targets' => is_array($health) ? $health : null,
            'hybrid_vhosts' => $hybrid[1],
            'validation' => $this->validation($name),
            'transactions' => array_values(array_filter($this->transactions(),
                static fn(array $t): bool => in_array($name, [$t['new'] ?? null, $t['previous'] ?? null, $t['restored'] ?? null], true))),
        ];
    }

    /** @return array<string,mixed>|null the compile summary of a generation (summary.json), null when absent or malformed */
    public function summary(string $name): ?array
    {
        if (!preg_match(self::NAME, $name)) {
            return null;
        }
        $record = json_decode((string) $this->text("generations/$name/summary.json", 16 * 1024 * 1024), true, 64);
        return is_array($record) ? $record : null;
    }

    /** Hybrid vhosts of the active generation (its Apache backends). @return list<string>|null */
    public function activeHybridVhosts(): ?array
    {
        $pointer = $this->pointer();
        return $pointer === null ? null : ($this->inspect($pointer)['hybrid_vhosts'] ?? null);
    }

    /**
     * Rollback candidates: generations of committed activations, newest first, without the active one.
     * The activator decides whether each may still be activated (validation binding, restriction epoch).
     * @return list<string>
     */
    public function rollbackCandidates(): array
    {
        $pointer = $this->pointer();
        $out = [];
        foreach (array_reverse($this->transactions()) as $tx) {
            $gen = $tx['new'] ?? null;
            if (($tx['state'] ?? null) === 'committed' && is_string($gen) && $gen !== $pointer && !in_array($gen, $out, true)
                && preg_match(self::NAME, $gen) && is_dir("{$this->state}/generations/$gen")) {
                $out[] = $gen;
            }
        }
        return $out;
    }

    /** @return list<array<string,mixed>> journal records in transaction order */
    public function transactions(): array
    {
        $records = [];
        foreach (@scandir("{$this->state}/journal") ?: [] as $name) {
            if (str_ends_with($name, '.json')) {
                $record = json_decode((string) $this->text("journal/$name", 1048576), true, 16);
                if (is_array($record)) {
                    $records[] = $record;
                }
            }
        }
        usort($records, static fn(array $a, array $b): int => [$a['seq'] ?? 0, $a['started'] ?? 0] <=> [$b['seq'] ?? 0, $b['started'] ?? 0]);
        return $records;
    }

    private function epoch(string $name): ?int
    {
        $text = $this->text("generations/$name/EPOCH");
        return $text !== null && preg_match('/^[0-9]+$/D', $text) ? (int) $text : null;
    }

    /** @return array<string,mixed>|null */
    private function validation(string $name): ?array
    {
        $record = json_decode((string) $this->text("validations/$name.json", 1048576), true, 8);
        return is_array($record) ? $record : null;
    }

    private function text(string $relative, int $limit = 4096): ?string
    {
        $text = @file_get_contents("{$this->state}/$relative", false, null, 0, $limit);
        return $text === false ? null : trim($text);
    }
}
