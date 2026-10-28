<?php
declare(strict_types=1);

namespace OlsCpanel\Ols\Generation;

use OlsCpanel\Infrastructure\Process\CommandFailed;
use OlsCpanel\Infrastructure\Process\CommandRunner;
use OlsCpanel\Infrastructure\Process\LocalCommandRunner;

/**
 * The engine for the root CLI: what the broker does for engine.sock, performed directly with the same
 * checks (docs/product-interfaces.md). Commands run through LocalCommandRunner; generations are written
 * under STATE/staging/<generation> and handed to ols-cpanel-activator (`stage`, `validate`, `activate`);
 * status, enforcement, recovery and vhost health are activator commands; the event spool is
 * STATE/events (malformed entries quarantined in STATE/events/quarantine), the hook's restriction intents
 * STATE/restrictions (folded into the epoch with activator `restrict`). Failures carry the broker's error codes (EngineError), so callers see the same codes on
 * either path. Every path is injectable for tests.
 */
final class LocalEngine implements Engine
{
    public const STATE = '/var/lib/ols-cpanel';
    public const ACTIVATOR = '/usr/local/ols-cpanel/libexec/ols-cpanel-activator';
    public const MAX_TREE = 64 * 1024 * 1024;
    public const MAX_EVENTS = 1000;
    /** Spool entries and restriction intents written by HookEntry: <nanoseconds>-<32 hex>.json */
    public const EVENT_NAME = '/^[0-9]{1,24}-[0-9a-f]{32}\.json$/D';
    /** Restriction intents (HookEntry::INTENTS), relative to the state directory. */
    public const RESTRICTIONS = 'restrictions';
    /** A restriction intent is a small JSON object; anything larger is not one (still folded, fail closed). */
    public const MAX_INTENT = 65536;
    /** Activation reloads OLS and waits for every vhost, and may roll back: minutes, never unbounded. */
    private const ACTIVATOR_TIMEOUT = 900;
    private const FILE = '#^(httpd_config\.conf|summary\.json|marker/generation|vhosts/([^/]+)/vhconf\.conf|health/([^/]+)/id)$#D';

    private CommandRunner $runner;

    public function __construct(?CommandRunner $runner = null, private readonly string $state = self::STATE,
                                private readonly string $activator = self::ACTIVATOR)
    {
        $this->runner = $runner ?? new LocalCommandRunner(LocalCommandRunner::MAX_OUTPUT, true);
    }

    public function run(string $name, array $argv, int $timeout): array
    {
        try {
            return $this->runner->run($name, $argv, $timeout);
        } catch (CommandFailed $failure) {
            throw new EngineError($failure->errorCode, $failure->getMessage());
        }
    }

    public function apply(string $generation, array $files, array $health, int $epoch, string $sourceSha256): array
    {
        self::checkTree($generation, $files, $health, $epoch, $sourceSha256);
        if (file_exists("{$this->state}/generations/$generation")) {
            throw new EngineError('EXISTS', "generation $generation exists (generations are immutable)");
        }
        $staging = "{$this->state}/staging";
        if (!is_dir($staging) && !@mkdir($staging, 0700, true)) {
            throw new EngineError('INTERNAL', "cannot create $staging");
        }
        $dir = "$staging/$generation";
        if (file_exists($dir)) {
            throw new EngineError('EXISTS', "staging tree $generation exists");
        }
        try {
            self::writeTree($dir, $files, $health, $epoch, $sourceSha256);
            $this->activator(['stage', $generation, $dir], 'stage');
        } finally {
            self::remove($dir);
        }
        return self::outcome($generation, $this->activator(['validate', $generation], 'validate'),
            fn(): array => $this->activator(['activate', $generation], 'activate'));
    }

    /**
     * Activate an existing generation (operator rollback); the activator refuses one whose validation no
     * longer binds or whose epoch predates the restriction epoch.
     * @return array<string,mixed>
     */
    public function activateExisting(string $generation): array
    {
        if (!preg_match('/^[A-Za-z0-9][A-Za-z0-9_-]*$/D', $generation)) {
            throw new EngineError('BAD_ARGS', 'invalid generation id');
        }
        return $this->activator(['activate', $generation], 'activate');
    }

    public function status(): array
    {
        $status = $this->activator(['status'], 'status');
        $pointer = $status['pointer'] ?? null;
        $source = null;
        if (is_string($pointer) && preg_match('/^[A-Za-z0-9][A-Za-z0-9_-]*$/D', $pointer)) {
            $text = @file_get_contents("{$this->state}/generations/$pointer/SOURCE_SHA256", false, null, 0, 200);
            $source = is_string($text) ? trim($text) : null;
        }
        return $status + ['source_sha256' => $source];
    }

    public function health(int $seconds): array
    {
        return $this->activator(['health', '--seconds', (string) max(0, min(60, $seconds))], 'health');
    }

    public function enforce(int $grace): array
    {
        return $this->activator(['enforce', '--grace', (string) max(0, $grace)], 'enforce');
    }

    public function recover(int $grace): array
    {
        return $this->activator(['recover', '--grace', (string) max(0, $grace)], 'recover');
    }

    public function pendingEvents(): array
    {
        $names = @scandir("{$this->state}/events");
        if ($names === false) {
            return [];
        }
        // Every *.json entry is listed (like the broker); one whose name is not a spool name is malformed.
        $names = array_values(array_filter($names, static fn(string $n): bool => str_ends_with($n, '.json')));
        usort($names, static fn(string $a, string $b): int => [strlen($a), $a] <=> [strlen($b), $b]);
        $out = [];
        foreach (array_slice($names, 0, self::MAX_EVENTS) as $name) {
            if (!preg_match(self::EVENT_NAME, $name)) {
                $out[] = ['name' => $name, 'error' => 'not a spool file name'];
                continue;
            }
            $path = "{$this->state}/events/$name";
            $text = is_link($path) || !is_file($path) ? false : @file_get_contents($path, false, null, 0, 65537);
            $event = is_string($text) && strlen($text) <= 65536 ? json_decode($text, true, 16) : null;
            $out[] = is_array($event) && !array_is_list($event) ? ['name' => $name, 'event' => $event]
                : ['name' => $name, 'error' => $text === false ? 'unreadable spool entry' : 'malformed spool entry'];
        }
        return $out;
    }

    public function eventsDone(array $names): array
    {
        $seen = [];
        foreach ($names as $name) {
            if (!is_string($name) || !preg_match(self::EVENT_NAME, $name) || isset($seen[$name])) {
                throw new EngineError('BAD_ARGS', 'not a spool file name (or repeated)');
            }
            $seen[$name] = true;
            if (!is_file("{$this->state}/events/$name") || is_link("{$this->state}/events/$name")) {
                throw new EngineError('NOT_FOUND', "no spool entry $name");
            }
        }
        $done = "{$this->state}/events/done";
        if (!is_dir($done) && !@mkdir($done, 0700, true)) {
            throw new EngineError('INTERNAL', "cannot create $done");
        }
        foreach ($names as $name) {
            if (!@rename("{$this->state}/events/$name", "$done/$name")) {
                throw new EngineError('INTERNAL', "cannot move spool entry $name");
            }
        }
        return array_values($names);
    }

    public function eventsQuarantine(array $names): array
    {
        $seen = [];
        foreach ($names as $name) {
            // One directory entry of the spool, as engine.events lists it: never a path, "." or "..".
            if (!is_string($name) || !str_ends_with($name, '.json') || strlen($name) > 255 || str_contains($name, '/')
                || str_contains($name, "\0") || isset($seen[$name])) {
                throw new EngineError('BAD_ARGS', 'not a spool entry name (or repeated)');
            }
            $seen[$name] = true;
            if (!file_exists("{$this->state}/events/$name") && !is_link("{$this->state}/events/$name")) {
                throw new EngineError('NOT_FOUND', 'no spool entry ' . substr($name, 0, 200));
            }
        }
        $quarantine = "{$this->state}/events/quarantine";
        if (!is_dir($quarantine) && !@mkdir($quarantine, 0700, true)) {
            throw new EngineError('INTERNAL', "cannot create $quarantine");
        }
        foreach ($names as $name) {
            $target = "$quarantine/$name";
            if (file_exists($target) || is_link($target)) {
                $target .= '.' . bin2hex(random_bytes(8));  // never replace an earlier quarantined entry
            }
            if (!@rename("{$this->state}/events/$name", $target)) {
                throw new EngineError('INTERNAL', 'cannot quarantine spool entry ' . substr($name, 0, 200));
            }
        }
        return array_values($names);
    }

    public function foldRestrictions(): array
    {
        $dir = "{$this->state}/" . self::RESTRICTIONS;
        $names = @scandir($dir);
        if ($names === false) {
            return ['folded' => [], 'epoch' => null];
        }
        $names = array_values(array_filter($names, static fn(string $n): bool => (bool) preg_match(self::EVENT_NAME, $n)));
        usort($names, static fn(string $a, string $b): int => [strlen($a), $a] <=> [strlen($b), $b]);
        $folded = [];
        $epoch = null;
        foreach ($names as $name) {
            $raised = $this->activator(['restrict', self::intentReason("$dir/$name", $name)], 'restrict');
            if (!is_int($raised['epoch'] ?? null)) {
                throw new EngineError('ACTIVATOR', 'activator restrict returned no epoch');
            }
            $epoch = $raised['epoch'];
            // Only now that the raised epoch is durable may the intent go.
            if (!@unlink("$dir/$name")) {
                throw new EngineError('INTERNAL', "cannot remove the folded restriction intent $name");
            }
            self::syncDirectory($dir);
            $folded[] = $name;
        }
        return ['folded' => $folded, 'epoch' => $epoch];
    }

    /**
     * The `restrict` reason of an intent: its "reason" when it is a well-formed intent, otherwise a reason
     * naming the file; an unreadable or malformed intent is still a restriction (fail closed).
     */
    public static function intentReason(string $path, string $name): string
    {
        $text = is_link($path) || !is_file($path) ? false : @file_get_contents($path, false, null, 0, self::MAX_INTENT + 1);
        $intent = is_string($text) && strlen($text) <= self::MAX_INTENT ? json_decode($text, true, 8) : null;
        $reason = is_array($intent) && is_string($intent['reason'] ?? null) ? $intent['reason'] : '';
        $reason = substr(preg_replace('/[^\x20-\x7e]/', '?', $reason) ?? '', 0, 200);
        return $reason !== '' ? $reason : "restriction intent $name (malformed)";
    }

    private static function syncDirectory(string $dir): void
    {
        $handle = @fopen($dir, 'r');
        if ($handle !== false) {
            fsync($handle);
            fclose($handle);
        }
    }

    /**
     * The checks engine.apply makes on its arguments (docs/product-interfaces.md).
     * @param array<string,string> $files
     * @param list<array<string,mixed>> $health
     */
    public static function checkTree(string $generation, array $files, array $health, int $epoch, string $sourceSha256): void
    {
        if (!preg_match(GenerationTree::ID, $generation)) {
            throw new EngineError('BAD_ARGS', 'generation id must be r<YYYYmmddHHMMSS>-<6 hex>');
        }
        if ($epoch < 0 || !preg_match('/^[0-9a-f]{64}$/D', $sourceSha256)) {
            throw new EngineError('BAD_ARGS', 'invalid epoch or source digest');
        }
        $total = 0;
        foreach ($files as $path => $content) {
            $path = (string) $path;
            if (!is_string($content) || !preg_match(self::FILE, $path, $m)
                || (($m[2] ?? '') !== '' && !GenerationTree::validVhost($m[2]))
                || (($m[3] ?? '') !== '' && !GenerationTree::validVhost($m[3]))) {
                throw new EngineError('BAD_ARGS', 'file not allowed in a generation: ' . substr($path, 0, 200));
            }
            $total += strlen($content);
        }
        if ($total > self::MAX_TREE) {
            throw new EngineError('TOO_LARGE', 'files exceed 64 MiB in total');
        }
        if (!array_is_list($health)) {
            throw new EngineError('BAD_ARGS', 'health must be a list');
        }
        foreach ($health as $target) {
            if (!is_array($target) || array_keys($target) !== ['vhost', 'host', 'url'] || !is_string($target['vhost'])
                || !GenerationTree::validVhost($target['vhost']) || !is_string($target['host'])
                || strlen($target['host']) > 253 || !preg_match(GenerationTree::DOMAIN, $target['host']) || !is_string($target['url'])
                || !GenerationTree::validHealthUrl($target['url'])) {
                throw new EngineError('BAD_ARGS', 'malformed health target');
            }
        }
    }

    /**
     * The staged tree: the files, health.json (byte-identical to the lab's `json.dumps(targets, indent=1)`),
     * EPOCH and SOURCE_SHA256; directories 0755, files 0644 like generation_tree.
     * @param array<string,string> $files
     * @param list<array<string,string>> $health
     */
    public static function writeTree(string $dir, array $files, array $health, int $epoch, string $sourceSha256): void
    {
        $all = $files + ['health.json' => GenerationTree::healthJson($health), 'EPOCH' => "$epoch\n", 'SOURCE_SHA256' => "$sourceSha256\n"];
        if (!@mkdir($dir, 0755) || !chmod($dir, 0755)) {
            throw new EngineError('INTERNAL', "cannot create $dir");
        }
        foreach ($all as $path => $content) {
            $target = "$dir/$path";
            $parent = dirname($target);
            if (!is_dir($parent)) {
                if (!@mkdir($parent, 0755, true)) {
                    throw new EngineError('INTERNAL', "cannot create $parent");
                }
                for ($d = $parent; $d !== $dir; $d = dirname($d)) {
                    chmod($d, 0755);
                }
            }
            if (file_put_contents($target, $content) !== strlen($content) || !chmod($target, 0644)) {
                throw new EngineError('INTERNAL', "cannot write $target");
            }
        }
    }

    /**
     * engine.apply's result from the validation verdict and, when valid, the activation.
     * @param array<string,mixed> $validation
     * @param \Closure():array<string,mixed> $activate
     * @return array{generation:string, valid:bool, result:string, reason:mixed}
     */
    public static function outcome(string $generation, array $validation, \Closure $activate): array
    {
        if (($validation['valid'] ?? false) !== true) {
            $report = trim((string) ($validation['report'] ?? '') . "\n" . (string) ($validation['stderr'] ?? ''));
            // The validator's findings name the cause; the report's tail usually has only the harmless last lines.
            $findings = array_values(array_filter((array) ($validation['findings'] ?? []), 'is_string'));
            $reason = $findings !== [] ? 'validation findings: ' . implode(' | ', array_slice($findings, 0, 10)) : substr($report, -1000);
            return ['generation' => $generation, 'valid' => false, 'result' => 'invalid', 'reason' => $reason ?: null];
        }
        $outcome = $activate();
        return ['generation' => $generation, 'valid' => true, 'result' => (string) ($outcome['result'] ?? 'unknown'),
            'reason' => $outcome['reason'] ?? $outcome['failing'] ?? null];
    }

    /**
     * @param list<string> $args
     * @return array<string,mixed>
     */
    private function activator(array $args, string $what): array
    {
        try {
            $result = $this->runner->run("activator-$what", [$this->activator, ...$args], self::ACTIVATOR_TIMEOUT);
        } catch (CommandFailed $failure) {
            throw new EngineError('ACTIVATOR', "activator $what: " . $failure->getMessage());
        }
        $decoded = $result['exit_code'] === 0 ? json_decode(trim($result['stdout']), true, 64) : null;
        if (!is_array($decoded) || array_is_list($decoded) && $decoded !== []) {
            $lines = preg_split('/\n/', trim($result['stderr'] ?? '')) ?: [''];
            throw new EngineError('ACTIVATOR', "activator $what failed (exit {$result['exit_code']}): " . end($lines));
        }
        return $decoded;
    }

    public static function remove(string $path): void
    {
        if (is_link($path) || is_file($path)) {
            @unlink($path);
            return;
        }
        if (!is_dir($path)) {
            return;
        }
        foreach (scandir($path) ?: [] as $name) {
            if ($name !== '.' && $name !== '..') {
                self::remove("$path/$name");
            }
        }
        @rmdir($path);
    }
}
