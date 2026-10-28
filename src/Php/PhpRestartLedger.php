<?php
declare(strict_types=1);

namespace OlsCpanel\Php;

use OlsCpanel\Cli\Refused;
use OlsCpanel\Deployment\DeploymentError;
use OlsCpanel\Deployment\Environment;
use OlsCpanel\Deployment\PhpRestart;
use OlsCpanel\Events\HookEntry;

/**
 * The persistent list of PHP worker restarts that are still owed (RV-31 item 8). A running lsphp keeps the
 * extensions and INI values it started with, so every change to a PHP version (OPcache tuning, a redis extension
 * installed, replaced or removed) makes the lsphp processes of EVERY account on that version stale. The change is
 * marked here, durably, BEFORE any restart is attempted; an entry is cleared only after the restart of that
 * account succeeded, and the PHP environment applier retries what is left on every pass (timer, path watcher,
 * `php env repair`), so a failed or interrupted restart is never forgotten.
 *
 * It lives in the PHP environment state (`php-env.json`, key `restarts`):
 *
 *   "restarts": {"ea-php83": {"revision": "<what changed>", "since": <unix time>, "unresolved": false,
 *                             "accounts": {"alice": "<revision the account is owed>", ...}}}
 *
 * `revision` identifies the artifact or configuration the workers must run (the SHA-256 of the INI text or of the
 * redis.so, or a removal marker); marking again with a new revision supersedes the old one for every account. When
 * the accounts of a version cannot be enumerated, the entry is `unresolved` and the enumeration is retried by
 * every settle; nothing is dropped. An account that has no domain on the version any more is dropped (its workers
 * of that version idle out by themselves).
 */
final class PhpRestartLedger
{
    public const KEY = 'restarts';
    private const LOCK = 'php-restarts.lock';

    /** @var \Closure():int */
    private \Closure $clock;

    /**
     * @param string $file the PHP environment state file (php-env.json)
     * @param \Closure(string):(list<string>|null) $accountsOf accounts with a vhost on a version; null when that cannot be told
     * @param \Closure(string):array<string,mixed> $restart restarts the lsphp processes of one account (`php restart --account`)
     */
    public function __construct(private readonly string $file, private readonly \Closure $accountsOf,
                                private readonly \Closure $restart, ?\Closure $clock = null)
    {
        $this->clock = $clock ?? static fn(): int => time();
    }

    /** The ledger of an environment: its state file, restarting through PhpRestart. @param \Closure(string):(list<string>|null) $accountsOf */
    public static function forEnvironment(Environment $env, \Closure $accountsOf): self
    {
        return new self($env->state . '/' . PhpEnvironment::FILE, $accountsOf, static fn(string $account): array => (new PhpRestart($env))->run($account),
            static fn(): int => $env->now());
    }

    public function path(): string
    {
        return $this->file;
    }

    /**
     * Marks every account on $version as owed a restart for $revision. Durable before it returns.
     */
    public function mark(string $version, string $revision): void
    {
        $accounts = ($this->accountsOf)($version);
        $this->update(function (array $restarts) use ($version, $revision, $accounts): array {
            $entry = $restarts[$version] ?? ['revision' => $revision, 'since' => ($this->clock)(), 'unresolved' => false, 'accounts' => []];
            $entry['revision'] = $revision;
            $entry['unresolved'] = $accounts === null;  // retried by every settle until the accounts can be enumerated
            foreach ($accounts ?? [] as $account) {
                $entry['accounts'][$account] = $revision;
            }
            // Everyone already owed a restart is now owed one for the newer revision.
            foreach (array_keys($entry['accounts']) as $account) {
                $entry['accounts'][$account] = $revision;
            }
            $restarts[$version] = $entry;
            return $restarts;
        });
    }

    /**
     * Tries every owed restart (of one version, or all) and clears what succeeded.
     * @return array{restarted:list<array{account:string, version:string, result:string}>, pending:array<string,list<string>>, unresolved:list<string>, errors:list<string>}
     */
    public function settle(?string $only = null): array
    {
        $done = [];
        $errors = [];
        foreach (array_keys($this->read()) as $version) {
            if ($only !== null && $version !== $only) {
                continue;
            }
            $current = ($this->accountsOf)($version);
            if ($current !== null) {
                // Enumeration worked: resolve an unresolved entry and drop accounts that left the version.
                $this->update(function (array $restarts) use ($version, $current): array {
                    if (!isset($restarts[$version])) {
                        return $restarts;
                    }
                    $now = $restarts[$version];
                    foreach ($current as $account) {
                        if (($now['unresolved'] ?? false) === true && !isset($now['accounts'][$account])) {
                            $now['accounts'][$account] = $now['revision'];
                        }
                    }
                    $now['unresolved'] = false;
                    foreach (array_keys($now['accounts']) as $account) {
                        if (!in_array($account, $current, true)) {
                            unset($now['accounts'][$account]);
                        }
                    }
                    $restarts[$version] = $now;
                    return $restarts;
                });
            }
        }
        $restartedNow = [];
        foreach ($this->read() as $version => $entry) {
            if ($only !== null && $version !== $only) {
                continue;
            }
            foreach ($entry['accounts'] as $account => $revision) {
                // `php restart --account` ends the lsphp of every version of the account, so one success settles all marks made before it.
                $result = ($restartedNow[$account] ?? false) === true ? 'restarted' : $this->restartOne($account, $errors);
                if ($result === 'restarted' || $result === 'gone') {
                    $restartedNow[$account] = $result === 'restarted' ? true : ($restartedNow[$account] ?? false);
                    $this->clear($version, $account, $revision);
                }
                $done[] = ['account' => $account, 'version' => $version, 'result' => $result];
            }
        }
        $pending = [];
        $unresolved = [];
        foreach ($this->read() as $version => $entry) {
            if ($only !== null && $version !== $only) {
                continue;
            }
            if ($entry['accounts'] !== []) {
                $pending[$version] = array_keys($entry['accounts']);
            }
            if ($entry['unresolved']) {
                $unresolved[] = $version;
            }
        }
        return ['restarted' => $done, 'pending' => $pending, 'unresolved' => $unresolved, 'errors' => $errors];
    }

    /** What is still owed. @return array<string,array{revision:string, since:int, unresolved:bool, accounts:array<string,string>}> */
    public function pending(): array
    {
        return array_filter($this->read(), static fn(array $e): bool => $e['accounts'] !== [] || $e['unresolved']);
    }

    /** One line per version for an error message. @param array{pending:array<string,list<string>>, unresolved:list<string>} $report */
    public static function describe(array $report): string
    {
        $parts = [];
        foreach ($report['pending'] as $version => $accounts) {
            $parts[] = "$version: " . implode(', ', array_slice($accounts, 0, 5)) . (count($accounts) > 5 ? ' and ' . (count($accounts) - 5) . ' more' : '');
        }
        foreach ($report['unresolved'] as $version) {
            $parts[] = "$version: accounts not enumerable";
        }
        return 'lsphp restart pending (' . implode('; ', $parts) . ')';
    }

    // --- Persistence ------------------------------------------------------------------------------------------------

    /** @param list<string> $errors @return string restarted | gone | failed */
    private function restartOne(string $account, array &$errors): string
    {
        try {
            $record = ($this->restart)($account);
            if (($record['result'] ?? '') === 'restarted') {
                return 'restarted';
            }
            $errors[] = "$account: " . ($record['error'] ?? 'the original lsphp processes are still running');
        } catch (DeploymentError | Refused $error) {
            if (str_starts_with($error->getMessage(), 'unknown account')) {
                return 'gone';  // the system account no longer exists: there is nothing to restart
            }
            $errors[] = "$account: " . substr(preg_replace('/[^\x20-\x7e]/', '?', $error->getMessage()) ?? '', 0, 200);
        } catch (\Throwable $error) {
            $errors[] = "$account: " . substr(preg_replace('/[^\x20-\x7e]/', '?', $error->getMessage()) ?? '', 0, 200);
        }
        return 'failed';
    }

    private function clear(string $version, string $account, string $revision): void
    {
        $this->update(static function (array $restarts) use ($version, $account, $revision): array {
            // A newer revision marked in the meantime keeps the account pending.
            if (($restarts[$version]['accounts'][$account] ?? null) === $revision) {
                unset($restarts[$version]['accounts'][$account]);
                if ($restarts[$version]['accounts'] === [] && ($restarts[$version]['unresolved'] ?? false) !== true) {
                    unset($restarts[$version]);
                }
            }
            return $restarts;
        });
    }

    /** @return array<string,array{revision:string, since:int, unresolved:bool, accounts:array<string,string>}> */
    public function read(): array
    {
        $data = $this->raw();
        $out = [];
        foreach (is_array($data[self::KEY] ?? null) ? $data[self::KEY] : [] as $version => $entry) {
            if (!is_string($version) || preg_match(OpcacheManager::VERSION, $version) !== 1 || !is_array($entry) || !is_string($entry['revision'] ?? null)
                || !is_array($entry['accounts'] ?? null)) {
                continue;
            }
            $accounts = [];
            foreach ($entry['accounts'] as $account => $revision) {
                if (is_string($account) && preg_match(PhpRestart::ACCOUNT, $account) === 1 && is_string($revision)) {
                    $accounts[$account] = $revision;
                }
            }
            ksort($accounts, SORT_STRING);
            $out[$version] = ['revision' => $entry['revision'], 'since' => is_int($entry['since'] ?? null) ? $entry['since'] : 0,
                'unresolved' => ($entry['unresolved'] ?? false) === true, 'accounts' => $accounts];
        }
        ksort($out, SORT_STRING);
        return $out;
    }

    /** The restarts as they are stored (for the owner of the state file when it rewrites it). */
    public function encoded(): \stdClass
    {
        return self::encode($this->read());
    }

    /** @param array<string,array{revision:string, since:int, unresolved:bool, accounts:array<string,string>}> $restarts */
    private static function encode(array $restarts): \stdClass
    {
        ksort($restarts, SORT_STRING);
        return (object) array_map(static fn(array $e): array => ['revision' => $e['revision'], 'since' => $e['since'],
            'unresolved' => $e['unresolved'], 'accounts' => (object) $e['accounts']], $restarts);
    }

    /** @return array<string,mixed> */
    private function raw(): array
    {
        $path = $this->path();
        if (!is_file($path) || is_link($path)) {
            return [];
        }
        $data = json_decode((string) @file_get_contents($path, false, null, 0, 1 << 20), true, 12);
        return is_array($data) ? $data : [];
    }

    /** @param \Closure(array<string,mixed>):array<string,mixed> $change read-modify-write of the restarts, under the ledger lock */
    private function update(\Closure $change): void
    {
        $dir = dirname($this->file);
        if (!is_dir($dir) && !@mkdir($dir, 0755, true) && !is_dir($dir)) {
            throw new Refused("cannot create $dir");
        }
        $lock = @fopen("$dir/" . self::LOCK, 'c');
        if ($lock === false || !flock($lock, LOCK_EX)) {
            throw new Refused('cannot take the PHP restart ledger lock');
        }
        try {
            $data = $this->raw();
            if (($data['schema_version'] ?? null) !== 1 || !is_array($data['versions'] ?? null)) {
                $data = ['schema_version' => 1, 'checked_at' => null, 'profile_error' => null, 'versions' => []];
            }
            // An entry with nobody owed and nothing unresolved is finished.
            $restarts = array_filter($change($this->read()), static fn(array $e): bool => $e['accounts'] !== [] || $e['unresolved']);
            ksort($restarts, SORT_STRING);
            $data[self::KEY] = self::encode($restarts);
            $data['versions'] = (object) $data['versions'];
            try {
                HookEntry::writeDurable($this->path(), json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n", 0644);
            } catch (\RuntimeException | \JsonException $error) {
                throw new Refused('cannot write ' . $this->path() . ': ' . $error->getMessage());
            }
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }
}
