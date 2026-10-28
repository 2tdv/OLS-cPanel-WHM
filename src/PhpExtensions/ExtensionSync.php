<?php
declare(strict_types=1);

namespace OlsCpanel\PhpExtensions;

use OlsCpanel\Infrastructure\Process\CommandRunner;
use OlsCpanel\Php\PhpRestartLedger;

/**
 * The installer plus the consequence of a change. A running lsphp keeps the extensions it started with, so when a
 * version gained, replaced or lost its redis extension EVERY account with a vhost on that version owes a restart
 * of its lsphp processes. The installer records that obligation durably in the PHP environment state (the restart
 * ledger, Php\PhpRestartLedger) before it changes anything the workers load, and this class then tries the owed
 * restarts (`php restart --account=U`); what fails stays recorded and is retried by the applier on every pass.
 * Accounts are found with WHM API `php_get_vhost_versions`; when that call fails the version is recorded as
 * "accounts unknown" and retried, never as "no accounts".
 */
final class ExtensionSync implements ExtensionService
{
    public const WHMAPI = '/usr/local/cpanel/bin/whmapi1';

    public function __construct(private readonly ExtensionInstaller $installer, private readonly PhpRestartLedger $ledger)
    {
    }

    /** The server wiring: local commands as root, restarts through `php restart`, the ledger in the PHP environment state. */
    public static function production(?\OlsCpanel\Deployment\Environment $env = null): self
    {
        $env ??= \OlsCpanel\Deployment\Environment::production();
        $runner = new \OlsCpanel\Infrastructure\Process\LocalCommandRunner();
        $ledger = self::ledger($env, $runner);
        return new self(new ExtensionInstaller($runner, changed: static fn(string $php, string $revision) => $ledger->mark($php, $revision)), $ledger);
    }

    /** A ledger whose account lists come from WHM, restarting through `$restart` (default `php restart --account`). */
    public static function ledger(\OlsCpanel\Deployment\Environment $env, CommandRunner $runner, ?\Closure $restart = null): PhpRestartLedger
    {
        $accounts = static fn(string $version): ?array => self::accountsOn($runner, $version);
        return $restart === null ? PhpRestartLedger::forEnvironment($env, $accounts)
            : new PhpRestartLedger($env->state . '/' . \OlsCpanel\Php\PhpEnvironment::FILE, $accounts, $restart, static fn(): int => $env->now());
    }

    public function status(): array
    {
        return $this->installer->status();
    }

    public function ensureForAccount(string $user, array $versions): array
    {
        return $this->withRestarts($this->installer->ensure($versions));
    }

    public function ensureVersions(array $versions): array
    {
        return $this->withRestarts($this->installer->ensure($versions));
    }

    public function sync(): array
    {
        return $this->withRestarts($this->installer->sync());
    }

    public function install(?string $only): array
    {
        return $this->withRestarts($this->installer->install($only));
    }

    public function remove(): array
    {
        return $this->withRestarts($this->installer->remove());
    }

    public function want(): void
    {
        $this->installer->want();
    }

    /**
     * Tries every owed restart (the installer already recorded the new ones) and adds the outcome to the report:
     * `restart` per account, `restart_pending` for what is still owed (then the result is a failure).
     * @param array<string,mixed> $report
     * @return array<string,mixed>
     */
    private function withRestarts(array $report): array
    {
        try {
            $settled = $this->ledger->settle();
        } catch (\Throwable $error) {
            $report['result'] = 'failed';
            $report['restart'] = [];
            $report['restart_error'] = substr(preg_replace('/[^\x20-\x7e]/', '?', $error->getMessage()) ?? '', 0, 200);
            return $report;
        }
        $restart = [];
        foreach ($settled['restarted'] as $done) {
            $restart[$done['account']] = $done['result'] === 'restarted' ? ['result' => 'restarted']
                : ['result' => 'failed', 'error' => 'the lsphp processes of the account are still running; retried by the next pass'];
        }
        $report['restart'] = $restart;
        if ($settled['pending'] !== [] || $settled['unresolved'] !== []) {
            $report['restart_pending'] = $settled['pending'];
            $report['restart_unresolved'] = $settled['unresolved'];
            $report['result'] = 'failed';
            $report['restart_error'] = PhpRestartLedger::describe($settled);
        }
        return $report;
    }

    /**
     * @return list<string>|null accounts with a vhost on the version; null when WHM cannot tell
     */
    private static function accountsOn(CommandRunner $runner, string $version): ?array
    {
        $done = $runner->run('phpext-vhost-versions', [self::WHMAPI, '--output=json', 'php_get_vhost_versions'], 60);
        $data = json_decode($done['stdout'], true, 16);
        if ($done['exit_code'] !== 0 || !is_array($data) || !is_array($data['data']['versions'] ?? null)) {
            return null;
        }
        $accounts = [];
        foreach ($data['data']['versions'] as $row) {
            if (is_array($row) && is_string($row['account'] ?? null) && ($row['version'] ?? null) === $version
                && preg_match('/^[a-z][a-z0-9_-]{0,31}$/D', $row['account']) === 1) {
                $accounts[$row['account']] = true;
            }
        }
        $names = array_keys($accounts);
        sort($names, SORT_STRING);
        return $names;
    }
}
