<?php
declare(strict_types=1);

namespace OlsCpanel\Php;

use OlsCpanel\Deployment\DeploymentError;
use OlsCpanel\Deployment\Environment;
use OlsCpanel\Deployment\PhpRestart;

/**
 * Restarts the lsphp of an account whose running processes carry a stale environment (lab 2026-10-28).
 *
 * OLS runs each account's lsphp detached (extProcessor `autoStart 2`), so a graceful reload or a new generation never
 * reaches a running lsphp parent: the `env` lines of the extProcessor only apply to a parent OLS starts. When a product
 * release changed them (release 37 added `LSAPI_MAX_IDLE=10`) the old parent kept the old environment, and a 116 MiB
 * worker stayed five minutes instead of ten seconds until `php restart --all` was run by hand. Nobody has to run it: the
 * PHP environment pass calls this check.
 *
 * Expected: the `env NAME=VALUE` lines inside `extProcessor <user>-php { ... }` of the active generation's tenant vhosts
 * (`<state>/active/vhosts/<vhost>/vhconf.conf`), only for the names the product sets itself (NAMES), and for a user only
 * the names on which every vhost of that user agrees (a vhost without the line counts as a different value, so the name is
 * skipped for that user rather than guessed). Running: `/proc/<pid>/environ` of each `lsphp` process of the user, read
 * with `cat` through the command runner; the pid comes from `pgrep -u <user>` and is digits only, so the only path ever
 * read is /proc/<numeric pid>/environ. A process whose environ cannot be read (it just exited, or is not readable) is
 * skipped, never treated as stale. A user is stale when any compared name is missing or differs in any process; a stale
 * user is restarted once through PhpRestart (the same code as `php restart --account`), which ends only that account's
 * lsphp so OLS starts fresh ones. An account that already matches costs reads only, so the normal pass restarts nothing.
 * Failures are reported and never fatal; at most MAX_PROCESSES environments are read per pass.
 */
final class LsphpEnvironmentCheck
{
    /** The environment names the product sets in an extProcessor (ServerCompiler); nothing else is compared. */
    public const NAMES = ['PHP_LSAPI_CHILDREN', 'LSAPI_MAX_IDLE', 'LSPHP_ENABLE_USER_INI', 'PHP_INI_SCAN_DIR'];
    public const MAX_PROCESSES = 500;
    private const PGREP = '/usr/bin/pgrep';
    private const CAT = '/usr/bin/cat';

    public function __construct(private readonly Environment $env)
    {
    }

    /** @return array{checked:int, restarted:list<string>, errors:list<string>} */
    public function run(): array
    {
        $report = ['checked' => 0, 'restarted' => [], 'errors' => []];
        foreach ($this->expected() as $user => $names) {
            if ($names === [] || $report['checked'] >= self::MAX_PROCESSES) {
                continue;
            }
            try {
                if (!$this->tenant($user)) {
                    continue;
                }
                if (!$this->stale($user, $names, $report['checked'])) {
                    continue;
                }
                $done = (new PhpRestart($this->env))->run($user);
                if ($done['result'] === 'restarted') {
                    $report['restarted'][] = $user;
                } else {
                    $report['errors'][] = "$user: the lsphp restart left {$done['remaining']} process(es) running";
                }
            } catch (DeploymentError $error) {
                $report['errors'][] = "$user: " . substr(preg_replace('/[^\x20-\x7e]/', '?', $error->getMessage()) ?? '', 0, 200);
            }
        }
        return $report;
    }

    /**
     * user => name => value, for the names every vhost of the user agrees on.
     * @return array<string,array<string,string>>
     */
    public function expected(): array
    {
        $seen = [];
        $files = glob($this->env->state . '/active/vhosts/*/vhconf.conf') ?: [];
        sort($files, SORT_STRING);
        foreach ($files as $file) {
            $text = is_file($file) ? @file_get_contents($file, false, null, 0, 4 << 20) : false;
            if (!is_string($text) || preg_match('/^extProcessor\s+(\S+)-php\s*\{\s*$(.*?)^\}/ms', $text, $block) !== 1
                || preg_match(PhpRestart::ACCOUNT, $block[1]) !== 1) {
                continue;
            }
            $values = [];
            foreach (explode("\n", $block[2]) as $line) {
                if (preg_match('/^\s*env\s+([A-Z_][A-Z0-9_]*)=(.*?)\s*$/', $line, $m) === 1 && in_array($m[1], self::NAMES, true)) {
                    $values[$m[1]] = $m[2];
                }
            }
            $seen[$block[1]][] = $values;
        }
        $expected = [];
        foreach ($seen as $user => $vhosts) {
            $expected[$user] = [];
            foreach (self::NAMES as $name) {
                $all = array_map(static fn(array $values): ?string => $values[$name] ?? null, $vhosts);
                if ($all[0] !== null && count(array_unique($all, SORT_REGULAR)) === 1) {
                    $expected[$user][$name] = $all[0];
                }
            }
        }
        return $expected;
    }

    /** A cPanel-range system account (never root or another system user). */
    private function tenant(string $user): bool
    {
        $uid = $this->env->host->run('lsphp-env-uid', ['/usr/bin/id', '-u', $user]);
        $number = trim($uid['stdout']);
        return $uid['exit_code'] === 0 && preg_match('/^\d{1,10}$/D', $number) === 1 && (int) $number >= PhpRestart::MIN_UID;
    }

    /**
     * @param array<string,string> $names
     * @param int $checked running count of environments read, bounded by MAX_PROCESSES
     */
    private function stale(string $user, array $names, int &$checked): bool
    {
        $found = $this->env->host->run('lsphp-env-pids', [self::PGREP, '-u', $user, '-x', PhpRestart::PROCESS]);
        if ($found['exit_code'] !== 0) {
            return false;  // exit 1: no process; anything else: nothing to judge
        }
        foreach (explode("\n", trim($found['stdout'])) as $line) {
            if ($checked >= self::MAX_PROCESSES) {
                return false;
            }
            if (preg_match('/^\d{1,9}$/D', trim($line)) !== 1) {
                continue;
            }
            $read = $this->env->host->run('lsphp-env-read', [self::CAT, '/proc/' . (int) trim($line) . '/environ']);
            if ($read['exit_code'] !== 0 || $read['stdout'] === '') {
                continue;
            }
            ++$checked;
            $running = [];
            foreach (explode("\0", $read['stdout']) as $entry) {
                $at = strpos($entry, '=');
                if ($at !== false && $at > 0) {
                    $running[substr($entry, 0, $at)] = substr($entry, $at + 1);
                }
            }
            foreach ($names as $name => $value) {
                if (($running[$name] ?? null) !== $value) {
                    return true;
                }
            }
        }
        return false;
    }
}
