<?php
declare(strict_types=1);

namespace OlsCpanel\Deployment;

use OlsCpanel\Infrastructure\Process\CommandRunner;

/**
 * Observations and checked commands on the host, all through the injected CommandRunner (argv arrays only):
 * cPanel's WHM API, listener owners (ss), Apache's service state, HTTP answers and file states. The same
 * checks the lab procedures used (ols_ownership_probe.owners/owned_by, service_probe COMMANDS).
 */
final class Host
{
    public const WHMAPI = '/usr/local/cpanel/bin/whmapi1';
    public const SYSTEMCTL = '/usr/bin/systemctl';
    /** Process names OLS's listeners carry. */
    public const OLS_PROCESSES = ['litespeed', 'openlitespeed', 'lshttpd'];

    /** @var \Closure(float):void */
    private \Closure $sleep;

    /** @param \Closure(float):void|null $sleep */
    public function __construct(private CommandRunner $runner, ?\Closure $sleep = null)
    {
        $this->sleep = $sleep ?? static function (float $seconds): void {
            usleep((int) ($seconds * 1_000_000));
        };
    }

    /**
     * @param list<string> $argv
     * @return array{exit_code:int, stdout:string, stderr?:string}
     */
    public function run(string $name, array $argv, int $timeout = 120): array
    {
        return $this->runner->run($name, $argv, $timeout);
    }

    /** Exit code 0 or a step failure with the command's last error text. */
    public function must(string $name, array $argv, int $timeout = 120): string
    {
        $record = $this->run($name, $argv, $timeout);
        if ($record['exit_code'] !== 0) {
            throw DeploymentError::step($name, 'exit ' . $record['exit_code'] . ' ' . self::tail($record['stderr'] ?? ''));
        }
        return $record['stdout'];
    }

    public function sleep(float $seconds): void
    {
        ($this->sleep)($seconds);
    }

    /** Polls $condition up to $tries times, $interval seconds apart. */
    public function waitFor(callable $condition, int $tries, float $interval): bool
    {
        for ($attempt = 1; $attempt <= $tries; ++$attempt) {
            if ($condition()) {
                return true;
            }
            if ($attempt < $tries) {
                $this->sleep($interval);
            }
        }
        return false;
    }

    /**
     * A successful WHM API v1 call (metadata.result 1 for exactly this command); its "data".
     * @param list<string> $args key=value arguments
     * @return array<string,mixed>
     */
    public function api(string $name, string $command, array $args = []): array
    {
        $record = $this->run($name, [self::WHMAPI, '--output=json', $command, ...$args]);
        if ($record['exit_code'] !== 0) {
            throw DeploymentError::step($name, "WHM API $command failed (exit {$record['exit_code']})");
        }
        try {
            $data = json_decode($record['stdout'], true, 64, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            throw DeploymentError::step($name, "WHM API $command answered no JSON");
        }
        $metadata = is_array($data) ? ($data['metadata'] ?? null) : null;
        if (!is_array($metadata) || !in_array($metadata['result'] ?? null, [1, '1', true], true)
            || ($metadata['command'] ?? null) !== $command) {
            throw DeploymentError::step($name, "WHM API $command reported a failure: "
                . self::tail(is_array($metadata) ? (string) ($metadata['reason'] ?? '') : ''));
        }
        $result = $data['data'] ?? [];
        return is_array($result) ? $result : [];
    }

    public function getTweak(string $key): string
    {
        $value = $this->api("tweak-get-$key", 'get_tweaksetting', ["key=$key"])['tweaksetting']['value'] ?? null;
        if (!is_string($value) && !is_int($value)) {
            throw DeploymentError::step("tweak-get-$key", 'no value in the answer');
        }
        return (string) $value;
    }

    /** @return array{enabled:bool, monitored:bool, running:bool} Apache's state per WHM servicestatus */
    public function apacheStatus(): array
    {
        $rows = $this->api('httpd-status', 'servicestatus', ['service=httpd'])['service'] ?? null;
        if (!is_array($rows) || count($rows) !== 1 || !is_array($rows[0]) || ($rows[0]['name'] ?? null) !== 'httpd') {
            throw DeploymentError::step('httpd-status', 'no unique Apache status');
        }
        $flag = static fn(mixed $v): bool => in_array($v, [1, '1', true], true);
        return ['enabled' => $flag($rows[0]['enabled'] ?? null), 'monitored' => $flag($rows[0]['monitored'] ?? null),
            'running' => $flag($rows[0]['running'] ?? null)];
    }

    /**
     * Listening TCP sockets on $ports: local address => process names (ss -H -ltnp).
     * @param list<int> $ports
     * @return array<string,list<string>>
     */
    public function listeners(array $ports, string $name = 'listeners'): array
    {
        $filter = '( ' . implode(' or ', array_map(static fn(int $p): string => "sport = :$p", $ports)) . ' )';
        $record = $this->run($name, ['/usr/sbin/ss', '-H', '-ltnp', $filter]);
        if ($record['exit_code'] !== 0) {
            throw DeploymentError::step($name, 'ss failed');
        }
        return self::owners($record['stdout']);
    }

    /** Port 80/443-style ownership: every port listens and only $names hold the sockets. */
    public function ownedBy(array $ports, array $names, string $name = 'listeners'): bool
    {
        $table = $this->listeners($ports, $name);
        foreach ($ports as $port) {
            if (array_filter(array_keys($table), static fn(string $a): bool => str_ends_with($a, ":$port")) === []) {
                return false;
            }
        }
        foreach ($table as $owners) {
            if ($owners === [] || array_diff($owners, $names) !== []) {
                return false;
            }
        }
        return true;
    }

    /** @param list<int> $ports */
    public function free(array $ports, string $name = 'listeners'): bool
    {
        return $this->listeners($ports, $name) === [];
    }

    /** Port of ols_ownership_probe.owners: local address => sorted process names from ss -p output. */
    public static function owners(string $ssText): array
    {
        $result = [];
        foreach (explode("\n", $ssText) as $line) {
            $fields = preg_split('/\s+/', trim($line)) ?: [];
            if (count($fields) < 4 || trim($line) === '') {
                continue;
            }
            $names = [];
            $users = implode(' ', array_slice($fields, 5));
            if (preg_match_all('/\("([^"]+)"/', $users, $match)) {
                $names = $match[1];
            }
            $result[$fields[3]] = array_values(array_unique([...($result[$fields[3]] ?? []), ...$names]));
            sort($result[$fields[3]], SORT_STRING);
        }
        return $result;
    }

    /**
     * Apache verified as the server (review RV-29): enabled, monitored and running per WHM, the only owner of
     * 80/443, and answering on 127.0.0.1. Any failed observation counts as not verified.
     */
    public function apacheServes(): bool
    {
        try {
            if ($this->apacheStatus() !== ['enabled' => true, 'monitored' => true, 'running' => true]
                || !$this->ownedBy([80, 443], ['httpd'], 'apache-owner')) {
                return false;
            }
        } catch (DeploymentError) {
            return false;
        }
        $answer = trim($this->run('apache-answers', ['/usr/bin/curl', '--noproxy', '*', '-s', '-o', '/dev/null', '-m', '10',
            '-w', '%{http_code}', 'http://127.0.0.1/'], 30)['stdout']);
        return preg_match('/^[1-4]\d\d$/D', $answer) === 1;
    }

    /**
     * Keeps a cutover's recovery armed: true when its timer is active or its recovery service runs (a service
     * waiting for the deployment lock runs once the holder releases it); otherwise the timer is armed again with
     * $delay (after clearing a failed unit of the same name) and checked.
     */
    public function keepRecoveryArmed(string $unit, string $script, string $delay): bool
    {
        if ($this->unitActive("$unit.timer", 'recovery-timer-active') || $this->unitActive("$unit.service", 'recovery-service-active')) {
            return true;
        }
        $this->run('recovery-reset', [self::SYSTEMCTL, 'reset-failed', "$unit.timer", "$unit.service"]);
        $this->run('rearm-recovery', ['/usr/bin/systemd-run', "--unit=$unit", "--on-active=$delay", '--timer-property=AccuracySec=1s',
            '/bin/sh', $script]);
        return $this->unitActive("$unit.timer", 'recovery-rearmed');
    }

    /** The unit is verifiably down ("inactive" or "failed"; "activating", "deactivating" or no answer are not). */
    public function unitStopped(string $unit, string $name = 'unit-stopped'): bool
    {
        return in_array(trim($this->run($name, [self::SYSTEMCTL, 'is-active', $unit])['stdout']), ['inactive', 'failed'], true);
    }

    public function unitActive(string $unit, string $name = 'unit-active'): bool
    {
        return trim($this->run($name, [self::SYSTEMCTL, 'is-active', $unit])['stdout']) === 'active';
    }

    /** HTTP status of $scheme://$host/ sent to $ip (curl --resolve); "000" when nothing answered. */
    public function httpStatus(string $scheme, string $host, string $ip, string $name = 'http'): string
    {
        $port = $scheme === 'https' ? 443 : 80;
        $address = str_contains($ip, ':') ? "[$ip]" : $ip;
        $record = $this->run($name, ['/usr/bin/curl', '--noproxy', '*', '-ks', '-o', '/dev/null', '--max-time', '10',
            '-w', '%{http_code}', '--resolve', "$host:$port:$address", "$scheme://$host/"], 30);
        $code = trim($record['stdout']);
        return preg_match('/^\d{3}$/D', $code) ? $code : '000';
    }

    /**
     * "owner:group:mode sha256" of a root-owned regular file, or null when absent. Anything else (a symlink,
     * another owner, a directory) is refused: product backups never read tenant-controlled paths as root.
     */
    public function systemFileState(string $path, string $name = 'file-state'): ?string
    {
        $stat = $this->run($name, ['/usr/bin/stat', '-c', '%F|%U:%G:%a', '--', $path]);
        if ($stat['exit_code'] !== 0) {
            if ($this->run("$name-exists", ['/usr/bin/test', '-e', $path])['exit_code'] !== 0
                && $this->run("$name-link", ['/usr/bin/test', '-L', $path])['exit_code'] !== 0) {
                return null;
            }
            throw DeploymentError::step($name, "cannot read the state of $path");
        }
        [$type, $owner] = explode('|', trim($stat['stdout']), 2) + [1 => ''];
        if ($type !== 'regular file' && $type !== 'regular empty file') {
            throw DeploymentError::step($name, "$path is a $type, not a regular file");
        }
        if (!str_starts_with($owner, 'root:')) {
            throw DeploymentError::step($name, "$path is not owned by root ($owner)");
        }
        $sum = $this->run("$name-sha256", ['/usr/bin/sha256sum', '--', $path]);
        $digest = substr(trim($sum['stdout']), 0, 64);
        if ($sum['exit_code'] !== 0 || !preg_match('/^[0-9a-f]{64}$/D', $digest)) {
            throw DeploymentError::step($name, "cannot digest $path");
        }
        return "$owner $digest";
    }

    public static function tail(string $text): string
    {
        return substr(preg_replace('/[^\x20-\x7e]+/', ' ', trim($text)) ?? '', -300);
    }
}
