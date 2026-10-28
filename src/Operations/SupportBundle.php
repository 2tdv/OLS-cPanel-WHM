<?php
declare(strict_types=1);

namespace OlsCpanel\Operations;

use OlsCpanel\Cli\Refused;
use OlsCpanel\Infrastructure\Process\CommandRunner;

/**
 * The support bundle (FV-07): one tar.gz of product diagnostics that the operator can attach to a support request, made by
 * `ols-cpanel support bundle` (root) and downloaded from the WHM Support view. Contents: package versions, platform facts,
 * `status` and `doctor` reports, the generation list and a reduced summary of the active generation (no document roots, no
 * .htaccess text, no TLS paths), the product's own configuration files and results, the recent audit records, the recent
 * journal of the product's units and the tail of the OpenLiteSpeed error log. Never included: private keys, certificates, the
 * broker's secret, anything under a document root, access logs, cPanel's own databases, the settings of the notification
 * webhook and e-mail addresses. Everything that is included passes through the Redactor (keys, passwords, tokens, URLs'
 * credentials and query strings, e-mail addresses always; IP addresses, domain names and account names unless "anonymize" is
 * switched off). The bundle is bounded (MAX_BYTES), root 0600 in `<state>/support/`, and only the last KEEP are kept.
 */
final class SupportBundle
{
    public const DIR = 'support';
    public const MAX_BYTES = 20 * 1024 * 1024;
    public const KEEP = 3;
    public const NAME = '/^bundle-[0-9]{10}-[0-9a-f]{8}\.tar\.gz$/D';
    public const TAR = '/usr/bin/tar';
    public const JOURNALCTL = '/usr/bin/journalctl';
    /** Product configuration and result files of the state directory that are copied (after redaction). */
    public const STATE_FILES = ['profile.json', 'cache-limits.json', 'cache-clean.json', 'objcache.json', 'php-env.json', 'upgrade.json',
        'update-check.json', 'notify-ledger.json', 'schedule.json', 'notify.json'];
    private const PART_LIMIT = 2 * 1024 * 1024;
    private const TAIL_LIMIT = 4 * 1024 * 1024;

    /** @var \Closure():int */
    private \Closure $clock;

    /** @param (\Closure():int)|null $clock */
    public function __construct(private readonly CommandRunner $runner, private readonly string $state,
                                private readonly string $cli = '/usr/local/ols-cpanel/bin/ols-cpanel',
                                private readonly string $errorLog = '/usr/local/lsws/logs/error.log',
                                private readonly string $userdata = '/etc/userdatadomains', ?\Closure $clock = null)
    {
        $this->clock = $clock ?? static fn(): int => time();
    }

    public function directory(): string
    {
        return $this->state . '/' . self::DIR;
    }

    /** @return list<array{name:string,size:int,created:int}> newest first */
    public function bundles(): array
    {
        $out = [];
        foreach (glob($this->directory() . '/bundle-*.tar.gz') ?: [] as $path) {
            $name = basename($path);
            if (preg_match(self::NAME, $name) === 1 && is_file($path) && !is_link($path)) {
                $out[] = ['name' => $name, 'size' => (int) filesize($path), 'created' => (int) substr($name, 7, 10)];
            }
        }
        usort($out, static fn(array $a, array $b): int => $b['created'] <=> $a['created'] ?: strcmp($b['name'], $a['name']));
        return $out;
    }

    /** @return array<string,mixed> */
    public function create(bool $anonymize = true): array
    {
        $now = ($this->clock)();
        $dir = $this->directory();
        if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) {
            throw new Refused('cannot create the bundle directory');
        }
        @chmod($dir, 0700);
        $work = $dir . '/work-' . bin2hex(random_bytes(6));
        if (!@mkdir($work, 0700)) {
            throw new Refused('cannot create a working directory');
        }
        try {
            [$domains, $accounts] = $this->hosted();
            $redactor = new Redactor($anonymize, $domains, $accounts, $this->salt());
            $files = $this->collect($redactor, $now);
            $total = 0;
            $manifest = [];
            foreach ($files as $name => $content) {
                $content = substr($content, 0, self::TAIL_LIMIT);
                $total += strlen($content);
                if ($total > self::MAX_BYTES - 1024 * 1024) {
                    $content = "[omitted: the bundle size limit was reached]\n";
                }
                file_put_contents("$work/$name", $content);
                @chmod("$work/$name", 0600);
                $manifest[] = ['file' => $name, 'bytes' => strlen($content), 'sha256' => hash('sha256', $content)];
            }
            $meta = ['product' => 'ols-cpanel', 'created' => gmdate('c', $now), 'anonymized' => $anonymize, 'redactions' => $redactor->counts(),
                'limit_bytes' => self::MAX_BYTES, 'files' => $manifest,
                'note' => 'Private keys, certificates, passwords and tokens are removed. E-mail addresses and URL query strings are removed.'
                    . ($anonymize ? ' IP addresses, domain names and account names are replaced by stable placeholders.' : '')];
            file_put_contents("$work/manifest.json", json_encode($meta, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");
            $name = 'bundle-' . sprintf('%010d', $now) . '-' . bin2hex(random_bytes(4)) . '.tar.gz';
            $out = "$dir/$name";
            $tar = $this->runner->run('support-tar', [self::TAR, '-czf', $out, '--owner=0', '--group=0', '-C', $work, '.'], 120);
            if ($tar['exit_code'] !== 0 || !is_file($out)) {
                @unlink($out);
                throw new Refused('the archive could not be made');
            }
            @chmod($out, 0600);
            $size = (int) filesize($out);
            if ($size > self::MAX_BYTES) {
                @unlink($out);
                throw new Refused('the bundle would exceed the size limit of ' . intdiv(self::MAX_BYTES, 1048576) . ' MB');
            }
        } finally {
            $this->remove($work);
        }
        foreach (array_slice($this->bundles(), self::KEEP) as $old) {
            @unlink("$dir/{$old['name']}");
        }
        return ['name' => $name, 'size' => $size, 'created' => $now, 'anonymized' => $anonymize, 'files' => count($manifest) + 1,
            'sha256' => hash_file('sha256', $out), 'redactions' => $redactor->counts()];
    }

    /**
     * Every file of the bundle, redacted. @return array<string,string> name => content
     */
    private function collect(Redactor $r, int $now): array
    {
        $files = [];
        $run = function (string $name, array $argv, int $timeout = 30) use ($r): string {
            $result = $this->runner->run($name, $argv, $timeout);
            return $result['exit_code'] === 0 || $result['stdout'] !== '' ? $result['stdout'] : 'unavailable (exit ' . $result['exit_code'] . ')';
        };
        $versions = ['product: ' . $run('bundle-rpm', ['/usr/bin/rpm', '-q', 'ols-cpanel', 'ols-cpanel-openlitespeed'], 20),
            'cpanel: ' . (self::first('/usr/local/cpanel/version') ?? 'unknown'),
            'os-release: ' . str_replace("\n", '; ', trim(self::first('/etc/os-release', 2048) ?? 'unknown')),
            'kernel: ' . trim($run('bundle-uname', ['/usr/bin/uname', '-r'], 10)), 'php: ' . PHP_VERSION, 'collected: ' . gmdate('c', $now)];
        $files['versions.txt'] = $r->text(implode("\n", $versions) . "\n");
        foreach (['status' => ['status', '--format=json'], 'doctor' => ['doctor', '--read-only', '--format=json'],
                  'generations' => ['generation', 'list', '--format=json']] as $name => $args) {
            $files["$name.json"] = $this->json($r, $run("bundle-$name", [$this->cli, ...$args], 60));
        }
        $summary = StateFile::read($this->state . '/active/summary.json');
        $files['active-summary.json'] = $this->json($r, $summary === null ? '{}' : (json_encode(self::reduced($summary), JSON_UNESCAPED_SLASHES) ?: '{}'));
        foreach (self::STATE_FILES as $file) {
            $data = StateFile::read($this->state . '/' . $file);
            if ($data === null) {
                continue;
            }
            if ($file === 'notify.json') {
                // Only whether notifications are on: never an address or the webhook URL.
                $data = ['enabled' => ($data['emails'] ?? []) !== [] || ($data['webhook'] ?? null) !== null, 'events' => $data['events'] ?? []];
            } elseif ($file === 'schedule.json') {
                $data['entries'] = array_map(static fn($e): array => is_array($e) ? array_diff_key($e, ['digest' => 0]) : [], is_array($data['entries'] ?? null) ? $data['entries'] : []);
            }
            $files[$file] = $this->json($r, json_encode($data, JSON_UNESCAPED_SLASHES) ?: '{}');
        }
        $audit = self::tail($this->state . '/broker-audit.log', 256 * 1024);
        $files['audit-recent.log'] = $r->text(implode("\n", array_slice(explode("\n", trim($audit ?? '')), -300)) . "\n");
        $journal = $this->runner->run('bundle-journal', [self::JOURNALCTL, '--no-pager', '-o', 'short-iso', '-n', '600', '-u', 'ols-cpanel*'], 30);
        $files['journal.log'] = $r->text(substr($journal['stdout'], -self::PART_LIMIT));
        $files['ols-error-log-tail.log'] = $r->text(self::tail($this->errorLog, 512 * 1024) ?? "unavailable\n");
        return $files;
    }

    /** The redacted, pretty JSON of a text that holds one JSON value; text that is not JSON is kept as redacted text. */
    private function json(Redactor $r, string $text): string
    {
        $data = json_decode($text, true, 64);
        return $data === null ? $r->text($text) : json_encode($r->data($data), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE) . "\n";
    }

    /**
     * The summary of a generation without paths and file text. @param array<string,mixed> $summary @return array<string,mixed>
     */
    private static function reduced(array $summary): array
    {
        $vhosts = [];
        foreach (is_array($summary['vhosts'] ?? null) ? $summary['vhosts'] : [] as $name => $v) {
            $vhosts[$name] = is_array($v) ? array_intersect_key($v, ['type' => 0, 'php' => 0, 'php_handler' => 0]) : [];
        }
        $blockers = [];
        foreach (is_array($summary['htaccess_blockers'] ?? null) ? $summary['htaccess_blockers'] : [] as $name => $list) {
            $blockers[$name] = is_array($list) ? count($list) : 0;
        }
        return ['compiled_at' => $summary['compiled_at'] ?? null, 'vhosts' => $vhosts, 'hybrid_vhosts' => $summary['hybrid_vhosts'] ?? [],
            'held_vhosts' => array_map(static fn($v): mixed => $v, is_array($summary['held_vhosts'] ?? null) ? $summary['held_vhosts'] : []),
            'htaccess_blocker_counts' => array_filter($blockers), 'suspended_accounts' => $summary['suspended_accounts'] ?? []];
    }

    /** @return array{0:list<string>,1:list<string>} the domains and the account names of this server */
    private function hosted(): array
    {
        $domains = [(string) gethostname()];
        $accounts = [];
        $text = is_file($this->userdata) && !is_link($this->userdata) ? (string) @file_get_contents($this->userdata, false, null, 0, 16 << 20) : '';
        foreach (explode("\n", $text) as $line) {
            if (preg_match('/^([A-Za-z0-9.-]+): ([a-z0-9_-]+)==/', $line, $m) === 1) {
                $domains[] = $m[1];
                $accounts[] = $m[2];
            }
        }
        $summary = StateFile::read($this->state . '/active/summary.json');
        foreach (is_array($summary['vhosts'] ?? null) ? array_keys($summary['vhosts']) : [] as $name) {
            $domains[] = (string) $name;
        }
        return [array_values(array_unique($domains)), array_values(array_unique($accounts))];
    }

    /** The per-server salt of the placeholders (created on first use, root 0600). */
    private function salt(): string
    {
        $path = $this->state . '/support-salt';
        $salt = is_file($path) && !is_link($path) ? trim((string) @file_get_contents($path, false, null, 0, 256)) : '';
        if (preg_match('/^[0-9a-f]{64}$/D', $salt) !== 1) {
            $salt = bin2hex(random_bytes(32));
            $tmp = $path . '.tmp-' . bin2hex(random_bytes(4));
            if (@file_put_contents($tmp, $salt . "\n") === false || !@chmod($tmp, 0600) || !@rename($tmp, $path)) {
                @unlink($tmp);
            }
        }
        return $salt;
    }

    private static function first(string $path, int $max = 128): ?string
    {
        return is_file($path) && !is_link($path) ? (string) @file_get_contents($path, false, null, 0, $max) : null;
    }

    /** The last $bytes of a regular file (never through a link), from the start of a line. */
    private static function tail(string $path, int $bytes): ?string
    {
        if (is_link($path) || !is_file($path)) {
            return null;
        }
        $size = (int) filesize($path);
        $handle = @fopen($path, 'rb');
        if ($handle === false) {
            return null;
        }
        if ($size > $bytes) {
            fseek($handle, $size - $bytes);
        }
        $text = (string) stream_get_contents($handle, $bytes);
        fclose($handle);
        return $size > $bytes && ($cut = strpos($text, "\n")) !== false ? substr($text, $cut + 1) : $text;
    }

    private function remove(string $path): void
    {
        foreach (glob($path . '/*') ?: [] as $file) {
            @unlink($file);
        }
        @rmdir($path);
    }
}
