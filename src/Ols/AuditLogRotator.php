<?php
declare(strict_types=1);

namespace OlsCpanel\Ols;

use OlsCpanel\Infrastructure\Process\LocalCommandRunner;
use OlsCpanel\Ols\Compiler\SecurityTranslator;

/**
 * Rotation of the ModSecurity audit log `/usr/local/lsws/logs/modsec_audit.log` (RV-57, RV-66). Rotate when the file is over
 * 50 MB, keep four rotated copies compressed with gzip (`modsec_audit.log.1.gz` .. `.4.gz`) and drop older ones.
 *
 * Why not logrotate (0.2.13): the distribution's logrotate.service runs with ProtectSystem=full, which mounts /usr read-only for
 * it, so the rule failed with "Read-only file system" every night and stopped the rotation of every other log of the server.
 *
 * Why OLS cannot do it: OpenLiteSpeed's rollingSize applies to its own error and access logs only. The ModSecurity module
 * (modules/modsecurity-ls) hands SecAuditLog to libmodsecurity, which opens the file once, appends to it and never rolls or
 * reopens it.
 *
 * Which unit runs it: ols-cpanel-cache-clean.service (`cache clean`, hourly), through `CacheCleanCommand`. It is the product's
 * root housekeeping pass with `Nice=19` and idle I/O (compressing 50 MB must never compete with the web server), it runs without
 * a shell in a hardened sandbox, and only needed `ReadWritePaths=-/usr/local/lsws/logs` added (the `-` keeps the unit starting
 * where the directory does not exist). The other candidates do not fit: ols-cpanel.service is OLS itself, the broker and the
 * reconciler are long-running and unprivileged or engine-only, and the notify and schedule units are tied to their own jobs
 * and cadence.
 *
 * How: no line is lost, so no copy-and-truncate. The file is renamed to `.1` (the open handle of OLS follows the inode) and OLS
 * is reloaded gracefully (`systemctl reload ols-cpanel.service`, the product's own SIGUSR1 restart that waits for the new main
 * process): the new workers create a fresh `modsec_audit.log` themselves, with the mode OLS gives it (SecAuditLogFileMode 0600),
 * so this class never creates the live file and never changes its mode. Draining workers may still append to `.1` for a while,
 * so `.1` is compressed by a later pass, once it has been quiet for SETTLE seconds (or at the next rotation, whichever comes
 * first). If the reload fails the file is moved back when no new one exists, so OLS keeps writing to the path it knows.
 *
 * Links are never followed: the live file and every rotated file are inspected with lstat; a link or a non-regular file is left
 * alone (and reported), compressed copies are created exclusively (`x` mode, which fails on an existing path, a link included).
 */
final class AuditLogRotator
{
    public const MAX_BYTES = 50 * 1024 * 1024;
    public const KEEP = 4;
    public const SETTLE = 600;
    private const CHUNK = 1 << 20;

    /** @var \Closure():bool */
    private \Closure $reload;
    /** @var \Closure():int */
    private \Closure $clock;

    /**
     * @param (\Closure():bool)|null $reload graceful OLS reload; true when it succeeded (or OLS is not running)
     * @param (\Closure():int)|null $clock unix time
     */
    public function __construct(private readonly string $log = SecurityTranslator::AUDIT_LOG, ?\Closure $reload = null,
                                ?\Closure $clock = null, private readonly int $maxBytes = self::MAX_BYTES,
                                private readonly int $keep = self::KEEP)
    {
        $this->reload = $reload ?? static function (): bool {
            $runner = new LocalCommandRunner();
            if ($runner->run('ols-active', ['/usr/bin/systemctl', 'is-active', '--quiet', 'ols-cpanel.service'], 15)['exit_code'] !== 0) {
                return true;
            }
            return $runner->run('ols-reload', ['/usr/bin/systemctl', 'reload', 'ols-cpanel.service'], 180)['exit_code'] === 0;
        };
        $this->clock = $clock ?? static fn(): int => time();
    }

    /** @return array<string,mixed> result: 'absent', 'current', 'rotated' or 'failed', plus bytes, rotated, compressed, problems */
    public function rotate(): array
    {
        $dir = dirname($this->log);
        $report = ['log' => $this->log, 'result' => 'current', 'bytes' => 0, 'rotated' => false, 'compressed' => [], 'problems' => []];
        if (is_link($dir) || !is_dir($dir)) {
            $report['result'] = is_link($dir) ? 'failed' : 'absent';
            if (is_link($dir)) {
                $report['problems'][] = 'the log directory is a link';
            }
            return $report;
        }
        $now = ($this->clock)();
        $stat = @lstat($this->log);
        $live = $stat !== false;
        if ($live && ($stat['mode'] & 0170000) !== 0100000) {
            $report['problems'][] = 'the audit log is not a regular file (left alone)';
            $live = false;
        }
        $report['bytes'] = $live ? (int) $stat['size'] : 0;
        // A previous rotation's plain copy is compressed once it is quiet (OLS workers that drained may have appended to it).
        $plain = $this->log . '.1';
        $plainStat = @lstat($plain);
        if ($plainStat !== false && ($plainStat['mode'] & 0170000) === 0100000 && !file_exists($plain . '.gz')
            && $plainStat['mtime'] <= $now - self::SETTLE && $this->compress($plain, $report)) {
            $report['compressed'][] = basename($plain);
        }
        if ($live && $stat['size'] > $this->maxBytes) {
            $this->rotateNow($plain, $report);
        }
        $this->dropOlder($report);
        if ($report['problems'] !== []) {
            $report['result'] = 'failed';
        } elseif ($report['rotated']) {
            $report['result'] = 'rotated';
        }
        return $report;
    }

    /** @param array<string,mixed> $report */
    private function rotateNow(string $plain, array &$report): void
    {
        // A plain `.1` that is still there (a second rotation before it settled) is compressed first, so no generation is lost.
        $plainStat = @lstat($plain);
        if ($plainStat !== false) {
            if (($plainStat['mode'] & 0170000) !== 0100000 || file_exists($plain . '.gz') || !$this->compress($plain, $report)) {
                $report['problems'][] = 'the previous rotated copy could not be compressed; nothing was rotated';
                return;
            }
            $report['compressed'][] = basename($plain);
        }
        @unlink("{$this->log}.{$this->keep}.gz");
        for ($i = $this->keep - 1; $i >= 1; --$i) {
            $from = "{$this->log}.$i.gz";
            if (@lstat($from) !== false && !@rename($from, "{$this->log}." . ($i + 1) . '.gz')) {
                $report['problems'][] = 'could not shift ' . basename($from);
                return;
            }
        }
        if (!@rename($this->log, $plain)) {
            $report['problems'][] = 'could not rename the audit log';
            return;
        }
        if (!($this->reload)()) {
            if (@lstat($this->log) === false) {
                @rename($plain, $this->log);
            }
            $report['problems'][] = 'OLS did not reload; the audit log was put back';
            return;
        }
        $report['rotated'] = true;
    }

    /**
     * Rotated copies beyond the retention (numbers above KEEP left by an earlier setting).
     * @param array<string,mixed> $report
     */
    private function dropOlder(array &$report): void
    {
        foreach (glob($this->log . '.*') ?: [] as $path) {
            if (preg_match('/\.(\d+)(\.gz)?$/D', $path, $m) === 1 && (int) $m[1] > $this->keep
                && is_file($path) && !is_link($path) && !@unlink($path)) {
                $report['problems'][] = 'could not remove ' . basename($path);
            }
        }
    }

    /**
     * gzip `$path` into `$path.gz` (same mode and owner), then remove it. Never follows a link.
     * @param array<string,mixed> $report
     */
    private function compress(string $path, array &$report): bool
    {
        $before = @lstat($path);
        $in = $before === false ? false : @fopen($path, 'rb');
        if ($in === false) {
            $report['problems'][] = 'could not open ' . basename($path);
            return false;
        }
        $opened = fstat($in);
        if (($before['mode'] & 0170000) !== 0100000 || $opened === false || $opened['ino'] !== $before['ino'] || $opened['dev'] !== $before['dev']) {
            fclose($in);
            $report['problems'][] = basename($path) . ' changed while it was opened';
            return false;
        }
        $target = $path . '.gz';
        $tmp = $target . '.tmp';
        $previous = umask(0077);
        try {
            @unlink($tmp);
            // Mode x: fails when the path exists, a link included; it is never followed.
            $out = @fopen($tmp, 'xb');
        } finally {
            umask($previous);
        }
        if ($out === false) {
            fclose($in);
            $report['problems'][] = 'could not create ' . basename($tmp);
            return false;
        }
        $ok = true;
        $context = deflate_init(ZLIB_ENCODING_GZIP, ['level' => 6]);
        while ($ok && !feof($in)) {
            $chunk = fread($in, self::CHUNK);
            if ($chunk === false) {
                $ok = false;
                break;
            }
            $ok = $chunk === '' || fwrite($out, deflate_add($context, $chunk, ZLIB_NO_FLUSH)) !== false;
        }
        $ok = $ok && fwrite($out, deflate_add($context, '', ZLIB_FINISH)) !== false;
        fclose($in);
        $ok = fclose($out) && $ok;
        if ($ok) {
            @chmod($tmp, $before['mode'] & 0777);
            @chown($tmp, $before['uid']);
            @chgrp($tmp, $before['gid']);
            @touch($tmp, (int) $before['mtime']);
            $ok = @rename($tmp, $target) && @unlink($path);
        }
        if (!$ok) {
            @unlink($tmp);
            $report['problems'][] = 'could not compress ' . basename($path);
        }
        return $ok;
    }
}
