<?php
declare(strict_types=1);

namespace OlsCpanel\Deployment;

/**
 * The logrotate rule of releases 0.2.13 and 0.2.14 (RV-57), retired by RV-66. The rule could never run: the distribution's
 * logrotate.service has ProtectSystem=full, so /usr/local/lsws/logs is read-only for it, and its failure also stopped the rotation of
 * every other log of the server. The package no longer ships it (the cache cleanup unit rotates the audit log, see
 * AuditLogRotator), and an RPM upgrade only removes an unchanged %config file, so `upgrade` and `uninstall` remove what is left.
 *
 * Only the product's own file goes: a regular file (never a link) owned by root whose text carries the product's marker line and
 * the audit log stanza. An administrator's own /etc/logrotate.d/ols-cpanel (any other content) is never touched.
 */
final class LegacyLogrotateRule
{
    public const PATH = '/etc/logrotate.d/ols-cpanel';
    /** The first comment line of the product's file; the stanza line is the second condition. */
    public const MARKER = '# OLS-cPanel: rotation of the ModSecurity audit log (RV-57).';
    public const STANZA = '/usr/local/lsws/logs/modsec_audit.log {';

    /** Whether the file at PATH is the product's (read only). */
    public static function present(Host $host, string $path = self::PATH): bool
    {
        $stat = $host->run('logrotate-rule-stat', ['/usr/bin/stat', '-c', '%F|%U:%G:%a', '--', $path]);
        if ($stat['exit_code'] !== 0 || !str_starts_with(trim($stat['stdout']), 'regular')) {
            return false;
        }
        [, $owner] = explode('|', trim($stat['stdout']), 2) + [1 => ''];
        if (!str_starts_with($owner, 'root:')) {
            return false;
        }
        $text = $host->run('logrotate-rule-read', ['/usr/bin/cat', '--', $path]);
        return $text['exit_code'] === 0 && str_contains($text['stdout'], self::MARKER) && str_contains($text['stdout'], self::STANZA);
    }

    /** @return string 'absent' (nothing of the product's there), 'removed' or 'failed' */
    public static function retire(Host $host, string $path = self::PATH): string
    {
        if (!self::present($host, $path)) {
            return 'absent';
        }
        // `rm -f --` unlinks a link as such and never follows it.
        return $host->run('logrotate-rule-remove', ['/usr/bin/rm', '-f', '--', $path])['exit_code'] === 0 ? 'removed' : 'failed';
    }
}
