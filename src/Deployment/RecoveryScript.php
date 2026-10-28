<?php
declare(strict_types=1);

namespace OlsCpanel\Deployment;

/**
 * The cutover's recovery script: one POSIX shell script, run as root, that returns the host to Apache and
 * undoes every cutover change. Port of build/vm-qualification/hybrid_lab.recovery_script, byte-identical for
 * the same arguments (tests/deployment_texts.py). It depends on nothing of the product (no PHP, no CLI, no
 * broker), so it also works when the product installation is broken: the recovery timer armed before the
 * first change and `apache-return` both run exactly this file. It holds a lock (one recovery at a time): the
 * product's script takes the deployment lock exclusively (`flock -w 900`; review RV-29), so no cutover, return,
 * uninstall or reconcile pass runs beside it, unless its caller already holds that lock and exports
 * OLS_CPANEL_DEPLOYMENT_LOCK=held (heldArgv()). It bounds every command, stops and disables the reconciler and OLS, removes the deployment profile and the
 * hybrid include, restores the captured tweak values, re-enables and restarts Apache, and retries until
 * Apache owns 80/443, the backend ports are closed and every captured value holds again; only then is the
 * backend-port firewall removed and cPanel's FileProtect resynchronised.
 *
 * The product changes no tenant file, so its script restores none (the lab's tenant-file mechanism stays
 * available with $product false, for byte equivalence). Hook unregistration is deliberately not part of it
 * (it needs the product).
 */
final class RecoveryScript
{
    public const LOCK = '/run/ols-cpanel-recover.lock';
    public const BACKEND_PORTS = [81, 444];
    public const LAB_UNITS = ['ols-cpanel.service', 'ols-cpanel-logs.service'];
    public const PRODUCT_UNITS = ['ols-cpanel-reconciler.service', 'ols-cpanel.service', 'ols-cpanel-logs.service'];
    public const PRODUCT_PROFILE = '/var/lib/ols-cpanel/profile.json';
    /** The deployment lock (docs/product-interfaces.md, "Locks, deadlines and recovery"). */
    public const DEPLOYMENT_LOCK = '/var/lib/ols-cpanel/deployment.lock';
    /** Exported as "held" by a holder of DEPLOYMENT_LOCK that runs the script synchronously. */
    public const DEPLOYMENT_LOCK_HELD = 'OLS_CPANEL_DEPLOYMENT_LOCK';
    /** cPanel's apache_port / apache_ssl_port values: "<IPv4>:<port>" or "[<IPv6>]:<port>". */
    public const TWEAK_VALUE = '/^(\d{1,3}(\.\d{1,3}){3}|\[[0-9a-fA-F:]+\]):\d{1,5}$/D';
    public const TWEAK_KEYS = ['apache_port', 'apache_ssl_port'];
    /** In the backup: the original csf.conf (FV-04). */
    public const FIREWALL_DIR = 'firewall';

    /**
     * @param string $backup backup directory (the script refers to "$B/files/<n>")
     * @param array<string,string> $originals tweak key => captured value (insertion order matters for the port list)
     * @param array<string,bool> $tenantFiles path => true when "$B/files/<n>" holds its copy, false when it did not exist
     * @param list<string> $createdDirs directories the change created (removed when empty)
     * @param array<string,string> $expected path => sha256 of the original content (verified after the restore)
     * @param bool $product the product's cutover recovery (PRODUCT_UNITS stopped and disabled, profile removed)
     * @param list<int> $backendPorts Apache's hybrid backend ports, closed again unless captured as original
     * @param array<string,mixed>|null $firewall the UDP 443 change of the cutover (FV-04) to undo:
     *        csf {type, before_sha256, after_sha256} (the captured csf.conf goes back byte for byte while the file still
     *        is what the cutover wrote, csf restarts until it has succeeded on the original) or firewalld {type, zone,
     *        runtime, permanent} (the runtime and/or permanent port the product added removed in that zone, no reload);
     *        null leaves the script as without HTTP/3
     */
    public static function render(string $backup, array $originals, array $tenantFiles, array $createdDirs, bool $hybrid,
                                  ?string $tenantUser = null, array $expected = [], bool $product = false,
                                  array $backendPorts = self::BACKEND_PORTS, ?array $firewall = null): string
    {
        if ($product && ($tenantFiles !== [] || $createdDirs !== [])) {
            throw new \InvalidArgumentException("the product's recovery restores no tenant files");
        }
        $units = implode(' ', $product ? self::PRODUCT_UNITS : self::LAB_UNITS);
        if ($hybrid) {
            if ($tenantFiles !== [] && ($tenantUser === null || $tenantUser === '')) {
                throw new \InvalidArgumentException('tenant files need the tenant user');
            }
            foreach ($originals as $key => $value) {
                if (!in_array($key, self::TWEAK_KEYS, true) || !preg_match(self::TWEAK_VALUE, $value)) {
                    throw new \InvalidArgumentException("unexpected tweak setting $key=" . var_export($value, true));
                }
            }
        }
        $asTenant = 'timeout 60 runuser -u ' . self::quote($tenantUser ?: 'nobody') . ' --';
        $lines = ['#!/bin/sh', $product ? '# OLS-cPanel recovery: Apache back on 80/443, every cutover change undone.'
            : '# OLS-cPanel lab recovery: Apache back on 80/443, every experiment change undone.',
            'B=' . self::quote($backup), 'PATH=/usr/bin:/bin:/usr/sbin:/sbin', "T='timeout 120'",
            ...($product ? ['if [ "${' . self::DEPLOYMENT_LOCK_HELD . ':-}" != held ]; then', '    exec 9>' . self::DEPLOYMENT_LOCK,
                "    flock -w 900 9 || { echo 'a deployment operation holds the deployment lock' >&2; exit 1; }", 'fi']
                : ['exec 9>' . self::LOCK, "flock -w 900 9 || { echo 'another recovery holds the lock' >&2; exit 1; }"]),
            'restore() {', "    \$T systemctl stop $units 2>/dev/null"];
        if ($product) {
            $lines[] = "    for u in $units; do \$T systemctl disable \"\$u\" 2>/dev/null; done";
            $lines[] = '    rm -f ' . self::quote(self::PRODUCT_PROFILE);
        }
        $files = $tenantFiles;
        ksort($files, SORT_STRING);
        $sortedOriginals = $originals;
        ksort($sortedOriginals, SORT_STRING);
        if ($hybrid) {
            $lines[] = '    rm -f ' . self::quote(HybridHost::REMOTEIP_CONF);
            $number = 0;
            foreach ($files as $path => $existed) {
                $lines[] = $existed
                    ? "    $asTenant sh -c 'cat > \"\$1\"' sh " . self::quote((string) $path) . " < \"\$B/files/$number\""
                    : "    $asTenant rm -f -- " . self::quote((string) $path);
                ++$number;
            }
            $dirs = $createdDirs;
            rsort($dirs, SORT_STRING);
            foreach ($dirs as $path) {
                $lines[] = "    $asTenant rmdir -- " . self::quote($path) . ' 2>/dev/null';
            }
            foreach ($sortedOriginals as $key => $value) {
                $lines[] = "    \$T /usr/local/cpanel/bin/whmapi1 set_tweaksetting key=$key value=" . self::quote($value) . ' >/dev/null';
            }
            $lines[] = '    $T /usr/local/cpanel/scripts/rebuildhttpdconf >/dev/null';
        }
        if ($firewall !== null) {
            array_push($lines, ...self::firewallLines($firewall));
        }
        array_push($lines, '    $T /usr/local/cpanel/bin/whmapi1 configureservice service=httpd enabled=1 monitored=1 >/dev/null',
            '    $T /usr/local/cpanel/scripts/restartsrv_httpd >/dev/null 2>&1', '}', 'healthy() {', '    for p in 80 443; do',
            '        ss -H -ltnp "( sport = :$p )" | grep -q \'"httpd"\' || return 1', '    done');
        if ($firewall !== null) {
            array_push($lines, ...self::firewallHealthLines($firewall));
        }
        if ($hybrid) {
            $ports = implode(' ', array_map(static function (string $value): string {
                $colon = strrpos($value, ':');
                return $colon === false ? $value : substr($value, $colon + 1);
            }, array_values($originals)));
            array_push($lines, '    for p in ' . implode(' ', $backendPorts) . "; do case \" $ports \" in *\" \$p \"*) continue;; esac",
                '        ss -H -ltn "( sport = :$p )" | grep -q . && return 1', '    done',
                '    test -e ' . self::quote(HybridHost::REMOTEIP_CONF) . ' && return 1');
            foreach ($sortedOriginals as $key => $value) {
                $lines[] = "    \$T /usr/local/cpanel/bin/whmapi1 --output=json get_tweaksetting key=$key "
                    . '| grep -qF ' . self::quote('"value":"' . $value . '"') . ' || return 1';
            }
            foreach ($files as $path => $existed) {
                if ($existed && array_key_exists($path, $expected)) {
                    $lines[] = "    [ \"\$($asTenant sh -c 'sha256sum < \"\$1\"' sh " . self::quote((string) $path)
                        . " | cut -d' ' -f1)\" = " . self::quote($expected[$path]) . ' ] || return 1';
                } elseif (!$existed) {
                    $lines[] = "    $asTenant test ! -e " . self::quote((string) $path) . ' || return 1';
                }
            }
            $dirs = $createdDirs;
            sort($dirs, SORT_STRING);
            foreach ($dirs as $path) {
                $lines[] = '    test ! -e ' . self::quote($path) . ' || return 1';
            }
        }
        if ($product) {
            $lines[] = '    test ! -e ' . self::quote(self::PRODUCT_PROFILE) . ' || return 1';
        }
        array_push($lines, "    code=\$(curl -s -o /dev/null -m 10 -w '%{http_code}' http://127.0.0.1/)",
            '    case "$code" in [1-4]??) return 0;; esac', '    return 1', '}',
            'for attempt in 1 2 3 4 5 6 7 8; do', '    restore', '    sleep 5', '    if healthy; then');
        if ($hybrid) {
            // Only now, with Apache back on its own ports, may the backend-port firewall go.
            $table = HybridHost::NFT_TABLE;
            array_push($lines, "        nft list table inet $table >/dev/null 2>&1 && \$T nft delete table inet $table",
                "        if nft list table inet $table >/dev/null 2>&1; then sleep 15; continue; fi");
            if ($product) {
                // The persisted copy goes with the table, or the next boot would close the ports of an Apache that owns 80/443 again.
                array_push($lines, '        rm -f ' . self::quote(Environment::STATE . '/' . HybridHost::FIREWALL_FILE),
                    '        $T systemctl disable ' . HybridHost::FIREWALL_UNIT . ' 2>/dev/null');
            }
        }
        array_push($lines, '        $T /usr/local/cpanel/scripts/enablefileprotect >/dev/null 2>&1', '        echo recovered',
            '        exit 0', '    fi', '    sleep 15', 'done', "echo 'recovery incomplete' >&2", 'exit 1', '');
        return implode("\n", $lines);
    }

    /**
     * The recovery lines that undo the UDP 443 change (FV-04), as hybrid_lab.firewall_restore_lines.
     * csf (RV-31 item 6): "file restored" and "firewall applied" are separate facts. The captured csf.conf goes back while
     * the file still is what the cutover wrote; csf restarts whenever the original file is in place and no restart has
     * succeeded in this run (CSF_APPLIED), so an attempt that restored the file but failed to restart retries the restart.
     * firewalld (items 3-5): exactly the runtime and/or permanent port the product added, in the recorded zone, no reload.
     * @param array{type:string, before_sha256?:string, after_sha256?:string, zone?:string, runtime?:bool, permanent?:bool} $firewall
     * @return list<string>
     */
    public static function firewallLines(array $firewall): array
    {
        if ($firewall['type'] === 'csf') {
            [$before, $after] = self::csfDigests($firewall);
            $conf = self::quote(Http3Firewall::CSF_CONF);
            $sum = "h=\$(sha256sum < $conf | cut -d' ' -f1)";
            return ['    if [ "${CSF_APPLIED:-}" != 1 ]; then',
                "        $sum",
                "        if [ \"\$h\" = $after ]; then cat \"\$B/" . self::FIREWALL_DIR . "/csf.conf\" > $conf; $sum; fi",
                "        if [ \"\$h\" = $before ]; then \$T " . Http3Firewall::CSF . ' -r >/dev/null 2>&1 && CSF_APPLIED=1; fi',
                '    fi'];
        }
        if ($firewall['type'] === 'firewalld') {
            $zone = self::quote(self::firewalldZone($firewall));
            $lines = [];
            if ($firewall['runtime'] ?? false) {
                $lines[] = "    \$T firewall-cmd --zone=$zone --remove-port=443/udp >/dev/null 2>&1";
            }
            if ($firewall['permanent'] ?? false) {
                $lines[] = "    \$T firewall-cmd --permanent --zone=$zone --remove-port=443/udp >/dev/null 2>&1";
            }
            return $lines;
        }
        throw new \InvalidArgumentException('unknown firewall type ' . var_export($firewall['type'], true));
    }

    /**
     * The healthy() lines of the firewall change: the csf restart must have succeeded on the original file, unless the
     * file is neither the cutover's nor the original (an administrator's edit is never fought).
     * @param array{type:string, before_sha256?:string, after_sha256?:string} $firewall
     * @return list<string>
     */
    public static function firewallHealthLines(array $firewall): array
    {
        if ($firewall['type'] !== 'csf') {
            return [];
        }
        [$before, $after] = self::csfDigests($firewall);
        $conf = self::quote(Http3Firewall::CSF_CONF);
        return ['    [ "${CSF_APPLIED:-}" = 1 ] || { h=$(sha256sum < ' . $conf . " | cut -d' ' -f1); [ \"\$h\" != $after ] && [ \"\$h\" != $before ]; } || return 1"];
    }

    /** @return array{string,string} before and after digests of a csf firewall argument */
    private static function csfDigests(array $firewall): array
    {
        foreach (['before_sha256', 'after_sha256'] as $key) {
            if (!preg_match('/^[0-9a-f]{64}$/D', (string) ($firewall[$key] ?? ''))) {
                throw new \InvalidArgumentException('the csf recovery needs the sha256 of the original and of the changed csf.conf');
            }
        }
        return [$firewall['before_sha256'], $firewall['after_sha256']];
    }

    private static function firewalldZone(array $firewall): string
    {
        $zone = (string) ($firewall['zone'] ?? '');
        if (preg_match(Http3Firewall::ZONE, $zone) !== 1) {
            throw new \InvalidArgumentException('the firewalld recovery needs the recorded zone');
        }
        if (!($firewall['runtime'] ?? false) && !($firewall['permanent'] ?? false)) {
            throw new \InvalidArgumentException('the firewalld recovery needs the state(s) the product added');
        }
        return $zone;
    }

    /**
     * The argv that runs a product recover.sh synchronously under the deployment lock its caller holds (the
     * command runner's environment is fixed, so the variable is passed through env).
     * @return list<string>
     */
    public static function heldArgv(string $script): array
    {
        return ['/usr/bin/env', self::DEPLOYMENT_LOCK_HELD . '=held', '/bin/sh', $script];
    }

    /** Python's shlex.quote: unchanged when only safe characters, otherwise single-quoted. */
    public static function quote(string $text): string
    {
        if ($text === '') {
            return "''";
        }
        if (!preg_match('/[^\w@%+=:,.\/-]/', $text)) {
            return $text;
        }
        return "'" . str_replace("'", "'\"'\"'", $text) . "'";
    }
}
