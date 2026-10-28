<?php
declare(strict_types=1);

namespace OlsCpanel\Deployment;

/**
 * The cutover backup, written before the first change (lab principle RV-27): /var/lib/ols-cpanel/backups/<id>/
 * (root 0700) with byte-exact copies (cp -p) of every host file a cutover may change, the captured tweak
 * values, the state of each file (owner:group:mode and sha256, or absent), the docroot ownership for the
 * return path (FileProtect), and recover.sh (RecoveryScript). The recovery restores through cPanel's own
 * interfaces (captured tweak values, rebuilt Apache configuration), not by copying these files back, so
 * later administrator changes to them survive; the copies are the record and the manual fallback. Only
 * root-owned regular files are copied: tenant-owned paths are never read as root (the product changes none).
 * Objects the product would create but that already exist (the remoteip include, the nftables table) are
 * refused, never adopted. HTTP/3 (FV-04): when it is enabled (Http3Input) and the host's firewall is csf or firewalld
 * without UDP 443, the change is recorded under "http3.firewall" (csf.conf copied to firewall/csf.conf) and
 * recover.sh undoes it; the manifest records what was found even when nothing is changed.
 */
final class Backup
{
    /** Host files a cutover may change (directly or through cPanel's tweak, rebuild and service APIs). */
    public const FILES = ['/var/cpanel/cpanel.config', HybridHost::HTTPD_CONF, '/etc/chkserv.d/chkservd.conf', HybridHost::REMOTEIP_CONF];
    public const ID = '/^c\d{14}-[0-9a-f]{6}$/D';

    public function __construct(private Environment $env)
    {
    }

    public static function unit(string $id): string
    {
        return "ols-cpanel-recover-$id";
    }

    /**
     * Creates backups/<id>; returns the manifest.
     * @param array<string,mixed> $plan the cutover plan
     * @param array<string,array<string,mixed>> $vhosts the compiled plan (docroots for the ownership record)
     * @return array<string,mixed>
     */
    public function create(string $id, array $plan, array $vhosts): array
    {
        if (!preg_match(self::ID, $id)) {
            throw DeploymentError::refused("invalid backup id $id");
        }
        $hybrid = $plan['profile']['hybrid_ports'] !== null;
        $ports = $hybrid ? $plan['profile']['hybrid_ports'] : null;
        $host = new HybridHost($this->env->host, $this->env->state);
        $originals = [];
        if ($hybrid) {
            $collisions = $host->collisions();
            if ($collisions !== []) {
                throw DeploymentError::refused('refusing to take over existing objects: ' . implode(', ', $collisions),
                    ['collisions' => $collisions]);
            }
            $originals = $host->captureTweaks();
            foreach ($originals as $key => $value) {
                $port = (int) substr($value, (int) strrpos($value, ':') + 1);
                $expected = $key === 'apache_port' ? 80 : 443;
                if ($port !== $expected) {
                    throw DeploymentError::refused("Apache is not on its standard port ($key=$value)");
                }
            }
        }
        Environment::ensureDir($this->env->state, 0755);
        Environment::ensureDir($this->env->backupsDir(), 0700);
        $dir = $this->env->backupsDir() . "/$id";
        if (file_exists($dir) || is_link($dir) || !@mkdir($dir, 0700)) {
            throw DeploymentError::refused("backup $dir already exists or cannot be created");
        }
        Environment::ensureDir("$dir/files", 0700);
        $files = [];
        foreach (self::FILES as $number => $path) {
            $state = $this->env->host->systemFileState($path, "backup-state-$number");
            $copy = null;
            if ($state !== null) {
                $copy = "files/$number";
                $this->env->host->must("backup-copy-$number", ['/usr/bin/cp', '-P', '-p', '--', $path, "$dir/$copy"]);
                if (!is_file("$dir/$copy") || hash_file('sha256', "$dir/$copy") !== substr($state, -64)) {
                    throw DeploymentError::step("backup-copy-$number", "the copy of $path differs from the original");
                }
            }
            $files[$path] = ['state' => $state ?? 'absent', 'copy' => $copy];
        }
        $ownership = [];
        foreach ($vhosts as $vhost) {
            $docroot = $vhost['docroot'] ?? null;
            if (is_string($docroot) && !isset($ownership[$docroot])) {
                $stat = $this->env->host->run('docroot-ownership', ['/usr/bin/stat', '-c', '%U:%G:%a', '--', $docroot]);
                $ownership[$docroot] = $stat['exit_code'] === 0 ? trim($stat['stdout']) : 'absent';
            }
        }
        ksort($ownership, SORT_STRING);
        try {
            $http3 = Http3Input::load($this->env->http3Path());
        } catch (\OlsCpanel\Ols\Compiler\CompilationRefused $refused) {
            throw DeploymentError::refused($refused->getMessage());
        }
        $firewall = null;
        if ($http3) {
            $firewall = (new Http3Firewall($this->env->host))->capture($dir, (new Http3Firewall($this->env->host))->inspect());
        }
        $script = RecoveryScript::render($dir, $originals, [], [], $hybrid, product: true,
            backendPorts: $ports ?? RecoveryScript::BACKEND_PORTS, firewall: Http3Firewall::recovery($firewall));
        Environment::writeFile("$dir/recover.sh", $script, 0700);
        $manifest = ['schema_version' => 1, 'id' => $id, 'plan' => $plan['id'], 'created' => gmdate('c', $this->env->now()),
            'hybrid' => $hybrid, 'hybrid_ports' => $ports, 'hybrid_vhosts' => array_column($plan['hybrid_vhosts'], 'vhost'),
            'tweaks' => (object) $originals, 'files' => $files, 'created_dirs' => [], 'profile_before' => 'absent',
            'http3' => ['enabled' => $http3, 'firewall' => $firewall],
            'docroot_ownership' => (object) $ownership, 'recover_sh' => 'recover.sh',
            'recover_sh_sha256' => hash('sha256', $script), 'recovery_unit' => self::unit($id)];
        Environment::writeFile("$dir/manifest.json", Environment::json($manifest), 0600);
        return json_decode(json_encode($manifest, JSON_THROW_ON_ERROR), true) + ['dir' => $dir];
    }

    /**
     * The newest backup (by creation time, then id), with its integrity.
     * @return array<string,mixed>|null manifest + "dir" + "intact" + "problem"
     */
    public function latest(): ?array
    {
        $found = [];
        foreach (glob($this->env->backupsDir() . '/c*', GLOB_ONLYDIR) ?: [] as $dir) {
            $id = basename($dir);
            if (!preg_match(self::ID, $id) || is_link($dir)) {
                continue;
            }
            $found[] = $this->load($id);
        }
        if ($found === []) {
            return null;
        }
        usort($found, static fn(array $a, array $b): int => [$a['created'] ?? '', $a['id']] <=> [$b['created'] ?? '', $b['id']]);
        return $found[count($found) - 1];
    }

    /** @return array<string,mixed> */
    public function load(string $id): array
    {
        $dir = $this->env->backupsDir() . "/$id";
        $text = @file_get_contents("$dir/manifest.json", false, null, 0, 1048577);
        $manifest = is_string($text) ? json_decode($text, true, 32) : null;
        if (!is_array($manifest) || ($manifest['id'] ?? null) !== $id || !is_string($manifest['recover_sh_sha256'] ?? null)) {
            return ['id' => $id, 'dir' => $dir, 'intact' => false, 'problem' => 'manifest missing or malformed'];
        }
        $script = "$dir/recover.sh";
        $problem = null;
        if (!is_file($script) || is_link($script)) {
            $problem = 'recover.sh missing';
        } elseif (!hash_equals($manifest['recover_sh_sha256'], (string) hash_file('sha256', $script))) {
            $problem = 'recover.sh differs from its recorded sha256';
        } elseif ((fileperms($script) & 0077) !== 0) {
            $problem = 'recover.sh is accessible to other users';
        }
        return $manifest + ['dir' => $dir, 'intact' => $problem === null, 'problem' => $problem];
    }
}
