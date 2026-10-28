<?php
declare(strict_types=1);

namespace OlsCpanel\ObjectCache;

/**
 * The ownership epoch of every domain: which account owns it now and since when (unix seconds), kept in
 * /var/lib/ols-cpanel/domain-owners.json (root 0600, written atomically). The broker returns a domain's logs to its
 * owner only from `since` on, so a domain that moves between two live accounts does not hand the earlier owner's request
 * history and PHP error details to the new one (tenant.logs, tenant.php_errors).
 *
 * Maintained by the object-cache reconcile pass from /etc/userdatadomains: a new domain or a changed owner starts a new
 * epoch (now), an unchanged owner keeps its `since`, a domain that is gone is dropped. The first file of an install
 * (an upgrade) records `since` 0 for every current domain, so nothing is hidden from the current owners. A file that
 * exists but cannot be read back is not "first": every current domain then starts a new epoch, the safe side.
 */
final class DomainOwners
{
    public function __construct(private readonly string $path)
    {
    }

    /**
     * @param list<string> $accounts every account cPanel has now
     * @param ?string $userdata the text of /etc/userdatadomains, null when it could not be read
     * @return array{changed:bool, domains:int}
     */
    public function update(array $accounts, ?string $userdata, ?int $now = null): array
    {
        $now ??= time();
        $current = [];
        foreach (preg_split('/\R/', (string) $userdata) ?: [] as $line) {
            $parts = explode(': ', $line, 2);
            $fields = explode('==', $parts[1] ?? '');
            $domain = $parts[0];
            if (count($parts) === 2 && preg_match('/^[a-z0-9][a-z0-9.-]{0,251}[a-z0-9]$/D', $domain) === 1
                && preg_match('/^[a-z][a-z0-9_-]{0,31}$/D', $fields[0]) === 1) {
                $current[$domain] = $fields[0];
            }
        }
        if ($userdata === null || ($current === [] && $accounts !== [])) {
            return ['changed' => false, 'domains' => 0];  // a failed read never rewrites ownership
        }
        $old = $this->load();
        $first = $old === null && !$this->exists();
        $next = [];
        foreach ($current as $domain => $owner) {
            $known = $old[$domain] ?? null;
            $next[$domain] = ['owner' => $owner, 'since' => $known !== null && $known['owner'] === $owner
                ? $known['since'] : ($first ? 0 : $now)];
        }
        ksort($next, SORT_STRING);
        if ($old === $next) {
            return ['changed' => false, 'domains' => count($next)];
        }
        $this->save($next);
        return ['changed' => true, 'domains' => count($next)];
    }

    private function exists(): bool
    {
        return file_exists($this->path) || is_link($this->path);
    }

    /** @return ?array<string,array{owner:string,since:int}> null when there is no usable file */
    private function load(): ?array
    {
        if (is_link($this->path) || !is_file($this->path)) {
            return null;
        }
        $data = json_decode((string) @file_get_contents($this->path, false, null, 0, 16 << 20), true, 8);
        if (!is_array($data)) {
            return null;
        }
        $out = [];
        foreach ($data as $domain => $row) {
            if (is_string($domain) && is_array($row) && is_string($row['owner'] ?? null) && is_int($row['since'] ?? null)) {
                $out[$domain] = ['owner' => $row['owner'], 'since' => $row['since']];
            }
        }
        ksort($out, SORT_STRING);
        return $out;
    }

    /** @param array<string,array{owner:string,since:int}> $data */
    private function save(array $data): void
    {
        $directory = dirname($this->path);
        if (!is_dir($directory) && !@mkdir($directory, 0755, true) && !is_dir($directory)) {
            throw new \RuntimeException('cannot create ' . $directory);
        }
        if (is_link($this->path)) {
            @unlink($this->path);
        }
        $temporary = $this->path . '.tmp' . bin2hex(random_bytes(4));
        $handle = @fopen($temporary, 'xb');
        if ($handle === false) {
            throw new \RuntimeException('cannot write the domain owner file');
        }
        $text = json_encode((object) $data, JSON_UNESCAPED_SLASHES) . "\n";
        $ok = @chmod($temporary, 0600) && fwrite($handle, $text) === strlen($text) && fflush($handle)
            && (!function_exists('fsync') || fsync($handle));
        fclose($handle);
        if (!$ok || !rename($temporary, $this->path)) {
            @unlink($temporary);
            throw new \RuntimeException('cannot write the domain owner file');
        }
    }
}
