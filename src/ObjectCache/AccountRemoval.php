<?php
declare(strict_types=1);

namespace OlsCpanel\ObjectCache;

/**
 * What the product itself keeps per account or per vhost outside the account's home, removed or sealed when the
 * account or vhost is gone from cPanel, so that a later account or domain with the same name does not inherit it
 * (review 8, findings 1 and 2). It runs in every object-cache reconcile pass (the hook for Accounts::Remove starts that
 * pass; the timer repeats it), as root, and never follows a link.
 *
 *  - Requests to the administrator (requests/): the records of an account that no longer exists, or whose recorded
 *    identity (cPanel's STARTDATE or the uid and home inode, see the broker) differs from the account's current one,
 *    are moved to requests-archive/ (root 0700), where only the administrator can read them.
 *  - OLS per-vhost error logs: `<vhost>-error.log*` (and the hybrid `tls.<vhost>` form) of vhosts that are no longer
 *    in /etc/userdatadomains are deleted. Nothing is deleted unless the domain table was read completely and is
 *    consistent with the account list.
 *
 * cPanel's own domain logs are removed by cPanel when it terminates an account (scripts/killacct); the broker also
 * refuses to serve any log last written before the account's creation.
 */
final class AccountRemoval
{
    private const REQUEST = '/^r[0-9]{10}-[0-9a-f]{8}\.json$/D';
    private const LOG = '/^(?<vhost>[a-z0-9][a-z0-9.-]{0,251}[a-z0-9])-error\.log(?:\.[A-Za-z0-9_-]{1,16}){0,2}$/D';

    public function __construct(private readonly string $requestsDir, private readonly string $archiveDir,
                                private readonly ?string $errorLogDir)
    {
    }

    /**
     * @param list<string> $accounts every account cPanel has now (authoritative)
     * @param ?string $userdata the text of /etc/userdatadomains, null when it could not be read
     * @param \Closure(string):?string $identity the current identity of an account, null when unknown
     * @return array{archived:int, logs_removed:int, errors:list<string>}
     */
    public function run(array $accounts, ?string $userdata, \Closure $identity): array
    {
        $result = ['archived' => 0, 'logs_removed' => 0, 'errors' => []];
        try {
            $result['archived'] = $this->archiveRequests(array_flip($accounts), $identity);
        } catch (\Throwable $error) {
            $result['errors'][] = 'requests: ' . substr($error->getMessage(), 0, 200);
        }
        try {
            $result['logs_removed'] = $this->removeLogs($accounts, $userdata);
        } catch (\Throwable $error) {
            $result['errors'][] = 'logs: ' . substr($error->getMessage(), 0, 200);
        }
        return $result;
    }

    /** @param array<string,int> $accounts */
    private function archiveRequests(array $accounts, \Closure $identity): int
    {
        if (!is_dir($this->requestsDir) || is_link($this->requestsDir)) {
            return 0;
        }
        $moved = 0;
        $current = [];
        foreach (scandir($this->requestsDir) ?: [] as $name) {
            $path = $this->requestsDir . '/' . $name;
            if (preg_match(self::REQUEST, $name) !== 1 || is_link($path) || !is_file($path)) {
                continue;
            }
            $record = json_decode((string) @file_get_contents($path, false, null, 0, 16384), true, 8);
            $user = is_array($record) ? ($record['user'] ?? null) : null;
            if (!is_string($user)) {
                continue;
            }
            $gone = !isset($accounts[$user]);
            if (!$gone) {
                $recorded = $record['identity'] ?? null;
                $now = $current[$user] ??= $identity($user);
                $gone = is_string($recorded) && is_string($now) && $recorded !== $now;
            }
            if (!$gone) {
                continue;
            }
            if (!is_dir($this->archiveDir) && !@mkdir($this->archiveDir, 0700, true) && !is_dir($this->archiveDir)) {
                throw new \RuntimeException('cannot create the request archive');
            }
            @chmod($this->archiveDir, 0700);
            if (!rename($path, $this->archiveDir . '/' . $name)) {
                throw new \RuntimeException("cannot archive $name");
            }
            ++$moved;
        }
        return $moved;
    }

    /** @param list<string> $accounts */
    /** Seconds a recently written error log is kept even when its vhost is not in the domain table. */
    private const KEEP_RECENT = 604800;

    private function removeLogs(array $accounts, ?string $userdata): int
    {
        if ($this->errorLogDir === null || $userdata === null || !is_dir($this->errorLogDir) || is_link($this->errorLogDir)) {
            return 0;
        }
        $domains = [];
        foreach (preg_split('/\R/', $userdata) ?: [] as $line) {
            $domain = explode(': ', $line, 2)[0];
            if ($domain !== '' && str_contains($line, ': ')) {
                $domains[$domain] = true;
            }
        }
        if ($domains === [] && $accounts !== []) {
            return 0;  // an empty table with accounts is a failed read, never "every domain was removed"
        }
        $removed = 0;
        foreach (scandir($this->errorLogDir) ?: [] as $name) {
            if (preg_match(self::LOG, $name, $match) !== 1 || str_contains($match['vhost'], '..')) {
                continue;
            }
            $vhost = $match['vhost'];
            $base = str_starts_with($vhost, 'tls.') ? substr($vhost, 4) : $vhost;
            $path = $this->errorLogDir . '/' . $name;
            if (isset($domains[$vhost]) || isset($domains[$base]) || is_link($path) || !is_file($path)) {
                continue;
            }
            // A log written in the last week belongs to a vhost that is still served in some form (a product vhost not listed
            // in the domain table, or a removal not yet compiled): never deleted. A new owner is protected meanwhile by the
            // account start date check of tenant.logs.
            $mtime = @filemtime($path);
            if ($mtime === false || time() - $mtime < self::KEEP_RECENT) {
                continue;
            }
            if (@unlink($path)) {
                ++$removed;
            }
        }
        return $removed;
    }
}
