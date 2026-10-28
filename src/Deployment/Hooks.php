<?php
declare(strict_types=1);

namespace OlsCpanel\Deployment;

/**
 * The product's cPanel hook registrations (plan section 15, G0-F): the hook entry for the restricting events
 * of ols_events.RESTRICTING and for the account, domain, PHP, certificate and .htaccess changes the lab
 * observed (docs/g0f-hooks.md; ols_reconcile_probe.HOOKS). All on stage "post", as the lab pipeline ran them;
 * API events of the Cpanel category run with escalated privileges (the cPanel user's own calls), WHM events
 * run as root already. Registration goes through cPanel's manage_hooks and is verified against its listing:
 * a misspelled event silently never fires, so only the listing proves a registration.
 */
final class Hooks
{
    public const MANAGE = '/usr/local/cpanel/bin/manage_hooks';
    /**
     * The registered executable. cPanel runs a script hook without arguments (event JSON on stdin), so the
     * entry is a fixed wrapper that runs `/usr/local/ols-cpanel/bin/ols-cpanel hook`.
     */
    public const ENTRY = '/usr/local/ols-cpanel/libexec/ols-cpanel-hook';
    public const STAGE = 'post';
    /** ols_events.RESTRICTING: the hook raises the restriction epoch before cPanel's operation is acknowledged. */
    public const RESTRICTING = ['Accounts::suspendacct', 'Accounts::Remove', 'Api2::SubDomain::delsubdomain',
        'Api2::AddonDomain::deladdondomain', 'Api2::Park::unpark', 'UAPI::SubDomain::delete_subdomain'];
    /** [category, event] */
    public const EVENTS = [
        ['Whostmgr', 'Accounts::Create'],
        ['Whostmgr', 'Accounts::Modify'],
        ['Whostmgr', 'Accounts::SiteIP::set'],
        ['PkgAcct', 'Restore'],
        ['Whostmgr', 'Transfers::Session'],
        ['Whostmgr', 'Accounts::Remove'],
        ['Whostmgr', 'Accounts::suspendacct'],
        ['Whostmgr', 'Accounts::unsuspendacct'],
        ['Whostmgr', 'Accounts::change_package'],
        ['Whostmgr', 'Lang::PHP::set_vhost_versions'],
        ['Whostmgr', 'SSL::installssl'],
        ['Whostmgr', 'SSL::delssl'],
        ['Whostmgr', 'AutoSSL::installssl'],
        ['Cpanel', 'UAPI::SubDomain::addsubdomain'],
        ['Cpanel', 'UAPI::SubDomain::delete_subdomain'],
        ['Cpanel', 'Api2::SubDomain::addsubdomain'],
        ['Cpanel', 'Api2::SubDomain::delsubdomain'],
        ['Cpanel', 'Api2::SubDomain::changedocroot'],
        ['Cpanel', 'Api2::AddonDomain::addaddondomain'],
        ['Cpanel', 'Api2::AddonDomain::deladdondomain'],
        ['Cpanel', 'Api2::Park::park'],
        ['Cpanel', 'Api2::Park::unpark'],
        ['Cpanel', 'UAPI::LangPHP::php_set_vhost_versions'],
        ['Cpanel', 'UAPI::LangPHP::php_ini_set_user_basic_directives'],
        ['Cpanel', 'UAPI::DirectoryPrivacy::configure_directory_protection'],
        ['Cpanel', 'UAPI::SSL::install_ssl'],
        ['Cpanel', 'UAPI::SSL::delete_ssl'],
        ['Cpanel', 'UAPI::Mime::add_redirect'],
        ['Cpanel', 'UAPI::Fileman::save_file_content'],
    ];

    public function __construct(private Host $host, private string $entry = self::ENTRY)
    {
    }

    /** @return list<array{category:string, event:string, stage:string, escalateprivs:string}> expected registrations */
    public function expected(): array
    {
        return array_map(static fn(array $e): array => ['category' => $e[0], 'event' => $e[1], 'stage' => self::STAGE,
            'escalateprivs' => $e[0] === 'Cpanel' ? '1' : '0'], self::EVENTS);
    }

    /** @return list<array{category:string, event:string, stage:string, escalateprivs:string}> this entry's registrations */
    public function registered(): array
    {
        $record = $this->host->run('hooks-list', [self::MANAGE, 'list']);
        if ($record['exit_code'] !== 0) {
            throw DeploymentError::step('hooks-list', 'manage_hooks list failed');
        }
        $mine = [];
        foreach (self::parseList($record['stdout']) as $entry) {
            if (($entry['hook'] ?? null) === $this->entry) {
                $mine[] = ['category' => $entry['category'], 'event' => $entry['event'], 'stage' => $entry['stage'] ?? '',
                    'escalateprivs' => ($entry['escalateprivs'] ?? '0') === '1' ? '1' : '0'];
            }
        }
        return $mine;
    }

    /**
     * Compares the listing with the expected registrations.
     * @return array{ok:bool, missing:list<string>, unexpected:list<string>, duplicates:list<string>, registered:int}
     */
    public function verify(): array
    {
        $key = static fn(array $r): string => "{$r['category']}::{$r['event']} {$r['stage']} escalateprivs={$r['escalateprivs']}";
        $have = array_map($key, $this->registered());
        $want = array_map($key, $this->expected());
        $counts = array_count_values($have);
        $duplicates = array_keys(array_filter($counts, static fn(int $n): bool => $n > 1));
        $missing = array_values(array_diff($want, $have));
        $unexpected = array_values(array_unique(array_diff($have, $want)));
        return ['ok' => $missing === [] && $unexpected === [] && $duplicates === [], 'missing' => $missing,
            'unexpected' => $unexpected, 'duplicates' => array_map('strval', $duplicates), 'registered' => count($have)];
    }

    /** Registers what is missing (idempotent), removes stray registrations of this entry, then verifies. */
    public function install(): array
    {
        $have = $this->registered();
        $wanted = $this->expected();
        foreach ($have as $entry) {
            if (!in_array($entry, $wanted, true)) {
                $this->delete($entry);
            }
        }
        $added = 0;
        foreach ($wanted as $entry) {
            if (!in_array($entry, $have, true)) {
                $argv = [self::MANAGE, 'add', 'script', $this->entry, '--manual', "--category={$entry['category']}",
                    "--event={$entry['event']}", "--stage={$entry['stage']}"];
                if ($entry['escalateprivs'] === '1') {
                    $argv[] = '--escalateprivs=1';
                }
                $this->host->must('hook-add', $argv);
                ++$added;
            }
        }
        $result = $this->verify();
        if (!$result['ok']) {
            throw DeploymentError::step('hooks-verify', 'the hook registry does not match after registration', $result);
        }
        return $result + ['added' => $added];
    }

    /** Removes every registration of this entry (one per manage_hooks call), then checks none is left. */
    public function remove(): array
    {
        $removed = 0;
        for ($round = 0; $round < 3; ++$round) {
            $have = $this->registered();
            if ($have === []) {
                return ['ok' => true, 'removed' => $removed];
            }
            foreach ($have as $entry) {
                $this->delete($entry);
                ++$removed;
            }
        }
        $left = count($this->registered());
        if ($left !== 0) {
            throw DeploymentError::step('hooks-remove', "$left registrations of " . $this->entry . ' remain');
        }
        return ['ok' => true, 'removed' => $removed];
    }

    private function delete(array $entry): void
    {
        $this->host->must('hook-del', [self::MANAGE, 'del', 'script', $this->entry, '--manual', "--category={$entry['category']}",
            "--event={$entry['event']}", "--stage={$entry['stage']}"]);
    }

    /**
     * Parses `manage_hooks list` (category at column 0, event one tab in, "key: value" lines two tabs in,
     * entries of one event separated by "--"; recorded in the G0-F lab runs).
     * @return list<array<string,string>> each entry's keys plus "category" and "event"
     */
    public static function parseList(string $text): array
    {
        $entries = [];
        $category = $event = null;
        $current = null;
        $flush = static function () use (&$current, &$entries): void {
            if ($current !== null && count($current) > 2) {
                $entries[] = $current;
            }
            $current = null;
        };
        foreach (explode("\n", $text) as $line) {
            if (trim($line) === '') {
                continue;
            }
            $depth = strspn($line, "\t");
            $body = trim($line);
            if ($depth === 0 && str_ends_with($body, ':')) {
                $flush();
                $category = substr($body, 0, -1);
                $event = null;
            } elseif ($depth === 1 && str_ends_with($body, ':')) {
                $flush();
                $event = substr($body, 0, -1);
            } elseif ($body === '--') {
                $flush();
            } elseif ($depth >= 2 && $category !== null && $event !== null && preg_match('/^([A-Za-z_]+):\s?(.*)$/D', $body, $m)) {
                $current ??= ['category' => $category, 'event' => $event];
                $current[$m[1]] = $m[2];
            }
        }
        $flush();
        return $entries;
    }
}
