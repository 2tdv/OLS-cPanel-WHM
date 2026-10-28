<?php
declare(strict_types=1);

namespace OlsCpanel\Deployment;

/**
 * The WHM and cPanel plugins as part of the product: deployed from the package's plugin trees
 * (/usr/local/ols-cpanel/plugins/{whm,cpanel}) at prepare and on every upgrade, so the copies cPanel serves
 * can never fall behind the installed engine (lab finding 2026-10-27: a stale cPanel copy of the .htaccess
 * translator reported problems the engine had already solved). Registration uses cPanel's own tools
 * (register_appconfig for WHM, install_plugin for the Jupiter theme); removal undoes both.
 */
final class Plugins
{
    public const SOURCE = '/usr/local/ols-cpanel/plugins';
    public const WHM_DIR = '/usr/local/cpanel/whostmgr/docroot/cgi/ols-cpanel';
    public const WHM_ICON = '/usr/local/cpanel/whostmgr/docroot/addon_plugins/ols-cpanel.svg';
    public const CPANEL_DIR = '/usr/local/cpanel/base/frontend/jupiter/ols_cpanel';
    public const APPCONFIG = 'ols-cpanel';
    private const REGISTER = '/usr/local/cpanel/bin/register_appconfig';
    private const UNREGISTER = '/usr/local/cpanel/bin/unregister_appconfig';
    private const INSTALL_PLUGIN = '/usr/local/cpanel/scripts/install_plugin';
    private const UNINSTALL_PLUGIN = '/usr/local/cpanel/scripts/uninstall_plugin';
    /** Files cPanel's install_plugin takes from the registration archive. */
    private const REGISTRATION = ['install.json', 'ols_cpanel.svg', 'ols_cpanel_group.svg', 'ols_cpanel_cache.svg', 'ols_cpanel_php.svg',
        'ols_cpanel_objcache.svg', 'ols_cpanel_speed.svg', 'ols_cpanel_logs.svg', 'ols_cpanel_traffic.svg', 'ols_cpanel_purge.svg'];

    /** Suffixes of the staged replacement and of the previous tree kept until registration succeeded. */
    private const STAGE = '.ols-new';
    private const PREVIOUS = '.ols-old';

    /** @var array{whm:string, cpanel:string, icon:string} */
    private array $destinations;

    /** @param array{whm?:string, cpanel?:string, icon?:string} $destinations overrides (tests) of the cPanel locations */
    public function __construct(private Host $host, private string $state, private string $source = self::SOURCE,
                                array $destinations = [])
    {
        $this->destinations = $destinations + ['whm' => self::WHM_DIR, 'cpanel' => self::CPANEL_DIR, 'icon' => self::WHM_ICON];
    }

    /**
     * Replaces both trees as complete units, then (re)registers them. Idempotent. RV-31 item 14: each replacement is
     * staged next to its destination (same filesystem) and validated (manifest and entry point present) before
     * anything live is touched; the switch is two renames per tree (previous tree aside, staged tree in), so a
     * request sees the old or the new tree, never a mix or a copy in progress; the previous trees are kept until
     * the registrations succeeded and are put back when anything fails. A failure leaves the old plugin working.
     * @return list<string> what was done
     */
    public function deploy(): array
    {
        // cPanel's register_appconfig and install_plugin create files every account reads (the feature file under
        // whostmgr/addonfeatures, dynamicui entries, icons) with the caller's umask. The installer runs with umask 077
        // and the broker unit with UMask=0077, which left them root-only: cPanel's feature checks then failed for every
        // account (lab 2026-10-28, fresh install: the cPanel plugin answered FEATURE_DISABLED). Register with 022.
        $umask = umask(0022);
        try {
            return $this->deployWithUmask();
        } finally {
            umask($umask);
        }
    }

    /** @return list<string> */
    private function deployWithUmask(): array
    {
        $trees = [['whm', 'index.cgi', $this->destinations['whm']], ['cpanel', 'index.live.php', $this->destinations['cpanel']]];
        foreach ($trees as [$tree, $entry]) {
            if (!is_file("{$this->source}/$tree/manifest.json") || !is_file("{$this->source}/$tree/$entry")) {
                throw DeploymentError::refused("plugin tree {$this->source}/$tree is missing from the package");
            }
        }
        $icon = $this->destinations['icon'];
        $items = [['whm', $this->destinations['whm']], ['cpanel', $this->destinations['cpanel']], ['icon', $icon]];
        // An earlier interrupted run: a live path that is missing while its previous tree exists goes back first.
        foreach ($items as [$key, $path]) {
            if (!$this->exists("plugin-$key-probe", $path) && $this->exists("plugin-$key-probe-old", $path . self::PREVIOUS)) {
                $this->host->must("plugin-$key-recover", ['/usr/bin/mv', '-T', '--', $path . self::PREVIOUS, $path]);
            }
        }
        // 1. Stage and validate (nothing live changes here).
        foreach ($trees as [$tree, $entry, $dest]) {
            $stage = $dest . self::STAGE;
            $this->host->must("plugin-$tree-stage-clean", ['/usr/bin/rm', '-rf', '--', $stage, $dest . self::PREVIOUS]);
            $this->host->must("plugin-$tree-stage", ['/usr/bin/cp', '-R', '--', "{$this->source}/$tree", $stage]);
            if ($tree === 'whm') {
                $this->host->must('plugin-whm-mode', ['/usr/bin/chmod', '0755', "$stage/$entry"]);
            }
            $this->host->must("plugin-$tree-validate", ['/usr/bin/test', '-f', "$stage/manifest.json", '-a', '-f', "$stage/$entry"]);
        }
        $this->host->must('plugin-icon-stage-clean', ['/usr/bin/rm', '-f', '--', $icon . self::STAGE, $icon . self::PREVIOUS]);
        $this->host->must('plugin-icon-stage', ['/usr/bin/install', '-m', '0644', "{$this->source}/whm/ols-cpanel.svg", $icon . self::STAGE]);
        $archive = $this->state . '/plugin-cpanel.tar.gz';
        $this->host->must('plugin-cpanel-archive', ['/usr/bin/tar', '-C', "{$this->source}/cpanel", '-czf', $archive,
            ...self::REGISTRATION]);
        // 2. Switch, then register; undo every switch when anything fails.
        $switched = [];
        try {
            foreach ($items as [$key, $path]) {
                $had = $this->exists("plugin-$key-live", $path);
                if ($had) {
                    $this->host->must("plugin-$key-aside", ['/usr/bin/mv', '-T', '--', $path, $path . self::PREVIOUS]);
                }
                $switched[] = [$key, $path, $had];
                $this->host->must("plugin-$key-switch", ['/usr/bin/mv', '-T', '--', $path . self::STAGE, $path]);
            }
            $this->host->must('plugin-whm-register', [self::REGISTER, "{$this->source}/whm/ols-cpanel.conf"]);
            $this->host->must('plugin-cpanel-register', [self::INSTALL_PLUGIN, $archive, '--theme', 'jupiter'], 300);
        } catch (DeploymentError $error) {
            foreach (array_reverse($switched) as [$key, $path, $had]) {
                $this->host->run("plugin-$key-rollback-remove", ['/usr/bin/rm', '-rf', '--', $path]);
                if ($had) {
                    $this->host->run("plugin-$key-rollback", ['/usr/bin/mv', '-T', '--', $path . self::PREVIOUS, $path]);
                }
            }
            foreach ($items as [$key, $path]) {
                $this->host->run("plugin-$key-rollback-clean", ['/usr/bin/rm', '-rf', '--', $path . self::STAGE]);
            }
            throw $error;
        }
        foreach ($items as [$key, $path]) {
            $this->host->run("plugin-$key-previous-remove", ['/usr/bin/rm', '-rf', '--', $path . self::PREVIOUS]);
        }
        return ['WHM plugin deployed and registered', 'cPanel plugin deployed and registered (Jupiter)'];
    }

    private function exists(string $name, string $path): bool
    {
        return $this->host->run($name, ['/usr/bin/test', '-e', $path])['exit_code'] === 0;
    }

    /** @return list<string> */
    public function remove(): array
    {
        $archive = $this->state . '/plugin-cpanel.tar.gz';
        if (is_file($archive)) {
            $this->host->run('plugin-cpanel-unregister', [self::UNINSTALL_PLUGIN, $archive, '--theme', 'jupiter'], 300);
        }
        $this->host->run('plugin-whm-unregister', [self::UNREGISTER, self::APPCONFIG]);
        foreach ([$this->destinations['whm'], $this->destinations['cpanel'], $this->destinations['icon']] as $path) {
            $this->host->run('plugin-remove', ['/usr/bin/rm', '-rf', '--', $path]);
        }
        return ['WHM and cPanel plugins unregistered and removed'];
    }
}
