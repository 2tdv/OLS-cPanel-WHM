<?php
declare(strict_types=1);

namespace OlsCpanel\Php;

use OlsCpanel\Ols\Compiler\CompilationRefused;
use OlsCpanel\Ols\Generation\GenerationTree;
use OlsCpanel\Ols\Generation\LocalEngine;

/**
 * Reconciler safety for PHP (FV-10): a vhost whose PHP version has no usable lsphp (`/opt/cpanel/ea-phpXX/root/usr/bin/lsphp`
 * missing or not executable: a version just added in EasyApache or MultiPHP, or a profile that removed
 * `ea-phpXX-php-litespeed`) must never be compiled into a configuration whose lsapi extProcessor points at nothing.
 *
 * For every such vhost served natively the guard puts the vhost's configuration from the ACTIVE generation back
 * (its own, working lsphp; the health additions of the tree are removed first because the tree adds them again),
 * so the site keeps answering as before until the version is complete, and the PHP environment applier is asked to
 * complete it (the caller's `$trigger`). A vhost with no usable earlier configuration (new, or its earlier PHP
 * is gone too) refuses the compilation with a clear reason and the same trigger; the pass retries, so the vhost
 * is compiled as soon as the applier has made lsphp usable. Hybrid vhosts served by Apache do not use lsphp and
 * are skipped. Read only: the reconciler runs unprivileged and only reads /opt/cpanel and the generation tree.
 */
final class LsphpGuard
{
    /** @param (\Closure(list<string>):void)|null $trigger asks the PHP environment applier to run, given the versions concerned */
    public function __construct(private readonly string $phpRoot = '/opt/cpanel', private readonly string $stateRoot = LocalEngine::STATE,
                                private readonly ?\Closure $trigger = null)
    {
    }

    public function usable(string $version): bool
    {
        return preg_match(OpcacheManager::VERSION, $version) === 1 && PhpEnvironment::lsphpPresent($this->phpRoot, $version);
    }

    /**
     * @param array{config:string, vhconf:array<string,string>, plan:array<string,array<string,mixed>>, summary:array<string,mixed>} $compiled
     * @return array{0:array<string,mixed>, 1:list<array{vhost:string, php:string, action:string}>} the compile with the kept configurations, and what was kept
     * @throws CompilationRefused when a vhost has no usable earlier configuration
     */
    public function apply(array $compiled): array
    {
        $missing = [];
        foreach ($compiled['plan'] as $name => $vhost) {
            $version = (string) ($vhost['php'] ?? '');
            if (($vhost['mode'] ?? 'native') === 'native' && !$this->usable($version)) {
                $missing[(string) $name] = $version;
            }
        }
        if ($missing === []) {
            return [$compiled, []];
        }
        $versions = array_values(array_unique($missing));
        sort($versions, SORT_STRING);
        if ($this->trigger !== null) {
            ($this->trigger)($versions);
        }
        $kept = [];
        $refused = [];
        foreach ($missing as $name => $version) {
            $previous = $this->previous($name);
            if ($previous === null) {
                $refused[$name] = $version;
                continue;
            }
            $compiled['vhconf'][$name] = $previous;
            $kept[] = ['vhost' => $name, 'php' => $version, 'action' => 'kept_previous'];
        }
        if ($refused !== []) {
            $names = array_keys($refused);
            throw new CompilationRefused('no usable lsphp for ' . implode(', ', array_unique($refused)) . ' (' . implode(', ', array_slice($names, 0, 5))
                . (count($names) > 5 ? ', ...' : '') . ') and no earlier configuration to keep: the PHP environment service is completing '
                . 'the version; this vhost is compiled on the next pass', $names);
        }
        return [$compiled, $kept];
    }

    /**
     * The vhost's configuration of the active generation as the compiler produced it (without the tree's health
     * rule and context), or null when there is none or its own lsphp is not usable either.
     */
    public function previous(string $vhost): ?string
    {
        if (!GenerationTree::validVhost($vhost)) {
            return null;
        }
        $target = @readlink("{$this->stateRoot}/active");
        if ($target === false || preg_match(GenerationTree::ID, basename($target)) !== 1) {
            return null;
        }
        $path = "{$this->stateRoot}/generations/" . basename($target) . "/vhosts/$vhost/vhconf.conf";
        $text = is_file($path) && !is_link($path) ? @file_get_contents($path, false, null, 0, 16 * 1024 * 1024) : false;
        if ($text === false || preg_match('#^\s+path\s+/opt/cpanel/(ea-php[0-9]{2,3})/root/usr/bin/lsphp$#m', $text, $m) !== 1
            || !$this->usable($m[1])) {
            return null;
        }
        // Undo what GenerationTree::build adds: the health rule after the rewrite rules marker, the health context at the end.
        $text = str_replace("<<<END_rules\n" . GenerationTree::HEALTH_RULE, "<<<END_rules\n", $text);
        $cut = strrpos($text, 'context ' . GenerationTree::HEALTH_URI . " {\n");
        return $cut === false ? null : substr($text, 0, $cut);
    }
}
