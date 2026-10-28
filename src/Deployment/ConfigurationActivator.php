<?php
declare(strict_types=1);

namespace OlsCpanel\Deployment;

/**
 * Compiles the current cPanel state with the deployment profile and activates it as a new generation
 * (the reconciler's single pass, forced). Used by cutover after profile.json is written, under the deployment
 * lock the cutover holds exclusively.
 */
interface ConfigurationActivator
{
    /**
     * @param string|null $expectedDigest CutoverPlan::digest of the approved plan: a compile with another digest
     *        (configuration or a referenced certificate, key or password file changed) is refused before anything
     *        is activated
     * @return array<string,mixed> the reconcile result: "action" ("committed" on success), "generation", "hybrid_vhosts", ...
     */
    public function activate(?string $expectedDigest = null): array;
}
