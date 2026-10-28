<?php
declare(strict_types=1);

namespace OlsCpanel\Deployment;

/**
 * A full, read-only compile of the current cPanel state with production listeners (ServerConfigurationBuilder
 * result: config, vhconf, plan, summary). Throws OlsCpanel\Ols\Compiler\CompilationRefused when the state
 * cannot be served as it is.
 */
interface Compilation
{
    /**
     * @param array{0:int,1:int}|null $hybridPorts Apache's backend ports when hybrid vhosts are allowed
     * @return array{config:string, vhconf:array<string,string>, plan:array<string,array<string,mixed>>, summary:array<string,mixed>}
     */
    public function compile(?array $hybridPorts): array;
}
