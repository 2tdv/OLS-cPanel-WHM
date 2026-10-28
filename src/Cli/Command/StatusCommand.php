<?php
declare(strict_types=1);

namespace OlsCpanel\Cli\Command;

use OlsCpanel\Cli\Application;
use OlsCpanel\Cli\Arguments;
use OlsCpanel\Cli\Command;
use OlsCpanel\Cli\EngineContext;
use OlsCpanel\Cli\Output;
use OlsCpanel\Deployment\Host;
use OlsCpanel\Deployment\HybridHost;
use OlsCpanel\Deployment\Profile;
use OlsCpanel\Infrastructure\Process\LocalCommandRunner;

/** Owner of 80/443, deployment profile, active generation, epoch, pending events and hybrid vhosts. */
final class StatusCommand implements Command
{
    public function __construct(private readonly EngineContext $context)
    {
    }

    public function words(): array
    {
        return ['status'];
    }

    public function summary(): string
    {
        return 'Ports 80/443, profile, active generation, epoch, pending events, hybrid vhosts';
    }

    public function run(array $argv, Output $out): int
    {
        new Arguments($argv, [], []);
        $engine = $this->context->engine();
        try {
            $profile = Profile::load($this->context->profilePath());
            $profileView = $profile === null ? null : ['production' => $profile->production, 'hybrid_ports' => $profile->hybridPorts];
        } catch (\RuntimeException $error) {
            $profileView = ['error' => $error->getMessage()];
        }
        $activator = $engine->status();
        $out->result([
            'role' => $this->context->role(),
            'ports' => $this->context->ports()->owners([80, 443]),
            'cut_over' => $profileView !== null,
            'profile' => $profileView,
            'active_generation' => $activator['pointer'] ?? null,
            'epoch' => $activator['epoch'] ?? null,
            'activator' => $activator,
            'pending_events' => count($engine->pendingEvents()),
            'hybrid_vhosts' => $this->context->store()->activeHybridVhosts(),
            'hybrid_firewall' => $this->firewall(),
        ]);
        return Application::EXIT_OK;
    }

    /**
     * Whether the hybrid firewall table is loaded: 'present', 'missing', 'not-hybrid' (no include, no hybrid profile) or
     * 'unknown' (not root: nft cannot be asked, so it is never reported as missing).
     */
    private function firewall(): string
    {
        if ($this->context->role() !== 'root') {
            return 'unknown';
        }
        try {
            return (new HybridHost(new Host(new LocalCommandRunner()), dirname($this->context->profilePath())))->firewallState();
        } catch (\Throwable) {
            return 'unknown';
        }
    }
}
