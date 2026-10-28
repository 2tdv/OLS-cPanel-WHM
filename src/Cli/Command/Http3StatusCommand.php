<?php
declare(strict_types=1);

namespace OlsCpanel\Cli\Command;

use OlsCpanel\Cli\Application;
use OlsCpanel\Cli\Arguments;
use OlsCpanel\Cli\Command;
use OlsCpanel\Cli\EngineContext;
use OlsCpanel\Cli\Output;
use OlsCpanel\Cli\UsageError;
use OlsCpanel\Deployment\Host;
use OlsCpanel\Deployment\Http3Firewall;
use OlsCpanel\Deployment\Http3Input;
use OlsCpanel\Infrastructure\Process\LocalCommandRunner;
use OlsCpanel\Ols\Compiler\CompilationRefused;
use OlsCpanel\Ols\Http3\ProtocolShare;

/**
 * HTTP/3 (FV-04; root): the operator input (/var/lib/ols-cpanel/http3.json), what the host firewall says about UDP 443
 * (read-only inspection, never a change) and the HTTP/1.x, HTTP/2 and HTTP/3 share of each vhost of the active
 * generation, from the last lines of its domlogs (--lines=N, 1..20000, default 2000). Read-only.
 */
final class Http3StatusCommand implements Command
{
    public const MAX_LINES = 20000;

    /** @param (\Closure():array<string,mixed>)|null $firewall the firewall inspection (default: through the local runner) */
    public function __construct(private readonly EngineContext $context, private readonly string $inputPath = Http3Input::PATH,
                                private readonly string $logDir = ProtocolShare::DOMLOGS, private readonly ?\Closure $firewall = null)
    {
    }

    public function words(): array
    {
        return ['http3', 'status'];
    }

    public function summary(): string
    {
        return 'HTTP/3 input, UDP 443 firewall state and the protocol share per vhost, --lines=N (root)';
    }

    public function run(array $argv, Output $out): int
    {
        $arguments = new Arguments($argv, [], ['lines']);
        $text = $arguments->value('lines');
        if ($text !== null && (!preg_match('/^[0-9]{1,5}$/D', $text) || (int) $text < 1 || (int) $text > self::MAX_LINES)) {
            throw new UsageError('--lines must be 1..' . self::MAX_LINES);
        }
        $lines = $text === null ? ProtocolShare::LINES : (int) $text;
        $this->context->root();
        $input = ['path' => $this->inputPath, 'present' => file_exists($this->inputPath) || is_link($this->inputPath)];
        try {
            $enabled = Http3Input::load($this->inputPath);
        } catch (CompilationRefused $error) {
            $enabled = null;
            $input['error'] = $error->getMessage();
        }
        $store = $this->context->store();
        $generation = $store->pointer();
        $summary = $generation === null ? null : $store->summary($generation);
        $vhosts = [];
        foreach (array_keys(is_array($summary) && is_array($summary['vhosts'] ?? null) ? $summary['vhosts'] : []) as $name) {
            if (preg_match(ProtocolShare::DOMAIN, (string) $name)) {
                $vhosts[] = (string) $name;
            }
        }
        $firewall = null;
        if ($enabled !== false) {
            try {
                $firewall = ($this->firewall ?? static fn(): array => (new Http3Firewall(new Host(new LocalCommandRunner())))->inspect())();
                unset($firewall['new_text']);
            } catch (\Throwable $error) {
                $firewall = ['type' => 'unknown', 'action' => 'none', 'detail' => 'the firewall could not be inspected: ' . Host::tail($error->getMessage())];
            }
        }
        $out->result(['active_generation' => $generation, 'enabled' => $enabled, 'input' => $input, 'firewall' => $firewall,
            'log_dir' => $this->logDir, 'lines' => $lines,
            'protocol_share' => ProtocolShare::shares($this->logDir, $vhosts, $lines)]);
        return Application::EXIT_OK;
    }
}
