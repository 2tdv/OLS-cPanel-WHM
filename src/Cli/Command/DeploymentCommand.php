<?php
declare(strict_types=1);

namespace OlsCpanel\Cli\Command;

use OlsCpanel\Cli\Application;
use OlsCpanel\Cli\Command;
use OlsCpanel\Cli\Output;
use OlsCpanel\Deployment\DeploymentError;
use OlsCpanel\Deployment\Environment;
use OlsCpanel\Deployment\Profile;
use OlsCpanel\Events\Reconciler;
use OlsCpanel\Ols\Generation\LocalEngine;

/**
 * Shared wiring of the deployment commands: the Environment (production by default, injected in tests), the
 * approval prompt (an exact text typed on a terminal, or --yes; never implied without a terminal) and the
 * report of refusals with their documented exit codes.
 */
abstract class DeploymentCommand implements Command
{
    /** @var \Closure():Environment */
    private \Closure $environment;
    /** @var resource */
    private $input;
    /** @var \Closure():bool */
    private \Closure $tty;

    /**
     * @param \Closure():Environment|null $environment
     * @param resource|null $input where the typed approval is read
     * @param \Closure():bool|null $tty whether input and output are a terminal
     */
    public function __construct(?\Closure $environment = null, $input = null, ?\Closure $tty = null)
    {
        // The configuration activator of cutover: the reconciler's forced pass on the local engine (root),
        // serialized with other passes by the reconcile lock.
        $this->environment = $environment ?? static fn(): Environment => Environment::production(
            new Reconciler(new LocalEngine(), null, null, null, Profile::PATH, Reconciler::LOCK, php: new \OlsCpanel\Php\LsphpGuard()));
        $this->input = $input ?? STDIN;
        $this->tty = $tty ?? fn(): bool => stream_isatty($this->input) && stream_isatty(STDERR);
    }

    protected function environment(): Environment
    {
        return ($this->environment)();
    }

    /**
     * Approval: --yes, or on a terminal the exact $expected text typed after the summary. Without a terminal
     * and without --yes nothing is approved (refused, exit 1).
     * @param list<string> $summary
     */
    protected function approve(Output $out, bool $yes, string $expected, array $summary, string $what): bool
    {
        if ($yes) {
            return true;
        }
        if (!($this->tty)()) {
            throw DeploymentError::refused("$what needs approval: run it on a terminal, or pass --yes");
        }
        $out->error(implode("\n", $summary));
        $out->error("To approve, type $expected and press Enter (anything else cancels):");
        $line = fgets($this->input, 256);
        return $line !== false && trim($line) === $expected;
    }

    /** Prints a refusal and returns its exit code. */
    protected function refused(Output $out, DeploymentError $error, string $command): int
    {
        $result = match ($error->exitCode) {
            Application::EXIT_BUSY => 'busy',
            Application::EXIT_AUDIT_ONLY => 'unsupported',
            default => 'refused',
        };
        if ($out->json()) {
            $out->result(['command' => $command, 'result' => $result, 'code' => $error->exitCode, 'error' => $error->getMessage()]
                + $error->details);
        } else {
            $out->error("$command: $result: " . $error->getMessage());
            if ($error->details !== []) {
                $out->error(json_encode($error->details, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) ?: '');
            }
        }
        return $error->exitCode;
    }
}
