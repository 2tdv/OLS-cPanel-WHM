<?php
declare(strict_types=1);

namespace OlsCpanel\Cli\Command;

use OlsCpanel\Cli\Application;
use OlsCpanel\Cli\Arguments;
use OlsCpanel\Cli\Command;
use OlsCpanel\Cli\EngineContext;
use OlsCpanel\Cli\Output;
use OlsCpanel\Cli\UsageError;

/**
 * Finish or undo interrupted activations and enforce the restriction epoch (activator recover). Operator
 * and boot recovery use no grace; --grace=N keeps HR-D11's grace (the reconciler uses 300). Exit 0 when
 * the result is coherent.
 */
final class RecoverCommand implements Command
{
    public function __construct(private readonly EngineContext $context)
    {
    }

    public function words(): array
    {
        return ['recover'];
    }

    public function summary(): string
    {
        return 'Recover interrupted activations and enforce the restriction epoch [--grace=N]';
    }

    public function run(array $argv, Output $out): int
    {
        $grace = (new Arguments($argv, [], ['grace']))->value('grace') ?? '0';
        if (!preg_match('/^(0|[1-9][0-9]{0,4})$/D', $grace)) {
            throw new UsageError('recover [--grace=N] (seconds, 0 to 99999)');
        }
        $result = $this->context->engine()->recover((int) $grace);
        $out->result($result);
        return ($result['coherent'] ?? false) === true ? Application::EXIT_OK : Application::EXIT_REFUSED;
    }
}
