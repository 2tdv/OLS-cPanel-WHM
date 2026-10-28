<?php
declare(strict_types=1);

namespace OlsCpanel\Cli\Command;

use OlsCpanel\Cli\Application;
use OlsCpanel\Cli\Command;
use OlsCpanel\Cli\EngineContext;
use OlsCpanel\Cli\Output;

/**
 * The cPanel hook entry: event JSON on stdin, spooled (restricting events raise the epoch first); prints
 * exactly "1" in every case, including wrong arguments and a caller other than root (exit 1, nothing
 * recorded), so the hook can never fail a cPanel operation.
 */
final class HookCommand implements Command
{
    private const MAX_INPUT = 16 * 1024 * 1024;

    /** @param resource|null $stdin */
    public function __construct(private readonly EngineContext $context, private $stdin = null)
    {
    }

    public function words(): array
    {
        return ['hook'];
    }

    public function summary(): string
    {
        return 'cPanel hook entry: spool the event on stdin, always print 1';
    }

    public function run(array $argv, Output $out): int
    {
        // PHP's CLI prints warnings on stdout by default; nothing but "1" may appear there.
        ini_set('display_errors', 'stderr');
        try {
            $this->context->root();
            if ($argv !== []) {
                throw new \InvalidArgumentException('hook takes no arguments');
            }
        } catch (\Throwable $error) {
            fwrite($out->stderr(), 'ols-cpanel hook: ' . $error->getMessage() . "\n");
            fwrite($out->stdout(), '1');
            return Application::EXIT_REFUSED;
        }
        $input = @stream_get_contents($this->stdin ?? STDIN, self::MAX_INPUT);
        $this->context->hook()->handle(is_string($input) ? $input : '', $out->stdout(), $out->stderr());
        return Application::EXIT_OK;
    }
}
