<?php
declare(strict_types=1);

namespace OlsCpanel\Cli\Command;

use OlsCpanel\Cli\Application;
use OlsCpanel\Cli\Arguments;
use OlsCpanel\Cli\Command;
use OlsCpanel\Cli\EngineContext;
use OlsCpanel\Cli\Output;

/**
 * Activate the newest previously committed generation that the activator still accepts (validation still
 * binds to the tree and OLS binary, epoch not older than the restriction epoch): a refused candidate is
 * skipped, any other outcome (rolled back, stopped) ends the attempt. Root only.
 */
final class RollbackCommand implements Command
{
    private const MAX_ATTEMPTS = 10;

    public function __construct(private readonly EngineContext $context)
    {
    }

    public function words(): array
    {
        return ['rollback'];
    }

    public function summary(): string
    {
        return 'Activate the newest earlier committed generation that is still valid and current (root)';
    }

    public function run(array $argv, Output $out): int
    {
        new Arguments($argv, [], []);
        $engine = $this->context->local();
        $from = $this->context->store()->pointer();
        $attempts = [];
        foreach (array_slice($this->context->store()->rollbackCandidates(), 0, self::MAX_ATTEMPTS) as $candidate) {
            $outcome = $engine->activateExisting($candidate);
            $attempts[] = ['generation' => $candidate, 'result' => $outcome['result'] ?? null, 'reason' => $outcome['reason'] ?? null];
            if (($outcome['result'] ?? null) !== 'refused') {
                $out->result(['action' => $outcome['result'] ?? null, 'from' => $from, 'generation' => $candidate,
                    'outcome' => $outcome, 'attempts' => $attempts]);
                return ($outcome['result'] ?? null) === 'committed' ? Application::EXIT_OK : Application::EXIT_REFUSED;
            }
        }
        $out->result(['action' => 'none', 'from' => $from, 'reason' => 'no earlier committed generation may be activated',
            'attempts' => $attempts]);
        return Application::EXIT_REFUSED;
    }
}
