<?php
declare(strict_types=1);

namespace OlsCpanel\Cli\Command;

use OlsCpanel\Cli\Application;
use OlsCpanel\Cli\Arguments;
use OlsCpanel\Cli\Command;
use OlsCpanel\Cli\EngineContext;
use OlsCpanel\Cli\Output;
use OlsCpanel\Cli\Refused;
use OlsCpanel\Cli\UsageError;

/**
 * `cache limits [--per-site-mb=N] [--server-percent=N] [--server-max-gb=N]`: shows the limits of the automatic LSCache cleanup, the
 * caps they give on this server's disk and the last cleanup (root); with options it changes those limits (written to
 * cache-limits.json, validated against the bounds). The WHM page cache view is the interactive form of this command.
 */
final class CacheLimitsCommand implements Command
{
    private const OPTIONS = ['per-site-mb' => 'per_site_mb', 'server-percent' => 'server_percent', 'server-max-gb' => 'server_max_gb'];

    public function __construct(private readonly EngineContext $context)
    {
    }

    public function words(): array
    {
        return ['cache', 'limits'];
    }

    public function summary(): string
    {
        return 'Show or set the LSCache cleanup limits: [--per-site-mb=N] [--server-percent=N] [--server-max-gb=N] (root)';
    }

    public function run(array $argv, Output $out): int
    {
        $args = new Arguments($argv, [], array_keys(self::OPTIONS));
        $this->context->root();
        $change = [];
        foreach (self::OPTIONS as $option => $key) {
            $value = $args->value($option);
            if ($value === null) {
                continue;
            }
            if (preg_match('/^[0-9]{1,9}$/D', $value) !== 1) {
                throw new UsageError("--$option takes a whole number");
            }
            $change[$key] = (int) $value;
        }
        try {
            if ($change !== []) {
                $this->context->cacheLimits()->save($change);
            }
            $report = $this->context->cacheCleaner()->status();
        } catch (\InvalidArgumentException $error) {
            throw new Refused($error->getMessage(), 0, $error);
        }
        $out->result(['command' => 'cache limits', 'changed' => $change !== []] + $report);
        return Application::EXIT_OK;
    }
}
