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
 * `cache purge (--all | --account=U | --domain=D)`: deletes the entries of the selected LSCache stores (root).
 * `--account` may accompany `--domain` as a check that the domain belongs to that account (the broker passes it
 * for tenant purges); `--all` takes no other option.
 */
final class CachePurgeCommand implements Command
{
    public function __construct(private readonly EngineContext $context)
    {
    }

    public function words(): array
    {
        return ['cache', 'purge'];
    }

    public function summary(): string
    {
        return 'Purge LSCache entries: --all, --account=U or --domain=D (root)';
    }

    public function run(array $argv, Output $out): int
    {
        $args = new Arguments($argv, ['all'], ['account', 'domain']);
        $account = $args->value('account');
        $domain = $args->value('domain');
        if ($args->flag('all') ? ($account !== null || $domain !== null) : ($account === null && $domain === null)) {
            throw new UsageError('cache purge takes --all, or --account=U and/or --domain=D');
        }
        $this->context->root();
        try {
            $result = ['command' => 'cache purge'] + $this->context->cache()->purge($account, $domain);
            $out->result($result);
            // A purge that left entries behind is not a success (the broker and the interfaces see the exit status).
            return $result['result'] === 'purged' ? Application::EXIT_OK : Application::EXIT_REFUSED;
        } catch (\InvalidArgumentException $error) {
            throw new Refused($error->getMessage(), 0, $error);
        }
        return Application::EXIT_OK;
    }
}
