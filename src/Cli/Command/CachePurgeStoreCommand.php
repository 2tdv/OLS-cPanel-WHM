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
use OlsCpanel\Ols\Cache\CacheStorage;

/**
 * `cache purge-store --root=R --store=S`: the confined helper of `cache purge` (RV-31 item 15). It deletes the entries of
 * one LSCache store with the privileges of the process that runs it and refuses to run as root: the privileged purge starts
 * it through setpriv as the store's owner (the OLS server user) without capabilities, so a directory swapped for a link
 * under a compromised OLS worker can only ever redirect deletions to what that user could already delete. Not an operator
 * command; --retire also removes obsolete control files. It prints the counts of what it removed and "failed" (removals that did not happen).
 */
final class CachePurgeStoreCommand implements Command
{
    public function __construct(private readonly EngineContext $context)
    {
    }

    public function words(): array
    {
        return ['cache', 'purge-store'];
    }

    public function summary(): string
    {
        return 'Internal: purge one LSCache store as its owner (refuses to run as root)';
    }

    public function run(array $argv, Output $out): int
    {
        $args = new Arguments($argv, ['retire'], ['root', 'store']);
        $root = $args->value('root');
        $store = $args->value('store');
        if ($root === null || $store === null || !str_starts_with($root, '/')) {
            throw new UsageError('cache purge-store takes an absolute --root=R and --store=S');
        }
        $this->context->unprivileged();
        try {
            $counts = (new CacheStorage($root))->purgeStore($store, $args->flag('retire'));
        } catch (\InvalidArgumentException $error) {
            throw new Refused($error->getMessage(), 0, $error);
        }
        $out->result(['command' => 'cache purge-store'] + $counts);
        return Application::EXIT_OK;
    }
}
