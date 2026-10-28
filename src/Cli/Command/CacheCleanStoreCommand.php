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
 * `cache clean-store --root=R --store=S --cutoff=T --cap=N --now=T`: the confined helper of `cache clean`, like `cache purge-store`:
 * it removes entries of one store with the privileges of the process that runs it and refuses to run as root (the privileged
 * cleanup starts it through setpriv as the store's owner, without capabilities). Not an operator command.
 */
final class CacheCleanStoreCommand implements Command
{
    public function __construct(private readonly EngineContext $context)
    {
    }

    public function words(): array
    {
        return ['cache', 'clean-store'];
    }

    public function summary(): string
    {
        return 'Internal: clean one LSCache store as its owner (refuses to run as root)';
    }

    public function run(array $argv, Output $out): int
    {
        $args = new Arguments($argv, [], ['root', 'store', 'cutoff', 'cap', 'now']);
        $root = $args->value('root');
        $store = $args->value('store');
        $numbers = [];
        foreach (['cutoff', 'cap', 'now'] as $name) {
            $value = $args->value($name);
            if ($value === null || preg_match('/^[0-9]{1,19}$/D', $value) !== 1 || (string) (int) $value !== $value) {
                throw new UsageError("cache clean-store needs --$name=<whole number>");
            }
            $numbers[$name] = (int) $value;
        }
        if ($root === null || $store === null || !str_starts_with($root, '/')) {
            throw new UsageError('cache clean-store takes an absolute --root=R and --store=S');
        }
        $this->context->unprivileged();
        try {
            $counts = (new CacheStorage($root))->trimStore($store, $numbers['cutoff'], $numbers['cap'], $numbers['now']);
        } catch (\InvalidArgumentException $error) {
            throw new Refused($error->getMessage(), 0, $error);
        }
        $out->result(['command' => 'cache clean-store'] + $counts);
        return Application::EXIT_OK;
    }
}
