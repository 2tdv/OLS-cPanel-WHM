<?php
declare(strict_types=1);

namespace OlsCpanel\Cli;

/**
 * `ols-cpanel` dispatcher: selects the command by its words (longest match), passes the remaining
 * arguments and maps failures to the documented exit codes (docs/product-interfaces.md).
 * With --format=json every exit prints exactly one JSON object on stdout (review RV-29, finding 17): the
 * command's own result, or for usage errors (64), internal errors (70), refusals (1) and busy (75)
 * `{"result": "usage" | "internal" | "refused" | "busy", "code": <exit code>, "error": <reason>}` (refusals
 * add "class", and "engine_code" for engine and broker errors). The only exception is `hook`, which always
 * prints exactly "1" for cPanel.
 */
final class Application
{
    public const EXIT_OK = 0;
    public const EXIT_REFUSED = 1;
    public const EXIT_AUDIT_ONLY = 2;
    public const EXIT_USAGE = 64;
    public const EXIT_INTERNAL = 70;
    public const EXIT_BUSY = 75;

    /** @var list<Command> */
    private array $commands;

    /** @param list<Command>|null $commands */
    public function __construct(?array $commands = null)
    {
        $this->commands = $commands ?? self::defaultCommands();
    }

    /** @return list<Command> */
    public static function defaultCommands(): array
    {
        $context = new EngineContext();
        return [
            new Command\DoctorCommand(),
            new Command\InstallCommand(opcache: static fn(\OlsCpanel\Deployment\Environment $e): \OlsCpanel\Php\OpcacheManager => new \OlsCpanel\Php\OpcacheManager($e),
                phpEnvironment: static fn(\OlsCpanel\Deployment\Environment $e): \OlsCpanel\Php\PhpEnvironment => \OlsCpanel\Php\PhpEnvironment::production($e)),
            new Command\ApacheReturnCommand(),
            new Command\HybridRefreshTrustCommand(),
            new Command\HooksCommand(),
            new Command\UninstallCommand(),
            new Command\StatusCommand($context),
            new Command\SyncCommand($context),
            new Command\HookCommand($context),
            new Command\GenerationListCommand($context),
            new Command\GenerationInspectCommand($context),
            new Command\RollbackCommand($context),
            new Command\RecoverCommand($context),
            new Command\WafStatusCommand($context),
            new Command\WafBlockedCommand($context),
            new Command\Http3StatusCommand($context),
            ...array_map(static fn(string $action): Command => new Command\ObjectCacheCommand($context, $action,
                static fn(): \OlsCpanel\ObjectCache\ObjectCacheManager => new \OlsCpanel\ObjectCache\ObjectCacheManager(
                    new \OlsCpanel\Infrastructure\Process\LocalCommandRunner(\OlsCpanel\Infrastructure\Process\LocalCommandRunner::MAX_OUTPUT, true),
                    extensions: \OlsCpanel\PhpExtensions\ExtensionSync::production())),
                array_keys(Command\ObjectCacheCommand::ACTIONS)),
            ...array_map(static fn(string $action): Command => new Command\PhpExtCommand($context, $action,
                static fn(): \OlsCpanel\PhpExtensions\ExtensionService => \OlsCpanel\PhpExtensions\ExtensionSync::production()),
                array_keys(Command\PhpExtCommand::ACTIONS)),
            new Command\CacheStatsCommand($context),
            new Command\CachePurgeCommand($context),
            new Command\CachePurgeStoreCommand($context),
            new Command\CacheCleanCommand($context),
            new Command\CacheCleanStoreCommand($context),
            new Command\CacheLimitsCommand($context),
            new Command\UpgradeCommand(),
            // FV-07 operations: notifications, maintenance windows, the update channel view and the support bundle.
            ...array_map(static fn(string $action): Command => new Command\NotifyCommand($context, $action), array_keys(Command\NotifyCommand::ACTIONS)),
            ...array_map(static fn(string $action): Command => new Command\ScheduleCommand($context, $action), array_keys(Command\ScheduleCommand::ACTIONS)),
            new Command\UpdateCheckCommand($context),
            new Command\UpdateInstallCommand($context),
            ...array_map(static fn(string $action): Command => new Command\SupportBundleCommand($context, $action), ['bundle', 'list']),
            new Command\PhpRestartCommand(),
            new Command\PhpStatusCommand(),
            new Command\PhpProcessesCommand(),
            ...array_map(static fn(string $action): Command => new Command\PhpOpcacheCommand($action), array_keys(Command\PhpOpcacheCommand::ACTIONS)),
            ...array_map(static fn(string $action): Command => new Command\PhpEnvCommand($action), array_keys(Command\PhpEnvCommand::ACTIONS)),
        ];
    }

    /** @param list<string> $argv arguments after the program name */
    public function run(array $argv, ?Output $output = null): int
    {
        $json = in_array('--format=json', $argv, true);
        $argv = array_values(array_filter($argv, static fn(string $a): bool => $a !== '--format=json'));
        $out = $output ?? new Output($json);
        if ($argv === [] || $argv === ['--help'] || $argv === ['help']) {
            $out->error($this->help());
            if ($argv === []) {
                return self::usage($out, 'a command is required');
            }
            if ($out->json()) {
                $out->result(['result' => 'help', 'code' => self::EXIT_OK, 'error' => null,
                    'commands' => array_map(static fn(Command $c): string => implode(' ', $c->words()), $this->commands)]);
            }
            return self::EXIT_OK;
        }
        $selected = null;
        foreach ($this->commands as $command) {
            $words = $command->words();
            if (array_slice($argv, 0, count($words)) === $words
                && ($selected === null || count($words) > count($selected->words()))) {
                $selected = $command;
            }
        }
        if ($selected === null) {
            $out->error('Unknown command. ' . $this->help());
            return self::usage($out, 'unknown command');
        }
        try {
            return $selected->run(array_slice($argv, count($selected->words())), $out);
        } catch (UsageError $error) {
            $out->error('Usage: ' . $error->getMessage());
            return self::usage($out, $error->getMessage());
        } catch (\OlsCpanel\Events\ReconcileBusy $error) {
            return self::failure($out, 'busy', $error, self::EXIT_BUSY);
        } catch (Refused | \OlsCpanel\Events\ReconcileRefused | \OlsCpanel\Ols\Compiler\CompilationRefused
                 | \OlsCpanel\Ols\Generation\EngineError | \OlsCpanel\Infrastructure\Process\CommandFailed $error) {
            return self::failure($out, 'refused', $error, self::EXIT_REFUSED);
        } catch (\Throwable $error) {
            // No parser input, path contents or traces: the class and a bounded message only.
            $message = 'Internal error (' . (new \ReflectionClass($error))->getShortName() . '): '
                . substr(preg_replace('/[^\x20-\x7e]/', '?', $error->getMessage()) ?? '', 0, 300);
            $out->error($message);
            return self::internal($out, $message);
        }
    }

    /** A usage error (exit 64); with --format=json also the JSON error object on stdout. */
    public static function usage(Output $out, string $message): int
    {
        return self::exit($out, 'usage', self::EXIT_USAGE, 'usage: ' . $message);
    }

    /** An internal error (exit 70); with --format=json also the JSON error object on stdout. */
    public static function internal(Output $out, string $message): int
    {
        return self::exit($out, 'internal', self::EXIT_INTERNAL, $message);
    }

    /** @param array<string,mixed> $details */
    private static function exit(Output $out, string $kind, int $code, string $message, array $details = []): int
    {
        if ($out->json()) {
            $out->result(['result' => $kind, 'code' => $code, 'error' => substr(preg_replace('/[^\x20-\x7e]/', '?', $message) ?? '', 0, 1000)]
                + $details);
        }
        return $code;
    }

    /**
     * A refusal or failure with its reason: on stderr, and with --format=json also as the one JSON object
     * on stdout (admin jobs return the command's JSON output).
     */
    private static function failure(Output $out, string $kind, \Throwable $error, int $code): int
    {
        $message = substr(preg_replace('/[^\x20-\x7e]/', '?', $error->getMessage()) ?? '', 0, 1000);
        $vhosts = $error instanceof \OlsCpanel\Ols\Compiler\CompilationRefused ? $error->vhosts() : [];
        $engineCode = $error instanceof \OlsCpanel\Ols\Generation\EngineError || $error instanceof \OlsCpanel\Infrastructure\Process\CommandFailed
            ? ['engine_code' => $error->errorCode] : [];
        self::exit($out, $kind, $code, $message, ['class' => (new \ReflectionClass($error))->getShortName()]
            + $engineCode + ($vhosts !== [] ? ['vhosts' => $vhosts] : []));
        $out->error(ucfirst($kind) . ': ' . $message);
        return $code;
    }

    public function help(): string
    {
        $lines = ['Usage: ols-cpanel <command> [options] [--format=json]', 'Commands:'];
        foreach ($this->commands as $command) {
            $lines[] = '  ' . str_pad(implode(' ', $command->words()), 22) . $command->summary();
        }
        return implode("\n", $lines);
    }
}
