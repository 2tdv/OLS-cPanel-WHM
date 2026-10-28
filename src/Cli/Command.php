<?php
declare(strict_types=1);

namespace OlsCpanel\Cli;

/** One `ols-cpanel` command (docs/product-interfaces.md, command-line interface). */
interface Command
{
    /** The words that select this command, e.g. ['generation', 'list']. @return list<string> */
    public function words(): array;

    /** One line for the help text. */
    public function summary(): string;

    /**
     * Runs the command on the arguments after its words (without `--format=json`, which selects the
     * Output). It declares its options through Arguments; returns the exit code (Application::EXIT_*).
     * @param list<string> $argv
     */
    public function run(array $argv, Output $out): int;
}
