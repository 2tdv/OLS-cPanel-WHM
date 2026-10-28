<?php
declare(strict_types=1);

namespace OlsCpanel\Cli;

/**
 * Options after the command words: `--name`, `--name=value` and positional values. A command declares the
 * options it accepts; anything else is a usage error, so a mistyped option never changes what runs.
 */
final class Arguments
{
    /** @var array<string,string|true> */
    private array $options = [];
    /** @var list<string> */
    private array $positional = [];

    /**
     * @param list<string> $argv
     * @param list<string> $flags options without a value
     * @param list<string> $valued options that take `=value`
     */
    public function __construct(array $argv, array $flags, array $valued, int $maxPositional = 0)
    {
        foreach ($argv as $arg) {
            if (!str_starts_with($arg, '--')) {
                $this->positional[] = $arg;
                continue;
            }
            [$name, $value] = str_contains($arg, '=') ? explode('=', substr($arg, 2), 2) : [substr($arg, 2), null];
            if (isset($this->options[$name])) {
                throw new UsageError("option --$name given twice");
            }
            if ($value === null && in_array($name, $flags, true)) {
                $this->options[$name] = true;
            } elseif ($value !== null && $value !== '' && in_array($name, $valued, true)) {
                $this->options[$name] = $value;
            } else {
                throw new UsageError("unknown or malformed option --$name");
            }
        }
        if (count($this->positional) > $maxPositional) {
            throw new UsageError('unexpected argument ' . $this->positional[$maxPositional]);
        }
    }

    public function flag(string $name): bool
    {
        return ($this->options[$name] ?? null) === true;
    }

    public function value(string $name): ?string
    {
        $value = $this->options[$name] ?? null;
        return is_string($value) ? $value : null;
    }

    public function positional(int $index): ?string
    {
        return $this->positional[$index] ?? null;
    }
}
