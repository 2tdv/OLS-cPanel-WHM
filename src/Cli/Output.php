<?php
declare(strict_types=1);

namespace OlsCpanel\Cli;

/** Command results: one JSON object with `--format=json`, otherwise readable text. */
final class Output
{
    /** @var resource */
    private $stdout;
    /** @var resource */
    private $stderr;

    /**
     * @param resource|null $stdout
     * @param resource|null $stderr
     */
    public function __construct(private bool $json = false, $stdout = null, $stderr = null)
    {
        $this->stdout = $stdout ?? STDOUT;
        $this->stderr = $stderr ?? STDERR;
    }

    public function json(): bool
    {
        return $this->json;
    }

    /**
     * The command's result: JSON as is, or text lines ("key: value" for scalars, JSON for the rest).
     * @param array<string,mixed> $result
     */
    public function result(array $result): void
    {
        if ($this->json) {
            fwrite($this->stdout, json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n");
            return;
        }
        foreach ($result as $key => $value) {
            $text = is_scalar($value) || $value === null ? var_export($value, true)
                : json_encode($value, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
            fwrite($this->stdout, "$key: " . (is_string($value) ? $value : $text) . "\n");
        }
    }

    public function error(string $message): void
    {
        fwrite($this->stderr, rtrim($message) . "\n");
    }

    /**
     * One compact JSON line (the service loop's log: one object per pass or enforcement), flushed at once.
     * @param array<string,mixed> $record
     */
    public function line(array $record): void
    {
        fwrite($this->stdout, json_encode($record, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR) . "\n");
        fflush($this->stdout);
    }

    /** @return resource the raw standard output (the cPanel hook answers exactly "1" on it) */
    public function stdout()
    {
        return $this->stdout;
    }

    /** @return resource */
    public function stderr()
    {
        return $this->stderr;
    }
}
