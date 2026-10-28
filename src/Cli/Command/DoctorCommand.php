<?php
declare(strict_types=1);

namespace OlsCpanel\Cli\Command;

use OlsCpanel\Cli\Application;
use OlsCpanel\Cli\Arguments;
use OlsCpanel\Cli\Command;
use OlsCpanel\Cli\Output;
use OlsCpanel\Cli\UsageError;
use OlsCpanel\Cpanel\Discovery\PlatformInspector;
use OlsCpanel\Infrastructure\Filesystem\ObservationReader;
use OlsCpanel\Infrastructure\Process\ProbeRunner;

/** Read-only platform and readiness report. Exit 2 while production activation is not allowed. */
final class DoctorCommand implements Command
{
    private const MAX_FIXTURE = 1048576;

    public function words(): array
    {
        return ['doctor'];
    }

    public function summary(): string
    {
        return 'Platform and readiness report (--read-only, JSON only; --fixture=FILE for synthetic input)';
    }

    public function run(array $argv, Output $out): int
    {
        $args = new Arguments($argv, ['read-only'], ['fixture']);
        if (!$args->flag('read-only') || !$out->json()) {
            throw new UsageError('doctor --read-only --format=json [--fixture=FILE]');
        }
        $fixture = $args->value('fixture');
        try {
            $observations = $fixture !== null ? $this->fixture($fixture) : $this->observe();
            $runtime = ['php' => PHP_VERSION, 'sapi' => PHP_SAPI, 'binary' => PHP_BINARY,
                'effective_uid' => function_exists('posix_geteuid') ? posix_geteuid() : null,
                'architecture' => php_uname('m'), 'kernel' => php_uname('r')];
            $report = (new PlatformInspector())->inspect($observations, $runtime, $fixture !== null);
        } catch (\Throwable) {
            // Do not print parser input, path contents or unredacted exceptions.
            $out->error('Observation failed; no supported inventory was produced.');
            return Application::internal($out, 'observation failed; no supported inventory was produced');
        }
        $out->result($report);
        return Application::EXIT_AUDIT_ONLY;
    }

    /** @return array<string,mixed> */
    private function fixture(string $path): array
    {
        if (!is_file($path) || filesize($path) > self::MAX_FIXTURE) {
            throw new \RuntimeException('Invalid fixture');
        }
        $text = file_get_contents($path, false, null, 0, self::MAX_FIXTURE + 1);
        if ($text === false || strlen($text) > self::MAX_FIXTURE) {
            throw new \RuntimeException('Invalid fixture');
        }
        $data = json_decode($text, true, 32, JSON_THROW_ON_ERROR);
        if (!is_array($data) || ($data['synthetic'] ?? null) !== true || !is_array($data['observations'] ?? null)) {
            throw new \RuntimeException('Fixture must be explicitly synthetic');
        }
        foreach ($data['observations'] as $observation) {
            if (!is_array($observation)) {
                throw new \RuntimeException('Invalid observation');
            }
        }
        return $data['observations'];
    }

    /** @return array<string,mixed> */
    private function observe(): array
    {
        $reader = new ObservationReader();
        $runner = new ProbeRunner();
        $observations = [];
        foreach (array_keys(ObservationReader::PATHS) as $source) {
            $observations[$source] = $reader->read($source);
        }
        foreach (array_keys(ProbeRunner::COMMANDS) as $source) {
            $observations[$source] = $runner->run($source);
        }
        return $observations;
    }
}
