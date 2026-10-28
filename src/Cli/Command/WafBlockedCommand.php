<?php
declare(strict_types=1);

namespace OlsCpanel\Cli\Command;

use OlsCpanel\Cli\Application;
use OlsCpanel\Cli\Arguments;
use OlsCpanel\Cli\Command;
use OlsCpanel\Cli\EngineContext;
use OlsCpanel\Cli\Output;
use OlsCpanel\Cli\UsageError;
use OlsCpanel\Ols\Compiler\ModSecurityAuditLog;
use OlsCpanel\Ols\Compiler\SecurityTranslator;

/** The newest blocked-request records of OLS's ModSecurity audit log, newest first (FV-02; root). */
final class WafBlockedCommand implements Command
{
    public const DEFAULT_LIMIT = 50;
    public const MAX_LIMIT = 1000;
    /** Bytes read from the end of the log. */
    public const TAIL_BYTES = 4194304;

    public function __construct(private readonly EngineContext $context, private readonly string $log = SecurityTranslator::AUDIT_LOG)
    {
    }

    public function words(): array
    {
        return ['waf', 'blocked'];
    }

    public function summary(): string
    {
        return 'Newest blocked requests from the audit log, --limit=N (root)';
    }

    public function run(array $argv, Output $out): int
    {
        $arguments = new Arguments($argv, [], ['limit']);
        $text = $arguments->value('limit');
        if ($text !== null && (!preg_match('/^[0-9]{1,4}$/D', $text) || (int) $text < 1 || (int) $text > self::MAX_LIMIT)) {
            throw new UsageError('--limit must be 1..' . self::MAX_LIMIT);
        }
        $limit = $text === null ? self::DEFAULT_LIMIT : (int) $text;
        $this->context->root();
        $tail = $this->tail();
        $parsed = $tail === null ? ['records' => [], 'skipped' => 0] : (new ModSecurityAuditLog())->parse($tail, $limit);
        $out->result(['log' => $this->log, 'available' => $tail !== null, 'limit' => $limit,
            'records' => array_reverse($parsed['records']), 'skipped' => $parsed['skipped']]);
        return Application::EXIT_OK;
    }

    private function tail(): ?string
    {
        $handle = @fopen($this->log, 'rb');
        if ($handle === false) {
            return null;
        }
        try {
            $size = (int) (fstat($handle)['size'] ?? 0);
            if ($size > self::TAIL_BYTES) {
                fseek($handle, $size - self::TAIL_BYTES);
            }
            return (string) stream_get_contents($handle, self::TAIL_BYTES);
        } finally {
            fclose($handle);
        }
    }
}
