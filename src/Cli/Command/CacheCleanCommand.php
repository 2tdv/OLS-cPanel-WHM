<?php
declare(strict_types=1);

namespace OlsCpanel\Cli\Command;

use OlsCpanel\Cli\Application;
use OlsCpanel\Cli\Arguments;
use OlsCpanel\Cli\Command;
use OlsCpanel\Cli\EngineContext;
use OlsCpanel\Cli\Output;
use OlsCpanel\Cli\Refused;

/**
 * `cache clean`: the automatic LSCache cleanup (root; run hourly by ols-cpanel-cache-clean.timer): removes expired entries, keeps
 * every store under its size cap and the server under its cap, trims harder when the disk is nearly full. See CacheCleaner.
 * The same pass rotates the ModSecurity audit log (RV-66, see AuditLogRotator for why this unit): first, and independent of the
 * cleanup, so neither can stop the other; a failure of either makes the unit fail.
 */
final class CacheCleanCommand implements Command
{
    public function __construct(private readonly EngineContext $context)
    {
    }

    public function words(): array
    {
        return ['cache', 'clean'];
    }

    public function summary(): string
    {
        return 'Remove expired LSCache entries and enforce the size caps (root; runs hourly by itself)';
    }

    public function run(array $argv, Output $out): int
    {
        new Arguments($argv, [], []);
        $this->context->root();
        try {
            $audit = $this->context->auditLogRotator()->rotate();
        } catch (\Throwable $error) {
            $audit = ['result' => 'failed', 'problems' => [$error->getMessage()]];
        }
        try {
            $report = $this->context->cacheCleaner()->clean();
        } catch (\InvalidArgumentException $error) {
            throw new Refused($error->getMessage(), 0, $error);
        }
        $out->result(['command' => 'cache clean'] + $report + ['audit_log' => $audit]);
        // A removal that did not happen is reported to the unit (failed, so it shows in systemctl and the journal).
        return $report['result'] === 'cleaned' && $audit['result'] !== 'failed' ? Application::EXIT_OK : Application::EXIT_REFUSED;
    }
}
