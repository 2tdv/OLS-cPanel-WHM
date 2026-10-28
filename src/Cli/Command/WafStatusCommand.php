<?php
declare(strict_types=1);

namespace OlsCpanel\Cli\Command;

use OlsCpanel\Cli\Application;
use OlsCpanel\Cli\Arguments;
use OlsCpanel\Cli\Command;
use OlsCpanel\Cli\EngineContext;
use OlsCpanel\Cli\Output;
use OlsCpanel\Deployment\SecurityInput;
use OlsCpanel\Ols\Compiler\CompilationRefused;

/**
 * The WAF as the active generation has it (FV-02; root): engine mode, vendors, rule and data files with the sha256
 * the compile read, rules disabled globally, per-domain disables and the exceptions of security.json. Read from the
 * active generation's summary.json, so it shows what is running, not what a new compile would produce.
 */
final class WafStatusCommand implements Command
{
    private const VENDOR_DIR = '/etc/apache2/conf.d/modsec_vendor_configs/';

    public function __construct(private readonly EngineContext $context, private readonly string $securityPath = SecurityInput::PATH)
    {
    }

    public function words(): array
    {
        return ['waf', 'status'];
    }

    public function summary(): string
    {
        return 'WAF engine, vendors, rule files, disables and exceptions (root)';
    }

    public function run(array $argv, Output $out): int
    {
        new Arguments($argv, [], []);
        $this->context->root();
        $store = $this->context->store();
        $generation = $store->pointer();
        $summary = $generation === null ? null : $store->summary($generation);
        $waf = is_array($summary) ? ($summary['waf'] ?? null) : null;
        $result = ['active_generation' => $generation, 'state' => is_array($waf) ? ($waf['state'] ?? 'unknown') : 'unknown'];
        if (is_array($waf) && ($waf['state'] ?? null) === 'translated') {
            $hashes = [];
            foreach ($waf['inputs'] ?? [] as $input) {
                $hashes[$input['path']] = $input['sha256'];
            }
            $files = static fn(array $paths): array => array_map(static fn(string $path): array
                => ['path' => $path, 'sha256' => $hashes[$path] ?? null], $paths);
            $vendors = [];
            foreach (array_merge($waf['rule_files'] ?? [], $waf['data_files'] ?? []) as $path) {
                if (str_starts_with($path, self::VENDOR_DIR)) {
                    $vendors[explode('/', substr($path, strlen(self::VENDOR_DIR)))[0]] = true;
                }
            }
            $vendors = array_map('strval', array_keys($vendors));
            sort($vendors, SORT_STRING);
            $result += ['engine' => $waf['engine'] ?? null, 'audit_log' => $waf['audit_log'] ?? null, 'vendors' => $vendors,
                'inputs' => $waf['inputs'] ?? [], 'rule_files' => $files($waf['rule_files'] ?? []),
                'data_files' => $files($waf['data_files'] ?? []), 'rules' => $waf['rules'] ?? null,
                'disabled_rules' => $waf['disabled_rules'] ?? [], 'differences' => $waf['differences'] ?? [],
                'domain_disables' => $waf['exceptions'] ?? []];
        }
        $result['security_json'] = $this->security();
        $out->result($result);
        return Application::EXIT_OK;
    }

    /** @return array<string,mixed> */
    private function security(): array
    {
        $view = ['path' => $this->securityPath, 'present' => file_exists($this->securityPath)];
        try {
            $input = SecurityInput::load($this->securityPath);
        } catch (CompilationRefused $error) {
            return $view + ['error' => $error->getMessage()];
        }
        return $view + ['exceptions' => $input['exceptions'] ?? [], 'per_client' => $input['per_client'] ?? null,
            'ip_allow' => $input['ip_allow'] ?? [], 'ip_block' => $input['ip_block'] ?? [],
            'accept_differences' => $input['accept_differences'] ?? []];
    }
}
