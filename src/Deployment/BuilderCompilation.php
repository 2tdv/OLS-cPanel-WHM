<?php
declare(strict_types=1);

namespace OlsCpanel\Deployment;

use OlsCpanel\Infrastructure\Process\CommandRunner;
use OlsCpanel\Ols\Compiler\CompilationRefused;
use OlsCpanel\Ols\Compiler\ServerConfigurationBuilder;
use OlsCpanel\Php\PhpLimits;

/**
 * The compile of every cPanel account (whmapi1 listaccts: user => main domain) through ServerConfigurationBuilder,
 * with the product's server template and error log directory.
 */
final class BuilderCompilation implements Compilation
{
    /** Server policy template shipped with the product (the lab's ownership_httpd_config.conf). */
    public const TEMPLATE = '/usr/local/ols-cpanel/share/ols/httpd_config.conf';
    /** Per-vhost OLS error logs. */
    public const ERROR_LOG_DIR = '/usr/local/lsws/logs/vhosts';

    /** @var \Closure(CommandRunner, array<string,string>, string, string, ?array, array, PhpLimits, bool):ServerConfigurationBuilder */
    private \Closure $builder;

    public function __construct(private CommandRunner $runner, private string $templatePath = self::TEMPLATE,
                                private string $errorLogDir = self::ERROR_LOG_DIR, ?\Closure $builder = null,
                                private string $securityPath = SecurityInput::PATH, private string $limitsPath = PhpLimits::PATH,
                                private string $http3Path = Http3Input::PATH)
    {
        $this->builder = $builder ?? static fn(CommandRunner $r, array $tenants, string $template, string $logs, ?array $ports, array $security,
                                               PhpLimits $limits, bool $http3 = true)
            => new ServerConfigurationBuilder($r, $tenants, $template, $logs, hybridPorts: $ports, security: $security, phpLimits: $limits,
                http3: $http3, previousVhost: (new \OlsCpanel\Php\LsphpGuard())->previous(...));
    }

    public function compile(?array $hybridPorts): array
    {
        $template = @file_get_contents($this->templatePath);
        if ($template === false || $template === '') {
            throw new CompilationRefused("server template {$this->templatePath} is unreadable");
        }
        // The product security input (FV-02): absent is `{}`; a malformed file refuses the compile (fail closed).
        $security = SecurityInput::load($this->securityPath);
        // The per-account PHP limits (FV-03): absent is the built-in set; a malformed file refuses the compile.
        try {
            $limits = PhpLimits::load($this->limitsPath);
        } catch (\InvalidArgumentException $error) {
            throw new CompilationRefused($error->getMessage(), [], $error);
        }
        // The operator's HTTP/3 input (FV-04): absent is enabled; a malformed file refuses the compile (fail closed).
        $http3 = Http3Input::load($this->http3Path);
        return ($this->builder)($this->runner, $this->tenants(), $template, $this->errorLogDir, $hybridPorts, $security, $limits, $http3)
            ->compile();
    }

    /** @return array<string,string> every cPanel account => its main domain */
    public function tenants(): array
    {
        $record = $this->runner->run('listaccts', [Host::WHMAPI, '--output=json', 'listaccts'], 120);
        $data = $record['exit_code'] === 0 ? json_decode($record['stdout'], true, 64) : null;
        if (!is_array($data) || !in_array($data['metadata']['result'] ?? null, [1, '1', true], true)
            || ($data['metadata']['command'] ?? null) !== 'listaccts') {
            throw new CompilationRefused('API command listaccts failed');
        }
        $accounts = $data['data']['acct'] ?? null;
        if (!is_array($accounts)) {
            throw new CompilationRefused('listaccts has no account array');
        }
        $tenants = [];
        foreach ($accounts as $row) {
            if (!is_array($row) || !is_string($row['user'] ?? null) || !is_string($row['domain'] ?? null) || isset($tenants[$row['user']])) {
                throw new CompilationRefused('listaccts has a malformed account row');
            }
            $tenants[$row['user']] = $row['domain'];
        }
        ksort($tenants, SORT_STRING);
        return $tenants;
    }
}
