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
use OlsCpanel\Deployment\Http3Input;
use OlsCpanel\Ols\Compiler\CompilationRefused;
use OlsCpanel\Ols\Http3\ProtocolShare;

/**
 * `http3 off --domain=D` / `http3 on --domain=D` (CMP-07; root): the per-domain HTTP/3 switch. `off` adds the domain to the
 * "off" list of /var/lib/ols-cpanel/http3.json (a vhost of the active generation only; a name that is not one is refused),
 * `on` removes it (a stale name can always be removed). The next reconciler pass (the input is part of its digest) compiles
 * `enableQuic 0` into that vhost, so OLS stops advertising HTTP/3 (Alt-Svc) for it. Idempotent; a malformed input file is
 * never overwritten. The WHM HTTP/3 page is the interactive form of this command.
 */
final class Http3DomainCommand implements Command
{
    public function __construct(private readonly EngineContext $context, private readonly bool $enable,
                                private readonly string $inputPath = Http3Input::PATH)
    {
    }

    public function words(): array
    {
        return ['http3', $this->enable ? 'on' : 'off'];
    }

    public function summary(): string
    {
        return $this->enable ? 'Advertise HTTP/3 again for one domain: --domain=D (root)'
            : 'Stop advertising HTTP/3 for one domain: --domain=D (root)';
    }

    public function run(array $argv, Output $out): int
    {
        $arguments = new Arguments($argv, [], ['domain']);
        $domain = $arguments->value('domain');
        if ($domain === null || strlen($domain) > 253 || !preg_match(ProtocolShare::DOMAIN, $domain)) {
            throw new UsageError('--domain takes a lower-case domain name');
        }
        $this->context->root();
        if (!$this->enable) {
            $store = $this->context->store();
            $generation = $store->pointer();
            $summary = $generation === null ? null : $store->summary($generation);
            $known = is_array($summary) && is_array($summary['vhosts'] ?? null) ? array_map('strval', array_keys($summary['vhosts'])) : [];
            if (!in_array($domain, $known, true)) {
                throw new Refused("$domain is not a vhost of the active generation");
            }
        }
        try {
            $now = Http3Input::change($this->enable ? [] : [$domain], $this->enable ? [$domain] : [], $this->inputPath);
        } catch (CompilationRefused $error) {
            throw new Refused($error->getMessage(), 0, $error);
        }
        $out->result(['command' => 'http3 ' . ($this->enable ? 'on' : 'off'), 'domain' => $domain, 'changed' => $now['changed'],
            'enabled' => $now['enabled'], 'off' => $now['off'],
            'applies' => 'the next reconciler pass compiles the change (within a minute)']);
        return Application::EXIT_OK;
    }
}
