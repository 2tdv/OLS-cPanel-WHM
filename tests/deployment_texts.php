<?php
declare(strict_types=1);

// Renders the deployment texts for the cases on stdin (JSON list) with the product classes; used by
// tests/deployment_texts.py, which compares them byte for byte with build/vm-qualification/hybrid_lab.py.
require dirname(__DIR__) . '/src/bootstrap.php';

use OlsCpanel\Deployment\Hooks;
use OlsCpanel\Deployment\HybridHost;
use OlsCpanel\Deployment\RecoveryScript;

$cases = json_decode(stream_get_contents(STDIN), true, 32, JSON_THROW_ON_ERROR);
$out = [];
foreach ($cases as $case) {
    try {
        $a = $case['args'];
        $out[] = ['text' => match ($case['fn']) {
            'recovery_script' => RecoveryScript::render($a['backup'], $a['originals'], array_map('boolval', $a['tenant_files']),
                $a['created_dirs'], $a['hybrid'], $a['tenant_user'], $a['expected'], $a['product'], $a['backend_ports'], $a['firewall']),
            'nft_ruleset' => HybridHost::nftRuleset($a['ports']),
            'remoteip_conf' => HybridHost::remoteipConf($a['proxies']),
            'hooks' => json_encode(['restricting' => Hooks::RESTRICTING,
                'objcache_events' => OlsCpanel\Events\HookEntry::OBJCACHE_EVENTS,
                'trust_events' => OlsCpanel\Events\HookEntry::TRUST_EVENTS, 'events' => (new Hooks(
                new OlsCpanel\Deployment\Host(new class implements OlsCpanel\Infrastructure\Process\CommandRunner {
                    public function run(string $name, array $argv, int $timeout): array
                    {
                        throw new LogicException('no commands');
                    }
                })))->expected()], JSON_THROW_ON_ERROR),
        }];
    } catch (InvalidArgumentException $error) {
        $out[] = ['error' => $error->getMessage()];
    }
}
echo json_encode($out, JSON_THROW_ON_ERROR);
