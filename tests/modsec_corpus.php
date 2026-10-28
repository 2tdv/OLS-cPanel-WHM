<?php
declare(strict_types=1);

// Runs the PHP WAF and security translators over a JSON corpus for tests/modsec_equivalence.py.
require dirname(__DIR__) . '/src/bootstrap.php';

use OlsCpanel\Ols\Compiler\CpanelSurface;
use OlsCpanel\Ols\Compiler\ModSecurityAuditLog;
use OlsCpanel\Ols\Compiler\ModSecurityRules;
use OlsCpanel\Ols\Compiler\SecurityTranslator;

$corpus = json_decode(file_get_contents($argv[1]), true, 512, JSON_THROW_ON_ERROR);
$translator = new SecurityTranslator();
$surface = new CpanelSurface();
$out = ['checker' => [], 'states' => [], 'policy' => [], 'apply' => [], 'audit' => [], 'userdata' => []];

foreach ($corpus['checker'] as $files) {
    $checker = new ModSecurityRules();
    foreach ($files as [$path, $text]) {
        $checker->checkFile($path, $text, substr($path, 0, (int) strrpos($path, '/')));
    }
    $checker->finish();
    $out['checker'][] = ['blockers' => $checker->blockers, 'differences' => $checker->differences, 'rules' => $checker->rules,
        'data_files' => $checker->dataFiles, 'defaults' => array_map(static fn(array $d): array
            => [$d['phase'], $d['norm'], $d['emit']], $checker->defaults)];
}
foreach ($corpus['states'] as $case) {
    $calls = [];
    $read = static function (string $name, array $argv) use ($case, &$calls): array {
        $calls[] = [$name, $argv];
        $path = $argv[count($argv) - 1];
        $present = array_key_exists($path, $case['files']) && $case['files'][$path] !== null;
        if ($argv[0] === '/usr/bin/test') {
            return ['exit_code' => $present ? 0 : 1, 'stdout' => ''];
        }
        return $present && $case['files'][$path] !== false ? ['exit_code' => 0, 'stdout' => $case['files'][$path]]
            : ['exit_code' => 1, 'stdout' => ''];
    };
    try {
        $result = $translator->compileSecurity($read, $case['plan'], $case['userdata'], $case['security'], $case['vhosts'],
            CpanelSurface::PROXY_VHOST, static fn(string $n): string => $surface->serviceVhostName($n),
            static fn(string $n): string => $surface->hybridTlsName($n));
        $out['states'][] = ['server' => $result['server'], 'per_client' => $result['per_client'], 'ip_allow' => $result['ip_allow'],
            'ip_block' => $result['ip_block'], 'vhosts' => (object) $result['vhosts'], 'summary' => $result['summary'], 'calls' => $calls,
            'applied' => $translator->applyServer($case['template'], $result)];
    } catch (InvalidArgumentException $error) {
        $out['states'][] = ['error' => $error->getMessage(), 'calls' => $calls];
    }
}
foreach ($corpus['policy'] as $case) {
    try {
        $out['policy'][] = $translator->policy($case['security'], $case['plan']);
    } catch (InvalidArgumentException $error) {
        $out['policy'][] = 'error: ' . $error->getMessage();
    }
}
foreach ($corpus['apply'] as $case) {
    try {
        $out['apply'][] = $translator->applyServer($case['config'], $case['compiled']);
    } catch (InvalidArgumentException $error) {
        $out['apply'][] = 'error: ' . $error->getMessage();
    }
}
$log = new ModSecurityAuditLog();
foreach ($corpus['audit'] as $case) {
    $out['audit'][] = $log->parse(base64_decode($case['text'], true), $case['limit']);
}
foreach ($corpus['userdata'] as $text) {
    try {
        $out['userdata'][] = $translator->userdataEngineOff($text, 'x.test');
    } catch (InvalidArgumentException $error) {
        $out['userdata'][] = 'error: ' . $error->getMessage();
    }
}
echo json_encode($out, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR), "\n";
