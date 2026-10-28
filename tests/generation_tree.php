<?php
declare(strict_types=1);

// The product's production generation tree and source digest against the lab reference (tests/generation_tree.py
// writes the scenarios: recorded cPanel inputs and the tree the lab tools made from them).
require dirname(__DIR__) . '/src/bootstrap.php';

use OlsCpanel\Events\SourceDigest;
use OlsCpanel\Infrastructure\Process\CommandRunner;
use OlsCpanel\Ols\Compiler\ServerConfigurationBuilder;
use OlsCpanel\Ols\Generation\GenerationTree;
use OlsCpanel\Ols\Generation\LocalEngine;

/** Recorded cPanel inputs; referenced-file digests answer sha256(path). */
final class TreeReplay implements CommandRunner
{
    /** @var array<string,array{exit_code:int, stdout:string}> */
    private array $calls = [];

    public function __construct(array $calls)
    {
        foreach ($calls as $call) {
            $this->calls[json_encode($call['argv'], JSON_UNESCAPED_SLASHES)] ??= ['exit_code' => $call['exit_code'], 'stdout' => $call['stdout']];
        }
    }

    public function run(string $name, array $argv, int $timeout): array
    {
        if ($name === 'referenced-digest') {
            $path = $argv[count($argv) - 1];
            return ['exit_code' => 0, 'stdout' => hash('sha256', $path) . "  $path\n"];
        }
        return $this->calls[json_encode($argv, JSON_UNESCAPED_SLASHES)] ?? throw new LogicException("unrecorded command ($name)");
    }
}

$count = 0;
function check(bool $condition, string $name): void
{
    global $count;
    if (!$condition) {
        throw new RuntimeException('FAIL: ' . $name);
    }
    ++$count;
}

$template = file_get_contents(dirname(__DIR__) . '/build/vm-qualification/ols-lab/ownership_httpd_config.conf');
$scenarios = json_decode(file_get_contents($argv[1]), true, 64, JSON_THROW_ON_ERROR);
$temp = sys_get_temp_dir() . '/ols-tree-' . bin2hex(random_bytes(6));
mkdir($temp, 0700);
try {
    foreach ($scenarios as $label => $scenario) {
        $runner = new TreeReplay($scenario['calls']);
        $compiled = (new ServerConfigurationBuilder($runner, ['olscpa' => 'olstest1.example.test', 'olscpb' => 'olstest2.example.test'],
            $template, '/var/lib/ols-cpanel-lab/logs', null, null, null, null, null, null, $scenario['hybrid_ports']))->compile();
        $source = SourceDigest::source($compiled, $scenario['epoch'], SourceDigest::referencedFiles($compiled, $runner));
        check($source === $scenario['source'], "$label: source digest equals the lab reconciler's");
        $arguments = (new GenerationTree())->arguments($compiled, $scenario['generation'], $scenario['epoch'], $source);
        LocalEngine::checkTree($arguments['generation'], $arguments['files'], $arguments['health'], $arguments['epoch'], $source);
        check($arguments['health'] === $scenario['targets'], "$label: health targets equal the lab's");
        $dir = "$temp/$label";
        LocalEngine::writeTree($dir, $arguments['files'], $arguments['health'], $arguments['epoch'], $source);
        $files = [];
        $modes = [];
        $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST);
        foreach ($iterator as $path => $info) {
            $relative = substr($path, strlen($dir) + 1);
            $modes[$relative] = fileperms($path) & 0o7777;
            if ($info->isFile()) {
                $files[$relative] = file_get_contents($path);
            }
        }
        // summary.json is product-only (the plugins' data); the lab tree has none.
        $summary = json_decode($files['summary.json'], true, 64, JSON_THROW_ON_ERROR);
        check(array_keys($summary) === ['cache', 'compiled_at', 'htaccess_blockers', 'hybrid_vhosts', 'missing_alias_dirs', 'security',
            'suspended_accounts', 'tls_sources', 'vhosts', 'waf'] && $summary['hybrid_vhosts'] === $compiled['summary']['hybrid_vhosts']
            && $summary['cache'] == ($compiled['summary']['cache'] ?? null) && $summary['waf'] == ($compiled['summary']['waf'] ?? null)
            && array_keys($summary['vhosts']['olstest2.example.test']) === ['aliases', 'docroot', 'php', 'php_handler', 'type', 'user']
            && preg_match('/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/D', $summary['compiled_at']) === 1
            && $modes['summary.json'] === 0o644, "$label: summary.json carries the plugins' compile summary");
        unset($files['summary.json'], $modes['summary.json']);
        ksort($files, SORT_STRING);
        ksort($modes, SORT_STRING);
        $expected = $scenario['files'];
        ksort($expected, SORT_STRING);
        $expectedModes = $scenario['modes'];
        ksort($expectedModes, SORT_STRING);
        check(array_keys($files) === array_keys($expected), "$label: the same " . count($expected) . ' files as the lab tree');
        foreach ($expected as $path => $content) {
            check($files[$path] === $content, "$label: $path byte-identical");
        }
        check($modes === $expectedModes, "$label: the same modes (directories 0755, files 0644)");
        echo "PASS: $label: " . count($expected) . ' files, ' . count($arguments['health']) . ' health targets, '
            . count($arguments['unprobed']) . " unprobed\n";
    }
} finally {
    exec('/usr/bin/rm -rf -- ' . escapeshellarg($temp));
}
echo "$count generation tree equivalence checks passed.\n";
