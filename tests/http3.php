<?php
declare(strict_types=1);

// Runs the HTTP/3 (FV-04) decisions for the corpus on stdin (JSON) with the product classes; used by tests/http3.py,
// which compares the results with build/vm-qualification/http3.py (the reference) as JSON.
require dirname(__DIR__) . '/src/bootstrap.php';

use OlsCpanel\Deployment\Http3Firewall;
use OlsCpanel\Deployment\Http3Input;
use OlsCpanel\Ols\Http3\ProtocolShare;

$corpus = json_decode(stream_get_contents(STDIN), true, 32, JSON_THROW_ON_ERROR);
$out = ['input' => [], 'csf' => [], 'ports' => [], 'nft' => [], 'classify' => [], 'tail' => [], 'share' => [], 'basis' => []];
foreach ($corpus['input'] as $text) {
    try {
        $out['input'][] = Http3Input::parse($text);
    } catch (InvalidArgumentException) {
        $out['input'][] = 'error';
    }
}
foreach ($corpus['csf'] as $text) {
    $plan = Http3Firewall::csfPlan($text);
    $out['csf'][] = ['keys' => (object) $plan['keys']] + $plan;
}
foreach ($corpus['ports'] as $value) {
    $out['ports'][] = Http3Firewall::portListCovers($value);
}
foreach ($corpus['nft'] as $text) {
    $out['nft'][] = Http3Firewall::nftInputDrop($text);
}
foreach ($corpus['lines'] as $line) {
    $out['classify'][] = ProtocolShare::classify($line);
}
foreach ($corpus['tail'] as $case) {
    $out['tail'][] = ProtocolShare::tailLines($case['path'], $case['count'], $case['max_bytes']);
}
foreach ($corpus['share'] as $case) {
    try {
        $out['share'][] = ProtocolShare::shares($case['dir'], $case['domains'], $case['count'], $case['max_bytes']);
    } catch (InvalidArgumentException) {
        $out['share'][] = 'error';
    }
}
foreach ($corpus['basis'] as [$part, $total]) {
    $out['basis'][] = ProtocolShare::basisPoints($part, $total);
}
echo json_encode($out, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR), "\n";
