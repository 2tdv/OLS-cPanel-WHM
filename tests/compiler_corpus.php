<?php
declare(strict_types=1);

// Runs the product translators over a JSON corpus for tests/compiler_equivalence.py.
require dirname(__DIR__) . '/src/bootstrap.php';

use OlsCpanel\Cpanel\Discovery\AccountVhosts;
use OlsCpanel\Ols\Compiler\CachePolicy;
use OlsCpanel\Ols\Compiler\CpanelSurface;
use OlsCpanel\Ols\Compiler\HtaccessTranslator;
use OlsCpanel\Ols\Compiler\ServerCompiler;
use OlsCpanel\Ols\Validation\ConfigLint;
use OlsCpanel\Php\Ini\FpmPoolTranslator;

$corpus = json_decode(file_get_contents($argv[1]), true, 64, JSON_THROW_ON_ERROR);
$out = ['htaccess' => [], 'fpm' => [], 'lint' => [], 'address' => [], 'surface' => [], 'proxy' => [], 'root_headers' => [], 'vhosts' => []];
foreach ($corpus['htaccess'] as $case) {
    $translator = new HtaccessTranslator();
    $result = $translator->translate($case['files'], $case['docroot']);
    $out['htaccess'][] = $result;
    $out['root_headers'][] = $translator->rootHeaderNames($result[1]);
}
$fpm = new FpmPoolTranslator();
foreach ($corpus['fpm'] as $case) {
    try {
        $entries = $fpm->translate($case['pool'], $case['constants']);
        $out['fpm'][] = ['entries' => $entries, 'block' => $fpm->overrideBlock($entries),
            'suffixes' => $fpm->suffixes($case['pool'])];
    } catch (InvalidArgumentException) {
        $out['fpm'][] = 'error';
    }
}
foreach ($corpus['lint'] as $case) {
    $out['lint'][] = (new ConfigLint())->lint($case['text'], $case['policy']);
}
foreach ($corpus['address'] as $address) {
    $out['address'][] = (new ConfigLint())->validAddress($address);
}
$surface = new CpanelSurface();
foreach ($corpus['surface'] as $i => $domain) {
    $out['surface'][] = [$surface->processors(), $surface->hostAliases($domain), $surface->rewriteRules($corpus['surface_service'][$i]),
        $surface->contexts($corpus['surface_missing'][$i], $corpus['surface_unset'][$i]), $surface->accessLogs($domain),
        $surface->serviceVhostName($domain), $surface->serviceServerBlock($domain, 'u'),
        $surface->serviceVhost('/home/u/public_html/x', $corpus['surface_service'][$i] ?: [$domain],
            $corpus['surface_unset'][$i] ? "/c/$domain" : null),
        $surface->suspensionRules($corpus['surface_missing'][$i])];
}
$out['proxy'] = [$surface->proxyHosts(), $surface->proxyServerBlock(), $surface->proxyVhost(),
    $surface->proxyVhost(CpanelSurface::SERVICE_CERTS[0]), $surface->defaultServerBlock(),
    $surface->defaultVhost(), $surface->defaultVhost(CpanelSurface::SERVICE_CERTS[0], ['/mailman/', '/pipermail/'])];
$model = new AccountVhosts();
foreach ($corpus['vhosts'] as $case) {
    try {
        $rows = $model->parseUserdataDomains($case['rows']);
        $found = $model->accountVhosts($case['user'], $rows, $case['userdata']);
        $out['vhosts'][] = [$rows, $found, array_map(static fn(array $v): array => $model->ancestors($v['docroot']), $found)];
    } catch (InvalidArgumentException) {
        $out['vhosts'][] = 'error';
    }
}
$out['apache'] = [];
foreach ($corpus['httpd'] as $text) {
    try {
        $out['apache'][] = [(object) $model->apacheDefaults($text), $model->apacheProxyEndpoints($text)];
    } catch (InvalidArgumentException) {
        $out['apache'][] = 'error';
    }
}
$out['ipv6'] = [];
foreach ($corpus['ip_output'] as $text) {
    try {
        $out['ipv6'][] = $model->boundIpv6($text);
    } catch (InvalidArgumentException) {
        $out['ipv6'][] = 'error';
    }
}
$server = new ServerCompiler();
$out['servers'] = array_map(static fn(array $c): string => $server->serverConfig($corpus['template'], $c['plan'], $c['ipv6'],
    $c['defaults'], $c['proxy'], null, $c['http3'] ?? true), $corpus['servers']);
$out['vhconf'] = array_map(static fn(array $c): string => $server->vhostConfig($c['v'], $c['pool'], $c['constants'], $c['access'],
    $c['tls'], '/var/log/ols-cpanel', $c['missing'], $c['unset'], $c['suspended'], $c['limits'] ?? null), $corpus['vhconf']);
$cache = new CachePolicy();
$out['cache'] = array_map(static fn(array $c): array => [$cache->vhostBlock($c['v'], $c['suspended']),
    $cache->vhostRules($c['v'], $c['suspended']), $cache->enabled($c['v'], $c['suspended'])], $corpus['cache']);
$out['cache'][] = [$cache->serverBlock(), $cache->disabledBlock(), $cache->summary($corpus['cache_plan'], ['olscpb']),
    $cache->serverBlock('/srv/c')];
$out['stores'] = [];
foreach ($corpus['stores'] as [$user, $vhost]) {
    try {
        $out['stores'][] = $cache->storagePath($user, $vhost);
    } catch (InvalidArgumentException) {
        $out['stores'][] = 'error';
    }
}
echo json_encode($out, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR), "\n";
