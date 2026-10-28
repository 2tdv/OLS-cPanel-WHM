<?php
declare(strict_types=1);

require dirname(__DIR__) . '/src/bootstrap.php';

use OlsCpanel\Cpanel\Discovery\PlatformInspector;
use OlsCpanel\Infrastructure\Filesystem\ObservationReader;
use OlsCpanel\Infrastructure\Process\ProbeRunner;

$fixture = json_decode(file_get_contents(__DIR__ . '/Fixtures/platform.json'), true, 32, JSON_THROW_ON_ERROR);
$base = $fixture['observations'];
$base['packages']['value'] .= "gpg-pubkey\tabcd-1234\t(none)\nunknown\t0^20251210.git-1\tnoarch\n";
$count = 0;
function check(bool $condition, string $name): void
{
    global $count;
    if (!$condition) {
        throw new RuntimeException('FAIL: ' . $name);
    }
    ++$count;
    echo "PASS: $name\n";
}
$inspect = static fn(array $input): array => (new PlatformInspector())->inspect($input, ['architecture' => 'x86_64'], true);
$valid = $inspect($base);
check($valid['observation_complete'], 'complete fixture observations');
check($valid['compatibility']['supported'] && $valid['blockers'] === [], 'AlmaLinux 9 x86_64 with cPanel is the supported platform of this release');
check(!$valid['compatibility']['production_activation_allowed'], 'synthetic observations never allow a switch');
check(!(new PlatformInspector())->inspect($base, ['architecture' => 'aarch64'], true)['compatibility']['supported'], 'another architecture is unsupported');
check($valid['discovery']['authoritative_deletions'] === false, 'no absence inference');
check($valid['synthetic'], 'fixtures explicitly synthetic');

foreach (['unavailable', 'changed', 'unsafe_source', 'timeout', 'error', 'output_limit'] as $status) {
    $bad = $base;
    $bad['cpanel'] = ['status' => $status, 'value' => '11.138.0.17'];
    $result = $inspect($bad);
    check(!$result['observation_complete'] && $result['platform']['cpanel']['value'] === null,
        'failed observation cannot become valid: ' . $status);
}
foreach (['', "11.138.0.17\ninjected", '138.0 build 17'] as $value) {
    $bad = $base;
    $bad['cpanel']['value'] = $value;
    check($inspect($bad)['platform']['cpanel']['status'] === 'invalid', 'invalid cPanel metadata');
}
foreach (['ID=almalinux', "ID=almalinux\nID=ubuntu\nVERSION_ID=9.8", "ID=almalinux\nVERSION_ID=\"9.8"] as $value) {
    $bad = $base;
    $bad['os']['value'] = $value;
    check($inspect($bad)['platform']['os']['status'] === 'invalid', 'incomplete/duplicate OS source');
}
$bad = $base;
$bad['os']['value'] = "ID=unrecognized\nVERSION_ID=1";
check(!$inspect($bad)['compatibility']['supported'] && in_array('PLATFORM_NOT_SUPPORTED', $inspect($bad)['blockers'], true), 'unknown OS stays unsupported');
$bad['os']['value'] = "ID=rocky\nVERSION_ID=9.6";
check(!$inspect($bad)['compatibility']['supported'], 'Rocky Linux is not supported by this release');
$bad = $base;
$bad['packages']['value'] = '';
check($inspect($bad)['platform']['packages']['value'] === null, 'empty output is not empty package inventory');
$bad['packages']['value'] = "invalid record";
check($inspect($bad)['platform']['packages']['status'] === 'invalid', 'corrupt packages refused');
$bad = $base;
$bad['monitor']['value'] = 'sshd:1';
check($inspect($bad)['platform']['httpd_monitor']['value'] === null, 'missing monitor is unknown');
$bad['monitor']['value'] = 'httpd:0';
check($inspect($bad)['platform']['httpd_monitor']['value'] === false, 'disabled differs from unknown');
$bad = $base;
unset($bad['apache']);
check(!$inspect($bad)['observation_complete'], 'missing source stays incomplete');
foreach ([new ProbeRunner(), new ObservationReader()] as $object) {
    try {
        $object instanceof ProbeRunner ? $object->run('restart') : $object->read('/etc/shadow');
        check(false, 'arbitrary operation must fail');
    } catch (InvalidArgumentException $e) {
        check(true, 'arbitrary operation refused');
    }
}
$bad = $base;
$bad['os']['value'] .= "\nSECRET_TOKEN=do-not-export";
check(!str_contains(json_encode($inspect($bad)), 'do-not-export'), 'unknown fields not exported');
echo "$count assertions passed\n";
