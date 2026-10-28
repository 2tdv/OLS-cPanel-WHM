<?php
declare(strict_types=1);

// Runs CacheStorage operations for tests/lscache.py: argv[1] = JSON {"root", "owner", "ops": [[action, account, vhost]]}.
require dirname(__DIR__) . '/src/bootstrap.php';

use OlsCpanel\Ols\Cache\CacheStorage;

$input = json_decode(file_get_contents($argv[1]), true, 16, JSON_THROW_ON_ERROR);
// The in-process worker: the purge helper's body without the privilege drop (the unit tests do not run as root); the helper
// chain itself is tested in tests/cache_upgrade.php.
$storage = new CacheStorage($input['root'], $input['owner'], null,
    static fn(string $root, string $store, int $uid, int $gid): array => (new CacheStorage($root))->purgeStore($store));
$out = [];
foreach ($input['ops'] as [$action, $account, $vhost]) {
    try {
        if ($action === 'trim') {
            // The cleanup primitive: ["trim", store, [cutoff, cap bytes, now]] (what the confined helper runs).
            $out[] = (object) (new CacheStorage($input['root'], $input['owner']))->trimStore($account, $vhost[0], $vhost[1], $vhost[2]);
            continue;
        }
        $result = $action === 'purge' ? $storage->purge($account, $vhost) : $storage->stats($account, $vhost);
        $out[] = (object) $result;
    } catch (InvalidArgumentException) {
        $out[] = 'error';
    }
}
echo json_encode($out, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR), "\n";
