<?php
declare(strict_types=1);

namespace OlsCpanel\Cpanel\Discovery;

final class PlatformInspector
{
    private function parsePairs(string $text, string $separator = '='): array
    {
        $pairs = [];
        foreach (explode("\n", trim($text)) as $line) {
            $line = trim($line);
            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }
            $parts = explode($separator, $line, 2);
            if (count($parts) !== 2 || isset($pairs[$parts[0]])) {
                throw new \UnexpectedValueException('Invalid or duplicate metadata field');
            }
            [$key, $value] = $parts;
            if (!preg_match('/^[A-Za-z_][A-Za-z0-9_]*$/D', $key)
                || preg_match('/[\x00-\x1f\x7f]/', $value)) {
                throw new \UnexpectedValueException('Invalid metadata');
            }
            if (str_starts_with($value, '"') || str_starts_with($value, "'")) {
                if (strlen($value) < 2 || substr($value, -1) !== $value[0]) {
                    throw new \UnexpectedValueException('Invalid quote');
                }
                $value = substr($value, 1, -1);
            }
            $pairs[$key] = $value;
        }
        return $pairs;
    }

    private function value(array $observation, callable $parse): array
    {
        $safe = array_intersect_key($observation, array_flip(['source', 'observed_at', 'sha256', 'exit_code']));
        if (($observation['status'] ?? null) !== 'observed' || !is_string($observation['value'] ?? null)) {
            return $safe + ['status' => $observation['status'] ?? 'unavailable', 'value' => null];
        }
        try {
            return $safe + ['status' => 'observed', 'value' => $parse($observation['value'])];
        } catch (\UnexpectedValueException $e) {
            return $safe + ['status' => 'invalid', 'value' => null];
        }
    }

    public function inspect(array $observations, array $runtime, bool $synthetic = false): array
    {
        $fields = [];
        $fields['os'] = $this->value($observations['os'] ?? [], function (string $text): array {
            $pairs = $this->parsePairs($text);
            foreach (['ID', 'VERSION_ID'] as $key) {
                if (!isset($pairs[$key]) || !preg_match('/^[a-zA-Z0-9._-]{1,64}$/D', $pairs[$key])) {
                    throw new \UnexpectedValueException('Missing OS identity');
                }
            }
            return array_intersect_key($pairs, array_flip(['ID', 'VERSION_ID']));
        });
        $fields['cpanel'] = $this->value($observations['cpanel'] ?? [], static function (string $text): string {
            $version = trim($text);
            if (!preg_match('/^\d+\.\d+\.\d+\.\d+$/D', $version)) {
                throw new \UnexpectedValueException('Invalid cPanel version');
            }
            return $version;
        });
        $fields['httpd_monitor'] = $this->value($observations['monitor'] ?? [], function (string $text): bool {
            $pairs = $this->parsePairs($text, ':');
            if (!isset($pairs['httpd']) || !in_array($pairs['httpd'], ['0', '1'], true)) {
                throw new \UnexpectedValueException('Missing monitor status');
            }
            return $pairs['httpd'] === '1';
        });
        $fields['apache_service'] = $this->value($observations['apache'] ?? [], function (string $text): array {
            $pairs = $this->parsePairs($text);
            foreach (['LoadState', 'ActiveState', 'SubState', 'UnitFileState', 'FragmentPath'] as $key) {
                if (!array_key_exists($key, $pairs)) {
                    throw new \UnexpectedValueException('Incomplete systemd response');
                }
            }
            return array_intersect_key($pairs, array_flip(['LoadState', 'ActiveState', 'SubState', 'UnitFileState', 'FragmentPath']));
        });
        $fields['packages'] = $this->value($observations['packages'] ?? [], static function (string $text): array {
            if (trim($text) === '') {
                throw new \UnexpectedValueException('Empty package database');
            }
            $result = [];
            foreach (explode("\n", trim($text)) as $line) {
                $parts = explode("\t", $line);
                if (count($parts) !== 3) {
                    throw new \UnexpectedValueException('Invalid package record');
                }
                foreach ($parts as $index => $part) {
                    if ($index === 2 && $parts[0] === 'gpg-pubkey' && $part === '(none)') {
                        continue;
                    }
                    if (!preg_match('/^[A-Za-z0-9_+.~:^\-]+$/D', $part)) {
                        throw new \UnexpectedValueException('Invalid package value');
                    }
                }
                if (preg_match('/^(ea-|cpanel-php|openlitespeed$|litespeed|lsphp|nginx|httpd|kernel|openssl|cloudlinux|cagefs|liblsapi)/', $parts[0])) {
                    $result[] = ['name' => $parts[0], 'version_release' => $parts[1], 'arch' => $parts[2]];
                }
            }
            usort($result, static fn(array $a, array $b): int => [$a['name'], $a['version_release'], $a['arch']] <=> [$b['name'], $b['version_release'], $b['arch']]);
            return $result;
        });
        $complete = true;
        foreach ($fields as $field) {
            $complete = $complete && $field['status'] === 'observed';
        }
        // Release 0.2.0 is built and tested on AlmaLinux 9 x86_64 with cPanel/WHM; that row is supported. Any other system is
        // reported as unsupported (the installer refuses it too); Rocky Linux, CloudLinux and release 8 follow in later releases.
        // A report built from synthetic observations never allows a switch.
        $os = $fields['os']['value'] ?? null;
        $supported = $complete && is_array($os) && strtolower((string) ($os['ID'] ?? '')) === 'almalinux'
            && explode('.', (string) ($os['VERSION_ID'] ?? ''))[0] === '9' && ($runtime['architecture'] ?? null) === 'x86_64'
            && is_string($fields['cpanel']['value'] ?? null);
        return [
            'schema_version' => 1, 'mode' => 'audit-only', 'synthetic' => $synthetic,
            'observed_at' => gmdate('c'), 'scope' => 'platform-baseline-only',
            'observation_complete' => $complete,
            'discovery' => ['accounts' => 'not_collected', 'domains' => 'not_collected',
                'authoritative_deletions' => false, 'cross_source_atomic' => false],
            'platform' => $fields, 'runtime' => $runtime,
            'compatibility' => ['status' => $supported ? 'supported' : 'unsupported', 'supported' => $supported,
                'production_activation_allowed' => $supported && !$synthetic, 'supported_platforms' => ['AlmaLinux 9 (x86_64) with cPanel/WHM']],
            'blockers' => array_values(array_filter([
                $complete ? null : 'INCOMPLETE_PLATFORM_OBSERVATION',
                $supported || !$complete ? null : 'PLATFORM_NOT_SUPPORTED',
            ])),
        ];
    }
}
