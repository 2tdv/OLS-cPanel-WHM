<?php
declare(strict_types=1);

namespace OlsCpanel\Ols\Validation;

/**
 * Product-side structural validation of a generated OLS plain configuration (OLS-05).
 * Runs before the binary test: OLS 1.9.3 -t never configures listeners. Messages match the
 * lab tool build/vm-qualification/ols_config_lint.py (checked by tests/compiler_equivalence.py).
 */
final class ConfigLint
{
    public const REQUIRED_SERVER = ['disableWebAdmin' => '1', 'autoDetectCdn' => '0', 'enableUpdateCheck' => '0'];
    public const REQUIRED_BLOCKS = ['CGIRLimit'];

    /** @return list<string> errors; empty means structurally valid */
    public function lint(string $text, bool $requirePolicy = true): array
    {
        [$root, $errors] = $this->parse($text);
        foreach ($root['children'] as $node) {
            if ($node['type'] !== 'listener') {
                continue;
            }
            $address = $node['values']['address'][0] ?? '';
            if (!$this->validAddress($address)) {
                $errors[] = "line {$node['line']}: listener {$node['name']} has invalid address '$address'";
            }
            if (($node['values']['secure'][0] ?? '0') === '1') {
                foreach (['keyFile', 'certFile'] as $key) {
                    if (empty($node['values'][$key])) {
                        $errors[] = "line {$node['line']}: secure listener {$node['name']} lacks $key";
                    }
                }
            }
        }
        if ($requirePolicy) {
            foreach (self::REQUIRED_SERVER as $key => $expected) {
                $actual = $root['values'][$key] ?? null;
                if ($actual !== [$expected]) {
                    $errors[] = "server directive $key must be exactly '$expected' (found " . $this->pyValue($actual) . ')';
                }
            }
            $present = array_column($root['children'], 'type');
            foreach (self::REQUIRED_BLOCKS as $block) {
                if (!in_array($block, $present, true)) {
                    $errors[] = "required server block $block is missing";
                }
            }
        }
        return $errors;
    }

    public function validAddress(string $address): bool
    {
        $colon = strrpos($address, ':');
        if ($colon === false) {
            return false;
        }
        $host = substr($address, 0, $colon);
        $port = substr($address, $colon + 1);
        if (!ctype_digit($port) || (int) $port < 1 || (int) $port > 65535) {
            return false;
        }
        if ($host === '*' || $host === '[ANY]') {
            return true;
        }
        if (str_starts_with($host, '[') && str_ends_with($host, ']')) {
            $host = substr($host, 1, -1);
        }
        return filter_var($host, FILTER_VALIDATE_IP) !== false;
    }

    /** @return array{0:array<string,mixed>,1:list<string>} */
    private function parse(string $text): array
    {
        $root = ['type' => 'root', 'name' => '', 'values' => [], 'children' => [], 'line' => 0];
        $stack = [&$root];
        $errors = [];
        foreach (preg_split('/\R/', $text) as $index => $raw) {
            $number = $index + 1;
            // Only whole-line comments: values such as rewrite rules may contain "#".
            $line = str_starts_with(ltrim($raw), '#') ? '' : trim($raw);
            if ($line === '') {
                continue;
            }
            $top = count($stack) - 1;
            if ($line === '}') {
                if ($top === 0) {
                    $errors[] = "line $number: unexpected '}'";
                } else {
                    array_pop($stack);
                }
                continue;
            }
            if (str_ends_with($line, '{')) {
                $head = preg_split('/\s+/', trim(substr($line, 0, -1)), -1, PREG_SPLIT_NO_EMPTY);
                $stack[$top]['children'][] = ['type' => $head[0] ?? '', 'name' => implode(' ', array_slice($head, 1)),
                    'values' => [], 'children' => [], 'line' => $number];
                $stack[] = &$stack[$top]['children'][array_key_last($stack[$top]['children'])];
                continue;
            }
            [$key, $value] = array_pad(explode(' ', $line, 2), 2, '');
            $stack[$top]['values'][$key][] = trim($value);
        }
        foreach (array_slice($stack, 1) as $node) {
            $errors[] = "line {$node['line']}: block '{$node['type']} {$node['name']}' is not closed";
        }
        return [$root, $errors];
    }

    /** Python str() of None or a list of strings, for messages identical to the lab tool. */
    private function pyValue(?array $value): string
    {
        if ($value === null) {
            return 'None';
        }
        return '[' . implode(', ', array_map(static fn(string $v): string => "'" . str_replace("'", "\\'", $v) . "'", $value)) . ']';
    }
}
