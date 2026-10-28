<?php
declare(strict_types=1);

namespace OlsCpanel\Php\Ini;

/**
 * Translates a cPanel-generated PHP-FPM pool into OLS phpIniOverride entries (OLS-15).
 * php_admin_* keep administrator precedence in OLS; php_value/php_flag stay user-overridable.
 * Behavior is lab-proven by build/vm-qualification/fpm_translate.py and kept equivalent to it.
 */
final class FpmPoolTranslator
{
    private const LINE = '/^\s*(php_admin_value|php_admin_flag|php_value|php_flag)\[([A-Za-z0-9_.]+)\]\s*=\s*(.*?)\s*$/';
    private const INI_TRUE = ['on', 'yes', 'true'];
    private const INI_FALSE = ['off', 'no', 'false', 'none', 'null'];
    private const FLAG_TRUE = ['1', 'on', 'yes', 'true'];
    private const FLAG_FALSE = ['0', 'off', 'no', 'false', 'none', ''];

    /**
     * @param array<string,int>|null $constants E_* values read from the target PHP binary
     * @return list<array{0:string,1:string,2:string}> [kind, key, value]
     */
    public function translate(string $pool, ?array $constants = null): array
    {
        $entries = [];
        foreach (preg_split('/\R/', $pool) as $raw) {
            if (!preg_match(self::LINE, $raw, $match)) {
                continue;
            }
            [, $kind, $key, $value] = $match;
            $quoted = strlen($value) >= 2 && $value[0] === $value[-1] && ($value[0] === '"' || $value[0] === "'");
            if ($quoted) {
                $value = substr($value, 1, -1);
            }
            if (str_contains($value, "\n") || str_contains($value, '}')) {
                throw new \InvalidArgumentException("unsafe value for $key");
            }
            $lowered = strtolower($value);
            if (str_ends_with($kind, '_flag')) {
                if (in_array($lowered, self::FLAG_TRUE, true)) {
                    $value = '1';
                } elseif (in_array($lowered, self::FLAG_FALSE, true)) {
                    $value = '0';
                } else {
                    throw new \InvalidArgumentException("invalid flag value for $key");
                }
            } elseif (!$quoted && in_array($lowered, [...self::INI_TRUE, ...self::INI_FALSE], true)) {
                // The INI parser maps bare boolean words; OLS passes the raw text instead.
                $value = in_array($lowered, self::INI_TRUE, true) ? '1' : '';
            } elseif (preg_match('/\bE_[A-Z_]+\b/', $value)) {
                if ($constants === null) {
                    throw new \InvalidArgumentException("$key uses constants; pass the target PHP's E_* constants");
                }
                $value = (string) $this->evaluateConstants($value, $constants);
            }
            $entries[] = [$kind, $key, $value];
        }
        return $entries;
    }

    /** @param list<array{0:string,1:string,2:string}> $entries */
    public function overrideBlock(array $entries): string
    {
        if ($entries === []) {
            return '';
        }
        $body = implode("\n", array_map(static fn(array $e): string => implode(' ', $e), $entries));
        return "phpIniOverride  {\n$body\n}\n";
    }

    /** @return list<string> script suffixes from security.limit_extensions */
    public function suffixes(string $pool): array
    {
        if (!preg_match('/^\s*security\.limit_extensions\s*=\s*(.+)$/m', $pool, $match)) {
            return ['php'];
        }
        $out = [];
        foreach (preg_split('/\s+/', trim($match[1])) as $suffix) {
            if (preg_match('/^\.?[A-Za-z0-9]+$/', $suffix)) {
                $out[] = ltrim($suffix, '.');
            }
        }
        return $out;
    }

    /**
     * Evaluates an INI constant expression such as "E_ALL & ~E_NOTICE" without eval().
     * Precedence (low to high): | ^ & ; unary ~ ; parentheses.
     * @param array<string,int> $constants
     */
    public function evaluateConstants(string $expression, array $constants): int
    {
        $tokens = [];
        $offset = 0;
        $length = strlen($expression);
        while ($offset < $length) {
            if (!preg_match('/\G\s*(?:(E_[A-Z_]+)|(\d+)|([|&^~()]))/', $expression, $m, 0, $offset)) {
                if (trim(substr($expression, $offset)) === '') {
                    break;
                }
                throw new \InvalidArgumentException("unsupported token in '$expression'");
            }
            if (($m[1] ?? '') !== '') {
                if (!array_key_exists($m[1], $constants)) {
                    throw new \InvalidArgumentException("unknown constant {$m[1]}");
                }
                $tokens[] = (int) $constants[$m[1]];
            } elseif (($m[2] ?? '') !== '') {
                $tokens[] = (int) $m[2];
            } else {
                $tokens[] = $m[3];
            }
            $offset += strlen($m[0]);
        }
        [$value, $index] = $this->parse($tokens, 0, 0);
        if ($index !== count($tokens)) {
            throw new \InvalidArgumentException("trailing tokens in '$expression'");
        }
        return $value;
    }

    /** @param list<int|string> $tokens @return array{0:int,1:int} */
    private function parse(array $tokens, int $index, int $precedence): array
    {
        $levels = ['|' => 1, '^' => 2, '&' => 3];
        [$value, $index] = $this->unary($tokens, $index);
        while ($index < count($tokens) && is_string($tokens[$index]) && isset($levels[$tokens[$index]])
            && $levels[$tokens[$index]] > $precedence) {
            $op = $tokens[$index];
            [$right, $index] = $this->parse($tokens, $index + 1, $levels[$op]);
            $value = match ($op) {
                '|' => $value | $right,
                '^' => $value ^ $right,
                default => $value & $right,
            };
        }
        return [$value, $index];
    }

    /** @param list<int|string> $tokens @return array{0:int,1:int} */
    private function unary(array $tokens, int $index): array
    {
        if ($index >= count($tokens)) {
            throw new \InvalidArgumentException('unexpected end of expression');
        }
        $token = $tokens[$index];
        if ($token === '~') {
            [$value, $index] = $this->unary($tokens, $index + 1);
            return [~$value, $index];
        }
        if ($token === '(') {
            [$value, $index] = $this->parse($tokens, $index + 1, 0);
            if ($index >= count($tokens) || $tokens[$index] !== ')') {
                throw new \InvalidArgumentException('unbalanced parentheses');
            }
            return [$value, $index + 1];
        }
        if (is_int($token)) {
            return [$token, $index + 1];
        }
        throw new \InvalidArgumentException("unexpected '$token'");
    }
}
