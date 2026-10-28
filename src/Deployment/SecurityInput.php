<?php
declare(strict_types=1);

namespace OlsCpanel\Deployment;

use OlsCpanel\Ols\Compiler\CompilationRefused;
use OlsCpanel\Ols\Compiler\SecurityTranslator;

/**
 * The product security input (FV-02), /var/lib/ols-cpanel/security.json (root, 0644): the operator's WAF
 * exceptions, per-client limits and IP lists in the schema of SecurityTranslator::policy (docs/product-interfaces.md).
 * Absent means `{}`. Anything unreadable, oversized, not a JSON object or invalid per the translator's own
 * validation is refused, never ignored: a compile with a broken security file fails closed.
 */
final class SecurityInput
{
    public const PATH = '/var/lib/ols-cpanel/security.json';
    public const MAX_BYTES = 262144;

    /**
     * @return array<string,mixed> the input for ServerConfigurationBuilder's `security` argument
     * @throws CompilationRefused
     */
    public static function load(string $path = self::PATH): array
    {
        if (!file_exists($path) && !is_link($path)) {
            return [];
        }
        $stat = @lstat($path);
        if ($stat === false || ($stat['mode'] & 0170000) !== 0100000) {
            throw new CompilationRefused("security input $path is not a regular file");
        }
        $euid = function_exists('posix_geteuid') ? posix_geteuid() : 0;
        if (($stat['mode'] & 0022) !== 0 || !in_array($stat['uid'], [0, $euid], true)) {
            throw new CompilationRefused("security input $path must be owned by root and writable by no one else");
        }
        $text = @file_get_contents($path, false, null, 0, self::MAX_BYTES + 1);
        if ($text === false || strlen($text) > self::MAX_BYTES) {
            throw new CompilationRefused("security input $path is unreadable or larger than " . self::MAX_BYTES . ' bytes');
        }
        try {
            $data = json_decode($text, true, 16, JSON_THROW_ON_ERROR);
        } catch (\JsonException $error) {
            throw new CompilationRefused("security input $path is not valid JSON: " . $error->getMessage());
        }
        if (!is_array($data) || ($data !== [] && array_is_list($data))) {
            throw new CompilationRefused("security input $path must be a JSON object");
        }
        self::validate($data, $path);
        return $data;
    }

    /**
     * The translator's validation, with every vhost an exception names taken as known (the compile checks it
     * against the real plan).
     * @param array<string,mixed> $data
     * @throws CompilationRefused
     */
    public static function validate(array $data, string $path = self::PATH): void
    {
        $plan = [];
        foreach (is_array($data['exceptions'] ?? null) ? $data['exceptions'] : [] as $item) {
            if (is_array($item) && is_string($item['vhost'] ?? null)) {
                $plan[$item['vhost']] = ['mode' => 'ols'];
            }
        }
        try {
            (new SecurityTranslator())->policy($data, $plan);
        } catch (\InvalidArgumentException $error) {
            throw new CompilationRefused("security input $path is invalid: " . $error->getMessage(), [], $error);
        }
    }
}
