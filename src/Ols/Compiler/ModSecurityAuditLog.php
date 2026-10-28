<?php
declare(strict_types=1);

namespace OlsCpanel\Ols\Compiler;

/**
 * Blocked-request log (FV-02): a bounded parser of libmodsecurity 3's native serial audit log as OLS writes it
 * (SecAuditLogType Serial, parts ABFHZ; SecurityTranslator::AUDIT_LOG). Port of parse_audit_log in
 * build/vm-qualification/modsec_translate.py; results are identical (tests/compiler_equivalence.py).
 *
 * Works on bytes from a bounded tail of the log: a transaction cut at the start or the end, a malformed one
 * or one without rule messages is skipped and counted, never guessed. Each record is {time (ISO 8601 UTC),
 * client, vhost (the Host header, else the message's hostname), uri, rule_id, message, action ("deny" for the
 * disruptive message, else "warning" for the first message)}. Only the request line's URI and the Host header
 * are read from the request: cookies, authorization and other headers never leave the parser; every value is
 * printable ASCII (other bytes become "?") and bounded.
 */
final class ModSecurityAuditLog
{
    private const BOUNDARY = '/^---([A-Za-z0-9]{8,64})---([A-Z])--$/D';
    private const HEAD = '/^\[([0-9]{2})\/([A-Za-z]{3})\/([0-9]{4}):([0-9]{2}):([0-9]{2}):([0-9]{2}) ([+-])([0-9]{2})([0-9]{2})\]'
        . ' [^ ]+ ([0-9A-Fa-f:.]{2,45}) [0-9]+ [^ ]+ [0-9]+$/D';
    private const MESSAGE = '/^ModSecurity: (Access denied with code [0-9]{3}|Warning\.)/';
    private const DENIED = 'ModSecurity: Access denied';
    private const MAX_LINE = 16384;
    private const MAX_SECTION_LINES = 200;
    private const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

    /** @return array{records:list<array<string,mixed>>, skipped:int} oldest first, at most $limit of the newest */
    public function parse(string $text, int $limit = 200): array
    {
        $limit = max(1, min($limit, 1000));
        $records = [];
        $skipped = 0;
        $current = null;
        $section = null;
        foreach (explode("\n", $text) as $raw) {
            $line = substr(str_ends_with($raw, "\r") ? substr($raw, 0, -1) : $raw, 0, self::MAX_LINE);
            if (!preg_match(self::BOUNDARY, $line, $boundary)) {
                if ($current !== null && $section !== null && $line !== '') {
                    $current['sections'][$section] ??= [];
                    if (count($current['sections'][$section]) < self::MAX_SECTION_LINES) {
                        $current['sections'][$section][] = $line;
                    }
                }
                continue;
            }
            $part = $boundary[2];
            if ($part === 'A') {
                if ($current !== null) {
                    ++$skipped;
                }
                $current = ['id' => $boundary[1], 'sections' => []];
                $section = 'A';
            } elseif ($current === null || $current['id'] !== $boundary[1]) {
                if ($current !== null || $part === 'Z') {
                    ++$skipped;
                }
                $current = $section = null;
            } elseif ($part === 'Z') {
                $record = $this->record($current['sections']);
                if ($record === null) {
                    ++$skipped;
                } else {
                    $records[] = $record;
                    if (count($records) > $limit) {
                        array_shift($records);
                    }
                }
                $current = $section = null;
            } else {
                $section = $part;
            }
        }
        if ($current !== null) {
            ++$skipped;
        }
        return ['records' => $records, 'skipped' => $skipped];
    }

    private static function clean(string $value, int $limit): string
    {
        return substr((string) preg_replace('/[^\x20-\x7e]/', '?', $value), 0, $limit);
    }

    private static function field(string $line, string $name): ?string
    {
        return preg_match('/\[' . $name . ' "((?:[^"\\\\]|\\\\.)*)"\]/s', $line, $match) ? str_replace('\\"', '"', $match[1]) : null;
    }

    private static function days(int $year, int $month): int
    {
        if ($month === 2) {
            return $year % 4 === 0 && ($year % 100 !== 0 || $year % 400 === 0) ? 29 : 28;
        }
        return in_array($month, [4, 6, 9, 11], true) ? 30 : 31;
    }

    /** @param list<string> $head */
    private static function time(array $head): ?string
    {
        [$day, $year, $hour, $minute, $second] = [(int) $head[1], (int) $head[3], (int) $head[4], (int) $head[5], (int) $head[6]];
        $month = array_search($head[2], self::MONTHS, true);
        if ($month === false || $year < 1970 || $year > 9999 || $hour > 23 || $minute > 59 || $second > 59) {
            return null;
        }
        if ($day < 1 || $day > self::days($year, $month + 1)) {
            return null;
        }
        $offset = ((int) $head[8] * 3600 + (int) $head[9] * 60) * ($head[7] === '+' ? 1 : -1);
        return gmdate('Y-m-d\TH:i:s\Z', gmmktime($hour, $minute, $second, $month + 1, $day, $year) - $offset);
    }

    private static function client(string $value): ?string
    {
        if (str_contains($value, ':') && str_contains($value, '.')) {
            return null;
        }
        $packed = @inet_pton($value);
        return $packed === false ? null : (string) inet_ntop($packed);
    }

    /** @param array<string,list<string>> $sections */
    private function record(array $sections): ?array
    {
        if (!preg_match(self::HEAD, $sections['A'][0] ?? '', $head)) {
            return null;
        }
        $moment = self::time($head);
        $client = self::client($head[10]);
        $messages = array_values(array_filter($sections['H'] ?? [], static fn(string $l): bool => (bool) preg_match(self::MESSAGE, $l)));
        if ($moment === null || $client === null || $messages === []) {
            return null;
        }
        $denied = array_values(array_filter($messages, static fn(string $l): bool => str_starts_with($l, self::DENIED)));
        $chosen = $denied[0] ?? $messages[0];
        $request = explode(' ', $sections['B'][0] ?? '');
        $uri = count($request) >= 3 ? $request[1] : self::field($chosen, 'uri');
        $host = null;
        foreach (array_slice($sections['B'] ?? [], 1) as $line) {
            if (strtolower(substr($line, 0, 5)) === 'host:') {
                $host = trim(substr($line, 5), " \t");
                break;
            }
        }
        $host ??= self::field($chosen, 'hostname');
        if ($host !== null) {
            $host = (string) preg_replace('/:[0-9]+$/D', '', $host);
            $host = preg_match('/^[A-Za-z0-9.-]{1,253}$/D', $host) ? strtolower($host) : null;
        }
        $ruleId = self::field($chosen, 'id');
        return ['time' => $moment, 'client' => $client, 'vhost' => $host, 'uri' => $uri === null ? null : self::clean($uri, 2048),
            'rule_id' => $ruleId !== null && preg_match('/^[0-9]{1,10}$/D', $ruleId) ? (int) $ruleId : null,
            'message' => self::clean(self::field($chosen, 'msg') ?? '', 512), 'action' => $denied !== [] ? 'deny' : 'warning'];
    }
}
