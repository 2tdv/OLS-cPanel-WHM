<?php
declare(strict_types=1);

namespace OlsCpanel\Ols\Compiler;

/**
 * Reads the ModSecurity rule files OLS will load, in load order, and records what libmodsecurity 3 (OLS's
 * mod_security) would refuse or do differently from cPanel's ModSecurity 2 (feature vertical FV-02). Port of
 * RuleChecker in build/vm-qualification/modsec_translate.py; results are identical (tests/compiler_equivalence.py).
 *
 * Blockers: directives, actions, operators, variables and transformations libmodsecurity 3 refuses or that are
 * not qualified for the product, Apache sections, duplicate or missing rule ids, rule modifiers that reach rules
 * loaded later (ModSecurity 2 ignores them, libmodsecurity 3 applies them), and default actions that would
 * govern different rules (libmodsecurity 3 accumulates every SecDefaultAction and applies all of them to every
 * rule of the phase). Differences: disclosed changes; the "weaker" ones block unless the operator accepts them.
 */
final class ModSecurityRules
{
    public const VENDOR_FILE = '#^/etc/apache2/conf\.d/modsec_vendor_configs/[A-Za-z0-9_-][A-Za-z0-9_.-]*(/[A-Za-z0-9_-][A-Za-z0-9_.-]*)*\.conf$#D';
    public const VENDOR_DATA = '#^/etc/apache2/conf\.d/modsec_vendor_configs/[A-Za-z0-9_-][A-Za-z0-9_.-]*(/[A-Za-z0-9_-][A-Za-z0-9_.-]*)*$#D';
    public const PASS = ['secrule', 'secaction', 'secmarker', 'secdefaultaction', 'secruleengine', 'secrequestbodyaccess',
        'secrequestbodylimit', 'secrequestbodynofileslimit', 'secrequestbodyinmemorylimit', 'secrequestbodylimitaction',
        'secresponsebodyaccess', 'secresponsebodymimetype', 'secresponsebodymimetypesclear', 'secresponsebodylimit',
        'secresponsebodylimitaction', 'secruleremovebyid', 'secruleremovebytag', 'secruleupdatetargetbyid',
        'secruleupdatetargetbytag', 'secruleupdateactionbyid', 'seccomponentsignature', 'secwebappid',
        'secargumentseparator', 'seccookieformat', 'secpcrematchlimit', 'secuploaddir', 'secuploadfilelimit',
        'secuploadfilemode', 'secxmlexternalentity', 'secargumentslimit', 'secrequestbodyjsondepthlimit',
        'secparsexmlintoargs', 'sechttpblkey', 'secauditengine', 'secauditlogrelevantstatus', 'secdebugloglevel'];
    public const OFF_ONLY = ['secconnengine', 'secdisablebackendcompression', 'seccontentinjection', 'sechashengine',
        'secinterceptonerror', 'secuploadkeepfiles', 'sectmpsaveuploadedfiles'];
    private const REFUSED = ['secserversignature', 'seccachetransformations', 'secchrootdir', 'sechashkey', 'sechashparam',
        'sechashmethodrx', 'sechashmethodpm', 'secgsblookupdb', 'secguardianlog', 'secconnreadstatelimit',
        'secconnwritestatelimit', 'secreadstatelimit', 'secwritestatelimit', 'secsensorid', 'secstreaminbodyinspection',
        'secstreamoutbodyinspection', 'seccookiev0separator', 'secruleperftime'];
    private const NOT_QUALIFIED = ['secrulescript' => 'Lua scripts are not qualified',
        'secremoterules' => 'remote rules are fetched at load time',
        'secremoterulesfailaction' => 'remote rules are fetched at load time',
        'secgeolookupdb' => 'geolocation is not part of the product build',
        'secunicodemapfile' => 'reads a file outside the checked inputs',
        'secruleremovebymsg' => 'ModSecurity 2 matches messages by regular expression, libmodsecurity 3 exactly',
        'secruleupdatetargetbymsg' => 'ModSecurity 2 matches messages by regular expression, libmodsecurity 3 exactly',
        'secruleinheritance' => 'configuration contexts are not translated',
        'include' => 'nested includes are not followed'];
    private const IGNORED = ['secdatadir' => 'persistent collections are kept per process in memory',
        'secpcrematchlimitrecursion' => 'the PCRE recursion limit is not applied',
        'sectmpdir' => 'the web server decides where request bodies are buffered',
        'secstatusengine' => 'status reporting is not available', 'seccollectiontimeout' => 'collections do not expire by timeout'];
    private const PRODUCT_AUDIT = ['secauditlog', 'secauditlog2', 'secauditlogtype', 'secauditlogstoragedir', 'secauditlogformat',
        'secauditlogdirmode', 'secauditlogfilemode', 'secauditlogparts', 'secdebuglog'];
    public const VALUES = ['secruleengine' => ['on', 'off', 'detectiononly'], 'secrequestbodyaccess' => ['on', 'off'],
        'secresponsebodyaccess' => ['on', 'off'], 'secrequestbodylimitaction' => ['reject', 'processpartial'],
        'secresponsebodylimitaction' => ['reject', 'processpartial'], 'secauditengine' => ['on', 'off', 'relevantonly'],
        'secxmlexternalentity' => ['on', 'off'], 'secparsexmlintoargs' => ['on', 'off', 'onlyargs'], 'seccookieformat' => ['0']];
    private const VARIABLES = 'ARGS_COMBINED_SIZE ARGS_GET_NAMES ARGS_NAMES ARGS_POST_NAMES AUTH_TYPE FILES_COMBINED_SIZE FILES_TMPNAMES '
        . 'FULL_REQUEST FULL_REQUEST_LENGTH GLOBAL INBOUND_DATA_ERROR MATCHED_VAR MATCHED_VAR_NAME MSC_PCRE_ERROR MSC_PCRE_LIMITS_EXCEEDED '
        . 'MULTIPART_BOUNDARY_QUOTED MULTIPART_BOUNDARY_WHITESPACE MULTIPART_CRLF_LF_LINES MULTIPART_DATA_AFTER MULTIPART_DATA_BEFORE '
        . 'MULTIPART_FILE_LIMIT_EXCEEDED MULTIPART_FILENAME MULTIPART_HEADER_FOLDING MULTIPART_INVALID_HEADER_FOLDING '
        . 'MULTIPART_INVALID_PART MULTIPART_INVALID_QUOTING MULTIPART_LF_LINE MULTIPART_MISSING_SEMICOLON MULTIPART_SEMICOLON_MISSING '
        . 'MULTIPART_NAME MULTIPART_STRICT_ERROR MULTIPART_UNMATCHED_BOUNDARY OUTBOUND_DATA_ERROR PATH_INFO QUERY_STRING REMOTE_ADDR '
        . 'REMOTE_HOST REMOTE_PORT REQBODY_ERROR REQBODY_ERROR_MSG REQBODY_PROCESSOR_ERROR REQBODY_PROCESSOR_ERROR_MSG REQBODY_PROCESSOR '
        . 'REQUEST_BASENAME REQUEST_BODY REQUEST_BODY_LENGTH REQUEST_FILENAME REQUEST_HEADERS_NAMES REQUEST_LINE REQUEST_METHOD '
        . 'REQUEST_PROTOCOL REQUEST_URI REQUEST_URI_RAW RESOURCE RESPONSE_BODY RESPONSE_CONTENT_LENGTH RESPONSE_CONTENT_TYPE '
        . 'RESPONSE_HEADERS_NAMES RESPONSE_PROTOCOL RESPONSE_STATUS SERVER_ADDR SERVER_NAME SERVER_PORT SESSIONID UNIQUE_ID '
        . 'URLENCODED_ERROR USERID WEBSERVER_ERROR_LOG ARGS ARGS_POST ARGS_GET FILES_SIZES FILES_NAMES FILES_TMP_CONTENT '
        . 'MATCHED_VARS_NAMES MATCHED_VARS FILES REQUEST_COOKIES REQUEST_HEADERS RESPONSE_HEADERS GEO REQUEST_COOKIES_NAMES '
        . 'MULTIPART_PART_HEADERS RULE SESSION IP USER STATUS STATUS_LINE TX WEBAPPID MODSEC_BUILD DURATION ENV HIGHEST_SEVERITY '
        . 'REMOTE_USER TIME TIME_DAY TIME_EPOCH TIME_HOUR TIME_MIN TIME_MON TIME_SEC TIME_WDAY TIME_YEAR XML';
    private const OPERATORS = 'beginsWith contains containsWord detectSQLi detectXSS endsWith eq ge gt ipMatch ipMatchF ipMatchFromFile '
        . 'le lt pm pmf pmFromFile rbl rx rxGlobal streq strmatch unconditionalMatch validateByteRange validateUrlEncoding '
        . 'validateUtf8Encoding verifyCC verifyCPF verifySSN verifySVNR within';
    private const FILE_OPERATORS = ['ipmatchf', 'ipmatchfromfile', 'pmf', 'pmfromfile'];
    private const OPERATORS_NOT_QUALIFIED = ['fuzzyhash', 'geolookup', 'inspectfile', 'validatedtd', 'validateschema', 'gsblookup',
        'rsub', 'validatehash'];
    private const ACTIONS = 'accuracy allow auditlog block capture chain ctl deny drop expirevar id initcol log logdata maturity msg '
        . 'multiMatch noauditlog nolog pass phase redirect rev setenv setrsc setsid setuid setvar severity skip skipAfter status t tag '
        . 'ver xmlns';
    private const ACTIONS_REFUSED = 'append deprecatevar pause prepend proxy sanitiseArg sanitiseMatched sanitiseMatchedBytes '
        . 'sanitiseRequestHeader sanitiseResponseHeader exec';
    private const CTL = 'auditEngine auditLogParts requestBodyProcessor forceRequestBodyVariable parseXmlIntoArgs requestBodyAccess '
        . 'ruleEngine ruleRemoveByTag ruleRemoveById ruleRemoveTargetById ruleRemoveTargetByTag';
    private const BODY_PROCESSORS = ['json', 'xml', 'urlencoded'];
    private const TRANSFORMATIONS = 'base64Encode base64Decode base64DecodeExt cmdLine compressWhitespace escapeSeqDecode cssDecode '
        . 'hexEncode hexDecode htmlEntityDecode jsDecode length lowercase md5 none normalisePath normalizePath normalisePathWin '
        . 'normalizePathWin parityEven7bit parityOdd7bit parityZero7bit removeComments removeCommentsChar removeNulls removeWhitespace '
        . 'replaceComments replaceNulls sha1 sqlHexDecode trim trimLeft trimRight uppercase urlEncode urlDecode urlDecodeUni utf8toUnicode';
    private const COLLECTION_ACTIONS = ['initcol', 'setsid', 'setuid', 'setrsc', 'expirevar'];
    private const DISRUPTIVE = ['deny', 'pass', 'allow', 'drop', 'redirect'];
    private const DEFAULT_ACTION_OK = ['deny', 'pass', 'allow', 'drop', 'redirect', 'phase', 'log', 'nolog', 'auditlog', 'noauditlog',
        'status', 't'];
    private const PHASES = ['1' => 1, '2' => 2, '3' => 3, '4' => 4, '5' => 5, 'request' => 2, 'response' => 4, 'logging' => 5];
    /** ModSecurity 2's built-in default action (every phase). */
    public const BUILTIN_DEFAULT = 'auditlog,log,pass';
    private const REGEX_META = '/[.*+?^$()\[\]{}|\\\\]/';
    public const RULE_ID = '/^[0-9]{1,10}$/D';
    private const ID_RANGE = '/^([0-9]{1,10})(-([0-9]{1,10}))?$/D';

    /** @var list<string> */
    public array $blockers = [];
    /** @var list<array{code:string, where:string, detail:string, weaker:bool}> */
    public array $differences = [];
    /** @var list<string> */
    public array $dataFiles = [];
    /** @var array<int,string> rule id => where */
    private array $ids = [];
    /** @var list<array{id:int, phase:int, tags:list<string>}> */
    public array $rules = [];
    /** @var list<array<string,mixed>> */
    public array $defaults = [];
    /** @var list<array{0:string, 1:mixed, 2:int, 3:string}> */
    private array $modifiers = [];
    private bool $bodyAccess = false;
    private bool $responseAccess = false;
    private bool $pendingChain = false;
    public ?string $engine = null;

    /** @return list<string> blank-separated words (spaces and tabs only) */
    public static function words(string $text): array
    {
        return preg_split('/[ \t]+/', $text, -1, PREG_SPLIT_NO_EMPTY);
    }

    /**
     * Directive lines: backslash continuations joined, blank and comment lines dropped; a comment ending in a
     * backslash (ambiguous between Apache and libmodsecurity 3) is returned as null.
     * @return list<array{0:int, 1:?string}>
     */
    public static function logicalLines(string $text): array
    {
        $out = [];
        $pending = null;
        $start = 0;
        foreach (explode("\n", $text) as $index => $raw) {
            $number = $index + 1;
            $line = str_ends_with($raw, "\r") ? substr($raw, 0, -1) : $raw;
            if ($pending === null) {
                $start = $number;
                if (str_starts_with(ltrim($line, " \t"), '#')) {
                    if (str_ends_with($line, '\\')) {
                        $out[] = [$number, null];
                    }
                    continue;
                }
                $pending = '';
            }
            if (str_ends_with($line, '\\')) {
                $pending .= substr($line, 0, -1);
                continue;
            }
            $pending .= $line;
            if (trim($pending, " \t") !== '') {
                $out[] = [$start, trim($pending, " \t")];
            }
            $pending = null;
        }
        if ($pending !== null && trim($pending, " \t") !== '') {
            $out[] = [$start, trim($pending, " \t")];
        }
        return $out;
    }

    /** @return list<string>|null Apache-style arguments, null for an unterminated quote */
    public static function splitArgs(string $line): ?array
    {
        $args = [];
        $i = 0;
        $n = strlen($line);
        while ($i < $n) {
            if ($line[$i] === ' ' || $line[$i] === "\t") {
                ++$i;
                continue;
            }
            if ($line[$i] === '"' || $line[$i] === "'") {
                $quote = $line[$i];
                ++$i;
                $value = '';
                while ($i < $n && $line[$i] !== $quote) {
                    if ($line[$i] === '\\' && $i + 1 < $n && $line[$i + 1] === $quote) {
                        $value .= $quote;
                        $i += 2;
                        continue;
                    }
                    $value .= $line[$i];
                    ++$i;
                }
                if ($i >= $n) {
                    return null;
                }
                $args[] = $value;
                ++$i;
                continue;
            }
            $start = $i;
            while ($i < $n && $line[$i] !== ' ' && $line[$i] !== "\t") {
                ++$i;
            }
            $args[] = substr($line, $start, $i - $start);
        }
        return $args;
    }

    /** @return list<string>|null action list items (comma-separated outside single quotes), null for an open quote */
    public static function splitActions(string $text): ?array
    {
        $items = [];
        $current = '';
        $quoted = false;
        $n = strlen($text);
        for ($i = 0; $i < $n; ++$i) {
            $char = $text[$i];
            if ($char === "'") {
                $quoted = !$quoted;
            }
            if ($char === ',' && !$quoted) {
                $items[] = trim($current, " \t");
                $current = '';
                continue;
            }
            $current .= $char;
        }
        if ($quoted) {
            return null;
        }
        $items[] = trim($current, " \t");
        return array_values(array_filter($items, static fn(string $i): bool => $i !== ''));
    }

    /** @return list<string>|null lower-case variable names of a target list, null when it cannot be read */
    public static function splitVariables(string $text): ?array
    {
        $names = [];
        $i = 0;
        $n = strlen($text);
        while ($i < $n) {
            while ($i < $n && ($text[$i] === '!' || $text[$i] === '&')) {
                ++$i;
            }
            $start = $i;
            while ($i < $n && preg_match('/[A-Za-z0-9_]/', $text[$i])) {
                ++$i;
            }
            if ($i === $start) {
                return null;
            }
            $names[] = strtolower(substr($text, $start, $i - $start));
            if ($i < $n && $text[$i] === ':') {
                ++$i;
                if ($names[count($names) - 1] === 'xml') {  // an XPath expression, not a regular expression
                    while ($i < $n && $text[$i] !== '|') {
                        ++$i;
                    }
                } elseif ($i < $n && $text[$i] === '/') {
                    ++$i;
                    while ($i < $n && $text[$i] !== '/') {
                        $i += $text[$i] === '\\' ? 2 : 1;
                    }
                    if ($i >= $n) {
                        return null;
                    }
                    ++$i;
                } elseif ($i < $n && $text[$i] === "'") {
                    ++$i;
                    while ($i < $n && $text[$i] !== "'") {
                        ++$i;
                    }
                    if ($i >= $n) {
                        return null;
                    }
                    ++$i;
                } else {
                    while ($i < $n && $text[$i] !== '|') {
                        ++$i;
                    }
                }
            }
            if ($i < $n) {
                if ($text[$i] !== '|') {
                    return null;
                }
                ++$i;
                if ($i === $n) {
                    return null;
                }
            }
        }
        return $names;
    }

    private static function unquote(string $value): string
    {
        return strlen($value) >= 2 && $value[0] === "'" && $value[strlen($value) - 1] === "'" ? substr($value, 1, -1) : $value;
    }

    /** @return list<string> */
    private static function lowered(string $list): array
    {
        return array_map('strtolower', explode(' ', $list));
    }

    public function block(string $where, string $reason): void
    {
        $this->blockers[] = "$where: $reason";
    }

    public function differ(string $code, string $where, string $detail, bool $weaker = false): void
    {
        $entry = ['code' => $code, 'where' => $where, 'detail' => $detail, 'weaker' => $weaker];
        if (!in_array($entry, $this->differences, true)) {
            $this->differences[] = $entry;
        }
    }

    /** @param ?string $dataBase directory relative data files are resolved against */
    public function checkFile(string $path, string $text, ?string $dataBase = null): void
    {
        foreach (self::logicalLines($text) as [$number, $line]) {
            $where = "$path:$number";
            if ($line === null) {
                $this->block($where, 'comment line ends with a line continuation');
                continue;
            }
            $this->directive($where, $line, $dataBase, true);
        }
        if ($this->pendingChain) {
            $this->block($path, 'the last rule announces a chain that never follows');
            $this->pendingChain = false;
        }
    }

    public function directive(string $where, string $line, ?string $dataBase = null, bool $inFile = false): void
    {
        if (str_starts_with($line, '<')) {
            $this->block($where, 'Apache configuration sections are not translated');
            return;
        }
        $args = self::splitArgs($line);
        if (!$args) {
            $this->block($where, 'unterminated quote');
            return;
        }
        $name = strtolower($args[0]);
        $rest = array_slice($args, 1);
        if (in_array($name, self::REFUSED, true)) {
            $this->block($where, "{$args[0]} is refused by libmodsecurity 3");
        } elseif (isset(self::NOT_QUALIFIED[$name])) {
            $this->block($where, "{$args[0]} is not qualified: " . self::NOT_QUALIFIED[$name]);
        } elseif (in_array($name, self::OFF_ONLY, true)) {
            if (array_map('strtolower', $rest) !== ['off']) {
                $this->block($where, "{$args[0]} is supported by libmodsecurity 3 only with Off");
            }
        } elseif (isset(self::IGNORED[$name])) {
            $this->differ("ignored-$name", $where, "{$args[0]} is ignored by libmodsecurity 3: " . self::IGNORED[$name]);
        } elseif (in_array($name, self::PRODUCT_AUDIT, true)) {
            if ($inFile) {
                $this->differ('product-audit-log', $where, "{$args[0]} is replaced by the product audit log settings");
            }
        } elseif (!in_array($name, self::PASS, true)) {
            $this->block($where, "unknown directive {$args[0]}");
        } else {
            $this->known($where, $name, $args[0], $rest, $dataBase);
        }
    }

    /** @param list<string> $rest */
    private function known(string $where, string $name, string $spelled, array $rest, ?string $dataBase): void
    {
        if (isset(self::VALUES[$name]) && (count($rest) !== 1 || !in_array(strtolower($rest[0]), self::VALUES[$name], true))) {
            $this->block($where, "$spelled has an unsupported value");
            return;
        }
        if ($name === 'secargumentseparator' && (count($rest) !== 1 || strlen($rest[0]) !== 1)) {
            $this->block($where, 'SecArgumentSeparator must be a single character');
            return;
        }
        if ($name === 'secrequestbodyaccess' && strtolower($rest[0]) === 'on') {
            $this->bodyAccess = true;
        }
        if ($name === 'secresponsebodyaccess' && strtolower($rest[0]) === 'on') {
            $this->responseAccess = true;
        }
        if ($name === 'secrule') {
            if (count($rest) !== 2 && count($rest) !== 3) {
                $this->block($where, 'SecRule needs targets, an operator and optional actions');
                return;
            }
            if (!$this->knownVariables($rest[0])) {
                $this->block($where, 'unknown or unreadable SecRule targets');
                return;
            }
            $this->operator($where, $rest[1], $dataBase);
            $this->rule($where, $rest[2] ?? '');
        } elseif ($name === 'secaction') {
            if (count($rest) !== 1) {
                $this->block($where, 'SecAction needs one action list');
                return;
            }
            $this->rule($where, $rest[0]);
        } elseif ($name === 'secdefaultaction') {
            if (count($rest) !== 1) {
                $this->block($where, 'SecDefaultAction needs one action list');
                return;
            }
            $this->defaultAction($where, $rest[0]);
        } elseif ($name === 'secmarker') {
            if (count($rest) !== 1) {
                $this->block($where, 'SecMarker needs one name');
            }
        } elseif ($name === 'secruleremovebyid') {
            $this->byIds($where, self::words(implode(' ', $rest)), $spelled);
        } elseif ($name === 'secruleupdatetargetbyid' || $name === 'secruleupdateactionbyid') {
            if (count($rest) !== 2 && count($rest) !== 3) {
                $this->block($where, "$spelled needs a rule id and its update");
                return;
            }
            $this->byIds($where, [$rest[0]], $spelled);
            if ($name === 'secruleupdateactionbyid') {
                $this->actions($where, $rest[1]);
            } else {
                foreach (array_slice($rest, 1) as $targets) {
                    if (!$this->knownVariables($targets)) {
                        $this->block($where, 'unknown or unreadable update targets');
                    }
                }
            }
        } elseif ($name === 'secruleremovebytag' || $name === 'secruleupdatetargetbytag') {
            if ($rest === []) {
                $this->block($where, "$spelled needs a tag");
                return;
            }
            if (preg_match(self::REGEX_META, $rest[0])) {
                $this->block($where, 'ModSecurity 2 matches tags by regular expression, libmodsecurity 3 exactly');
                return;
            }
            $this->modifiers[] = ['tag', $rest[0], count($this->rules), $where];
        }
    }

    private function knownVariables(string $text): bool
    {
        $names = self::splitVariables($text);
        $known = self::lowered(self::VARIABLES);
        return $names !== null && array_diff($names, $known) === [];
    }

    private function operator(string $where, string $text, ?string $dataBase): void
    {
        $body = str_starts_with($text, '!') ? substr($text, 1) : $text;
        if (!str_starts_with($body, '@')) {
            return;  // an implicit @rx
        }
        if (!preg_match('/^@([A-Za-z0-9]+)(?:[ \t]+(.*))?$/sD', $body, $match)) {
            $this->block($where, 'unreadable operator');
            return;
        }
        $name = strtolower($match[1]);
        $argument = $match[2] ?? '';
        if (in_array($name, self::OPERATORS_NOT_QUALIFIED, true)) {
            $this->block($where, "operator @{$match[1]} is not qualified for libmodsecurity 3 in the product");
        } elseif (!in_array($name, self::lowered(self::OPERATORS), true)) {
            $this->block($where, "unknown operator @{$match[1]}");
        } elseif (in_array($name, self::FILE_OPERATORS, true)) {
            foreach (self::words($argument) as $item) {
                if (preg_match('/^[a-z][a-z0-9+.-]*:\/\//i', $item)) {
                    $this->block($where, 'rule data from a URL is not qualified');
                    continue;
                }
                $path = str_starts_with($item, '/') ? $item : ($dataBase !== null && $dataBase !== '' ? "$dataBase/$item" : '');
                if (!preg_match(self::VENDOR_DATA, $path)) {
                    $this->block($where, "rule data file $item is outside the vendor configurations");
                } elseif (!in_array($path, $this->dataFiles, true)) {
                    $this->dataFiles[] = $path;
                }
            }
        }
    }

    /** @return list<string>|null the checked items of an action list */
    public function actions(string $where, string $text): ?array
    {
        $items = self::splitActions($text);
        if ($items === null) {
            $this->block($where, 'unterminated quote in the action list');
            return null;
        }
        foreach ($items as $item) {
            [$key, $value] = array_pad(explode(':', $item, 2), 2, '');
            $key = strtolower(trim($key, " \t"));
            if (in_array($key, self::lowered(self::ACTIONS_REFUSED), true)) {
                $this->block($where, "action $key is refused by libmodsecurity 3");
            } elseif (!in_array($key, self::lowered(self::ACTIONS), true)) {
                $this->block($where, "unknown action $key");
            } elseif ($key === 't' && !in_array(strtolower(trim($value, " \t")), self::lowered(self::TRANSFORMATIONS), true)) {
                $this->block($where, 'unknown transformation');
            } elseif ($key === 'ctl') {
                [$option, $setting] = array_pad(explode('=', $value, 2), 2, '');
                $option = strtolower(trim($option, " \t"));
                if (!in_array($option, self::lowered(self::CTL), true)) {
                    $this->block($where, 'ctl option is not supported by libmodsecurity 3');
                } elseif ($option === 'requestbodyprocessor' && !in_array(strtolower(trim($setting, " \t")), self::BODY_PROCESSORS, true)) {
                    $this->block($where, 'request body processor is not supported by libmodsecurity 3');
                }
            } elseif (in_array($key, self::COLLECTION_ACTIONS, true)) {
                $this->differ('persistent-collections', $where,
                    "collections live in each OLS process's memory (SecDataDir is not used by libmodsecurity 3)");
            }
        }
        return $items;
    }

    /** @param list<string> $items @return list<string> */
    private static function keys(array $items): array
    {
        return array_map(static fn(string $i): string => strtolower(trim(explode(':', $i, 2)[0], " \t")), $items);
    }

    private static function valueOf(string $item): string
    {
        return trim(explode(':', $item, 2)[1] ?? '', " \t");
    }

    private function rule(string $where, string $text): void
    {
        $items = $text !== '' ? $this->actions($where, $text) : [];
        if ($items === null) {
            return;
        }
        $keys = self::keys($items);
        $values = [];
        foreach ($keys as $index => $key) {
            $values[$key] = self::valueOf($items[$index]);
        }
        $child = $this->pendingChain;
        $this->pendingChain = in_array('chain', $keys, true);
        if ($child) {
            if (in_array('id', $keys, true)) {
                $this->block($where, 'a chained rule carries its own id');
            }
            return;
        }
        if (!in_array('id', $keys, true) || !preg_match(self::RULE_ID, self::unquote($values['id']))) {
            $this->block($where, 'rule without a numeric id');
            return;
        }
        $id = (int) self::unquote($values['id']);
        if (isset($this->ids[$id])) {
            $this->block($where, "rule id $id is already defined at {$this->ids[$id]}");
            return;
        }
        $phase = self::PHASES[strtolower(self::unquote($values['phase'] ?? '2'))] ?? null;
        if ($phase === null) {
            $this->block($where, 'unknown phase');
            return;
        }
        $this->ids[$id] = $where;
        $tags = [];
        foreach ($keys as $index => $key) {
            if ($key === 'tag') {
                $tags[] = self::unquote(self::valueOf($items[$index]));
            }
        }
        $this->rules[] = ['id' => $id, 'phase' => $phase, 'tags' => $tags];
    }

    /** Records one SecDefaultAction; returns its index in defaults, or null when it is refused. */
    public function defaultAction(string $where, string $text, bool $inline = false): ?int
    {
        $items = $this->actions($where, $text);
        if ($items === null) {
            return null;
        }
        $keys = self::keys($items);
        $bad = array_diff($keys, self::DEFAULT_ACTION_OK);
        $compact = array_map(static fn(string $i): string => strtolower(str_replace(' ', '', $i)), $items);
        if ($bad !== [] || in_array('t:none', $compact, true)) {
            $this->block($where, 'SecDefaultAction holds actions libmodsecurity 3 refuses there');
            return null;
        }
        if (array_intersect($keys, self::DISRUPTIVE) === [] || !in_array('phase', $keys, true)) {
            $this->block($where, 'SecDefaultAction needs a phase and a disruptive action');
            return null;
        }
        $phase = self::PHASES[strtolower(self::unquote(self::valueOf($items[array_search('phase', $keys, true)])))] ?? null;
        if ($phase === null) {
            $this->block($where, 'unknown phase');
            return null;
        }
        $norm = [];
        foreach ($keys as $index => $key) {
            if ($key !== 'phase') {
                $norm[] = strtolower(str_replace([' ', "\t"], '', $items[$index]));
            }
        }
        sort($norm, SORT_STRING);
        $file = substr($where, 0, (int) strrpos($where, ':'));
        if (!$inline) {
            foreach ($this->defaults as $existing) {
                if ($existing['phase'] === $phase && $existing['file'] === $file) {
                    $this->block($where, 'SecDefaultAction for one phase twice in one file');
                    return null;
                }
            }
        }
        $after = count(array_filter($this->rules, static fn(array $r): bool => $r['phase'] === $phase));
        $this->defaults[] = ['phase' => $phase, 'norm' => implode(',', $norm), 'where' => $where, 'inline' => $inline,
            'file' => $file, 'after' => $after, 'emit' => true];
        return count($this->defaults) - 1;
    }

    /** @param list<string> $tokens */
    private function byIds(string $where, array $tokens, string $spelled): void
    {
        if ($tokens === []) {
            $this->block($where, "$spelled needs rule ids");
        }
        foreach ($tokens as $token) {
            if (!preg_match(self::ID_RANGE, self::unquote($token), $match)) {
                $this->block($where, "$spelled has an unreadable rule id");
                continue;
            }
            $low = (int) $match[1];
            $high = isset($match[3]) && $match[3] !== '' ? (int) $match[3] : $low;
            if ($high < $low) {
                $this->block($where, "$spelled has an empty id range");
                continue;
            }
            $this->modifiers[] = ['id', [$low, $high], count($this->rules), $where];
        }
    }

    /** The last SecRuleEngine value of a directive line (ModSecurity 2's default is Off). */
    public function trackEngine(string $line): void
    {
        $args = self::splitArgs($line) ?? [''];
        if (strtolower($args[0]) === 'secruleengine' && count($args) === 2 && in_array(strtolower($args[1]), self::VALUES['secruleengine'], true)) {
            $this->engine = ['on' => 'On', 'off' => 'Off', 'detectiononly' => 'DetectionOnly'][strtolower($args[1])];
        }
    }

    /** Checks that need the whole load order (modifier reach and default actions). */
    public function finish(): void
    {
        foreach ($this->modifiers as [$kind, $target, $defined, $where]) {
            $hit = null;
            foreach (array_slice($this->rules, $defined) as $rule) {
                if ($kind === 'id' ? ($target[0] <= $rule['id'] && $rule['id'] <= $target[1]) : in_array($target, $rule['tags'], true)) {
                    $hit = $rule['id'];
                    break;
                }
            }
            if ($hit !== null) {
                $this->block($where, "modifies rule $hit, which is loaded later (ModSecurity 2 ignores it, libmodsecurity 3 applies it)");
            }
            if ($kind === 'tag') {
                foreach ($this->rules as $rule) {
                    foreach ($rule['tags'] as $tag) {
                        if ($target !== $tag && str_contains($tag, $target)) {
                            $this->differ('tag-match', $where,
                                'ModSecurity 2 also matches tags that contain the text; libmodsecurity 3 only equal tags');
                        }
                    }
                }
            }
        }
        $phases = array_values(array_unique(array_column($this->defaults, 'phase')));
        sort($phases);
        foreach ($phases as $phase) {
            $mine = array_keys(array_filter($this->defaults, static fn(array $d): bool => $d['phase'] === $phase));
            $total = count(array_filter($this->rules, static fn(array $r): bool => $r['phase'] === $phase));
            $active = $this->defaults[$mine[0]]['after'] > 0 ? [self::BUILTIN_DEFAULT] : [];
            foreach ($mine as $position => $index) {
                $entry = $this->defaults[$index];
                $end = isset($mine[$position + 1]) ? $this->defaults[$mine[$position + 1]]['after'] : $total;
                if ($end > $entry['after']) {
                    $active[] = $entry['norm'];
                } elseif ($entry['inline']) {
                    $this->defaults[$index]['emit'] = false;  // superseded before any rule of its phase
                    $this->differ('superseded-default-action', $entry['where'],
                        "SecDefaultAction for phase $phase governs no rule and is not loaded");
                }
            }
            $emitted = [];
            foreach ($mine as $index) {
                if ($this->defaults[$index]['emit']) {
                    $emitted[] = $this->defaults[$index]['norm'];
                }
            }
            $emitted = array_values(array_unique($emitted === [] ? [self::BUILTIN_DEFAULT] : $emitted));
            if (count($emitted) > 1 || array_diff(array_unique($active), $emitted) !== []) {
                $this->block($this->defaults[$mine[count($mine) - 1]]['where'], "rules of phase $phase have different default actions"
                    . ' under ModSecurity 2; libmodsecurity 3 applies one set to all of them');
            }
        }
        if ($this->bodyAccess) {
            $this->differ('oversized-request-body', 'SecRequestBodyAccess',
                'OLS does not inspect a request body larger than SecRequestBodyLimit (Apache inspects or rejects it)', true);
        }
        if ($this->responseAccess) {
            $this->differ('oversized-response-body', 'SecResponseBodyAccess',
                'OLS does not inspect a response body larger than SecResponseBodyLimit', true);
        }
    }
}
