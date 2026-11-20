<?php
declare(strict_types=1);

namespace OlsCpanel\Deployment;

use OlsCpanel\Ols\Compiler\CachePolicy;
use OlsCpanel\Ols\Generation\EngineError;
use OlsCpanel\Ols\Generation\GenerationTree;
use OlsCpanel\Ols\Generation\LocalEngine;

/**
 * `install --preview --plan=<id>` (CMP-03): how OpenLiteSpeed will answer every site, compared with Apache, before the
 * switch. Apache keeps serving; nothing a cutover changes is touched.
 *
 * What it does, under the deployment lock (so no cutover, recovery or reconcile pass runs beside it):
 *  1. The plan is loaded and the cPanel state compiled again with the plan's profile; a compile that differs from the
 *     plan (configuration or a referenced certificate, key or password file changed) is refused, as the cutover does.
 *  2. Apache's answer (status code) is recorded for every site over HTTP and HTTPS at the site's address, with the Host
 *     header and SNI of the site: the same requests, the same recording as the cutover's baseline.
 *  3. The plan's generation is written to a private server root below <state>/preview/<id>/ with every listener moved to
 *     127.0.0.1 and a free high port (PreviewConfig, PreviewPorts). No listener is ever on a public address, on 80/443 or
 *     on the hybrid ports, and the final text is checked for it.
 *  4. OpenLiteSpeed is started by one script inside a private mount, PID and /run namespace (unshare --mount --pid
 *     --fork): /run, /tmp and /dev/shm are fresh tmpfs, so the live PID file, sockets and shared memory are neither seen
 *     nor touched (OLS patches 0009 and 0011 keep every runtime path under /run/ols-cpanel and the shm directory the
 *     configuration names), and every log directory and the page cache tree are tmpfs too, so no request reaches a live
 *     access log, the log shipper's FIFOs or a cache store. The server root is the private one (LSWS_HOME). The script
 *     sends each site's requests to the loopback ports (same Host header, SNI by name), stops OLS and exits; when it ends,
 *     for any reason, the kernel kills every process of the namespace.
 *     Two things the cutover itself provides are given to the namespace only:
 *      - the server's workers run as the web server user (nobody) and reach lscgid's socket below <state>/preview/server,
 *        so the private root and the generation directory are traversable (0711; their files stay root-only where they
 *        hold anything private), otherwise no PHP process starts ("cgidSuEXEC failed");
 *      - with Apache serving under mod_ruid2, cPanel FileProtect leaves every public_html as user:user 0750; the cutover
 *        runs enablefileprotect once OLS serves, which makes it user:nobody 0750. The preview changes no file: inside the
 *        namespace a private copy of /etc/group, bind-mounted over the real one, makes the web server user a member of
 *        each probed account's own group (PreviewConfig::accountGroups), so the workers reach the document roots as they
 *        will after the cutover. Neither the host's /etc/group nor any file mode outside <state>/preview changes.
 *     The tail of the server's and the vhosts' error logs ([ERROR] and [WARN] lines) is kept in the result as "log".
 *  5. Both answers are compared with Cutover::differences (the cutover's own comparison); a site served by Apache
 *     behind OLS (hybrid) is not requested: Apache's answer is its answer.
 *  6. The private root is removed (sockets and other special files included, links never followed), also on failure; a
 *     removal that leaves anything behind is reported in the result as "cleanup". The result is stored in
 *     <state>/previews/<plan id>.json (root 0600).
 *
 * Never changed: Apache, the live configuration (/usr/local/lsws, the active generation, profile.json), the firewall,
 * cPanel tweaks, ports 80/443. A site's own code runs for a request as it does for any visitor.
 */
final class Preview
{
    public const SCHEMA_VERSION = 1;
    public const UNSHARE = '/usr/bin/unshare';
    public const BINARY = '/usr/local/lsws/bin/openlitespeed';
    public const LIVE_ROOT = '/usr/local/lsws';
    /** The whole script (start, requests, stop) must end within this; the runner kills the process group after it. */
    public const TIMEOUT = 110;
    public const PARALLEL = 8;
    /** One request's limit (seconds). 50 requests for 25 sites in 8 parallel lanes stay well under a minute. */
    public const REQUEST_SECONDS = 8;
    /** Writable directories of the private root; everything else is linked to the live root (read-only use). */
    public const WRITABLE = ['logs', 'tmp', 'cachedata', 'autoupdate', 'cgid', 'admin'];
    public const STATES = ['same', 'different', 'hybrid', 'unprobed', 'apache_silent'];
    /** The private root's mode: the web server user must reach lscgid's socket in <root>/server/cgid. */
    public const ROOT_MODE = 0711;
    public const PASSWD = '/etc/passwd';
    public const GROUP = '/etc/group';

    /** Requests of "<scheme> <host> <address> <port>" lines, sent in parallel; prints "<scheme>://<host>/ <status>". */
    private const PROBE = 'xargs -r -P %d -L 1 -a "$PROBES" /bin/sh -c \'a=$3; case $a in *:*) a="[$a]";; esac; '
        . 'c=$(/usr/bin/curl --noproxy "*" -ks -o /dev/null --max-time %d -w "%%{http_code}" -H "Host: $2" --resolve "$2:$4:$a" "$1://$2:$4/"); '
        . 'echo "$1://$2/ $c"\' sh';

    /**
     * Arguments: root, ports (space separated), probes file, ready port, binary, then the mount words of
     * PreviewConfig::mounts() and the "u:<web server user>" and "g:<account group>" words of PreviewConfig::accountGroups().
     * Output: PREVIEW-READY, the answers, PREVIEW-STOPPED and the [ERROR]/[WARN] tail of the server's and vhosts' error
     * logs as PREVIEW-LOG lines; or PREVIEW-FAILED <reason> and the tail of the server's error log as PREVIEW-LOG lines.
     */
    private static function inner(): string
    {
        return str_replace('@PROBE@', sprintf(self::PROBE, self::PARALLEL, self::REQUEST_SECONDS), <<<'SH'
set -u
root=$1; ports=$2; PROBES=$3; ready=$4; bin=$5; shift 5
export PROBES
log() { for f in "$root/logs/error.log" "$root/logs/stderr.log"; do [ -f "$f" ] && tail -n 15 "$f" | sed 's/^/PREVIEW-LOG /'; done; }
fail() { echo "PREVIEW-FAILED $1"; log; exit 1; }
mount -t tmpfs -o mode=1777 tmpfs /tmp && mount -t tmpfs -o mode=1777 tmpfs /dev/shm && mount -t tmpfs -o mode=0755 tmpfs /run \
    || fail "cannot create the private mounts"
for p in $ports; do
    if /usr/sbin/ss -H -ltn "sport = :$p" | grep -q .; then fail "port $p is already in use"; fi
done
mkdir -p /run/ols-cpanel/lshttpd /run/ols-cpanel/status /run/ols-cpanel/shm /run/ols-cpanel/logs /tmp/lshttpd
chmod 0755 /run/ols-cpanel/lshttpd
chown nobody:nobody /run/ols-cpanel/status /run/ols-cpanel/shm && chmod 0755 /run/ols-cpanel/status && chmod 0750 /run/ols-cpanel/shm
web=; groups=; covered=
for d in "$@"; do
    case "$d" in
        m:*) mount -t tmpfs -o mode=1777 tmpfs "${d#m:}" || fail "cannot cover ${d#m:}"; covered="$covered ${d#m:}" ;;
        d:*) mkdir -p "${d#d:}" ;;
        u:*) web=${d#u:} ;;
        g:*) groups="$groups ${d#g:}" ;;
    esac
done
if [ -n "$web" ] && [ -n "$groups" ]; then
    # Namespace only: the web server user joins each account's group, as enablefileprotect's user:nobody 0750 allows after the cutover.
    awk -F: -v OFS=: -v add="$groups" -v web="$web" 'BEGIN { n = split(add, a, " "); for (i = 1; i <= n; i++) want[a[i]] = 1 }
        ($1 in want) && index("," $4 ",", "," web ",") == 0 { $4 = ($4 == "" ? web : $4 "," web) } { print }' /etc/group >/tmp/group \
        && chmod 0644 /tmp/group && mount --bind /tmp/group /etc/group || fail "cannot add $web to the account groups"
fi
LSWS_HOME=$root; export LSWS_HOME
"$bin" >"$root/logs/stderr.log" 2>&1 &
i=0
while [ "$i" -lt 100 ]; do
    /usr/bin/curl --noproxy '*' -s -o /dev/null --max-time 2 "http://127.0.0.1:$ready/" && break
    sleep 0.25
    i=$((i + 1))
done
[ "$i" -lt 100 ] || fail "OpenLiteSpeed did not answer on 127.0.0.1:$ready"
for p in $ports; do
    /usr/sbin/ss -H -ltn "sport = :$p" | awk -v want="127.0.0.1:$p" '$4 != want { bad = 1 } END { exit bad }' \
        || fail "port $p is not bound to 127.0.0.1 only"
done
echo PREVIEW-READY
timeout 60 @PROBE@
pid=$(cat /run/ols-cpanel/lshttpd/lshttpd.pid 2>/dev/null)
if [ -n "$pid" ]; then
    kill -TERM "$pid" 2>/dev/null
    j=0
    while kill -0 "$pid" 2>/dev/null && [ "$j" -lt 100 ]; do sleep 0.1; j=$((j + 1)); done
fi
echo PREVIEW-STOPPED
{ for f in "$root/logs/error.log" "$root/logs/stderr.log"; do [ -f "$f" ] && cat "$f"; done
  for c in $covered; do find "$c" -xdev -type f -name '*error*.log' -size -8M -exec cat {} + 2>/dev/null; done
} | grep -a -e '\[ERROR\]' -e '\[WARN\]' | tail -n 40 | sed 's/^/PREVIEW-LOG /'
exit 0
SH);
    }

    public function __construct(private Environment $env, private string $liveRoot = self::LIVE_ROOT,
                                private string $binary = self::BINARY, private ?\Closure $random = null,
                                private string $passwd = self::PASSWD, private string $group = self::GROUP)
    {
    }

    /**
     * Removes a private root completely: directories, files, sockets, FIFOs and links (a link itself, never its target).
     * @return string|null null when nothing is left, else what remains (for the result)
     */
    public static function clear(string $root): ?string
    {
        LocalEngine::remove($root);
        clearstatcache();
        if (!file_exists($root) && !is_link($root)) {
            return null;
        }
        $left = [];
        $walk = static function (string $path) use (&$walk, &$left): void {
            if (count($left) >= 5) {
                return;
            }
            if (!is_link($path) && is_dir($path)) {
                $names = array_diff(scandir($path) ?: [], ['.', '..']);
                if ($names === []) {
                    $left[] = $path;
                }
                foreach ($names as $name) {
                    $walk("$path/$name");
                }
                return;
            }
            $left[] = $path;
        };
        $walk($root);
        return Host::tail(implode(', ', $left));
    }

    public static function path(Environment $env, string $planId): string
    {
        return $env->state . '/previews/' . $planId . '.json';
    }

    /**
     * The stored preview of a plan, or null (none, unreadable, or not this schema).
     * @return array<string,mixed>|null
     */
    public static function load(Environment $env, string $planId): ?array
    {
        if (!preg_match(CutoverPlan::ID, $planId)) {
            return null;
        }
        $path = self::path($env, $planId);
        $text = is_link($path) ? false : @file_get_contents($path, false, null, 0, 4194305);
        $data = is_string($text) ? json_decode($text, true, 16) : null;
        return is_array($data) && ($data['schema_version'] ?? null) === self::SCHEMA_VERSION && ($data['plan'] ?? null) === $planId ? $data : null;
    }

    /**
     * Compares the two sets of answers site by site with the cutover's comparison.
     * @param list<string> $vhosts every vhost of the plan
     * @param list<string> $hybrid vhosts served by Apache behind OLS (not requested)
     * @param array<string,string> $unprobed vhost => why OLS could not be asked (no listener for its address)
     * @param array<string,string> $apache status per "<scheme>://<vhost>/"
     * @param array<string,string> $ols status per request (missing = no answer recorded)
     * @return array{sites:list<array<string,mixed>>, summary:array<string,int>}
     */
    public static function compare(array $vhosts, array $hybrid, array $unprobed, array $apache, array $ols): array
    {
        sort($vhosts, SORT_STRING);
        $sites = [];
        $summary = array_fill_keys(self::STATES, 0) + ['total' => 0];
        foreach ($vhosts as $name) {
            $keys = ["http://$name/", "https://$name/"];
            if (in_array($name, $hybrid, true)) {
                $row = ['vhost' => $name, 'state' => 'hybrid'];
            } elseif (isset($unprobed[$name])) {
                $row = ['vhost' => $name, 'state' => 'unprobed', 'reason' => $unprobed[$name]];
            } else {
                $requests = [];
                foreach ($keys as $key) {
                    $requests[] = ['request' => $key, 'apache' => $apache[$key] ?? '000', 'ols' => $ols[$key] ?? '000'];
                }
                $baseline = array_column($requests, 'apache', 'request');
                $now = array_column($requests, 'ols', 'request');
                $different = Cutover::differences($baseline, $now);
                $state = in_array('000', $baseline, true) ? 'apache_silent' : ($different === [] ? 'same' : 'different');
                $row = ['vhost' => $name, 'state' => $state, 'requests' => $requests];
            }
            $sites[] = $row;
            ++$summary[$row['state']];
            ++$summary['total'];
        }
        return ['sites' => $sites, 'summary' => $summary];
    }

    /**
     * @return array<string,mixed> the stored result ("state": complete | failed); refusals throw DeploymentError
     */
    public function run(string $planId): array
    {
        $this->env->requireRoot();
        $planner = new CutoverPlan($this->env);
        $plan = $planner->load($planId);
        $lock = $this->env->lock();
        $started = hrtime(true);
        $root = $this->env->state . '/preview';
        try {
            $this->preflight();
            $compiled = $planner->compile($plan['profile']['hybrid_ports']);
            if (!hash_equals($plan['compile_sha256'], CutoverPlan::digest($compiled, $planner->referencedFiles($compiled)))) {
                throw DeploymentError::refused("the cPanel state or a certificate, key or password file it references changed since plan "
                    . "$planId was prepared; run install --prepare again");
            }
            $vhosts = array_map('strval', array_keys($compiled['plan']));
            $hybrid = array_column($plan['hybrid_vhosts'], 'vhost');
            $asked = array_values(array_diff($vhosts, $hybrid));
            $apache = $this->apacheAnswers($compiled['plan'], $asked, $root);
            self::clear($root);  // left by an earlier run that was killed
            Environment::ensureDir($root, self::ROOT_MODE);
            $result = $this->serve($compiled, $asked, $root);
            $left = self::clear($root);
            $result['cleanup'] = $left === null ? 'removed' : "not removed: $left";
            $result += ['plan' => $planId, 'schema_version' => self::SCHEMA_VERSION, 'compile_sha256' => $plan['compile_sha256'],
                'created' => gmdate('c', $this->env->now()), 'seconds' => round((hrtime(true) - $started) / 1e9, 1)];
            if ($result['state'] === 'complete') {
                $result += self::compare($vhosts, $hybrid, $result['unprobed'], $apache, $result['answers']);
            }
            unset($result['answers'], $result['unprobed']);
            $this->store($planId, $result);
            return $result;
        } finally {
            self::clear($root);
            fclose($lock);
        }
    }

    /** Before the switch only: no profile, OLS stopped, the OLS binary installed. */
    private function preflight(): void
    {
        try {
            $profile = Profile::load($this->env->profilePath());
        } catch (\RuntimeException $error) {
            throw DeploymentError::refused($error->getMessage());
        }
        if ($profile !== null) {
            throw DeploymentError::refused('already cut over (' . $this->env->profilePath() . ' exists): a preview is for the time before the switch');
        }
        if ($this->env->host->unitActive(CutoverPlan::OLS_UNIT, 'ols-stopped')) {
            throw DeploymentError::refused(CutoverPlan::OLS_UNIT . ' is running; a preview is for the time before the switch');
        }
        if (!is_file($this->binary) || !is_dir($this->liveRoot)) {
            throw DeploymentError::refused('the OpenLiteSpeed binary is not installed');
        }
    }

    /**
     * Apache's status for every request, recorded like the cutover's baseline (same requests, parallel).
     * @param array<string,array<string,mixed>> $plan
     * @param list<string> $asked
     * @return array<string,string>
     */
    private function apacheAnswers(array $plan, array $asked, string $dir): array
    {
        Environment::ensureDir($dir, self::ROOT_MODE);
        $lines = [];
        foreach ($asked as $name) {
            $ip = self::addressOf($plan[$name] ?? []);
            $lines[] = "http $name $ip 80";
            $lines[] = "https $name $ip 443";
        }
        $file = "$dir/apache.probes";
        Environment::writeFile($file, implode("\n", $lines) . "\n", 0600);
        $script = 'PROBES=$1; export PROBES; timeout 60 ' . sprintf(self::PROBE, self::PARALLEL, self::REQUEST_SECONDS);
        $run = $this->env->host->run('preview-apache', ['/bin/sh', '-c', $script, 'sh', $file], 90);
        return self::parseAnswers($run['stdout']);
    }

    /**
     * Starts the prepared generation on loopback ports in the private namespace, asks it, stops it.
     * @param array<string,mixed> $compiled
     * @param list<string> $asked
     * @return array<string,mixed> state, ports, answers, unprobed (or reason and log on a failure)
     */
    private function serve(array $compiled, array $asked, string $root): array
    {
        $host = $this->env->host;
        $table = $host->run('preview-ports', ['/usr/sbin/ss', '-H', '-ltn']);
        if ($table['exit_code'] !== 0) {
            throw DeploymentError::step('preview-ports', 'ss failed');
        }
        // One listener per IPv4 address and port (the compile adds loopback's beside several addresses) plus the generation
        // marker's: a reserve of ports, of which the rewrite uses what the listeners need.
        $addresses = array_unique(array_map(static fn(array $v): string => self::addressOf($v), $compiled['plan']));
        $ports = PreviewPorts::pick((count($addresses) + 1) * 2 + 1, PreviewPorts::listening($table['stdout']), $this->random);
        $gen = "$root/gen";
        try {
            $tree = (new GenerationTree($gen))->build($compiled, 'preview');
            $rewritten = PreviewConfig::rewrite($tree['files']['httpd_config.conf'], $ports);
            $tree['files']['httpd_config.conf'] = $rewritten['config'];
            Environment::ensureDir($gen, self::ROOT_MODE);
            LocalEngine::writeTree("$gen/preview", $tree['files'], $tree['health'], 0, str_repeat('0', 64));
        } catch (\InvalidArgumentException | EngineError $error) {
            throw DeploymentError::refused('the prepared configuration could not be staged for the preview: ' . $error->getMessage());
        }
        $used = array_column($rewritten['listeners'], 'new');
        $this->stage("$root/server", $rewritten['config']);
        $unprobed = [];
        $probes = [];
        foreach ($asked as $name) {
            $ip = self::addressOf($compiled['plan'][$name] ?? []);
            $http = PreviewConfig::portFor($rewritten['listeners'], $ip, 80);
            $https = PreviewConfig::portFor($rewritten['listeners'], $ip, 443);
            if ($http === null || $https === null) {
                $unprobed[$name] = 'no IPv4 listener on port ' . ($http === null ? 80 : 443) . " maps $ip";
                continue;
            }
            $probes[] = "http $name 127.0.0.1 $http";
            $probes[] = "https $name 127.0.0.1 $https";
        }
        $first = null;
        foreach ($rewritten['listeners'] as $listener) {
            if ($listener['port'] === 80) {
                $first = $listener['new'];
                break;
            }
        }
        $first ??= $used[0] ?? null;
        Environment::writeFile("$root/ols.probes", implode("\n", $probes) . "\n", 0600);
        $texts = [$rewritten['config']];
        foreach ($tree['files'] as $path => $text) {
            if (str_starts_with($path, 'vhosts/')) {
                $texts[] = $text;
            }
        }
        $base = ['ports' => ['bind' => '127.0.0.1', 'listeners' => array_values(array_map(
            static fn(array $l): array => ['address' => $l['address'] . ':' . $l['port'], 'port' => $l['new']], $rewritten['listeners']))]];
        if ($first === null) {
            return $base + ['state' => 'failed', 'reason' => 'the configuration has no IPv4 listener to start on'];
        }
        $users = [];
        foreach ($asked as $name) {
            $users[] = (string) ($compiled['plan'][$name]['user'] ?? '');
        }
        $web = PreviewConfig::webUser($rewritten['config']);
        $groups = PreviewConfig::accountGroups($users, (string) @file_get_contents($this->passwd), (string) @file_get_contents($this->group));
        $argv = [self::UNSHARE, '--mount', '--pid', '--fork', '--kill-child', '--mount-proc', '--propagation', 'private',
            '/bin/sh', '-c', self::inner(), 'sh', "$root/server", implode(' ', $used), "$root/ols.probes", (string) $first, $this->binary,
            ...PreviewConfig::mounts($texts, $this->env->cacheRoot),
            ...($web !== null && $groups !== [] ? ["u:$web", ...array_map(static fn(string $g): string => "g:$g", $groups)] : [])];
        $run = $host->run('preview-ols', array_values($argv), self::TIMEOUT);
        $out = $run['stdout'];
        if (preg_match('/^PREVIEW-FAILED (.*)$/m', $out, $m)) {
            preg_match_all('/^PREVIEW-LOG (.*)$/m', $out, $log);
            return $base + ['state' => 'failed', 'reason' => Host::tail($m[1]), 'log' => array_map([Host::class, 'tail'], array_slice($log[1], -15))];
        }
        if (!str_contains($out, 'PREVIEW-READY') || !str_contains($out, 'PREVIEW-STOPPED') || $run['exit_code'] !== 0) {
            return $base + ['state' => 'failed', 'reason' => 'the preview did not finish (exit ' . $run['exit_code'] . '): '
                . Host::tail(($run['stderr'] ?? '') . ' ' . $out)];
        }
        preg_match_all('/^PREVIEW-LOG (.*)$/m', $out, $log);
        return $base + ['state' => 'complete', 'answers' => self::parseAnswers($out), 'unprobed' => $unprobed,
            'log' => array_map([Host::class, 'tail'], array_slice($log[1], -40))];
    }

    /**
     * The private server root: writable directories, the live root's other entries linked (read-only use), the
     * rewritten main configuration, and the live mime.properties.
     */
    private function stage(string $dir, string $config): void
    {
        Environment::ensureDir($dir, 0755);
        foreach (self::WRITABLE as $name) {
            Environment::ensureDir("$dir/$name", 0755);
        }
        foreach (['admin/conf', 'admin/tmp', 'admin/logs', 'admin/cgid', 'conf'] as $name) {
            Environment::ensureDir("$dir/$name", 0755);
        }
        foreach (scandir($this->liveRoot) ?: [] as $entry) {
            if ($entry === '.' || $entry === '..' || in_array($entry, [...self::WRITABLE, 'conf'], true) || !preg_match('/^[A-Za-z0-9._-]+$/D', $entry)) {
                continue;
            }
            if (!@symlink("{$this->liveRoot}/$entry", "$dir/$entry")) {
                throw DeploymentError::refused("cannot link $entry into the preview root");
            }
        }
        Environment::writeFile("$dir/conf/httpd_config.conf", $config, 0644);
        $mime = "{$this->liveRoot}/conf/mime.properties";
        if (is_file($mime)) {
            Environment::writeFile("$dir/conf/mime.properties", (string) file_get_contents($mime), 0644);
        }
    }

    /** @param array<string,mixed> $result */
    private function store(string $planId, array $result): void
    {
        $dir = $this->env->state . '/previews';
        Environment::ensureDir($dir, 0700);
        Environment::writeFile(self::path($this->env, $planId), Environment::json($result), 0600);
        // Previews of plans that no longer exist are not kept.
        foreach (scandir($dir) ?: [] as $name) {
            if (preg_match('/^(p\d{14}-[0-9a-f]{6})\.json$/D', $name, $m) && !is_file($this->env->plansDir() . "/{$m[1]}.json")) {
                @unlink("$dir/$name");
            }
        }
    }

    /** The address a vhost is requested at (the cutover's rule): its own IPv4 address, else loopback. */
    private static function addressOf(array $vhost): string
    {
        return is_string($vhost['ip'] ?? null) && $vhost['ip'] !== '' ? $vhost['ip'] : '127.0.0.1';
    }

    /**
     * "<scheme>://<host>/ <status>" lines; a status that is not three digits counts as no answer.
     * @return array<string,string>
     */
    public static function parseAnswers(string $text): array
    {
        $out = [];
        foreach (explode("\n", $text) as $line) {
            if (preg_match('#^(https?://[a-z0-9.-]+/)(?: (\S*))?$#D', trim($line), $m)) {
                $out[$m[1]] = preg_match('/^\d{3}$/D', $m[2] ?? '') === 1 ? $m[2] : '000';
            }
        }
        return $out;
    }
}
