<?php
declare(strict_types=1);

// FV-08: the safe .htaccess rewrite with backup and undo (src/Ols/Compiler/HtaccessRewrite.php) against temporary homes.
require dirname(__DIR__) . '/src/bootstrap.php';

use OlsCpanel\Ols\Compiler\HtaccessRewrite;
use OlsCpanel\Ols\Compiler\HtaccessRewriteRefused;
use OlsCpanel\Ols\Compiler\HtaccessTranslator;

$count = 0;
function check(bool $condition, string $name): void
{
    global $count;
    if (!$condition) {
        throw new RuntimeException('FAIL: ' . $name);
    }
    ++$count;
}

function refused(callable $call, string $reason, string $name): void
{
    try {
        $call();
    } catch (HtaccessRewriteRefused $e) {
        check($e->reason === $reason, "$name (got {$e->reason})");
        return;
    }
    check(false, "$name (not refused)");
}

function rmtree(string $path): void
{
    if (is_link($path) || is_file($path)) {
        unlink($path);
        return;
    }
    foreach (scandir($path) ?: [] as $name) {
        if ($name !== '.' && $name !== '..') {
            rmtree("$path/$name");
        }
    }
    rmdir($path);
}

$base = sys_get_temp_dir() . '/ols-htaccess-rewrite-' . getmypid();
mkdir($base, 0700);
register_shutdown_function(static fn() => rmtree($base));
$home = "$base/home/olscpa";
$other = "$base/home/olscpb";
foreach ([$home . '/public_html/shop', $home . '/private', $other . '/public_html'] as $dir) {
    mkdir($dir, 0755, true);
}
$docroots = ["$home/public_html", "$home/public_html/shop"];
$rewrite = new HtaccessRewrite($home);

// The rewrites: exactly the two documented ones, nothing else.
$bom = "\xEF\xBB\xBF# cache rules\nExpiresActive On\nExpiresByType image/png \"access plus 1 month\"\n";
$translator = new HtaccessTranslator();
[, , $before] = $translator->translate(['' => $bom], '/home/olscpa/public_html');
$proposal = HtaccessRewrite::proposal($bom);
[, , $after] = $translator->translate(['' => $proposal['text']], '/home/olscpa/public_html');
check($before !== [] && $after === [] && $proposal['rules'] === ['bom'], 'a byte order mark is the translator\'s blocker and the rewrite removes it');
check($proposal['text'] === substr($bom, 3), 'only the three bytes are removed');
$mac = "RewriteEngine On\rRewriteRule ^a$ /b [L]\r";
check(HtaccessRewrite::proposal($mac) === ['text' => "RewriteEngine On\nRewriteRule ^a$ /b [L]\n", 'rules' => ['cr_line_endings']], 'lone CR line endings');
foreach (["RewriteEngine On\r\nRewriteRule ^a$ /b [L]\r\n", "a\r\nb\rc\n", "Header set X-Y z\n", "php_value x 1\n", "", "# \xEF\xBB\xBF inside\n"] as $same) {
    check(HtaccessRewrite::proposal($same) === null, 'no rewrite for ' . json_encode($same));
}
check(HtaccessRewrite::proposal("\xEF\xBB\xBFa\rb")['rules'] === ['bom', 'cr_line_endings'], 'both rules');

// Apply: backup, new bytes, permissions kept.
$file = "$home/public_html/.htaccess";
file_put_contents($file, $bom);
chmod($file, 0640);
$digest = HtaccessRewrite::digest($bom);
$done = $rewrite->apply('~/public_html/.htaccess', $digest, $docroots);
check(file_get_contents($file) === substr($bom, 3), 'the file holds the rewritten text');
check((fileperms($file) & 0777) === 0640, 'permissions are kept');
check($done['before_digest'] === $digest && $done['after_digest'] === HtaccessRewrite::digest(substr($bom, 3)), 'digests are reported');
$dir = "$home/.ols-cpanel/htaccess-backups";
check(file_get_contents("$dir/{$done['id']}.bak") === $bom, 'the backup is the original bytes');
check((fileperms($dir) & 0777) === 0700 && (fileperms("$dir/{$done['id']}.bak") & 0777) === 0600, 'private backup folder and files');
check(glob("$home/public_html/.htaccess.ols-*") === [], 'no temporary file is left');
$list = $rewrite->backups();
check(count($list) === 1 && $list[0]['id'] === $done['id'] && $list[0]['path'] === '~/public_html/.htaccess' && !$list[0]['undone'], 'the backup is listed');

// Undo restores the bytes exactly, once.
$edited = file_get_contents($file) . "# edit\n";
file_put_contents($file, $edited);
refused(fn() => $rewrite->undo($done['id'], $docroots), 'STALE', 'undo after a later edit');
file_put_contents($file, substr($bom, 3));
$undone = $rewrite->undo($done['id'], $docroots);
check(file_get_contents($file) === $bom && HtaccessRewrite::digest(file_get_contents($file)) === $digest && $undone['digest'] === $digest, 'undo restores the bytes exactly');
check($rewrite->backups()[0]['undone'] === true, 'the undone change is marked');
refused(fn() => $rewrite->undo($done['id'], $docroots), 'NOT_FOUND', 'a change is undone once');

// Refusals: stale digest, nothing to rewrite, bad paths, other accounts, links, forged ids.
refused(fn() => $rewrite->apply('~/public_html/.htaccess', str_repeat('0', 64), $docroots), 'STALE', 'a changed file');
file_put_contents($file, "Header set X-Y z\n");
refused(fn() => $rewrite->apply('~/public_html/.htaccess', HtaccessRewrite::digest("Header set X-Y z\n"), $docroots), 'NO_REWRITE', 'nothing to rewrite');
file_put_contents($file, $bom);
foreach (['', '~/public_html/.htaccess/', '~/public_html/../../olscpb/public_html/.htaccess', '~/../olscpb/public_html/.htaccess',
          '/home/olscpa/public_html/.htaccess', "$home/public_html/.htaccess", '~/public_html/x.htaccess', '~/public_html/.htaccess ',
          "~/public_html/.htaccess\n", '~//public_html/.htaccess', '~/public_html/./.htaccess', '~/public_html/a b/.htaccess',
          '~/public_html/.htpasswd', '~/.bashrc', '~/public_html/%2e%2e/.htaccess', "~/public_html/\0/.htaccess"] as $bad) {
    refused(fn() => $rewrite->apply($bad, $digest, $docroots), $bad === '' || str_contains($bad, 'olscpb') || $bad === '~/.bashrc' ? 'BAD_PATH' : 'BAD_PATH', 'bad path ' . json_encode($bad));
}
file_put_contents("$home/.htaccess", $bom);
refused(fn() => $rewrite->apply('~/.htaccess', $digest, $docroots), 'OUT_OF_SCOPE', 'a file outside the site folders');
file_put_contents("$other/public_html/.htaccess", $bom);
refused(fn() => $rewrite->apply('~/public_html/.htaccess', $digest, ["$other/public_html"]), 'OUT_OF_SCOPE', 'a document root of another account');
refused(fn() => $rewrite->apply('~/public_html/.htaccess', $digest, ['/']), 'OUT_OF_SCOPE', 'a root that is not inside the home');
check(file_get_contents("$other/public_html/.htaccess") === $bom, 'another account\'s file is untouched');
// Links: a linked file, a linked directory, a linked backup folder; none is followed.
unlink($file);
file_put_contents("$other/public_html/.htaccess", $bom);
symlink("$other/public_html/.htaccess", $file);
refused(fn() => $rewrite->apply('~/public_html/.htaccess', $digest, $docroots), 'LINK', 'a linked file');
check(file_get_contents("$other/public_html/.htaccess") === $bom, 'the linked target is untouched');
unlink($file);
symlink("$other/public_html", "$home/public_html/linked");
refused(fn() => $rewrite->apply('~/public_html/linked/.htaccess', $digest, $docroots), 'LINK', 'a linked directory');
unlink("$home/public_html/linked");
file_put_contents("$home/public_html/shop/.htaccess", $bom);
rmtree("$home/.ols-cpanel");
mkdir("$base/elsewhere");
symlink("$base/elsewhere", "$home/.ols-cpanel");
refused(fn() => $rewrite->apply('~/public_html/shop/.htaccess', $digest, $docroots), 'BACKUP', 'a linked backup folder');
check(glob("$base/elsewhere/*") === [] && file_get_contents("$home/public_html/shop/.htaccess") === $bom, 'nothing was written through the link');
unlink("$home/.ols-cpanel");
// Forged undo ids never reach the file system.
foreach (['', '../x', '20261028T120000Z-zzzzzzzz', '20261028T120000Z-0000000', '../../etc/passwd', "20261028T120000Z-00000000\0"] as $id) {
    refused(fn() => $rewrite->undo($id, $docroots), 'NOT_FOUND', 'forged id ' . json_encode($id));
}
// A forged meta file naming another account's path is refused by the scope check.
$real = $rewrite->apply('~/public_html/shop/.htaccess', $digest, $docroots);
$metaFile = "$home/.ols-cpanel/htaccess-backups/{$real['id']}.json";
$meta = json_decode(file_get_contents($metaFile), true);
$meta['path'] = '~/../olscpb/public_html/.htaccess';
file_put_contents($metaFile, json_encode($meta));
refused(fn() => $rewrite->undo($real['id'], $docroots), 'BAD_PATH', 'a forged backup record');
$meta['path'] = '~/.htaccess';
file_put_contents($metaFile, json_encode($meta));
refused(fn() => $rewrite->undo($real['id'], $docroots), 'OUT_OF_SCOPE', 'a forged record outside the site folders');
// A damaged backup is refused and the file stays.
$meta['path'] = '~/public_html/shop/.htaccess';
file_put_contents($metaFile, json_encode($meta));
file_put_contents("$home/.ols-cpanel/htaccess-backups/{$real['id']}.bak", 'tampered');
refused(fn() => $rewrite->undo($real['id'], $docroots), 'CORRUPT', 'a damaged backup');
check(file_get_contents("$home/public_html/shop/.htaccess") === substr($bom, 3), 'the file stays when the backup is damaged');
// Size bound.
file_put_contents("$home/public_html/big/.htaccess" === '' ? '' : "$home/public_html/shop/.htaccess", "\xEF\xBB\xBF" . str_repeat('#', HtaccessRewrite::MAX_BYTES));
refused(fn() => $rewrite->apply('~/public_html/shop/.htaccess', str_repeat('0', 64), $docroots), 'UNREADABLE', 'a file over the size limit');
// Pruning keeps the newest backups.
$dirs = "$home/.ols-cpanel/htaccess-backups";
for ($i = 0; $i < HtaccessRewrite::KEEP + 5; ++$i) {
    $id = sprintf('202001%02dT000000Z-%08x', ($i % 28) + 1, $i);
    file_put_contents("$dirs/$id.bak", 'x');
    file_put_contents("$dirs/$id.json", json_encode(['id' => $id, 'path' => '~/.htaccess', 'before_digest' => str_repeat('a', 64),
        'after_digest' => str_repeat('b', 64), 'applied_at' => 1, 'undone_at' => null, 'rules' => []]));
}
file_put_contents("$home/public_html/shop/.htaccess", $bom);
$rewrite->apply('~/public_html/shop/.htaccess', $digest, $docroots);
check(count(glob("$dirs/*.json")) === HtaccessRewrite::KEEP && count(glob("$dirs/*.bak")) === HtaccessRewrite::KEEP, 'old backups are pruned');
try {
    new HtaccessRewrite('relative/home');
    check(false, 'a relative home is refused');
} catch (HtaccessRewriteRefused) {
    check(true, 'a relative home is refused');
}

// Review 8: umask, the per-account lock, the digest re-check before the rename and the pinned directories.
$old = umask(0000);
file_put_contents("$home/public_html/.htaccess", $bom);
chmod("$home/public_html/.htaccess", 0644);
$umaskDone = $rewrite->apply('~/public_html/.htaccess', HtaccessRewrite::digest($bom), $docroots);
check(umask() === 0000, 'the umask is restored');
check((fileperms("$home/.ols-cpanel/htaccess-backups/{$umaskDone['id']}.bak") & 0777) === 0600
    && (fileperms("$home/.ols-cpanel/htaccess.lock") & 0777) === 0600, 'files are created private even under umask 0');
check((fileperms("$home/public_html/.htaccess") & 0777) === 0644, 'the original mode is set before the rename');
umask($old);

$lock = fopen("$home/.ols-cpanel/htaccess.lock", 'cb');
flock($lock, LOCK_EX);
$started = microtime(true);
// A concurrent change holds the lock: refused as BUSY after the wait.
refused(fn() => $rewrite->undo($umaskDone['id'], $docroots), 'BUSY', 'a change while another holds the account lock');
check(microtime(true) - $started >= HtaccessRewrite::LOCK_WAIT - 0.5, 'the lock is waited for');
flock($lock, LOCK_UN);
fclose($lock);
$undoneAgain = $rewrite->undo($umaskDone['id'], $docroots);
check($undoneAgain['id'] === $umaskDone['id'] && file_get_contents("$home/public_html/.htaccess") === $bom, 'the lock is released and the change goes through');

// The digest is compared again right before the rename, and a pinned directory that changes is refused.
$guard = new HtaccessRewrite($home);
$resolve = new ReflectionMethod($guard, 'resolve');
$replace = new ReflectionMethod($guard, 'replace');
$path = $resolve->invoke($guard, '~/public_html/.htaccess', $docroots);
refused(fn() => $replace->invoke($guard, $path, 'new', str_repeat('0', 64)), 'STALE', 'replace refuses a file that no longer has the expected digest');
check(file_get_contents($path) === $bom && glob("$home/public_html/.htaccess.ols-*") === [], 'a refused replace leaves the file and no temporary file');
$replace->invoke($guard, $path, "swapped\n", HtaccessRewrite::digest($bom));
check(file_get_contents($path) === "swapped\n", 'replace writes when the digest matches');
file_put_contents($path, $bom);
rename("$home/public_html", "$home/public_html.real");
mkdir("$home/public_html");
file_put_contents("$home/public_html/.htaccess", $bom);
refused(fn() => $replace->invoke($guard, $path, 'new', HtaccessRewrite::digest($bom)), 'LINK', 'a directory replaced after the walk is refused');
rmtree("$home/public_html");
rename("$home/public_html.real", "$home/public_html");
$path = $resolve->invoke($guard, '~/public_html/.htaccess', $docroots);
rename("$home/public_html", "$home/public_html.real");
symlink("$home/public_html.real", "$home/public_html");
refused(fn() => $replace->invoke($guard, $path, 'new', HtaccessRewrite::digest($bom)), 'LINK', 'a link put in place of a directory after the walk is refused');
unlink("$home/public_html");
rename("$home/public_html.real", "$home/public_html");

echo "OK: $count checks\n";
