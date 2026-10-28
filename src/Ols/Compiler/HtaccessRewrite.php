<?php
declare(strict_types=1);

namespace OlsCpanel\Ols\Compiler;

/**
 * Safe rewrite of a tenant's own .htaccess with a backup and an exact undo (FV-08). It runs inside the cPanel
 * plugin page, which LivePHP executes as the logged-in account, so every read and write below is made with the
 * account's own privileges: root never writes into a home, and no other account's file is reachable.
 *
 * The advisor offers a rewrite only where the new text means exactly what the author wrote and Apache accepts it
 * (proposal()). Cases it can rewrite:
 *  - "bom": a UTF-8 byte order mark at the start of the file glues itself to the first directive (or turns a comment
 *    into an unknown directive); the mark is removed.
 *  - "cr_line_endings": a file whose lines end with a lone carriage return (old Mac editors) is one long line for
 *    Apache; each lone CR becomes a line feed. Applied only when the file has no line feed at all.
 * Nothing else is rewritten: a directive the advisor reports as unsupported stays the owner's decision.
 *
 * Scope. The path is the advisor's display form "~/dir/.htaccess"; it must be a file named .htaccess below one of
 * the account's own site document roots, with no link in any component below the home, at most MAX_BYTES long.
 * apply() refuses when the file's SHA-256 is not the one the advisor read, stores the original bytes in
 * ~/.ols-cpanel/htaccess-backups/ (0700, 0600 files, never through a link), writes the new text to a temporary file
 * next to the original and renames it into place. undo() restores the stored bytes exactly, and only when the file
 * still is what apply() wrote.
 *
 * Concurrency. apply() and undo() run under an exclusive per-account lock (~/.ols-cpanel/htaccess.lock), so two of
 * them never interleave. The file's digest is compared again immediately before the rename, after the temporary file
 * is complete, which leaves only the time between that last comparison and the rename call. An editor that saves
 * inside that interval, which is not bound by the lock, can still lose its save: the guarantee is "a changed file is
 * refused, and the window for a missed change is the few instructions between the last comparison and the rename",
 * not an absolute one. The original bytes are always in the backup.
 *
 * Links. PHP has no openat(), so a component of the path cannot be held open while the file is replaced. The
 * strongest practical check is made: every directory below the home is pinned during the walk by its (device,
 * inode), and before each read and before the rename the pins are compared again with lstat (a component that became
 * a link or another directory is refused), the real path of the directory is compared with the one seen during the
 * walk, and the file is opened and compared with lstat to rule out a link swapped in between. A race inside those
 * checks remains possible, but the process runs as the account, so at most the account's own files are affected.
 */
final class HtaccessRewrite
{
    public const MAX_BYTES = 262144;
    public const BACKUP_DIR = '.ols-cpanel/htaccess-backups';
    public const KEEP = 50;
    private const PATH_RE = '/^~\/((?:[A-Za-z0-9._-]{1,100}\/){0,20})\.htaccess$/D';
    private const ID_RE = '/^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$/D';
    public const LOCK_FILE = '.ols-cpanel/htaccess.lock';
    /** Seconds apply() and undo() wait for another change of the same account to finish. */
    public const LOCK_WAIT = 5;
    private const BOM = "\xEF\xBB\xBF";

    private readonly string $home;
    /** @var list<array{0:string,1:int,2:int}> path, device and inode of the home and of every directory of the last resolve() */
    private array $pins = [];
    private string $realDir = '';

    public function __construct(string $home)
    {
        $this->home = rtrim($home, '/');
        if ($this->home === '' || $this->home[0] !== '/') {
            throw new HtaccessRewriteRefused('HOME', 'The home directory is unknown.');
        }
    }

    /** @return array{text:string,rules:list<string>}|null the rewritten text and the rules applied, or null */
    public static function proposal(string $text): ?array
    {
        $rules = [];
        if (str_starts_with($text, self::BOM)) {
            $text = substr($text, 3);
            $rules[] = 'bom';
        }
        if (!str_contains($text, "\n") && str_contains($text, "\r")) {
            $text = str_replace("\r", "\n", $text);
            $rules[] = 'cr_line_endings';
        }
        return $rules === [] ? null : ['text' => $text, 'rules' => $rules];
    }

    public static function digest(string $bytes): string
    {
        return hash('sha256', $bytes);
    }

    /**
     * The absolute path of a display path inside one of the account's document roots; every component below the
     * home must be a real directory and the file a regular file.
     *
     * @param list<string> $docroots
     */
    public function resolve(string $display, array $docroots): string
    {
        if (preg_match(self::PATH_RE, $display, $m) !== 1 || preg_match('#(?:^|/)\.\.?(?:/|$)#', $m[1]) === 1) {
            throw new HtaccessRewriteRefused('BAD_PATH', 'That is not an .htaccess path of this account.');
        }
        $path = $this->home . '/' . $m[1] . '.htaccess';
        $inside = false;
        foreach ($docroots as $root) {
            $root = rtrim($root, '/');
            if ($root !== '' && ($root === $this->home || str_starts_with($root, $this->home . '/'))
                && str_starts_with($path, $root . '/')) {
                $inside = true;
                break;
            }
        }
        if (!$inside) {
            throw new HtaccessRewriteRefused('OUT_OF_SCOPE', 'That file is not inside one of your site folders.');
        }
        $walk = $this->home;
        $home = @stat($this->home);
        if ($home === false || ($home['mode'] & 0170000) !== 0040000) {
            throw new HtaccessRewriteRefused('HOME', 'The home directory is not usable.');
        }
        $pins = [[$walk, (int) $home['dev'], (int) $home['ino']]];
        $parts = array_values(array_filter(explode('/', rtrim($m[1], '/') . '/.htaccess'), static fn(string $p): bool => $p !== ''));
        foreach ($parts as $index => $part) {
            $walk .= '/' . $part;
            $st = @lstat($walk);
            if ($st !== false && ($st['mode'] & 0170000) === 0120000) {
                throw new HtaccessRewriteRefused('LINK', 'The path contains a link, which is never followed.');
            }
            $last = $index === count($parts) - 1;
            if ($st === false || ($st['mode'] & 0170000) !== ($last ? 0100000 : 0040000)) {
                throw new HtaccessRewriteRefused('NOT_FOUND', 'The file does not exist.');
            }
            if (!$last) {
                $pins[] = [$walk, (int) $st['dev'], (int) $st['ino']];
            }
        }
        $real = realpath(dirname($path));
        if ($real === false) {
            throw new HtaccessRewriteRefused('NOT_FOUND', 'The file does not exist.');
        }
        $this->pins = $pins;
        $this->realDir = $real;
        return $path;
    }

    /** Refuses when anything on the way to `$path` is no longer what resolve() saw (see the class comment, "Links"). */
    private function verify(string $path): void
    {
        $moved = static fn(): HtaccessRewriteRefused => new HtaccessRewriteRefused('LINK', 'The folder changed while the file was being handled; nothing was written.');
        if ($this->pins === []) {
            throw $moved();
        }
        foreach ($this->pins as $index => [$dir, $dev, $ino]) {
            $st = $index === 0 ? @stat($dir) : @lstat($dir);
            if ($st === false || ($st['mode'] & 0170000) !== 0040000 || (int) $st['dev'] !== $dev || (int) $st['ino'] !== $ino) {
                throw $moved();
            }
        }
        if (realpath(dirname($path)) !== $this->realDir) {
            throw $moved();
        }
        $file = @lstat($path);
        if ($file === false || ($file['mode'] & 0170000) !== 0100000) {
            throw $moved();
        }
    }

    /** Runs `$work` holding the account's exclusive htaccess lock; BUSY when another change does not finish in LOCK_WAIT seconds. */
    private function locked(\Closure $work): mixed
    {
        $lockPath = $this->home . '/' . self::LOCK_FILE;
        $this->backupDir();  // creates and checks ~/.ols-cpanel
        if (is_link($lockPath)) {
            throw new HtaccessRewriteRefused('BACKUP', 'The lock file is not usable.');
        }
        $previous = umask(0077);
        try {
            $handle = @fopen($lockPath, 'cb');
        } finally {
            umask($previous);
        }
        if ($handle === false) {
            throw new HtaccessRewriteRefused('BACKUP', 'The lock file cannot be opened.');
        }
        $deadline = microtime(true) + self::LOCK_WAIT;
        while (!flock($handle, LOCK_EX | LOCK_NB)) {
            if (microtime(true) >= $deadline) {
                fclose($handle);
                throw new HtaccessRewriteRefused('BUSY', 'Another change to your .htaccess files is in progress; try again in a moment.');
            }
            usleep(50000);
        }
        try {
            return $work();
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
    }

    private function read(string $path): string
    {
        $this->verify($path);
        $handle = @fopen($path, 'rb');
        $open = $handle === false ? false : fstat($handle);
        $named = @lstat($path);
        if ($handle === false || $open === false || $named === false || $open['ino'] !== $named['ino'] || $open['dev'] !== $named['dev']
            || ($named['mode'] & 0170000) !== 0100000) {
            if ($handle !== false) {
                fclose($handle);
            }
            throw new HtaccessRewriteRefused('UNREADABLE', 'The file cannot be read or changed while it was opened.');
        }
        $bytes = $open['size'] <= self::MAX_BYTES ? stream_get_contents($handle, self::MAX_BYTES + 1) : false;
        fclose($handle);
        if ($bytes === false || strlen($bytes) > self::MAX_BYTES) {
            throw new HtaccessRewriteRefused('UNREADABLE', 'The file cannot be read or is larger than 256 KiB.');
        }
        return $bytes;
    }

    private function backupDir(): string
    {
        $dir = $this->home;
        foreach (explode('/', self::BACKUP_DIR) as $part) {
            $dir .= '/' . $part;
            if (is_link($dir) || (file_exists($dir) && !is_dir($dir))) {
                throw new HtaccessRewriteRefused('BACKUP', 'The backup folder is not usable.');
            }
            if (!is_dir($dir) && !@mkdir($dir, 0700) && !is_dir($dir)) {
                throw new HtaccessRewriteRefused('BACKUP', 'The backup folder cannot be created.');
            }
        }
        @chmod($dir, 0700);
        return $dir;
    }

    /** Writes `$bytes` to a new file (never an existing one) with `$mode`. */
    private function create(string $path, string $bytes, int $mode): void
    {
        // Created private whatever the umask is; the final mode is set below, before the file is renamed into place.
        $previous = umask(0077);
        try {
            $h = @fopen($path, 'xb');
        } finally {
            umask($previous);
        }
        if ($h === false) {
            throw new HtaccessRewriteRefused('WRITE', 'A file could not be created.');
        }
        $ok = fwrite($h, $bytes) === strlen($bytes) && fflush($h) && @fsync($h);
        fclose($h);
        if (!$ok || !@chmod($path, $mode)) {
            @unlink($path);
            throw new HtaccessRewriteRefused('WRITE', 'A file could not be written.');
        }
    }

    /**
     * Replaces `$path` with `$bytes` (same directory, atomic rename), keeping its permissions, only when the file still has
     * the digest `$expected`: it is compared again after the temporary file is complete, immediately before the rename.
     */
    private function replace(string $path, string $bytes, string $expected): void
    {
        $mode = (@fileperms($path) ?: 0644) & 0777;
        $temp = dirname($path) . '/.htaccess.ols-' . bin2hex(random_bytes(6));
        $this->create($temp, $bytes, $mode);
        try {
            if (!hash_equals($expected, self::digest($this->read($path)))) {
                throw new HtaccessRewriteRefused('STALE', 'The file changed since it was checked; check it again.');
            }
        } catch (HtaccessRewriteRefused $refused) {
            @unlink($temp);
            throw $refused;
        }
        if (!@rename($temp, $path)) {
            @unlink($temp);
            throw new HtaccessRewriteRefused('WRITE', 'The file could not be replaced.');
        }
    }

    /**
     * @param list<string> $docroots
     * @return array{id:string,path:string,before_digest:string,after_digest:string,rules:list<string>}
     */
    public function apply(string $display, string $expectedDigest, array $docroots): array
    {
        return $this->locked(fn(): array => $this->applyLocked($display, $expectedDigest, $docroots));
    }

    /**
     * @param list<string> $docroots
     * @return array{id:string,path:string,before_digest:string,after_digest:string,rules:list<string>}
     */
    private function applyLocked(string $display, string $expectedDigest, array $docroots): array
    {
        $path = $this->resolve($display, $docroots);
        $before = $this->read($path);
        if (!hash_equals(self::digest($before), $expectedDigest)) {
            throw new HtaccessRewriteRefused('STALE', 'The file changed since it was checked; check it again.');
        }
        $proposal = self::proposal($before);
        if ($proposal === null) {
            throw new HtaccessRewriteRefused('NO_REWRITE', 'There is nothing to rewrite safely in this file.');
        }
        $dir = $this->backupDir();
        $id = gmdate('Ymd\THis\Z') . '-' . bin2hex(random_bytes(4));
        $meta = ['id' => $id, 'path' => $display, 'before_digest' => self::digest($before),
                 'after_digest' => self::digest($proposal['text']), 'rules' => $proposal['rules'], 'applied_at' => time(), 'undone_at' => null];
        $this->create("$dir/$id.bak", $before, 0600);
        $this->create("$dir/$id.json", json_encode($meta, JSON_THROW_ON_ERROR), 0600);
        try {
            // The digest is checked once more, right before the rename.
            $this->replace($path, $proposal['text'], $meta['before_digest']);
        } catch (HtaccessRewriteRefused $refused) {
            @unlink("$dir/$id.bak");
            @unlink("$dir/$id.json");
            throw $refused;
        }
        $this->prune($dir);
        return ['id' => $id, 'path' => $display, 'before_digest' => $meta['before_digest'], 'after_digest' => $meta['after_digest'],
                'rules' => $proposal['rules']];
    }

    /**
     * Restores the stored bytes of one apply() exactly.
     *
     * @param list<string> $docroots
     * @return array{id:string,path:string,digest:string}
     */
    public function undo(string $id, array $docroots): array
    {
        return $this->locked(fn(): array => $this->undoLocked($id, $docroots));
    }

    /**
     * @param list<string> $docroots
     * @return array{id:string,path:string,digest:string}
     */
    private function undoLocked(string $id, array $docroots): array
    {
        $meta = $this->meta($id);
        if ($meta === null || $meta['undone_at'] !== null) {
            throw new HtaccessRewriteRefused('NOT_FOUND', 'There is no such change to undo.');
        }
        $path = $this->resolve($meta['path'], $docroots);
        if (!hash_equals($meta['after_digest'], self::digest($this->read($path)))) {
            throw new HtaccessRewriteRefused('STALE', 'The file was edited after the change; undoing would lose that edit.');
        }
        $dir = $this->backupDir();
        $backup = @file_get_contents("$dir/$id.bak");
        if ($backup === false || !hash_equals($meta['before_digest'], self::digest($backup))) {
            throw new HtaccessRewriteRefused('CORRUPT', 'The backup copy is missing or damaged.');
        }
        $this->replace($path, $backup, $meta['after_digest']);
        $meta['undone_at'] = time();
        $json = "$dir/$id.json";
        @unlink($json);
        $this->create($json, json_encode($meta, JSON_THROW_ON_ERROR), 0600);
        return ['id' => $id, 'path' => $meta['path'], 'digest' => $meta['before_digest']];
    }

    /** @return array<string,mixed>|null */
    private function meta(string $id): ?array
    {
        if (preg_match(self::ID_RE, $id) !== 1) {
            return null;
        }
        $text = @file_get_contents($this->home . '/' . self::BACKUP_DIR . "/$id.json", false, null, 0, 4096);
        $meta = is_string($text) ? json_decode($text, true) : null;
        $ok = is_array($meta) && ($meta['id'] ?? null) === $id && is_string($meta['path'] ?? null)
            && preg_match('/^[0-9a-f]{64}$/D', (string) ($meta['before_digest'] ?? '')) === 1
            && preg_match('/^[0-9a-f]{64}$/D', (string) ($meta['after_digest'] ?? '')) === 1;
        return $ok ? $meta + ['undone_at' => null, 'applied_at' => 0, 'rules' => []] : null;
    }

    /** @return list<array{id:string,path:string,applied_at:int,undone:bool,rules:list<string>}> newest first */
    public function backups(): array
    {
        $dir = $this->home . '/' . self::BACKUP_DIR;
        if (is_link($dir) || !is_dir($dir)) {
            return [];
        }
        $ids = [];
        foreach (scandir($dir) ?: [] as $name) {
            if (str_ends_with($name, '.json') && preg_match(self::ID_RE, substr($name, 0, -5)) === 1) {
                $ids[] = substr($name, 0, -5);
            }
        }
        rsort($ids);
        $out = [];
        foreach (array_slice($ids, 0, self::KEEP) as $id) {
            $meta = $this->meta($id);
            if ($meta !== null) {
                $out[] = ['id' => $id, 'path' => $meta['path'], 'applied_at' => (int) $meta['applied_at'],
                          'undone' => $meta['undone_at'] !== null, 'rules' => array_values((array) $meta['rules'])];
            }
        }
        return $out;
    }

    private function prune(string $dir): void
    {
        $ids = [];
        foreach (scandir($dir) ?: [] as $name) {
            if (str_ends_with($name, '.json') && preg_match(self::ID_RE, substr($name, 0, -5)) === 1) {
                $ids[] = substr($name, 0, -5);
            }
        }
        rsort($ids);
        foreach (array_slice($ids, self::KEEP) as $old) {
            @unlink("$dir/$old.bak");
            @unlink("$dir/$old.json");
        }
    }
}

final class HtaccessRewriteRefused extends \RuntimeException
{
    public function __construct(public readonly string $reason, string $message)
    {
        parent::__construct($message);
    }
}
