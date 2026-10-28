<?php
declare(strict_types=1);

namespace OlsCpanel\Infrastructure\System;

/**
 * Which processes listen on TCP ports (for `status`: who owns 80/443), from /proc: the listening sockets
 * of /proc/net/tcp and tcp6, matched to processes through their /proc/<pid>/fd links. Only root sees
 * every process's descriptors; for anyone else unmatched sockets are reported as "unknown".
 */
final class PortOwners
{
    public function __construct(private readonly string $proc = '/proc')
    {
    }

    /**
     * @param list<int> $ports
     * @return array<int,list<string>> port => sorted process names ("unknown" when not visible); [] when free
     */
    public function owners(array $ports): array
    {
        $inodes = [];
        foreach (['tcp', 'tcp6'] as $table) {
            $lines = @file("{$this->proc}/net/$table", FILE_IGNORE_NEW_LINES) ?: [];
            foreach (array_slice($lines, 1) as $line) {
                $fields = preg_split('/\s+/', trim($line)) ?: [];
                // local_address is HEXADDR:HEXPORT; state 0A is LISTEN; field 9 is the socket inode.
                if (count($fields) > 9 && $fields[3] === '0A') {
                    $port = hexdec(substr($fields[1], strrpos($fields[1], ':') + 1));
                    if (in_array($port, $ports, true)) {
                        $inodes[$fields[9]] = $port;
                    }
                }
            }
        }
        $owners = array_fill_keys($ports, []);
        $found = [];
        if ($inodes !== []) {
            foreach (@scandir($this->proc) ?: [] as $pid) {
                if (!ctype_digit($pid)) {
                    continue;
                }
                foreach (@scandir("{$this->proc}/$pid/fd") ?: [] as $fd) {
                    $link = @readlink("{$this->proc}/$pid/fd/$fd");
                    if (is_string($link) && preg_match('/^socket:\[([0-9]+)\]$/D', $link, $m) && isset($inodes[$m[1]])) {
                        $name = trim((string) @file_get_contents("{$this->proc}/$pid/comm")) ?: 'unknown';
                        $owners[$inodes[$m[1]]][] = $name;
                        $found[$m[1]] = true;
                    }
                }
            }
        }
        foreach ($inodes as $inode => $port) {
            if (!isset($found[$inode])) {
                $owners[$port][] = 'unknown';
            }
        }
        foreach ($owners as $port => $names) {
            $names = array_values(array_unique($names));
            sort($names, SORT_STRING);
            $owners[$port] = $names;
        }
        return $owners;
    }
}
