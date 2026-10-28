<?php
declare(strict_types=1);

namespace OlsCpanel\Ui;

/**
 * Script and stylesheet tags for one prebuilt interface entry, from the Vite build manifest
 * (hashed names; plan 21.3). Paths are relative to the host page so they stay inside the
 * session-prefixed WHM/cPanel URL.
 */
final class AssetManifest
{
    public function __construct(private readonly array $manifest)
    {
    }

    public static function fromFile(string $path): self
    {
        $data = is_file($path) ? json_decode((string) file_get_contents($path), true) : null;
        return new self(is_array($data) ? $data : []);
    }

    public function tags(string $entry): ?string
    {
        if (!isset($this->manifest[$entry]['file'])) {
            return null;
        }
        $css = [];
        $seen = [];
        $walk = function (string $key) use (&$walk, &$css, &$seen): void {
            if (isset($seen[$key]) || !isset($this->manifest[$key])) {
                return;
            }
            $seen[$key] = true;
            foreach ($this->manifest[$key]['imports'] ?? [] as $import) {
                $walk($import);
            }
            foreach ($this->manifest[$key]['css'] ?? [] as $file) {
                $css[$file] = true;
            }
        };
        $walk($entry);
        $out = '';
        foreach (array_keys($css) as $file) {
            $out .= '<link rel="stylesheet" href="' . htmlspecialchars($file, ENT_QUOTES) . "\">\n";
        }
        return $out . '<script type="module" src="' . htmlspecialchars($this->manifest[$entry]['file'], ENT_QUOTES) . "\"></script>\n";
    }
}
