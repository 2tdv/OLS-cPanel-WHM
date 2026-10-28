<?php
declare(strict_types=1);

namespace OlsCpanel\Ols\Compiler;

/**
 * The configuration cannot be compiled without changing what cPanel's Apache serves (fail closed):
 * malformed cPanel state, an unsupported PHP handler, an .htaccess that cannot be read or translated
 * completely, or a generated configuration that fails lint. Nothing is applied.
 */
final class CompilationRefused extends \RuntimeException
{
    /** @var list<string> */
    private array $vhosts;

    /** @param list<string> $vhosts vhosts that must stay on Apache (empty when the refusal is global) */
    public function __construct(string $message, array $vhosts = [], ?\Throwable $previous = null)
    {
        parent::__construct($message, 0, $previous);
        $this->vhosts = $vhosts;
    }

    /** @return list<string> */
    public function vhosts(): array
    {
        return $this->vhosts;
    }
}
